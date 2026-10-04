#!/usr/bin/env python3
"""Run a real Qwen3 + llama.cpp + AgentCore acceptance test on Windows.

This is intentionally destructive only inside a unique temporary directory.
It creates a disposable Owner account/database, downloads the pinned model to
an isolated model root, and never changes an installed CyberSentinel profile.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _wait_for_operation(manager, expected: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    last_progress = -1
    while time.monotonic() < deadline:
        state = manager.public_state()["manager"]
        operation = state.get("operation", {})
        status = operation.get("status")
        progress = int(operation.get("progress", 0) or 0)
        if progress != last_progress:
            print(
                f"Acceptance operation {status}: {progress}% "
                f"({operation.get('bytes_downloaded', 0)}/{operation.get('total_bytes', 0)} bytes)",
                file=sys.stderr,
                flush=True,
            )
            last_progress = progress
        if status == expected:
            return state
        if status == "failed":
            raise RuntimeError(f"model_operation_failed:{operation.get('error', 'unknown')}")
        time.sleep(0.5)
    raise TimeoutError(f"model_operation_timeout:{expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True, help="Directory containing the verified llama-server.exe")
    parser.add_argument("--timeout-seconds", type=int, default=10800, help="Maximum wait for download/activation (default: 3 hours)")
    parser.add_argument("--keep-artifacts", action="store_true", help="Keep the isolated acceptance database and downloaded model for inspection")
    args = parser.parse_args()

    if os.name != "nt":
        print(json.dumps({"status": "NOT_RUN", "reason": "windows_only_acceptance"}, indent=2))
        return 2
    if args.timeout_seconds < 60:
        parser.error("--timeout-seconds must be at least 60")

    root = Path(tempfile.mkdtemp(prefix="cybersentinel-windows-acceptance-"))
    os.environ["DB_PATH"] = str(root / "owner-and-policy.sqlite3")
    manager = None
    owner_session = None
    succeeded = False
    report: dict[str, object] = {
        "classification": "REAL_LOCAL_MODEL_WINDOWS_ACCEPTANCE",
        "status": "FAIL",
        "model_id": "qwen3-4b-q4-k-m",
        "runtime_dir": str(args.runtime_dir.resolve()),
    }

    try:
        from agent.agent_core import AgentCore
        from agent.local_runtime.catalog import get_model
        from agent.local_runtime.hardware import assess_compatibility, detect_hardware
        from agent.local_runtime.manager import LocalModelManager
        from agent.local_runtime.runtime import LlamaCppRuntime
        from agent.mission import MissionStore
        from agent.model_router import ModelRouter
        from security import owner_password

        runtime_dir = args.runtime_dir.resolve()
        if not (runtime_dir / "llama-server.exe").is_file():
            raise FileNotFoundError("llama_runtime_not_installed")
        spec = get_model("qwen3-4b-q4-k-m")
        hardware = detect_hardware(root / "model-state" / "models")
        compatibility = assess_compatibility(spec, hardware)
        report["hardware"] = {
            "os": hardware.get("os"),
            "architecture": hardware.get("architecture"),
            "cpu_model": hardware.get("cpu_model"),
            "cpu_count": hardware.get("cpu_count"),
            "ram_gib": hardware.get("ram_gib"),
            "vram_gib": hardware.get("vram_gib"),
            "free_disk_gib": hardware.get("free_disk_gib"),
        }
        if not compatibility["compatible"]:
            raise RuntimeError("model_not_compatible:" + ",".join(compatibility["reasons"]))

        print("Creating a disposable Owner session in isolated acceptance storage.", file=sys.stderr, flush=True)
        acceptance_password = "acceptance-" + uuid.uuid4().hex
        owner_password.create_owner_account(owner_password.OWNER_USERNAME, acceptance_password)
        owner_session = owner_password.login(owner_password.OWNER_USERNAME, acceptance_password)

        router = ModelRouter([])
        manager = LocalModelManager(
            root / "model-state",
            runtime=LlamaCppRuntime(runtime_dir),
            router=router,
        )
        manager.install(spec.model_id)
        _wait_for_operation(manager, "complete", args.timeout_seconds)
        installed = manager.models_root / spec.model_id / spec.filename
        if not installed.is_file():
            raise RuntimeError("verified_model_file_missing_after_install")
        manager.activate(spec.model_id)
        _wait_for_operation(manager, "complete", 240)
        print("Checking real local inference on the activated llama.cpp provider.", file=sys.stderr, flush=True)
        inference = manager.test_inference()
        if inference.get("real_inference") is not True or inference.get("provider") != "local_llama_cpp":
            raise RuntimeError("local_inference_identity_not_verified")

        mission_store_path = root / "missions.sqlite3"
        core = AgentCore(router, store=MissionStore(mission_store_path), max_iterations=10)
        print("Running an Owner-authenticated status-tool mission through AgentCore.", file=sys.stderr, flush=True)
        mission = core.run_owner_mission(
            "Investigate current system status and verify the observation using the status tool, then report only what was actually observed.",
            owner_session_token=owner_session["session_id"],
            request_id="windows-acceptance-" + uuid.uuid4().hex,
            completion_criteria=[
                {
                    "criterion": "A status-tool observation is recorded and verified",
                    "check": "status tool observation",
                    "required": True,
                }
            ],
        )
        reopened = MissionStore(mission_store_path).load(mission.mission_id)
        if reopened is None:
            raise RuntimeError("mission_persistence_reload_failed")
        if reopened.status.value != "GOAL_COMPLETED":
            raise RuntimeError("mission_not_completed:" + reopened.status.value)
        if not reopened.evidence:
            raise RuntimeError("mission_evidence_not_persisted")

        worker = manager._operation_thread
        if worker is not None and worker.is_alive():
            worker.join(timeout=10)
        manager.deactivate()
        stopped = _wait_for_operation(manager, "complete", 60)
        if stopped["runtime"].get("status") != "stopped" or stopped.get("active_model_id"):
            raise RuntimeError("local_runtime_stop_not_verified")

        report.update(
            status="PASS",
            model={"model_id": spec.model_id, "revision": spec.revision, "sha256": spec.sha256, "installed_size_bytes": installed.stat().st_size},
            inference={"provider": inference["provider"], "model": inference["model"], "response": inference["response"]},
            mission={
                "mission_id": mission.mission_id,
                "status": reopened.status.value,
                "trajectory_events": [item.get("event") for item in reopened.trajectory],
                "evidence_count": len(reopened.evidence),
                "mission_store_reopened": True,
            },
            runtime_stopped=True,
        )
        succeeded = True
    except Exception as exc:
        report["error"] = str(exc)[:300]
        report["error_type"] = type(exc).__name__
    finally:
        if owner_session:
            try:
                owner_password.logout(owner_session["session_id"])
            except Exception:
                pass
        if manager is not None:
            try:
                manager.shutdown()
            except Exception as exc:
                report["runtime_cleanup_error"] = type(exc).__name__
        if succeeded and not args.keep_artifacts:
            shutil.rmtree(root, ignore_errors=True)
        else:
            report["isolated_artifacts_path"] = str(root)
        print(json.dumps(report, ensure_ascii=False, default=str, indent=2))
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
