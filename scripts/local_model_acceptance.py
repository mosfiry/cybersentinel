#!/usr/bin/env python3
"""Run a real Qwen3 + llama.cpp + AgentCore acceptance test on Linux or Windows.

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
PINNED_RUNTIME_ARCHIVE_SHA256 = {
    "windows-x64-cpu": "14cf1303ca9ac3abd94816850532f9f9a69ac66fbaca3776fc6f9061c2fac1d1",
    "linux-x64-cpu": "c150306eb16b5ab696f76a8bdf810c35fd98a24e82158742e6fa28f420ff8410",
}
SAFE_ERROR_CODES = {
    "model_operation_failed",
    "model_operation_timeout",
    "llama_runtime_manifest_or_binary_integrity_invalid",
    "model_not_compatible",
    "verified_model_file_missing_after_install",
    "installed_model_digest_mismatch",
    "local_inference_failed",
    "local_inference_identity_not_verified",
    "remote_or_ambiguous_provider_configured",
    "mission_persistence_reload_failed",
    "mission_not_completed",
    "mission_model_loop_missing",
    "mission_model_turn_missing",
    "mission_provider_identity_mismatch",
    "mission_tool_scope_mismatch",
    "mission_final_response_missing",
    "mission_final_turn_not_text_only",
    "status_tool_not_successful",
    "status_evidence_not_verified",
    "mission_trajectory_integrity_invalid",
    "mission_tool_evidence_trajectory_incomplete",
    "local_runtime_stop_not_verified",
}
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


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resolve_artifact_root(requested: Path | None) -> tuple[Path, bool]:
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="cybersentinel-local-model-acceptance-")), True
    raw = requested.expanduser()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if raw.is_symlink() or not raw.is_dir():
        raise ValueError("resume_artifacts_dir_must_be_an_existing_real_directory")
    root = raw.resolve()
    if (
        root == temp_root
        or not root.is_relative_to(temp_root)
        or not root.name.startswith("cybersentinel-local-model-acceptance-")
    ):
        raise ValueError("resume_artifacts_dir_must_be_a_cybersentinel_temp_directory")
    return root, False


def _new_mission_store_path(artifact_root: Path) -> Path:
    """Allocate a unique attempt directory; AgentCore derives its queue beside this DB."""
    if artifact_root.is_symlink() or not artifact_root.is_dir():
        raise ValueError("acceptance_artifact_root_invalid")
    root = artifact_root.resolve(strict=True)
    run_dir = Path(tempfile.mkdtemp(prefix="mission-run-", dir=root))
    if run_dir.is_symlink() or run_dir.resolve(strict=True).parent != root:
        raise ValueError("acceptance_mission_store_path_invalid")
    return run_dir / "missions.sqlite3"


def _safe_error_code(exc: Exception) -> str:
    from agent.context import ContextBudgetExceeded

    if isinstance(exc, ContextBudgetExceeded):
        return "context_budget_exceeded"
    candidate = str(exc).split(":", 1)[0]
    if candidate in SAFE_ERROR_CODES:
        return candidate
    return "timeout" if isinstance(exc, TimeoutError) else "acceptance_failed"


def _verify_trajectory(events: list[dict], mission_id: str, request_id: str) -> bool:
    from agent.trajectory import EventType, TrajectoryEvent

    previous = ""
    for item in events:
        if not isinstance(item, dict):
            return False
        try:
            event = TrajectoryEvent(
                EventType(item["event"]),
                str(item["mission_id"]),
                str(item["request_id"]),
                step_id=str(item.get("step_id", "")),
                timestamp=str(item["timestamp"]),
                provenance=dict(item.get("provenance", {})),
                data=dict(item.get("data", {})),
                previous_hash=previous,
            )
        except (KeyError, TypeError, ValueError):
            return False
        if (
            event.mission_id != mission_id
            or event.request_id != request_id
            or item.get("previous_hash") != previous
            or item.get("event_hash") != event.event_hash
        ):
            return False
        previous = event.event_hash
    return bool(events)


def validate_acceptance_mission(mission, expected_model_id: str) -> dict[str, object]:
    """Validate persisted tool/evidence lineage; model and tool output stay untrusted."""
    if getattr(getattr(mission, "status", None), "value", None) != "GOAL_COMPLETED":
        raise RuntimeError("mission_not_completed")

    progress = getattr(mission, "progress", {})
    loop = progress.get("model_loop") if isinstance(progress, dict) else None
    if not isinstance(loop, dict):
        raise RuntimeError("mission_model_loop_missing")
    turns = loop.get("turns")
    tool_results = loop.get("tool_results")
    if not isinstance(turns, list) or not turns:
        raise RuntimeError("mission_model_turn_missing")
    if any(
        not isinstance(turn, dict)
        or turn.get("provider") != "local_llama_cpp"
        or turn.get("model") != expected_model_id
        for turn in turns
    ):
        raise RuntimeError("mission_provider_identity_mismatch")
    final_turn = turns[-1]
    final_content = final_turn.get("content")
    final_calls = final_turn.get("tool_calls")
    if (
        not isinstance(final_content, str)
        or not final_content.strip()
        or len(final_content.encode("utf-8")) > 32_000
    ):
        raise RuntimeError("mission_final_response_missing")
    if not isinstance(final_calls, list) or final_calls:
        raise RuntimeError("mission_final_turn_not_text_only")
    if not isinstance(tool_results, list) or any(
        not isinstance(result, dict) or result.get("name") != "status"
        for result in tool_results
    ):
        raise RuntimeError("mission_tool_scope_mismatch")
    successful = [
        result for result in tool_results
        if result.get("name") == "status" and result.get("ok") is True
    ]
    if not successful:
        raise RuntimeError("status_tool_not_successful")

    successful_call_ids = {str(item.get("tool_call_id", "")) for item in successful}
    evidence = getattr(mission, "evidence", None)
    verified = [
        item for item in evidence if isinstance(item, dict)
        and item.get("criterion_id") == "status-snapshot"
        and item.get("passed") is True
        and item.get("source") == "status"
        and isinstance(item.get("provenance"), dict)
        and item["provenance"].get("mission_id") == mission.mission_id
        and item["provenance"].get("verification_authority") == "validated_status_snapshot"
        and item["provenance"].get("tool_call_id") in successful_call_ids
    ] if isinstance(evidence, list) else []
    if not verified:
        raise RuntimeError("status_evidence_not_verified")

    events = getattr(mission, "trajectory", None)
    if not isinstance(events, list) or not _verify_trajectory(events, mission.mission_id, mission.request_id):
        raise RuntimeError("mission_trajectory_integrity_invalid")
    event_names = [str(item.get("event", "")) for item in events]
    if not {"ToolExecuted", "GoalVerified", "MissionCompleted"}.issubset(event_names):
        raise RuntimeError("mission_tool_evidence_trajectory_incomplete")
    try:
        final_model_index = max(index for index, name in enumerate(event_names) if name == "ModelTurn")
        tool_executed_index = max(index for index, name in enumerate(event_names) if name == "ToolExecuted")
        goal_verified_index = event_names.index("GoalVerified")
    except ValueError as exc:
        raise RuntimeError("mission_tool_evidence_trajectory_incomplete") from exc
    if not tool_executed_index < final_model_index < goal_verified_index:
        raise RuntimeError("mission_tool_evidence_trajectory_incomplete")

    return {
        "mission_id": mission.mission_id,
        "status": mission.status.value,
        "provider_bound_turns": len(turns),
        "final_response_present": True,
        "final_response_bytes": len(final_content.encode("utf-8")),
        "final_turn_tool_calls": 0,
        "successful_status_tool_calls": len(successful),
        "evidence_references": [
            {
                "criterion_id": item["criterion_id"],
                "source": item["source"],
                "verification_authority": item["provenance"]["verification_authority"],
                "reference_sha256": __import__("hashlib").sha256(
                    json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
                ).hexdigest(),
            }
            for item in verified
        ],
        "trajectory_events": event_names,
        "trajectory_integrity_verified": True,
        "mission_store_reopened": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True, help="Directory containing the pinned, verified llama-server runtime")
    parser.add_argument("--timeout-seconds", type=int, default=10800, help="Maximum wait for download/activation (default: 3 hours)")
    parser.add_argument("--keep-artifacts", action="store_true", help="Keep the isolated acceptance database and downloaded model for inspection")
    parser.add_argument("--artifacts-dir", type=Path, help="Resume from an existing isolated temp acceptance directory without deleting it")
    args = parser.parse_args()

    if os.name == "nt":
        runtime_platform, server_name = "windows-x64-cpu", "llama-server.exe"
        acceptance_platform = "windows"
    elif os.name == "posix" and sys.platform.startswith("linux"):
        runtime_platform, server_name = "linux-x64-cpu", "llama-server"
        acceptance_platform = "linux"
    else:
        print(json.dumps({"status": "NOT_RUN", "reason": "unsupported_acceptance_platform"}, indent=2))
        return 2
    if args.timeout_seconds < 60:
        parser.error("--timeout-seconds must be at least 60")

    try:
        root, owns_root = _resolve_artifact_root(args.artifacts_dir)
    except ValueError as exc:
        parser.error(str(exc))
    os.environ["DB_PATH"] = str(root / ("owner-and-policy-" + uuid.uuid4().hex + ".sqlite3"))
    manager = None
    owner_session = None
    succeeded = False
    stage = "runtime_validation"
    report: dict[str, object] = {
        "classification": "REAL_LOCAL_MODEL_ACCEPTANCE",
        "platform": acceptance_platform,
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
        from tools.registry import REGISTRY

        runtime_dir = args.runtime_dir.resolve()
        server_path = runtime_dir / server_name
        manifest_path = runtime_dir / "runtime-manifest.json"
        if not server_path.is_file() or not manifest_path.is_file():
            raise FileNotFoundError("llama_runtime_not_installed")
        runtime_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            runtime_manifest.get("tag") != "b11146"
            or runtime_manifest.get("platform") != runtime_platform
            or runtime_manifest.get("server_binary") != server_name
            or runtime_manifest.get("asset_sha256") != PINNED_RUNTIME_ARCHIVE_SHA256[runtime_platform]
            or runtime_manifest.get("server_binary_sha256") != _sha256_file(server_path)
        ):
            raise RuntimeError("llama_runtime_manifest_or_binary_integrity_invalid")
        report["runtime"] = {
            "tag": runtime_manifest["tag"],
            "platform": runtime_platform,
            "asset_sha256": runtime_manifest.get("asset_sha256"),
            "server_binary_sha256": runtime_manifest["server_binary_sha256"],
        }
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

        stage = "owner_setup"
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
        stage = "model_installation"
        manager.install(spec.model_id)
        _wait_for_operation(manager, "complete", args.timeout_seconds)
        installed = manager.models_root / spec.model_id / spec.filename
        if not installed.is_file():
            raise RuntimeError("verified_model_file_missing_after_install")
        if _sha256_file(installed) != spec.sha256:
            raise RuntimeError("installed_model_digest_mismatch")
        stage = "model_activation"
        manager.activate(spec.model_id)
        _wait_for_operation(manager, "complete", 240)
        stage = "real_local_inference"
        print("Checking real local inference on the activated llama.cpp provider.", file=sys.stderr, flush=True)
        inference = manager.test_inference()
        if (
            inference.get("real_inference") is not True
            or inference.get("provider") != "local_llama_cpp"
            or inference.get("model") != spec.model_id
            or "CYBERSENTINEL_LOCAL_OK" not in str(inference.get("response", ""))
        ):
            raise RuntimeError("local_inference_identity_not_verified")
        providers = list(getattr(router, "providers", ()))
        if len(providers) != 1 or getattr(providers[0], "name", "") != "local_llama_cpp":
            raise RuntimeError("remote_or_ambiguous_provider_configured")

        stage = "mission_execution"
        mission_store_path = _new_mission_store_path(root)
        mission_store = MissionStore(mission_store_path)
        core = AgentCore(router, store=mission_store, max_iterations=10)
        print("Running an Owner-authenticated status-tool mission through AgentCore.", file=sys.stderr, flush=True)
        forbidden_tools = sorted(set(REGISTRY) - {"status", "workspace_read", "git_read"})
        request_id = "local-model-acceptance-" + uuid.uuid4().hex
        mission = core.run_owner_mission(
            "Use exactly one tool: status. Read the current local system status, then report only what was actually returned. Do not use network access or any other tool.",
            owner_session_token=owner_session["session_id"],
            request_id=request_id,
            scope_context={
                "scope": ["workspace"],
                "target_id": "local-model-acceptance-status",
                "workspace_root": str(root),
                "allowed_networks": [],
                "allowed_credentials": [],
                "forbidden_actions": forbidden_tools,
            },
            completion_criteria=[
                {
                    "criterion_id": "status-snapshot",
                    "description": "The status tool returns a schema-valid local status snapshot",
                    "check": "status_snapshot",
                    "required": True,
                }
            ],
        )
        stage = "mission_persistence_validation"
        reopened = MissionStore(mission_store_path).load(mission.mission_id)
        if reopened is None:
            raise RuntimeError("mission_persistence_reload_failed")
        mission_summary = validate_acceptance_mission(reopened, spec.model_id)

        stage = "runtime_shutdown"
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
            inference={
                "provider": inference["provider"],
                "model": inference["model"],
                "response_sha256": __import__("hashlib").sha256(str(inference["response"]).encode("utf-8")).hexdigest(),
                "response_bytes": len(str(inference["response"]).encode("utf-8")),
                "expected_marker_observed": True,
            },
            mission=mission_summary,
            runtime_stopped=True,
        )
        succeeded = True
    except Exception as exc:
        report["error_code"] = _safe_error_code(exc)
        report["error_type"] = type(exc).__name__
        report["failed_stage"] = stage
        from agent.context import ContextBudgetExceeded
        if isinstance(exc, ContextBudgetExceeded):
            report["context_budget"] = {
                "required_messages": int(exc.required_messages),
                "message_limit": int(exc.limits.max_context_messages),
                "required_chars": int(exc.required_chars),
                "character_limit": int(exc.limits.max_context_chars),
                "required_tokens": int(exc.required_tokens),
                "token_limit": int(exc.limits.max_context_tokens or 0),
            }
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
        retain_artifacts = args.keep_artifacts or not owns_root
        if succeeded and not retain_artifacts:
            shutil.rmtree(root, ignore_errors=True)
        else:
            report["isolated_artifacts_path"] = str(root)
        print(json.dumps(report, ensure_ascii=False, default=str, indent=2))
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
