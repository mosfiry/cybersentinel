#!/usr/bin/env python3
"""Real process-boundary Mission checkpoint/restart/resume acceptance.

A first child process creates an Owner Mission and completes only its first
read-only step, persists a completed checkpoint, then remains alive until the
parent terminates it with SIGTERM. A second fresh Python process reopens the
same SQLite stores, reauthenticates the Owner, resumes the remaining step, and
verifies integrity, scope binding, and no duplicate action execution.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from scripts.acceptance_result import apply_cleanup_gate

PLAN = ["status", "latest_intel"]


class RestartAcceptanceProvider:
    name = "restart-acceptance-provider"
    model = "deterministic-tool-proposal"

    def __init__(self):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.planning_calls = 0
        self.generate_calls = 0

    def tool_calling(self, _messages, tools, **_kwargs):
        from agent.provider_api import ProviderResponse, ToolCall
        self.planning_calls += 1
        offered = {
            item.get("function", {}).get("name")
            for item in tools
            if isinstance(item, dict) and isinstance(item.get("function"), dict)
        }
        if not set(PLAN).issubset(offered):
            return ProviderResponse(content="required read-only tools unavailable")
        return ProviderResponse(tool_calls=[
            ToolCall("status", {}, "restart-status-step"),
            ToolCall("latest_intel", {}, "restart-latest-intel-step"),
        ])

    def generate(self, _messages, **_kwargs):
        self.generate_calls += 1
        return {"content": "{}"}


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with temp.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(temp, path)


def _install_owner(token: str, state_dir: Path):
    import pytest
    from owner_session_testutils import allow_owner_sessions, persist_canonical_scope, workspace_scope_context
    import security.scope_store as scope_store

    patcher = pytest.MonkeyPatch()
    allow_owner_sessions(patcher, token)
    patcher.setattr(scope_store, "SCOPE_DB_PATH", state_dir / "scope.sqlite3")
    scope_store.init_scope_store()
    return patcher, persist_canonical_scope, workspace_scope_context


def _phase_seed(state_dir: Path, mission_path: Path, token: str) -> int:
    from agent.agent_core import AgentCore
    from agent.mission import MissionStatus, MissionStore
    from agent.model_router import ModelRouter

    patcher, persist_scope, build_scope = _install_owner(token, state_dir)
    try:
        snapshot = persist_scope(
            patcher,
            state_dir,
            owner_session_token=token,
            target_id="restart-resume-target",
        )
        scope_context = build_scope(snapshot, state_dir)
        provider = RestartAcceptanceProvider()
        store = MissionStore(mission_path)
        core = AgentCore(ModelRouter([provider]), store=store)
        mission = core.run_owner_mission(
            "Verify status and latest intelligence in two read-only steps, preserving the checkpoint across process restart",
            owner_session_token=token,
            scope_context=scope_context,
            completion_criteria=[{
                "criterion_id": "restart-status",
                "description": "the read-only status snapshot was observed",
                "check": "status_snapshot",
                "required": True,
            }],
            run=False,
        )
        if [step.action for step in mission.plan.steps] != PLAN:
            raise RuntimeError("seed_plan_did_not_match_two_read_only_steps")
        if mission.status is not MissionStatus.READY or not mission.verify_integrity():
            raise RuntimeError("seed_mission_not_ready_or_integrity_invalid")
        first = core.resume_mission(mission.mission_id, owner_session_token=token, max_slices=1)
        persisted = MissionStore(mission_path).load(mission.mission_id)
        if persisted is None:
            raise RuntimeError("mission_missing_after_seed_checkpoint")
        if (
            first.current_step != 1
            or persisted.current_step != 1
            or persisted.status is not MissionStatus.READY
            or persisted.checkpoint.get("status") != "completed"
            or len(persisted.action_history) != 1
            or not persisted.verify_integrity()
            or not persisted.scope_snapshot
            or persisted.scope_snapshot.get("scope_snapshot_id") != snapshot.snapshot_id
        ):
            raise RuntimeError("completed_checkpoint_not_durable_or_scope_changed")
        action = persisted.action_history[0]
        if action.get("status") != "completed" or action.get("step_id") != persisted.plan.steps[0].step_id:
            raise RuntimeError("first_step_action_record_incomplete")
        _atomic_json(mission_path.parent / "seed-result.json", {
            "phase": "seed",
            "pid": os.getpid(),
            "mission_id": mission.mission_id,
            "status": persisted.status.value,
            "current_step": persisted.current_step,
            "plan_actions": [step.action for step in persisted.plan.steps],
            "checkpoint": dict(persisted.checkpoint),
            "integrity_hash": persisted.integrity_hash,
            "integrity_valid": persisted.verify_integrity(),
            "action_history_count": len(persisted.action_history),
            "completed_action_id": action.get("action_id"),
            "scope_snapshot_id": snapshot.snapshot_id,
            "scope_ref": persisted.provenance.get("mission_memory_scope_ref") or persisted.scope_snapshot.get("scope_snapshot_id"),
            "authorization_snapshot_present": bool(persisted.authorization_snapshot),
            "provider_planning_calls": provider.planning_calls,
            "provider_generate_calls": provider.generate_calls,
        })
        # Keep the process alive with all stores closed. The parent sends SIGTERM,
        # giving a real OS process boundary after the durable checkpoint commit.
        signal.pause()
        return 99
    finally:
        patcher.undo()


def _phase_resume(state_dir: Path, mission_path: Path, token: str, mission_id: str, expected_hash: str) -> int:
    from agent.agent_core import AgentCore
    from agent.mission import MissionStatus, MissionStore
    from agent.model_router import ModelRouter

    patcher, _persist_scope, _build_scope = _install_owner(token, state_dir)
    try:
        store = MissionStore(mission_path)
        reopened = store.load(mission_id)
        if reopened is None or not reopened.verify_integrity():
            raise RuntimeError("reopened_mission_missing_or_integrity_invalid")
        if reopened.integrity_hash != expected_hash or reopened.current_step != 1 or reopened.checkpoint.get("status") != "completed":
            raise RuntimeError("reopened_checkpoint_or_integrity_hash_mismatch")
        if [step.action for step in reopened.plan.steps] != PLAN:
            raise RuntimeError("reopened_plan_changed")
        provider = RestartAcceptanceProvider()
        core = AgentCore(ModelRouter([provider]), store=store)
        final = core.resume_mission(mission_id, owner_session_token=token, max_slices=4)
        persisted = MissionStore(mission_path).load(mission_id)
        if persisted is None:
            raise RuntimeError("mission_missing_after_resume")
        actions = [item for item in persisted.action_history if isinstance(item, dict) and item.get("status") == "completed"]
        tools = [
            str((item.get("observation") or {}).get("source", item.get("tool_name", item.get("tool", ""))))
            for item in actions
        ]
        tool_counts = dict(Counter(tools))
        action_ids = [str(item.get("action_id", "")) for item in actions]
        unique_action_ids = len(action_ids) == len(set(action_ids)) and all(action_ids)
        scope_id = str((persisted.scope_snapshot or {}).get("scope_snapshot_id", ""))
        snapshot_id = str((persisted.authorization_snapshot or {}).get("scope_snapshot_id", ""))
        if (
            final.status is not MissionStatus.GOAL_COMPLETED
            or persisted.status is not MissionStatus.GOAL_COMPLETED
            or not persisted.verify_integrity()
            or persisted.verification_state.get("verified") is not True
            or persisted.current_step != len(PLAN)
            or tool_counts != {"status": 1, "latest_intel": 1}
            or not unique_action_ids
            or len(actions) != 2
            or scope_id != str(reopened.scope_snapshot.get("scope_snapshot_id", ""))
            or not persisted.authorization_snapshot
        ):
            raise RuntimeError("restart_resume_completion_integrity_scope_or_idempotency_failed")
        _atomic_json(state_dir / "resume-result.json", {
            "phase": "resume",
            "pid": os.getpid(),
            "mission_id": mission_id,
            "status": persisted.status.value,
            "current_step": persisted.current_step,
            "checkpoint": dict(persisted.checkpoint),
            "integrity_hash": persisted.integrity_hash,
            "integrity_valid": persisted.verify_integrity(),
            "validator_verified": persisted.verification_state.get("verified") is True,
            "action_history_count": len(actions),
            "tool_counts": tool_counts,
            "action_ids_unique": unique_action_ids,
            "action_records": [
                {
                    "action_id": str(item.get("action_id", "")),
                    "step_id": str(item.get("step_id", "")),
                    "tool": str((item.get("observation") or {}).get("source", "")),
                    "status": str(item.get("status", "")),
                }
                for item in actions
            ],
            "scope_snapshot_id_preserved": scope_id == str(reopened.scope_snapshot.get("scope_snapshot_id", "")),
            "authorization_snapshot_present": bool(persisted.authorization_snapshot),
            "provider_planning_calls_after_restart": provider.planning_calls,
            "provider_generate_calls_after_restart": provider.generate_calls,
            "evidence_count": len(persisted.evidence),
        })
        return 0
    finally:
        patcher.undo()


def _child_env(token: str) -> dict[str, str]:
    env = os.environ.copy()
    env["CS_RESTART_ACCEPTANCE_OWNER_SESSION"] = token
    return env


def _last_json(stdout: str) -> dict:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError("child_result_json_missing")


def _parent(args) -> int:
    artifact = args.artifact.expanduser().resolve()
    state_root = args.state_dir.expanduser().resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    run_dir = state_root / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(mode=0o700)
    mission_path = run_dir / "missions.sqlite3"
    token = "restart-resume-acceptance-" + uuid.uuid4().hex
    seed_process = None
    result = {
        "schema": "real-process-restart-resume-acceptance-v1",
        "status": "FAIL",
        "provider_mode": "deterministic tool proposal; canonical Owner MissionRuntime and read-only tools are real",
        "process_boundary": {},
        "seed_checkpoint": {},
        "resume": {},
        "checks": {},
        "cleanup": {},
    }
    failure_phase = "seed_process_start"
    try:
        command = [sys.executable, str(Path(__file__).resolve()), "--phase", "seed", "--state-dir", str(run_dir), "--mission-db", str(mission_path)]
        seed_process = subprocess.Popen(command, cwd=str(ROOT), env=_child_env(token), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        seed_result_path = run_dir / "seed-result.json"
        deadline = time.monotonic() + 25.0
        while time.monotonic() < deadline and not seed_result_path.exists():
            if seed_process.poll() is not None:
                stdout, stderr = seed_process.communicate()
                raise RuntimeError("seed_child_failed:" + type(RuntimeError()).__name__ + ":" + str(seed_process.returncode) + ":" + _last_json(stdout).get("failure", "") if stdout.strip() else "seed_child_failed")
            time.sleep(0.05)
        if not seed_result_path.exists():
            seed_process.terminate()
            seed_process.wait(timeout=3.0)
            raise RuntimeError("seed_checkpoint_readiness_timeout")
        seed_result = json.loads(seed_result_path.read_text(encoding="utf-8"))
        if seed_result.get("phase") != "seed" or not seed_result.get("integrity_valid"):
            raise RuntimeError("seed_checkpoint_result_invalid")
        if seed_process.pid == seed_result.get("pid"):
            seed_result["parent_observed_child_pid"] = seed_process.pid
        result["seed_checkpoint"] = {
            key: seed_result[key]
            for key in (
                "mission_id", "status", "current_step", "plan_actions", "checkpoint",
                "integrity_hash", "integrity_valid", "action_history_count", "completed_action_id",
                "scope_snapshot_id", "authorization_snapshot_present",
            )
        }
        result["checks"]["checkpoint_committed_before_termination"] = (
            seed_result.get("status") == "READY"
            and seed_result.get("current_step") == 1
            and seed_result.get("checkpoint", {}).get("status") == "completed"
            and seed_result.get("action_history_count") == 1
        )
        failure_phase = "seed_process_termination"
        seed_process.terminate()
        try:
            seed_return = seed_process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            seed_process.kill()
            seed_return = seed_process.wait(timeout=3.0)
        stdout, stderr = seed_process.communicate(timeout=2.0)
        terminated_with_sigterm = seed_return == -signal.SIGTERM
        result["process_boundary"]["seed_pid"] = int(seed_result.get("pid", 0))
        result["process_boundary"]["seed_exit_code"] = seed_return
        result["process_boundary"]["seed_sigterm_observed"] = terminated_with_sigterm
        result["checks"]["seed_process_terminated_after_durable_checkpoint"] = terminated_with_sigterm
        if not result["checks"]["checkpoint_committed_before_termination"] or not terminated_with_sigterm:
            raise RuntimeError("seed_process_not_terminated_after_valid_checkpoint")

        failure_phase = "resume_process"
        resume_command = [
            sys.executable, str(Path(__file__).resolve()), "--phase", "resume",
            "--state-dir", str(run_dir), "--mission-db", str(mission_path),
            "--mission-id", str(seed_result["mission_id"]),
            "--expected-hash", str(seed_result["integrity_hash"]),
        ]
        resumed = subprocess.run(resume_command, cwd=str(ROOT), env=_child_env(token), capture_output=True, text=True, check=False)
        if resumed.returncode != 0:
            raise RuntimeError("resume_child_failed:" + str(resumed.returncode) + ":" + (_last_json(resumed.stdout).get("failure", "") if resumed.stdout.strip() else "no-result"))
        resume_result = json.loads((run_dir / "resume-result.json").read_text(encoding="utf-8"))
        result["resume"] = resume_result
        result["process_boundary"]["resume_pid"] = int(resume_result.get("pid", 0))
        result["process_boundary"]["resume_exit_code"] = resumed.returncode
        result["checks"]["fresh_process_reopened_mission"] = (
            int(resume_result.get("pid", 0)) != int(seed_result.get("pid", 0))
            and resume_result.get("mission_id") == seed_result.get("mission_id")
        )
        result["checks"]["owner_authorization_and_scope_survived_restart"] = (
            resume_result.get("scope_snapshot_id_preserved") is True
            and resume_result.get("authorization_snapshot_present") is True
        )
        result["checks"]["resume_completed_and_validator_passed"] = (
            resume_result.get("status") == "GOAL_COMPLETED"
            and resume_result.get("integrity_valid") is True
            and resume_result.get("validator_verified") is True
        )
        result["checks"]["no_duplicate_or_unsafe_reexecution"] = (
            resume_result.get("action_history_count") == 2
            and resume_result.get("tool_counts") == {"latest_intel": 1, "status": 1}
            and resume_result.get("action_ids_unique") is True
            and resume_result.get("current_step") == 2
        )
        result["checks"]["no_replanning_after_restore"] = resume_result.get("provider_planning_calls_after_restart") == 0
        if not all(result["checks"].values()):
            raise RuntimeError("one_or_more_restart_resume_acceptance_checks_failed")
        result["status"] = "PASS"
    except BaseException as exc:
        result["failure"] = {"phase": failure_phase, "class": type(exc).__name__}
        if seed_process is not None and seed_process.poll() is None:
            seed_process.terminate()
            try:
                seed_process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                seed_process.kill()
                seed_process.wait(timeout=2.0)
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
        result["cleanup"]["temporary_state_removed"] = not run_dir.exists()
        result["cleanup"]["seed_process_stopped"] = seed_process is None or seed_process.poll() is not None
        apply_cleanup_gate(result, {
            "temporary_state_removed": result["cleanup"]["temporary_state_removed"],
            "seed_process_stopped": result["cleanup"]["seed_process_stopped"],
        })
        if result["status"] != "PASS" and "failure" not in result:
            result["failure"] = {"phase": failure_phase, "class": "AcceptanceCheckFailed"}
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": result["status"],
            "artifact": str(artifact),
            "checks": result["checks"],
            "cleanup": result["cleanup"],
            "failure": result.get("failure"),
        }, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("parent", "seed", "resume"), default="parent")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--mission-db", type=Path)
    parser.add_argument("--mission-id")
    parser.add_argument("--expected-hash", default="")
    args = parser.parse_args()
    if args.phase == "parent":
        if args.artifact is None:
            parser.error("--artifact is required for the parent phase")
        return _parent(args)
    token = os.environ.get("CS_RESTART_ACCEPTANCE_OWNER_SESSION", "")
    if not token or args.mission_db is None:
        raise SystemExit("child phase requires acceptance session env and --mission-db")
    state_dir = args.state_dir.expanduser().resolve()
    if args.phase == "seed":
        return _phase_seed(state_dir, args.mission_db.expanduser().resolve(), token)
    if not args.mission_id or not args.expected_hash:
        raise SystemExit("resume phase requires --mission-id and --expected-hash")
    return _phase_resume(state_dir, args.mission_db.expanduser().resolve(), token, args.mission_id, args.expected_hash)


if __name__ == "__main__":
    raise SystemExit(main())
