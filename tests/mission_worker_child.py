from __future__ import annotations

"""Real-process test harness for the existing supervised MissionWorker.

This module is launched only by test_v10_process_death.py. It uses the normal
bridge factory and RuntimeSupervisor, with DB_PATH constrained by the parent to
a pytest temporary directory. Barriers pause after durable boundaries; the
parent, not this child, sends SIGTERM/SIGKILL.
"""

import argparse
from dataclasses import replace
import json
import os
import signal
import sqlite3
import sys
from typing import Any


def _emit(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def _barrier(point: str, **fields: Any) -> None:
    _emit("barrier", point=point, **fields)
    command = sys.stdin.readline()
    if command.strip() != "continue":
        raise RuntimeError("parent did not release the V10 process barrier")


def _increment_test_counter(tool_name: str) -> None:
    """Count completed local handlers in an isolated test-only SQLite table."""
    from core import db as core_db

    with core_db.connect() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS v10_test_dispatch_counts ("
            "tool_name TEXT PRIMARY KEY, call_count INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO v10_test_dispatch_counts(tool_name,call_count) VALUES(?,1) "
            "ON CONFLICT(tool_name) DO UPDATE SET call_count=call_count+1",
            (tool_name,),
        )
        connection.commit()


def _wrap_tool_handler(tool_name: str, *, mode: str) -> None:
    from tools import registry

    spec = registry.REGISTRY[tool_name]
    original = spec.handler

    def wrapped(argument, *args, **kwargs):
        if mode == "before_handler":
            _barrier("before_handler", tool=tool_name)
        result = original(argument, *args, **kwargs)
        _increment_test_counter(tool_name)
        if mode == "after_handler":
            _barrier("after_handler", tool=tool_name)
        return result

    registry.REGISTRY[tool_name] = replace(spec, handler=wrapped)


def _install_hooks(mode: str, worker: Any, mission_id: str) -> None:
    if mode in {"count_only", "count_status", "after_handler", "before_handler", "before_watch_handler", "after_evidence", "after_terminal_save"}:
        tool_name = (
            "status"
            if mode in {"before_handler", "count_status"}
            else "run_project_tests"
            if mode == "after_evidence"
            else "watch"
        )
        hook_mode = "before_handler" if mode in {"before_handler", "before_watch_handler"} else "after_handler" if mode == "after_handler" else "count_only"
        _wrap_tool_handler(tool_name, mode=hook_mode)

    if mode in {"after_claim", "race_claim"}:
        original_factory = worker.runtime_factory

        def runtime_factory():
            runtime = original_factory()
            _barrier(
                "after_claim_before_bind",
                mission_id=mission_id,
                worker_id=worker.worker_id,
                worker_instance_id=worker.worker_instance_id,
                runtime_generation=worker.runtime_generation,
            )
            return runtime

        worker.runtime_factory = runtime_factory

    if mode == "before_poll":
        original_run_once = worker.run_once
        # The supervisor is attached in main() after worker construction.
        worker._v10_original_run_once = original_run_once

    if mode == "after_evidence":
        from agent.evidence import EvidenceChainStore

        original_append = EvidenceChainStore._append_fenced

        def append_then_pause(store, payload, fence):
            record = original_append(store, payload, fence)
            _barrier(
                "after_evidence_commit",
                mission_id=mission_id,
                sequence=record.get("sequence"),
                evidence_id=record.get("evidence_id"),
            )
            return record

        EvidenceChainStore._append_fenced = append_then_pause

    if mode == "after_terminal_save":
        from agent.mission import MissionStatus, MissionStore

        original_save = MissionStore.save

        def save_then_pause(store, mission, *args, **kwargs):
            saved = original_save(store, mission, *args, **kwargs)
            if mission.mission_id == mission_id and mission.status is MissionStatus.GOAL_COMPLETED:
                _barrier("after_terminal_mission_commit", mission_id=mission_id)
            return saved

        MissionStore.save = save_then_pause


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--mission-id", required=True)
    parser.add_argument(
        "--mode",
        choices=(
            "count_only",
            "count_status",
            "after_claim",
            "race_claim",
            "before_poll",
            "before_handler",
            "before_watch_handler",
            "after_handler",
            "after_evidence",
            "after_terminal_save",
        ),
        default="count_only",
    )
    args = parser.parse_args(argv)
    if not os.environ.get("DB_PATH") or os.environ.get("PYTHON_DOTENV_DISABLED") != "1":
        parser.error("child requires an isolated DB_PATH and disabled dotenv loading")

    try:
        from agent.runtime_supervisor import RuntimeSupervisor
        from bridge import build_mission_worker

        worker = build_mission_worker(worker_id=args.worker_id)
        _install_hooks(args.mode, worker, args.mission_id)
        supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)

        if args.mode == "before_poll":
            original_run_once = worker._v10_original_run_once

            def gate_before_claim(*, now=None, max_slices=None):
                _barrier("before_claim", mission_id=args.mission_id)
                if supervisor.state.value != "RUNNING":
                    return None
                return original_run_once(now=now, max_slices=max_slices)

            worker.run_once = gate_before_claim

        with supervisor.install_signal_handlers():
            health = supervisor.start()
            _emit(
                "ready",
                pid=os.getpid(),
                worker_id=worker.worker_id,
                worker_instance_id=worker.worker_instance_id,
                runtime_generation=worker.runtime_generation,
                recovered_expired_leases=health.get("recovered_expired_leases", 0),
            )
            command = sys.stdin.readline()
            if command.strip() != "poll":
                raise RuntimeError("parent did not authorize the bounded V10 poll")
            result = supervisor.run_once()
            _emit(
                "poll_result",
                pid=os.getpid(),
                mission_id=args.mission_id,
                claimed=result is not None,
                queue_state=getattr(getattr(result, "state", None), "value", None),
                claim_phase=getattr(result, "claim_phase", None),
                worker_id=worker.worker_id,
                runtime_generation=worker.runtime_generation,
            )
            # Drive the existing supervisor's normal stop path after the single
            # bounded poll. If SIGTERM already requested drain, this is a no-op
            # poll followed by the same stop/deactivate path.
            supervisor.serve_forever(max_iterations=0)
        _emit("stopped", pid=os.getpid(), state=supervisor.state.value)
        return 0
    except BaseException as exc:
        _emit("child_error", error_type=type(exc).__name__, message=str(exc)[:240])
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
