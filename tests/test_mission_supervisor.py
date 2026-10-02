from __future__ import annotations

import json
import sqlite3
from threading import Event
import time

import pytest

from agent.effect_intent import ExternalEffectState
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_supervisor import MissionSupervisor
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.planning import Plan, PlanStep
from runtime_authorization import make_test_snapshot
from tools import registry as tool_registry


BASE = "2026-01-01T00:00:00+00:00"
TOOL = "m2d.supervisor.synthetic_local"


class SimulatedProcessDeath(BaseException):
    """Stop the worker between durable DISPATCHING and a result commit."""


def _register_local_tool(monkeypatch, handler):
    from security import authorization

    spec = tool_registry.ToolSpec(
        TOOL,
        "Deterministic local M2.d supervisor fixture",
        "analysis",
        False,
        str,
        handler,
        timeout=3,
    )
    monkeypatch.setitem(tool_registry.REGISTRY, TOOL, spec)
    monkeypatch.setattr(tool_registry, "KNOWN_TOOLS", tool_registry.KNOWN_TOOLS | {TOOL})
    monkeypatch.setattr(authorization, "KNOWN_TOOLS", authorization.KNOWN_TOOLS | {TOOL})


def _registry_executor(mission, step, action_id):
    payload = json.dumps({"mission_id": mission.mission_id, "action_id": action_id})
    return tool_registry.execute(step.action, payload, request_id=mission.request_id or "local-request")


def _make_job(authority, tmp_path):
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    runtime = MissionRuntime(
        store,
        executor=_registry_executor,
        authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)),
    )
    plan = Plan.initial("complete one deterministic local action").replan(
        steps=(PlanStep("local-effect", "run the registered synthetic action", action=TOOL),),
        reason="M2.d supervisor lifecycle test",
    )
    mission = runtime.create(
        "local supervisor fixture",
        "complete one deterministic local action",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )
    queue.enqueue(mission.mission_id, available_at=BASE)
    return store, queue, mission


def _worker(authority, *, worker_id="supervisor-test", lease_seconds=30):
    return MissionWorker(
        MissionQueue(authority),
        lambda: MissionRuntime(MissionStore(authority), executor=_registry_executor),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )


def _wait_until(predicate, *, timeout=5.0):
    """Bounded Event.wait polling; tests use no unbounded or random sleeps."""
    deadline = time.monotonic() + timeout
    wake = Event()
    while time.monotonic() < deadline:
        if predicate():
            return True
        wake.wait(min(0.005, max(0.0, deadline - time.monotonic())))
    return bool(predicate())


def _intent(authority, mission_id):
    with sqlite3.connect(authority) as db:
        return db.execute(
            "SELECT state FROM external_effect_intents WHERE mission_id=?",
            (mission_id,),
        ).fetchone()


@pytest.mark.parametrize(
    ("poll_interval", "max_backoff"),
    [
        (0, 1),
        (float("nan"), 1),
        (0.1, float("inf")),
        (0.1, float("nan")),
        (1, 0.5),
    ],
)
def test_polling_and_backoff_configuration_must_be_finite_and_bounded(tmp_path, poll_interval, max_backoff):
    authority = tmp_path / "authority.sqlite3"
    with pytest.raises(ValueError):
        MissionSupervisor(
            _worker(authority, worker_id="invalid-config"),
            poll_interval=poll_interval,
            max_backoff=max_backoff,
        )


def test_explicit_start_processes_queue_and_persists_confirmation(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    handler_entered = Event()

    def local_handler(argument):
        payload = json.loads(argument)
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (payload["mission_id"],),
            ).fetchone()[0]
        assert state == ExternalEffectState.DISPATCHING.value
        handler_entered.set()
        return {"success": True, "criterion_id": "goal", "source": "synthetic-local", "receipt_id": "receipt-supervisor"}

    _register_local_tool(monkeypatch, local_handler)
    store, queue, mission = _make_job(authority, tmp_path)
    supervisor = MissionSupervisor(_worker(authority), poll_interval=0.005, max_backoff=0.04)

    supervisor.start()
    assert handler_entered.wait(timeout=5), "supervisor did not enter the local effect handler"
    assert _wait_until(lambda: queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED)
    assert supervisor.stop(timeout=5)

    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.GOAL_COMPLETED
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.CONFIRMED.value,)
    assert supervisor.last_result is not None
    assert supervisor.last_result.state is WorkerMissionState.COMPLETED
    assert store.load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED


def test_stop_at_idle_is_graceful_and_does_not_claim_work(tmp_path):
    authority = tmp_path / "authority.sqlite3"
    queue = MissionQueue(authority)
    supervisor = MissionSupervisor(_worker(authority, worker_id="idle-worker"), poll_interval=0.005, max_backoff=0.02)

    assert not supervisor.is_running
    assert supervisor.poll_count == 0
    supervisor.start()
    assert _wait_until(lambda: supervisor.poll_count >= 1)
    assert 0 < supervisor.current_backoff <= supervisor.max_backoff
    assert supervisor.stop(timeout=5)

    assert not supervisor.is_running
    assert queue.list() == []


def test_stop_during_run_waits_for_real_worker_completion_without_false_ack(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    entered = Event()
    release = Event()

    def local_handler(argument):
        entered.set()
        assert release.wait(timeout=5), "test barrier was not released"
        return {"success": True, "criterion_id": "goal", "source": "synthetic-local", "receipt_id": "receipt-after-stop"}

    _register_local_tool(monkeypatch, local_handler)
    _, queue, mission = _make_job(authority, tmp_path)
    supervisor = MissionSupervisor(_worker(authority, worker_id="stop-worker"), poll_interval=0.005, max_backoff=0.04)

    supervisor.start()
    assert entered.wait(timeout=5), "worker did not reach the deterministic handler barrier"
    assert supervisor.stop(timeout=0.01) is False
    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    release.set()
    assert supervisor.stop(timeout=5)

    assert MissionStore(authority).load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.CONFIRMED.value,)


def test_duplicate_start_is_rejected_for_same_instance_and_worker_identity(tmp_path):
    authority = tmp_path / "authority.sqlite3"
    queue = MissionQueue(authority)
    first = MissionSupervisor(_worker(authority, worker_id="single-worker"), poll_interval=0.005, max_backoff=0.02)
    duplicate = MissionSupervisor(_worker(authority, worker_id="single-worker"), poll_interval=0.005, max_backoff=0.02)

    first.start()
    assert _wait_until(lambda: first.poll_count >= 1)
    with pytest.raises(RuntimeError, match="already running"):
        first.start()
    with pytest.raises(RuntimeError, match="already running"):
        duplicate.start()
    assert first.stop(timeout=5)
    assert queue.list() == []


def test_two_supervisors_compete_on_real_queue_claim_without_duplicate_dispatch(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    entered = Event()
    release = Event()
    calls = []

    def local_handler(argument):
        calls.append(json.loads(argument)["mission_id"])
        entered.set()
        assert release.wait(timeout=5), "test barrier was not released"
        return {"success": True, "criterion_id": "goal", "source": "synthetic-local", "receipt_id": "receipt-one-claim"}

    _register_local_tool(monkeypatch, local_handler)
    _, queue, mission = _make_job(authority, tmp_path)
    supervisor_a = MissionSupervisor(_worker(authority, worker_id="competing-a"), poll_interval=0.005, max_backoff=0.04)
    supervisor_b = MissionSupervisor(_worker(authority, worker_id="competing-b"), poll_interval=0.005, max_backoff=0.04)

    supervisor_a.start()
    supervisor_b.start()
    assert entered.wait(timeout=5), "neither supervisor claimed the queued mission"
    item = queue.get(mission.mission_id)
    assert item.lease_claim is not None
    assert item.lease_claim.worker_id in {"competing-a", "competing-b"}
    assert calls == [mission.mission_id]
    release.set()
    assert _wait_until(lambda: queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED)
    assert supervisor_a.stop(timeout=5)
    assert supervisor_b.stop(timeout=5)

    assert calls == [mission.mission_id]
    assert MissionStore(authority).load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.CONFIRMED.value,)


def test_handler_exception_remains_unknown_and_supervisor_does_not_fail_ack(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    entered = Event()

    def ambiguous_local_handler(_argument):
        entered.set()
        raise RuntimeError("synthetic handler result was lost")

    _register_local_tool(monkeypatch, ambiguous_local_handler)
    _, queue, mission = _make_job(authority, tmp_path)
    supervisor = MissionSupervisor(_worker(authority, worker_id="unknown-worker"), poll_interval=0.005, max_backoff=0.04)

    supervisor.start()
    assert entered.wait(timeout=5), "worker did not attempt the local effect"
    assert _wait_until(lambda: queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL)
    assert supervisor.stop(timeout=5)

    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.UNKNOWN.value,)
    assert queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert supervisor.last_result is not None
    assert supervisor.last_result.state is WorkerMissionState.WAITING_FOR_TOOL


def test_restart_reopens_sqlite_and_marks_dispatching_unknown_before_any_retry(monkeypatch, tmp_path):
    authority = tmp_path / "authority.sqlite3"
    calls = []

    def crash_after_dispatch(argument):
        calls.append(json.loads(argument)["mission_id"])
        with sqlite3.connect(authority) as db:
            state = db.execute(
                "SELECT state FROM external_effect_intents WHERE mission_id=?",
                (calls[-1],),
            ).fetchone()[0]
        assert state == ExternalEffectState.DISPATCHING.value
        raise SimulatedProcessDeath("simulated worker process death")

    _register_local_tool(monkeypatch, crash_after_dispatch)
    _, first_queue, mission = _make_job(authority, tmp_path)
    first_supervisor = MissionSupervisor(
        _worker(authority, worker_id="crashed-worker", lease_seconds=1),
        poll_interval=0.005,
        max_backoff=0.02,
    )
    first_supervisor.start()
    assert _wait_until(lambda: first_supervisor.last_exception is not None)
    assert first_supervisor.stop(timeout=5)

    assert "SimulatedProcessDeath" in (first_supervisor.last_error or "")
    assert first_queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.DISPATCHING.value,)

    # Reopen the real SQLite-backed queue and expire the crashed worker's lease.
    restarted_queue = MissionQueue(authority)
    with sqlite3.connect(authority) as db:
        db.execute(
            "UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=?",
            ("2020-01-01T00:00:00+00:00", mission.mission_id),
        )
    second_supervisor = MissionSupervisor(
        _worker(authority, worker_id="restarted-worker", lease_seconds=30),
        poll_interval=0.005,
        max_backoff=0.04,
    )
    second_supervisor.start()
    assert _wait_until(lambda: restarted_queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL)
    assert second_supervisor.stop(timeout=5)

    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None and persisted.status is MissionStatus.RECOVERY_REQUIRED
    assert _intent(authority, mission.mission_id) == (ExternalEffectState.UNKNOWN.value,)
    assert restarted_queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert calls == [mission.mission_id], "restart retried a possibly-sent effect"
