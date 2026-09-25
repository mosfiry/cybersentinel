from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from agent.mission import MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_context import ContextRecord, MissionContext
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker, WorkerMissionState
from agent.self_repair import BoundedSelfRepair
from agent.verification import FindingClaim, VerificationEngine, VerificationPlan, VerificationResult
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import get_tool, tool_definitions
from workspace.environment import Workspace, WorkspaceBoundaryError, WorkspacePolicy, WorkspacePolicyError
from api.missions import MissionService
from agent.planning import Plan


def snapshot(*, root: str = "/workspace/project", actions=None, tools=None, live: bool = False, forbidden=None) -> MissionAuthorizationSnapshot:
    created = datetime.now(timezone.utc) if live else datetime(2026, 1, 1, tzinfo=timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner-1",
        mission_id="mission-1",
        target_identity="workspace-1",
        scope=["repository"],
        allowed_actions=["read", "test"] if actions is None else actions,
        forbidden_actions=["delete"] if forbidden is None else forbidden,
        allowed_tools=["run_project_tests"] if tools is None else tools,
        time_window={"timezone": "UTC"},
        max_duration=3600,
        rate_limits={"run_project_tests": 2},
        network_boundary={"allowed": []},
        data_boundary={"allowed": ["workspace-1"]},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": root},
        policy_version="policy-v1",
        owner_approval="approval-1",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(hours=1)).isoformat(),
    )


def test_workspace_root_path_validation_and_file_operations(tmp_path):
    ws = Workspace(tmp_path, authorization_snapshot=snapshot(root=str(tmp_path), actions=["read", "write", "edit", "create", "move", "delete"], tools=[], live=True, forbidden=[]))
    ws.write("src/app.py", "print('ok')\n")
    assert ws.read("src/app.py") == "print('ok')\n"
    ws.edit("src/app.py", "ok", "done")
    assert "done" in ws.read("src/app.py")
    assert "src" in ws.list(".")
    with pytest.raises(WorkspaceBoundaryError):
        ws.read("../outside.txt")
    with pytest.raises(WorkspaceBoundaryError):
        ws.delete(".")


def test_workspace_shell_and_process_timeout_are_policy_governed(tmp_path):
    ws = Workspace(tmp_path, policy=WorkspacePolicy(allowed_shell_commands=("python",), default_timeout=0.05), authorization_snapshot=snapshot(root=str(tmp_path), actions=["shell", "process"], tools=[], live=True))
    result = ws.run_shell("python -c 'print(42)'", timeout=2)
    assert result.ok and result.stdout.strip() == "42"
    with pytest.raises(WorkspacePolicyError):
        ws.run_shell("bash -c 'echo unsafe'")
    timed = ws.run_process(("python", "-c", "import time; time.sleep(1)"), timeout=0.01)
    assert timed.timed_out and timed.exit_code is None


def test_tool_registry_exposes_typed_metadata_without_second_registry():
    definitions = {item["tool_id"]: item for item in tool_definitions()}
    assert definitions["run_project_tests"]["required_authorization"] == "owner"
    assert get_tool("run_project_tests").version == "1.0.0"
    assert "evidence_requirements" in definitions["run_project_tests"]


def test_authorization_snapshot_is_hashed_immutable_and_amendable():
    auth = snapshot()
    assert auth.authorization_hash == auth.compute_hash()
    assert auth.check(action="read", tool_id="run_project_tests", target_identity="workspace-1", at="2026-01-01T00:30:00+00:00")[0]
    assert not auth.check(action="delete", tool_id="run_project_tests", target_identity="workspace-1", at="2026-01-01T00:30:00+00:00")[0]
    assert not auth.check(action="read", tool_id="run_project_tests", target_identity="other", at="2026-01-01T00:30:00+00:00")[0]
    amended = auth.amend(owner_approval="approval-2", changes={"allowed_actions": ("read", "test", "write")}, created_at="2026-01-01T01:00:00+00:00", expires_at="2026-01-01T02:00:00+00:00")
    assert amended.version == 2
    assert amended.authorization_hash != auth.authorization_hash
    with pytest.raises(Exception):
        auth.allowed_actions += ("write",)


def test_queue_worker_and_restart_recovery(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-1", available_at="2026-01-01T00:00:00+00:00")
    claimed = queue.claim_next(now="2026-01-01T00:00:00+00:00")
    assert claimed.state is WorkerMissionState.EXECUTING
    recovered = queue.recover_after_restart()
    assert recovered[0].state is WorkerMissionState.QUEUED

    class Mission:
        status = MissionStatus.GOAL_COMPLETED
        evidence = [{"criterion_id": "done"}]
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None):
            assert mission_id == "mission-1"
            return Mission()

    worker = MissionWorker(queue, lambda: Runtime())
    result = worker.run_once(now="2026-01-01T00:00:00+00:00")
    assert result.state is WorkerMissionState.COMPLETED


def test_reenqueue_clears_stale_lease_and_error(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-requeued", available_at="2026-01-01T00:00:00+00:00")
    queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id="old-worker", lease_seconds=3600)
    queue.update("mission-requeued", WorkerMissionState.EXECUTING, error="old failure", worker_id="old-worker")

    requeued = queue.enqueue("mission-requeued", available_at="2026-01-01T00:01:00+00:00")
    assert requeued.state is WorkerMissionState.QUEUED
    assert requeued.last_error == ""
    assert requeued.lease_owner is None
    assert requeued.lease_expires_at is None

    reclaimed = queue.claim_next(now="2026-01-01T00:01:00+00:00", worker_id="new-worker")
    assert reclaimed is not None
    assert reclaimed.lease_owner == "new-worker"


def test_concurrent_workers_claim_a_mission_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-once", available_at="2026-01-01T00:00:00+00:00")

    def claim(worker_id):
        return queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id=worker_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, ("worker-a", "worker-b")))

    successful = [item for item in claims if item is not None]
    assert len(successful) == 1
    assert queue.get("mission-once").attempts == 1


def test_worker_preserves_recovery_required_for_reconciliation(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-recovery", available_at="2026-01-01T00:00:00+00:00")

    class Mission:
        status = MissionStatus.RECOVERY_REQUIRED
        evidence = []
        error = "in-flight tool outcome is unknown"

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None):
            assert mission_id == "mission-recovery"
            return Mission()

    result = MissionWorker(queue, lambda: Runtime()).run_once(now="2026-01-01T00:00:00+00:00")
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.last_error == "in-flight tool outcome is unknown"


def test_scheduler_supports_one_time_and_recurring_dispatch(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    one = scheduler.schedule("mission-one", run_at="2026-01-01T00:00:00+00:00", schedule_id="one")
    recurring = scheduler.schedule("mission-recurring", run_at="2026-01-01T00:00:00+00:00", interval_seconds=60, schedule_id="recurring")
    dispatched = scheduler.dispatch_due(now="2026-01-01T00:01:00+00:00")
    assert {item.schedule_id for item in dispatched} == {"one", "recurring"}
    assert scheduler.get("one").state is WorkerMissionState.COMPLETED
    assert scheduler.get("recurring").state is WorkerMissionState.SCHEDULED
    assert scheduler.get("recurring").next_run_at == "2026-01-01T00:02:00+00:00"


def test_context_separation_and_independent_verification():
    context = MissionContext("mission-1")
    context.add("mission", ContextRecord("m1", {"decision": "run tests"}, "owner_instruction"))
    context.add("knowledge", ContextRecord("k1", {"fact": "external"}, "external_data"))
    with pytest.raises(ValueError):
        context.add("authorization", ContextRecord("a1", {"allowed": True}, "model"))

    claim = FindingClaim("tests pass", "workspace-1", reproduction="pytest")
    plan = VerificationPlan("pytest-validator", required_evidence=("pytest",), validator=lambda _claim, _evidence: VerificationResult.PASS)
    report = VerificationEngine().verify(claim, plan, [{"source": "pytest", "type": "command", "result": {"exit_code": 0}}])
    assert report.result is VerificationResult.PASS
    unknown = VerificationEngine().verify(claim, VerificationPlan("missing"), [])
    assert unknown.result is VerificationResult.UNKNOWN


def test_self_repair_records_bounded_cycle():
    attempts = {"count": 0}

    def action():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("compile failed")
        return {"exit_code": 0}

    result = BoundedSelfRepair(max_retries=2).run(action, lambda exc: str(exc), lambda _diagnosis, _attempt: None, lambda value: value["exit_code"] == 0)
    assert result.success is True
    assert any(item.phase == "failure" for item in result.records)
    assert any(item.phase == "repair" for item in result.records)


def test_mission_service_uses_canonical_runtime_and_persistent_queue(tmp_path):
    from agent.mission import MissionStore

    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda _mission, _step, _action: {"success": True, "criterion_id": "done", "source": "test"}, authorization_snapshot_factory=make_test_snapshot)
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    service = MissionService(runtime, queue, scheduler)
    mission = service.create_mission("build", "build", Plan.initial("build"))
    started = service.start_mission(mission["mission_id"])
    assert started["state"] == WorkerMissionState.QUEUED
    service.pause_mission(mission["mission_id"])
    assert service.status(mission["mission_id"])["checkpoint"]["status"] == "paused"
    scheduled = service.schedule_mission(mission["mission_id"], run_at="2026-01-01T00:00:00+00:00", schedule_id="svc")
    assert scheduled["schedule_id"] == "svc"
