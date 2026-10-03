from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from agent.mission import MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_context import ContextRecord, MissionContext
from agent.mission_worker import ExecutionFenceError, MissionQueue, MissionScheduler, MissionWorker, WorkerMissionState
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
    claimed = queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id="worker-a", lease_seconds=60)
    assert claimed.state is WorkerMissionState.EXECUTING
    recovered = queue.recover_after_restart(now="2026-01-01T00:01:01+00:00")
    assert recovered[0].state is WorkerMissionState.QUEUED

    class Mission:
        status = MissionStatus.GOAL_COMPLETED
        evidence = [{"criterion_id": "done"}]
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "mission-1"
            return Mission()

    worker = MissionWorker(queue, lambda: Runtime())
    result = worker.run_once()
    assert result.state is WorkerMissionState.COMPLETED


def test_reenqueue_does_not_steal_live_lease_and_clears_after_expiry_recovery(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    claimed_at = datetime.now(timezone.utc)
    claimed_at_text = claimed_at.isoformat()
    recovery_at = (claimed_at + timedelta(seconds=3601)).isoformat()
    queue.enqueue("mission-requeued", available_at=claimed_at_text)
    claimed = queue.claim_next(now=claimed_at_text, worker_id="old-worker", lease_seconds=3600)
    assert claimed is not None
    queue.update("mission-requeued", WorkerMissionState.EXECUTING, error="old failure", worker_id="old-worker", lease_epoch=claimed.lease_epoch, now=claimed_at_text)

    live = queue.get("mission-requeued")
    still_live = queue.enqueue("mission-requeued", available_at=recovery_at)
    assert still_live.state is WorkerMissionState.EXECUTING
    assert still_live.lease_owner == "old-worker"
    assert still_live.lease_expires_at == live.lease_expires_at
    assert still_live.lease_epoch == live.lease_epoch
    assert still_live.last_error == "old failure"

    recovered = queue.recover_after_restart(now=recovery_at)
    assert len(recovered) == 1
    assert recovered[0].state is WorkerMissionState.QUEUED
    assert recovered[0].lease_epoch > claimed.lease_epoch
    requeued = queue.enqueue("mission-requeued", available_at=recovery_at)
    assert requeued.state is WorkerMissionState.QUEUED
    assert requeued.last_error == ""
    assert requeued.lease_owner is None
    assert requeued.lease_expires_at is None

    reclaimed = queue.claim_next(now=recovery_at, worker_id="new-worker")
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


def test_worker_does_not_mark_mission_failed_after_lease_takeover(tmp_path):
    import sqlite3

    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-taken-over", available_at="2026-01-01T00:00:00+00:00")

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            with sqlite3.connect(queue.db_path) as db:
                db.execute("UPDATE mission_queue SET lease_owner=? WHERE mission_id=?", ("replacement-worker", mission_id))
            heartbeat()

    result = MissionWorker(queue, lambda: Runtime(), worker_id="stale-worker").run_once(now=datetime.now(timezone.utc).isoformat())
    assert result.state is WorkerMissionState.EXECUTING
    assert result.lease_owner == "replacement-worker"
    assert result.last_error == ""


def test_worker_does_not_overwrite_requeued_mission_after_handler_lease_expiry(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    started_at = datetime.now(timezone.utc)
    queue.enqueue("mission-expired-handler", available_at=started_at.isoformat())
    recovery_at = (started_at + timedelta(seconds=120)).isoformat()

    class Mission:
        status = MissionStatus.GOAL_COMPLETED
        evidence = [{"criterion_id": "done"}]
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            queue.recover_expired(now=recovery_at)
            return Mission()

    result = MissionWorker(queue, lambda: Runtime(), worker_id="expired-worker", lease_seconds=60).run_once(now=started_at.isoformat())
    assert result.state is WorkerMissionState.QUEUED
    assert result.last_error == "worker lease expired"


def test_worker_parks_unexpected_runtime_error_for_reconciliation(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-auth-error", available_at="2026-01-01T00:00:00+00:00")

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            raise PermissionError("authorization denied")

    result = MissionWorker(queue, lambda: Runtime(), worker_id="worker").run_once()
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.last_error == "worker runtime failed; execution outcome requires reconciliation"
    assert result.lease_owner is None


def test_worker_does_not_retry_typeerror_that_mentions_heartbeat(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("ambiguous-heartbeat", available_at="2026-01-01T00:00:00+00:00")
    calls = []

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            calls.append(mission_id)
            raise TypeError("heartbeat failed after dispatch")

    result = MissionWorker(queue, lambda: Runtime(), worker_id="worker").run_once()
    assert calls == ["ambiguous-heartbeat"]
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.last_error == "worker runtime failed; execution outcome requires reconciliation"
    assert result.lease_owner is None


def test_worker_lease_duration_is_configurable_and_validated(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-lease-config", available_at="2026-01-01T00:00:00+00:00")
    run_started_at = datetime.now(timezone.utc)

    class Mission:
        status = MissionStatus.GOAL_COMPLETED
        evidence = [{"criterion_id": "done"}]
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            item = queue.get(mission_id)
            seconds_left = (datetime.fromisoformat(item.lease_expires_at) - datetime.now(timezone.utc)).total_seconds()
            assert 14 <= seconds_left <= 17
            return Mission()

    with pytest.raises(ValueError, match="lease_seconds"):
        MissionWorker(queue, lambda: Runtime(), lease_seconds=0)
    result = MissionWorker(queue, lambda: Runtime(), lease_seconds=17).run_once(now=run_started_at.isoformat())
    assert result.state is WorkerMissionState.COMPLETED


def test_worker_preserves_recovery_required_for_reconciliation(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    queue.enqueue("mission-recovery", available_at="2026-01-01T00:00:00+00:00")

    class Mission:
        status = MissionStatus.RECOVERY_REQUIRED
        evidence = []
        error = "in-flight tool outcome is unknown"

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "mission-recovery"
            return Mission()

    result = MissionWorker(queue, lambda: Runtime()).run_once()
    assert result.state is WorkerMissionState.WAITING_FOR_TOOL
    assert result.last_error == "in-flight tool outcome is unknown"


def test_scheduler_without_mission_store_fails_closed(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    with pytest.raises(ExecutionFenceError, match="authoritative MissionStore"):
        scheduler.schedule("mission-one", run_at="2026-01-01T00:00:00+00:00", schedule_id="one")
    with pytest.raises(ExecutionFenceError, match="authoritative MissionStore"):
        scheduler.cancel_scheduled("legacy-scheduled-mission")
    queue.enqueue("legacy-scheduled-mission", available_at="2026-01-01T00:00:00+00:00", state=WorkerMissionState.SCHEDULED)
    with pytest.raises(ExecutionFenceError, match="authoritative MissionStore"):
        scheduler.dispatch_due(now="2026-01-01T00:01:00+00:00")
    assert queue.get("legacy-scheduled-mission").state is WorkerMissionState.SCHEDULED
    assert queue.claim_next(now="2026-01-01T00:01:00+00:00", worker_id="worker") is None


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


def test_mission_service_uses_canonical_runtime_and_persistent_queue(tmp_path, monkeypatch):
    import core.db as core_db
    from agent.mission import MissionStore
    from agent.agent_core import AgentCore
    from agent.model_router import ModelRouter
    from owner_session_testutils import allow_owner_sessions

    allow_owner_sessions(monkeypatch, "service-owner")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "owner_auth.sqlite3")
    now = datetime.now(timezone.utc).isoformat()
    with core_db.connect() as auth_db:
        auth_db.execute(
            "INSERT INTO owner_accounts(username,password_hash,kdf_algorithm,kdf_params_json,status) "
            "VALUES(?,?,?,?,?)",
            ("owner-one", "test-verifier", "scrypt", "{}", "active"),
        )
        auth_db.execute(
            "INSERT INTO owner_sessions(session_id,owner_id,created_at,authenticated_at,expires_at,status,auth_method) "
            "VALUES(?,?,?,?,?,?,?)",
            ("service-owner", 1, now, now, "2999-01-01T00:00:00+00:00", "active", "username_password"),
        )
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda _mission, _step, _action: {"success": True, "criterion_id": "done", "source": "test"}, authorization_snapshot_factory=make_test_snapshot)
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    scheduler = MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue)
    core = AgentCore(ModelRouter([]), store=store)
    service = MissionService(runtime, queue, scheduler, owner_revalidator=core.prepare_mission_for_queue)
    mission = service.create_mission("build", "build", Plan.initial("build"), owner_identity_ref="owner:1")
    assert mission["request_id"]
    initial_iterations = store.load(mission["mission_id"]).iteration_count
    started = service.start_mission(mission["mission_id"], owner_session_token="service-owner")
    assert started["state"] == WorkerMissionState.QUEUED
    service.pause_mission(mission["mission_id"], owner_session_token="service-owner")
    assert service.status(mission["mission_id"], owner_session_token="service-owner")["checkpoint"]["status"] == "paused"
    resumed = service.resume_mission(mission["mission_id"], owner_session_token="service-owner")
    assert "pause_requested" not in resumed["progress"]
    assert queue.get(mission["mission_id"]).state == WorkerMissionState.QUEUED
    assert store.load(mission["mission_id"]).iteration_count == initial_iterations
    scheduled = service.schedule_mission(mission["mission_id"], owner_session_token="service-owner", run_at="2026-01-01T00:00:00+00:00", schedule_id="svc")
    assert scheduled["schedule_id"] == "svc"
