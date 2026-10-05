from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from agent.intelligence_layer.graph import AgentGraphPolicy
from agent.intelligence_layer.models import AgentLifecycle, TaskLifecycle
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import WorkerMissionState
from agent.planning import FailureClass, Plan, PlanStep, RecoveryPolicy
from api.missions import MissionService
from runtime_authorization import make_test_snapshot


class _Queue:
    def enqueue(self, mission_id, *, state=None):
        return SimpleNamespace(state=state or WorkerMissionState.QUEUED)


def _runtime(tmp_path: Path, executor, **kwargs) -> MissionRuntime:
    return MissionRuntime(
        MissionStore(tmp_path / "missions.sqlite3"),
        executor=executor,
        authorization_snapshot_factory=make_test_snapshot,
        task_graph_policy=AgentGraphPolicy(max_agents=1, max_tasks=16, max_parallel_tasks=1, max_retries=1),
        **kwargs,
    )


def _service_for(rt: MissionRuntime, mission_id: str) -> MissionService:
    service = MissionService(rt, _Queue())
    service._authorized_mission = lambda requested_id, owner_session_token: (rt.store.load(requested_id), "test-owner")
    return service


def test_graph_gates_real_plan_dispatch_and_state_is_durable(tmp_path):
    calls = []

    def execute(mission, step, action_id):
        calls.append((step.step_id, action_id))
        return {"success": True, "result": {"step": step.step_id}}

    rt = _runtime(tmp_path, execute)
    plan = Plan.initial("execute dependent steps").replan(
        steps=(
            PlanStep("inspect", "inspect target", action="search"),
            PlanStep("verify", "verify result", prerequisites=("inspect",), action="run_project_tests"),
        ),
        reason="test plan",
    )
    mission = rt.create("execute dependent steps", "execute dependent steps", plan, owner_identity_ref="test-owner")
    state_at_create = mission.agent_task_graph_state
    assert state_at_create["plan_fingerprint"] == plan.fingerprint

    first = rt.run_slice(mission.mission_id)
    persisted_first = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    graph_first = persisted_first.agent_task_graph_state["graph"]
    first_ids = persisted_first.agent_task_graph_state["step_task_ids"]
    assert first.status is MissionStatus.READY
    assert graph_first["tasks"][0]["task_id"] == first_ids["inspect"]
    assert next(item for item in graph_first["tasks"] if item["task_id"] == first_ids["inspect"])["lifecycle"] == TaskLifecycle.COMPLETED.value
    assert next(item for item in graph_first["tasks"] if item["task_id"] == first_ids["verify"])["lifecycle"] == TaskLifecycle.READY.value

    second = rt.run_slice(mission.mission_id)
    persisted_second = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    graph_second = persisted_second.agent_task_graph_state["graph"]
    assert second.current_step == 2
    assert all(item["lifecycle"] == TaskLifecycle.COMPLETED.value for item in graph_second["tasks"])
    assert all(item["result_validation_state"] == "UNVERIFIED" for item in graph_second["tasks"])
    assert calls == [("inspect", f"{mission.mission_id}:2:inspect:0"), ("verify", f"{mission.mission_id}:2:verify:1")]


def test_graph_dependency_mismatch_fails_closed_before_executor(tmp_path):
    calls = []
    rt = _runtime(tmp_path, lambda mission, step, action_id: calls.append(step.step_id) or {"success": True})
    plan = Plan.initial("blocked dependency").replan(
        steps=(
            PlanStep("first", "first", prerequisites=("second",), action="search"),
            PlanStep("second", "second", action="run_project_tests"),
        ),
        reason="invalid execution order",
    )
    mission = rt.create("blocked dependency", "blocked dependency", plan, owner_identity_ref="test-owner")

    blocked = rt.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert blocked.failures[-1]["boundary"] == "agent_task_graph"
    assert calls == []


def test_graph_retry_is_bounded_and_follows_existing_mission_recovery_policy(tmp_path):
    calls = []

    def execute(mission, step, action_id):
        calls.append(action_id)
        if len(calls) == 1:
            return {"success": False, "failure_class": FailureClass.TRANSIENT.value, "error": "temporary failure"}
        return {"success": True, "result": "recovered"}

    rt = _runtime(
        tmp_path,
        execute,
        recovery_policy=RecoveryPolicy(max_retries=1, retryable=frozenset({FailureClass.TRANSIENT})),
    )
    plan = Plan.initial("bounded retry").replan(steps=(PlanStep("step", "step", action="search"),), reason="test plan")
    mission = rt.create("bounded retry", "bounded retry", plan, owner_identity_ref="test-owner")

    first = rt.run_slice(mission.mission_id)
    second = rt.run_slice(mission.mission_id)
    state = second.agent_task_graph_state
    graph_task = state["graph"]["tasks"][0]

    assert first.status is MissionStatus.READY
    assert graph_task["lifecycle"] == TaskLifecycle.COMPLETED.value
    assert graph_task["attempt_count"] == 2
    assert len(calls) == 2
    assert calls[0] == calls[1]  # Existing stable execution identity remains the idempotency boundary.


def test_crash_keeps_graph_task_running_and_never_replays_unknown_effect(tmp_path):
    calls = []

    def crash(mission, step, action_id):
        calls.append(action_id)
        raise RuntimeError("simulated loss after dispatch")

    rt = _runtime(tmp_path, crash)
    plan = Plan.initial("recover safely").replan(steps=(PlanStep("step", "step", action="search"),), reason="test plan")
    mission = rt.create("recover safely", "recover safely", plan, owner_identity_ref="test-owner")

    first = rt.run_slice(mission.mission_id)
    recovered = rt.run_slice(mission.mission_id)
    persisted = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    graph_task = persisted.agent_task_graph_state["graph"]["tasks"][0]

    assert first.checkpoint["status"] == "in_flight"
    assert recovered.status is MissionStatus.RECOVERY_REQUIRED
    assert graph_task["lifecycle"] == TaskLifecycle.RUNNING.value
    assert calls == [f"{mission.mission_id}:2:step:0"]


def test_owner_cancellation_marks_pending_graph_tasks_cancelled(tmp_path):
    rt = _runtime(tmp_path, lambda mission, step, action_id: {"success": True})
    plan = Plan.initial("cancel pending").replan(steps=(PlanStep("step", "step", action="search"),), reason="test plan")
    mission = rt.create("cancel pending", "cancel pending", plan, owner_identity_ref="test-owner")

    cancelled = _service_for(rt, mission.mission_id).cancel_mission(mission.mission_id, owner_session_token="owner-session")
    task = cancelled["agent_task_graph_state"]["graph"]["tasks"][0]
    agent = cancelled["agent_task_graph_state"]["graph"]["agents"][0]

    assert cancelled["status"] == MissionStatus.CANCELLED.value
    assert task["lifecycle"] == TaskLifecycle.CANCELLED.value
    assert agent["lifecycle"] == AgentLifecycle.CANCELLED.value


def test_owner_cancel_of_recovery_requests_stop_without_claiming_effect_stopped(tmp_path):
    def crash(mission, step, action_id):
        raise RuntimeError("outcome unknown")

    rt = _runtime(tmp_path, crash)
    plan = Plan.initial("cancel unknown effect").replan(steps=(PlanStep("step", "step", action="search"),), reason="test plan")
    mission = rt.create("cancel unknown effect", "cancel unknown effect", plan, owner_identity_ref="test-owner")
    rt.run_slice(mission.mission_id)
    rt.run_slice(mission.mission_id)
    assert rt.store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED

    cancelled = _service_for(rt, mission.mission_id).cancel_mission(mission.mission_id, owner_session_token="owner-session")
    task = cancelled["agent_task_graph_state"]["graph"]["tasks"][0]

    assert cancelled["status"] == MissionStatus.RECOVERY_REQUIRED.value
    assert cancelled["progress"]["owner_cancel_requested"] is True
    assert task["lifecycle"] == TaskLifecycle.RUNNING.value
    assert task["cancel_requested"] is True


def test_fresh_owner_snapshot_rebinds_graph_without_replaying_completed_steps(tmp_path):
    calls = []
    rt = _runtime(tmp_path, lambda mission, step, action_id: calls.append(step.step_id) or {"success": True})
    plan = Plan.initial("reauthorize graph").replan(
        steps=(
            PlanStep("first", "first", action="search"),
            PlanStep("second", "second", prerequisites=("first",), action="run_project_tests"),
        ),
        reason="test plan",
    )
    mission = rt.create("reauthorize graph", "reauthorize graph", plan, owner_identity_ref="test-owner")
    after_first = rt.run_slice(mission.mission_id)
    before_hash = after_first.agent_task_graph_state["graph"]["authorization_hash"]

    refreshed = rt.store.load(mission.mission_id)
    refreshed.authorization_snapshot = make_test_snapshot(refreshed).to_dict()
    rt.store.save(refreshed)
    after_second = rt.run_slice(mission.mission_id)

    tasks = after_second.agent_task_graph_state["graph"]["tasks"]
    assert after_second.current_step == 2
    assert after_second.agent_task_graph_state["graph"]["authorization_hash"] != before_hash
    assert all(item["lifecycle"] == TaskLifecycle.COMPLETED.value for item in tasks)
    assert calls == ["first", "second"]


def test_expired_snapshot_cannot_claim_or_dispatch_a_graph_task(tmp_path):
    calls = []
    rt = _runtime(tmp_path, lambda mission, step, action_id: calls.append(step.step_id) or {"success": True})
    plan = Plan.initial("expired graph authorization").replan(
        steps=(PlanStep("step", "step", action="search"),),
        reason="test plan",
    )
    mission = rt.create("expired graph authorization", "expired graph authorization", plan, owner_identity_ref="test-owner")
    expired = rt.store.load(mission.mission_id)
    snapshot = make_test_snapshot(expired).to_dict()
    snapshot["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    expired.authorization_snapshot = snapshot
    rt.store.save(expired)

    blocked = rt.run_slice(mission.mission_id)
    task = blocked.agent_task_graph_state["graph"]["tasks"][0]

    assert blocked.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert task["lifecycle"] == TaskLifecycle.READY.value
    assert calls == []


def test_legacy_mission_payload_without_graph_field_remains_loadable():
    plan = Plan.initial("legacy mission").replan(
        steps=(PlanStep("step", "step", action="search"),),
        reason="legacy fixture",
    )
    original = Mission.create("legacy mission", "legacy mission", plan, owner_identity_ref="test-owner")
    payload = original.to_dict()
    payload.pop("agent_task_graph_state")
    payload.pop("integrity_hash")
    payload["integrity_hash"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()

    restored = Mission.from_dict(payload)

    assert restored.mission_id == original.mission_id
    assert restored.agent_task_graph_state == {}


def test_malformed_persisted_graph_mapping_safety_blocks_before_dispatch(tmp_path):
    calls = []
    rt = _runtime(tmp_path, lambda mission, step, action_id: calls.append(step.step_id) or {"success": True})
    plan = Plan.initial("tampered graph").replan(
        steps=(PlanStep("step", "step", action="search"),),
        reason="test plan",
    )
    mission = rt.create("tampered graph", "tampered graph", plan, owner_identity_ref="test-owner")
    tampered = rt.store.load(mission.mission_id)
    tampered.agent_task_graph_state["step_task_ids"]["step"] = "forged-task-id"
    rt.store.save(tampered)

    blocked = rt.run_slice(mission.mission_id)

    assert blocked.status is MissionStatus.SAFETY_BLOCKED
    assert blocked.failures[-1]["boundary"] == "agent_task_graph"
    assert calls == []
