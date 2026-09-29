from __future__ import annotations
from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs

from pathlib import Path

import pytest

from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep


class ScriptedModel:
    def __init__(self, mission_id: str):
        self.mission_id = mission_id
        self.turns = []

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.turns.append(list(messages))
        if len(self.turns) == 1:
            return ModelTurn(
                turn_id,
                tool_calls=(ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="r1", plan_version=plan_version, step_id="observe", action_id="a1", tool_call_id="call_001"),),
            )
        assert any(message.role == "tool" and "tool_observation" in message.content for message in self.turns[-1])
        return ModelTurn(turn_id, content="goal verified", finish_reason="stop")


def test_native_loop_executes_tool_then_models_again(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"ok": True, "criterion_id": "goal", "source": "fixture-result"})
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("investigate").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("investigate", "investigate", plan, completion_criteria=[{"criterion_id": "goal", "check": "system_online"}], **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="native-protocol-test"))
    model = ScriptedModel(mission.mission_id)

    result = runtime.run_model_loop(mission.mission_id, model, tools=[{"name": "status"}], max_turns=3)

    assert result.status is MissionStatus.GOAL_COMPLETED
    assert len(model.turns) == 2
    assert len(result.progress["model_loop"]["turns"]) == 2
    assert result.progress["model_loop"]["seen_call_ids"] == ["call_001"]
    assert any(event["event"] == "ModelTurn" for event in result.trajectory)


def test_native_loop_rejects_cross_mission_call_without_execution(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args) or {"ok": True})

    class MaliciousModel:
        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            return ModelTurn(turn_id, tool_calls=(ToolCallProposal.create("status", {}, mission_id="other-mission", run_id=run_id, turn_id=turn_id, plan_version=plan_version, tool_call_id="call-old"),))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    mission = runtime.create("check", "check", Plan.initial("check").replan(steps=(PlanStep("s", "s", action="status"),), reason="test"))
    result = runtime.run_model_loop(mission.mission_id, MaliciousModel(), tools=[], max_turns=1)

    assert calls == []
    assert result.progress["model_loop"]["tool_results"][0]["error"] == "tool call belongs to another mission"
    assert result.status is MissionStatus.FAILED_RETRY_EXHAUSTED


def test_native_loop_rejects_dependent_step_before_prerequisite(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: calls.append(args[0]) or {"success": True})

    class DependentFirstModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = ToolCallProposal.create(
                "status",
                {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                plan_version=plan_version,
                step_id="dependent",
                action_id="dependent-action",
                tool_call_id="dependent-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("dependency order").replan(
        steps=(
            PlanStep("dependent", "dependent", action="status", prerequisites=("prerequisite",)),
            PlanStep("prerequisite", "prerequisite", action="status"),
        ),
        reason="reverse topological order regression",
    )
    mission = runtime.create(
        "dependency order",
        "dependency order",
        plan,
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="native-dag-test"),
    )

    result = runtime.run_model_loop(mission.mission_id, DependentFirstModel(), tools=[{"name": "status"}], max_turns=1)

    assert calls == []
    assert "prerequisite" in result.progress["model_loop"]["tool_results"][0]["error"]


def test_parallel_native_loop_rejects_dependent_call_in_same_batch(tmp_path, monkeypatch):
    import tools.registry

    executions = []
    monkeypatch.setattr(tools.registry, "execute", lambda name, *args, **kwargs: executions.append(name) or {"success": True})

    class ParallelDependentModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposals = (
                ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="prerequisite", action_id="prerequisite-action", tool_call_id="prerequisite-call"),
                ToolCallProposal.create("status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="dependent", action_id="dependent-action", tool_call_id="dependent-call"),
            )
            return ModelTurn(turn_id, tool_calls=proposals)

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("parallel dependency").replan(
        steps=(
            PlanStep("dependent", "dependent", action="status", prerequisites=("prerequisite",)),
            PlanStep("prerequisite", "prerequisite", action="status"),
        ),
        reason="parallel prerequisite gate regression",
    )
    mission = runtime.create("parallel dependency", "parallel dependency", plan, **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="parallel-dag-test"))

    result = runtime.run_model_loop(mission.mission_id, ParallelDependentModel(), tools=[{"name": "status"}], max_turns=1)

    assert executions == ["status"]
    tool_results = result.progress["model_loop"]["tool_results"]
    assert tool_results[0]["tool_call_id"] == "prerequisite-call"
    assert tool_results[1]["tool_call_id"] == "dependent-call"
    assert "prerequisite" in tool_results[1]["error"]


def test_completed_write_step_cannot_be_reopened_as_auxiliary(tmp_path):
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("write once").replan(steps=(PlanStep("watch-step", "add watch", action="watch"),), reason="write replay regression")
    mission = runtime.create("write once", "write once", plan)
    mission.record_action("watch-action", "watch-step", "completed", {"ok": True}, plan_fingerprint=plan.fingerprint)
    proposal = ToolCallProposal.create(
        "watch",
        {"query": "critical"},
        mission_id=mission.mission_id,
        run_id="run-1",
        turn_id="turn-1",
        plan_version=plan.version,
        step_id="watch-step",
        tool_call_id="watch-replay",
    )

    _bound, planned_step, error = runtime._bind_proposal_to_ready_step(mission, proposal)

    assert planned_step is None
    assert error == "plan step is already completed"


def test_false_native_tool_result_is_not_recorded_as_completed(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: {"success": False, "error": "service is unavailable"})

    class FailingStatusModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = ToolCallProposal.create(
                "status", {}, mission_id=mission_id, run_id=run_id, turn_id=turn_id,
                plan_version=plan_version, step_id="observe", action_id="observe-action", tool_call_id="observe-call",
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("verify status").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="false result regression")
    mission = runtime.create("verify status", "verify status", plan, **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="false-result-test"))

    result = runtime.run_model_loop(mission.mission_id, FailingStatusModel(), tools=[{"name": "status"}], max_turns=1)

    assert result.action_history[0]["status"] == "failed"
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is False
    assert result.status.name != "GOAL_COMPLETED"


def test_provider_switch_preserves_durable_mission_security_and_context(tmp_path, monkeypatch):
    import copy
    import json

    from agent.model_protocol import RouterNativeModel
    from agent.model_router import ModelRouter
    from agent.provider_api import ProviderCapabilities
    from runtime_authorization import signed_test_owner_kwargs

    class FakeProvider:
        def __init__(self, name, response):
            self.name = name
            self.model = f"{name}-model"
            self.response = response
            self.capabilities = ProviderCapabilities(generate=True, tool_calling=False)
            self.requests = []

        def generate(self, messages, temperature=0, **kwargs):
            self.requests.append(messages)
            return {"content": self.response}

    database = Path(tmp_path) / "provider-switch.sqlite3"
    store_a = MissionStore(database)
    runtime_a = MissionRuntime(store_a, executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    scope_snapshot = {
        "target_id": "test-target",
        "allowed_targets": ["https://scope.example"],
        "allowed_networks": [],
        "allowed_credentials": [],
        "workspace_root": "/workspace/test",
    }
    mission = runtime_a.create(
        "continue the same mission",
        "continue the same mission",
        Plan.initial("continue the same mission").replan(
            steps=(PlanStep("observe", "observe", action="status"),), reason="provider-switch fixture"
        ),
        scope_snapshot=scope_snapshot,
        provenance={"source": "provider-switch-test", "verification": "NOT_VERIFIED"},
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="provider-switch-test"),
    )
    mission.evidence = [{
        "criterion_id": "fixture-evidence",
        "passed": False,
        "source": "mock-provider-test",
        "result": {"observation": "unverified fixture"},
        "provenance": {"source_id": "fixture-source", "verification": "NOT_VERIFIED"},
    }]
    mission.knowledge_context = [{
        "knowledge_id": "fixture-context",
        "source": "mock-provider-test",
        "text": "durable context marker",
        "provenance": {"source_id": "context-source", "verification": "NOT_VERIFIED"},
    }]
    store_a.save(mission)
    durable_before_switch = MissionStore(database).load(mission.mission_id)
    expected = {
        "mission_id": durable_before_switch.mission_id,
        "authorization_context": copy.deepcopy(durable_before_switch.authorization_context),
        "scope_snapshot": copy.deepcopy(durable_before_switch.scope_snapshot),
        "policy_snapshot": copy.deepcopy(durable_before_switch.policy_snapshot),
        "authorization_snapshot": copy.deepcopy(durable_before_switch.authorization_snapshot),
        "evidence": copy.deepcopy(durable_before_switch.evidence),
        "provenance": copy.deepcopy(durable_before_switch.provenance),
        "knowledge_context": copy.deepcopy(durable_before_switch.knowledge_context),
    }

    provider_a = FakeProvider("provider-a", "first provider checkpoint")
    first = runtime_a.run_model_loop(
        mission.mission_id,
        RouterNativeModel(ModelRouter([provider_a])),
        tools=[],
        max_turns=1,
    )
    assert first.status is MissionStatus.READY
    saved_after_a = MissionStore(database).load(mission.mission_id)
    for field, value in expected.items():
        assert getattr(saved_after_a, field) == value

    provider_b = FakeProvider("provider-b", "continued with replacement provider")
    runtime_b = MissionRuntime(
        MissionStore(database), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot
    )
    continued = runtime_b.run_model_loop(
        mission.mission_id,
        RouterNativeModel(ModelRouter([provider_b])),
        tools=[],
        max_turns=1,
    )

    assert continued.status is MissionStatus.READY
    saved_after_b = MissionStore(database).load(mission.mission_id)
    for field, value in expected.items():
        assert getattr(saved_after_b, field) == value
    turns = saved_after_b.progress["model_loop"]["turns"]
    assert [turn["provider"] for turn in turns] == ["provider-a", "provider-b"]

    def durable_state(provider):
        content = next(message["content"] for message in provider.requests[0] if message["content"].startswith("DURABLE_STATE\n"))
        return json.loads(content.removeprefix("DURABLE_STATE\n"))

    state_a = durable_state(provider_a)
    state_b = durable_state(provider_b)
    for section in ("owner", "mission", "plan", "observation", "evidence", "knowledge", "tool", "tool_definitions"):
        assert state_b[section] == state_a[section]
    assert state_b["mission"]["mission_id"] == expected["mission_id"]
    assert state_b["evidence"] == expected["evidence"]
    assert state_b["knowledge"] == expected["knowledge_context"]
    assert saved_after_b.verification_state["verified"] is False


def _live_owner_session_mission(tmp_path, monkeypatch, *, request_id, steps):
    import core.db as core_db
    from security import owner_password, owner_policy
    from security.authorization_context import AuthorizationContext

    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "owner-sessions.sqlite3")
    monkeypatch.setattr(owner_policy, "STATE_PATH", Path(tmp_path) / "owner-policy-state.json")
    owner_password.create_owner_account(owner_password.OWNER_USERNAME, "integration-test-password")
    session = owner_password.login(owner_password.OWNER_USERNAME, "integration-test-password")
    evidence = owner_policy.authenticate_owner(session["session_id"], request_id)
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    context = AuthorizationContext(request_id, evidence, policy, session_id=session["session_id"])
    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda *_: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("perform authorized tool actions").replan(steps=steps, reason="live-session-test")
    mission = runtime.create(
        "perform authorized tool actions",
        "perform authorized tool actions",
        plan,
        request_id=request_id,
        owner_identity_ref=str(evidence.owner_id),
        authorization_context=context.to_dict(),
        policy_snapshot=policy.to_dict(),
    )
    return runtime, mission, session["session_id"]


@pytest.mark.parametrize(
    ("actions", "omit_context_session"),
    [
        (("watch",), False),
        (("watch", "unwatch"), False),
        (("watch",), True),
    ],
)
def test_revoked_owner_session_during_inference_blocks_tool_dispatch(tmp_path, monkeypatch, actions, omit_context_session):
    import threading

    import security.owner_password as owner_password
    import tools.registry

    steps = tuple(PlanStep(f"{name}-step", f"{name} tool", action=name) for name in actions)
    runtime, mission, session_id = _live_owner_session_mission(
        tmp_path,
        monkeypatch,
        request_id=f"dispatch-race-{len(actions)}-{int(omit_context_session)}",
        steps=steps,
    )
    if omit_context_session:
        mission.authorization_context = dict(mission.authorization_context)
        mission.authorization_context["session_id"] = None
        runtime.store.save(mission)
    inference_started = threading.Event()
    release_inference = threading.Event()
    executions = []
    monkeypatch.setattr(tools.registry, "execute", lambda *args, **kwargs: executions.append(args[0]) or {"ok": True})

    class InferenceBarrierModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            inference_started.set()
            assert release_inference.wait(5), "test did not release model inference"
            proposals = tuple(
                ToolCallProposal.create(
                    name,
                    {"query": "revocation-race"},
                    mission_id=mission_id,
                    run_id=run_id,
                    turn_id=turn_id,
                    plan_version=plan_version,
                    step_id=f"{name}-step",
                    tool_call_id=f"{turn_id}-{name}",
                )
                for name in actions
            )
            return ModelTurn(turn_id, tool_calls=proposals)

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runtime.run_model_loop,
            mission.mission_id,
            InferenceBarrierModel(),
            tools=[{"name": name} for name in actions],
            max_turns=1,
        )
        assert inference_started.wait(5), "model inference did not reach the barrier"
        assert owner_password.revoke_session(session_id)
        release_inference.set()
        result = future.result(timeout=10)

    assert executions == []
    tool_results = result.progress["model_loop"]["tool_results"]
    assert len(tool_results) == len(actions)
    assert all(not item["ok"] and "session" in item["error"].casefold() for item in tool_results)


def test_parallel_dispatch_rechecks_owner_session_after_each_external_tool_call(tmp_path, monkeypatch):
    import threading

    import security.owner_password as owner_password
    import tools.registry

    runtime, mission, session_id = _live_owner_session_mission(
        tmp_path,
        monkeypatch,
        request_id="parallel-dispatch-revocation-race",
        steps=(
            PlanStep("watch-step", "add watch", action="watch"),
            PlanStep("unwatch-step", "remove watch", action="unwatch"),
        ),
    )
    first_dispatch_finished = threading.Event()
    resolve_lock = threading.Lock()
    resolve_count = 0
    resolve_session = owner_password.resolve_session

    def ordered_resolve(session_token):
        nonlocal resolve_count
        with resolve_lock:
            resolve_count += 1
            ordinal = resolve_count
        if ordinal > 1:
            assert first_dispatch_finished.wait(5), "second dispatch did not wait for first dispatch revocation"
        return resolve_session(session_token)

    monkeypatch.setattr(owner_password, "resolve_session", ordered_resolve)
    executions = []

    def execute(name, *_args, **_kwargs):
        executions.append(name)
        if len(executions) == 1:
            assert owner_password.revoke_session(session_id)
            first_dispatch_finished.set()
        return {"ok": True}

    monkeypatch.setattr(tools.registry, "execute", execute)

    class ParallelModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposals = (
                ToolCallProposal.create("watch", {"query": "race"}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="watch-step", tool_call_id="parallel-watch-call"),
                ToolCallProposal.create("unwatch", {"query": "race"}, mission_id=mission_id, run_id=run_id, turn_id=turn_id, plan_version=plan_version, step_id="unwatch-step", tool_call_id="parallel-unwatch-call"),
            )
            return ModelTurn(turn_id, tool_calls=proposals)

    result = runtime.run_model_loop(
        mission.mission_id,
        ParallelModel(),
        tools=[{"name": "watch"}, {"name": "unwatch"}],
        max_turns=1,
    )

    assert len(executions) == 1
    tool_results = result.progress["model_loop"]["tool_results"]
    assert len(tool_results) == 2
    assert sum(bool(item["ok"]) for item in tool_results) == 1
    denied = next(item for item in tool_results if not item["ok"])
    assert "session" in denied["error"].casefold()
