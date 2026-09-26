"""B3-C5-D: cross-run authorization proof binding (run_id) adversarial battery.

Closes the B3 cross-run authorization gap: a proof issued for one execution
run can never validate or execute in another run. The run identity is bound
across generation (ExecutionAuthorizationProof.derive via the canonical
MissionExecutionBoundary, which reads the live mission run id), the binding
hash + HMAC signature, serialization (to_dict/from_dict), validation
(verify, validate_against_mission) and the tool registry boundary.

Every rejection case asserts that NO TOOL HANDLER EXECUTED.
"""

from __future__ import annotations

from dataclasses import replace as dataclass_replace
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from security.execution_proof import ExecutionAuthorizationProof, RejectionCode
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import execute as registry_execute


def _runtime(tmp_path, factory=make_test_snapshot):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=factory)


def _mission(runtime, action="status", **kwargs):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}], **kwargs)


def _snapshot(mission):
    return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))


def _proof(mission, *, run_id="", tool="status", argument=None, **overrides):
    kwargs = dict(
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool=tool,
        argument=argument,
        snapshot=_snapshot(mission),
        tool_call_id="call_x",
        run_id=run_id,
        plan_hash=mission.plan.fingerprint,
        scope=mission.scope_snapshot,
        mission_status=mission.status.value,
        lifecycle_revision=len(mission.transitions),
    )
    kwargs.update(overrides)
    return ExecutionAuthorizationProof.derive(**kwargs)


class OneTurnModel:
    def __init__(self, proposals):
        self.proposals = tuple(proposals)
        self.done = False

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        if self.done:
            return ModelTurn(turn_id, content="done")
        self.done = True
        return ModelTurn(turn_id, tool_calls=self.proposals)


class CountingStatus:
    def __init__(self):
        self.calls = 0

    def handler(self, argument=None, **kwargs):
        self.calls += 1
        return {"ok": True, "criterion_id": "goal", "source": "status"}


@pytest.fixture
def counting_status(monkeypatch):
    counter = CountingStatus()
    spec = tools.registry.get_tool("status")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "status", dataclass_replace(spec, handler=counter.handler))
    return counter


def test_run_id_is_bound_in_schema_serialization_and_signature(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof_a = _proof(mission, run_id="run-a")
    proof_b = _proof(mission, run_id="run-b")
    assert proof_a.run_id == "run-a"
    assert proof_a.to_dict()["run_id"] == "run-a"
    assert proof_a.execution_binding_hash != proof_b.execution_binding_hash
    assert proof_a.proof_signature != proof_b.proof_signature
    round_trip = ExecutionAuthorizationProof.from_dict(proof_a.to_dict())
    assert round_trip.run_id == "run-a"
    assert round_trip.execution_binding_hash == proof_a.execution_binding_hash
    assert ExecutionAuthorizationProof.verify(round_trip, name="status", argument=None)[0] is True


def test_legacy_proof_dict_without_run_id_deserializes_with_empty_run(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    data = _proof(mission, run_id="run-a").to_dict()
    data.pop("run_id")
    legacy = ExecutionAuthorizationProof.from_dict(data)
    assert legacy.run_id == ""
    ok, _reason, code = ExecutionAuthorizationProof.verify(legacy, name="status", argument=None, run_id="run-a")
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value


def test_verify_rejects_cross_run_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, run_id="run-a")
    ok, _reason, code = ExecutionAuthorizationProof.verify(proof, name="status", argument=None, run_id="run-b")
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value
    ok, _reason, _code = ExecutionAuthorizationProof.verify(proof, name="status", argument=None, run_id="run-a")
    assert ok is True


def test_registry_rejects_cross_run_proof_before_handler(tmp_path, counting_status):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, run_id="run-a")
    with pytest.raises(PermissionError, match=RejectionCode.RUN_MISMATCH.value):
        registry_execute(
            "status",
            None,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=proof,
            execution_class="MISSION_BOUND",
            execution_run_id="run-b",
        )
    assert counting_status.calls == 0
    registry_execute(
        "status",
        None,
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        mission_authorization=_snapshot(mission),
        execution_proof=proof,
        execution_class="MISSION_BOUND",
        execution_run_id="run-a",
    )
    assert counting_status.calls == 1


def test_validate_against_mission_rejects_cross_run_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-b"
    stale = _proof(mission, run_id="run-a")
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(stale, mission)
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value
    legacy = _proof(mission, run_id="")
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(legacy, mission)
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value
    fresh = _proof(mission, run_id="run-b")
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(fresh, mission)
    assert ok is True and code == ""
    no_run_mission = _mission(runtime)
    claimed = _proof(no_run_mission, run_id="run-a")
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(claimed, no_run_mission)
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value
    compatible = _proof(no_run_mission, run_id="")
    ok, _reason, _code = ExecutionAuthorizationProof.validate_against_mission(compatible, no_run_mission)
    assert ok is True


def test_model_loop_binds_live_run_id_into_proof(tmp_path, monkeypatch):
    import tools.registry

    captured = {}

    def fake_execute(name, argument=None, **kwargs):
        captured["name"] = name
        captured["proof"] = kwargs.get("execution_proof")
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-run", authorization_context=make_test_authorization_context("req-run", tmp_path).to_dict())
    proposal = ToolCallProposal.create("status", None, mission_id=mission.mission_id, run_id="run-1", turn_id="run-1:turn:1", action_id="a1", tool_call_id="call_001")
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([proposal]), tools=[], run_id="run-1", max_turns=2)
    proof = captured.get("proof")
    assert isinstance(proof, ExecutionAuthorizationProof)
    assert captured["name"] == "status"
    assert proof.run_id == "run-1"
    assert proof.to_dict()["run_id"] == "run-1"
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is True


def test_proof_from_one_run_cannot_execute_in_another_run(tmp_path, monkeypatch, counting_status):
    import tools.registry

    captured = {}

    def fake_execute(name, argument=None, **kwargs):
        captured["proof"] = kwargs.get("execution_proof")
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-xrun", authorization_context=make_test_authorization_context("req-xrun", tmp_path).to_dict())
    proposal = ToolCallProposal.create("status", None, mission_id=mission.mission_id, run_id="run-1", turn_id="run-1:turn:1", action_id="a1", tool_call_id="call_001")
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([proposal]), tools=[], run_id="run-1", max_turns=2)
    proof = captured["proof"]
    assert isinstance(proof, ExecutionAuthorizationProof) and proof.run_id == "run-1"
    # A later, different run of the same mission rotates the live run identity.
    result.progress["model_run_id"] = "run-2"
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, result)
    assert ok is False and code == RejectionCode.RUN_MISMATCH.value
    with pytest.raises(PermissionError, match=RejectionCode.RUN_MISMATCH.value):
        registry_execute(
            "status",
            None,
            mission_id=result.mission_id,
            request_id=result.request_id,
            mission_authorization=_snapshot(result),
            execution_proof=proof,
            execution_class="MISSION_BOUND",
            execution_run_id="run-2",
        )
    assert counting_status.calls == 0
