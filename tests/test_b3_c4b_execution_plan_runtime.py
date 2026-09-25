"""B3-C4B adversarial battery: canonical ExecutionPlan runtime integration.

Covers INV-C4-1..INV-C4-15 and the 32-case adversarial matrix from the C4B
contract. Every negative case asserts BOTH the structured failure AND that
NO TOOL HANDLER EXECUTED (the registry execute path is monkeypatched with a
recording stub). Hermetic: scripted models, monkeypatched registry, local
snapshot factories, no network, no policy state on disk.

Hermetic fixtures reuse tests/runtime_authorization.py exactly like the
existing snapshot-gate and proof-boundary batteries.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from security.execution_plan import ExecutionPlanError, derive_execution_plan
from security.execution_plan_runtime import (
    bind_execution_plan,
    canonical_plan_identity,
    derive_mission_execution_plan,
    gate_action_against_plan,
    legacy_plan_effective_tools,
    mission_binding_fingerprint,
    owner_budget_from_snapshot,
    proposal_action_identity,
    reconstruct_execution_plan,
    validate_stored_execution_plan,
)
from security.execution_proof import ExecutionAuthorizationProof, RejectionCode, canonical_mission_plan_identity
from security.mission_authorization import MissionAuthorizationSnapshot
from security.owner_budget import OwnerAuthorizedToolBudget


def _runtime(tmp_path, factory=make_test_snapshot):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=factory)


def _mission(runtime, action="status", **kwargs):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}], **kwargs)


def _restricted(mission, **overrides):
    snapshot = make_test_snapshot(mission)
    fields = {"allowed_tools": ("status",), "allowed_actions": ("status",), "forbidden_actions": (), "authorization_hash": ""}
    fields.update(overrides)
    from dataclasses import replace
    return replace(snapshot, **fields)


class ScriptedModel:
    """Yields scripted tool-call turns, then a final content turn."""

    def __init__(self, mission_id, turns):
        self.mission_id = mission_id
        self.turns = list(turns)
        self.count = 0

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        self.count += 1
        if self.count <= len(self.turns):
            proposals = tuple(
                ToolCallProposal.create(name, args, mission_id=mission_id, run_id=run_id, turn_id=turn_id, request_id="r1", plan_version=plan_version, step_id="s1", action_id=action_id, tool_call_id=call_id)
                for name, args, action_id, call_id in self.turns[self.count - 1]
            )
            return ModelTurn(turn_id, tool_calls=proposals)
        return ModelTurn(turn_id, content="done", finish_reason="stop")


def _recording_registry(monkeypatch):
    """Replace the registry execute path with a handler-side recorder."""
    calls = []

    def record(name, argument=None, **kwargs):
        calls.append({"tool": name, "argument": argument, "proof": kwargs.get("execution_proof")})
        return {"ok": True, "criterion_id": "goal", "source": "fixture"}

    monkeypatch.setattr("tools.registry.execute", record)
    return calls


def _prepared_bound_mission(runtime, mission, proposals):
    """Bind a derived ExecutionPlan to a mission without running the loop."""
    plan = derive_mission_execution_plan(mission, proposals)
    bind_execution_plan(mission, plan)
    runtime.store.save(mission)
    return plan


# ---------------------------------------------------------------------------
# Pure derivation layer (B3-C3 contract preserved inside the runtime adapter)
# ---------------------------------------------------------------------------


def test_c4b_derivation_uses_owner_budget_intersection_only(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    budget = owner_budget_from_snapshot(mission)
    proposals = [
        ToolCallProposal.create("status", {}, mission_id=mission.mission_id, tool_call_id="call_1", action_id="a1"),
        ToolCallProposal.create("search", {"query": "q"}, mission_id=mission.mission_id, tool_call_id="call_2", action_id="a2"),
    ]
    plan = derive_mission_execution_plan(mission, proposals)
    assert plan.mission_fingerprint == mission_binding_fingerprint(mission)
    tools = [action.tool_name for action in plan.actions]
    assert set(tools) <= set(budget.tools)
    assert tools == ["status", "search"]
    # INV-C4-11: an empty Owner Budget intersection fails closed at the pure
    # derivation layer (C3 semantics unchanged).
    search_only = tuple(action for action in plan.actions if action.tool_name == "search")
    with pytest.raises(ExecutionPlanError):
        derive_execution_plan(OwnerAuthorizedToolBudget(frozenset({"status"})), search_only)
    with pytest.raises(ExecutionPlanError):
        derive_execution_plan(budget, ())


def test_c4b_inv2_model_supplied_authority_fields_fail_closed(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    # Keys rejected by the existing canonical ActionIntent validation
    # (reused, not duplicated): derivation fails closed.
    for forbidden_key in ("owner_budget", "owner_approval", "authorization", "execution_proof", "proof", "capability", "grant", "permission", "allowed_tools", "scope_expansion", "credential", "api_key"):
        proposal = ToolCallProposal.create("status", {forbidden_key: ["watch"]}, mission_id=mission.mission_id, tool_call_id=f"call_{forbidden_key}")
        with pytest.raises(PermissionError):
            derive_mission_execution_plan(mission, [proposal])


def test_c4b_inv2_unrejected_authority_named_arguments_remain_inert(tmp_path):
    """INV-C4-2: a model value that survives argument validation is still
    never interpreted as Owner authority. Effective actions come only from
    Owner Budget intersect ActionIntent.tool_name; the injected values flow
    as descriptive arguments to the tool handler (query extraction) only."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = ToolCallProposal.create("status", {"effective_actions": ["watch"], "approval": True, "snapshot": {"allowed_tools": ["watch"]}}, mission_id=mission.mission_id, tool_call_id="call_inert")
    plan = derive_mission_execution_plan(mission, [proposal])
    assert [action.tool_name for action in plan.actions] == ["status"]
    assert all(action.tool_name in owner_budget_from_snapshot(mission).tools for action in plan.actions)
    # The forged values are absent from every authority surface: the budget
    # is reconstructed only from the Owner-minted snapshot allowlist.
    assert "watch" not in owner_budget_from_snapshot(mission).tools


def test_c4b_action_identity_is_deterministic_and_unique():
    first = ToolCallProposal.create("status", {}, mission_id="m", tool_call_id="call_1", action_id="a1")
    second = ToolCallProposal.create("search", {}, mission_id="m", tool_call_id="call_2", action_id="a1")
    assert proposal_action_identity(first) == "a1:call_1"
    assert proposal_action_identity(second) == "a1:call_2"
    assert proposal_action_identity(first) != proposal_action_identity(second)


# ---------------------------------------------------------------------------
# Execution gate (section 9): action-in-plan, tool, arguments, identity
# ---------------------------------------------------------------------------


def test_c4b_gate_rejects_unplanned_action_tool_and_arguments(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    plan = derive_mission_execution_plan(mission, [ToolCallProposal.create("status", {"query": "q"}, mission_id=mission.mission_id, tool_call_id="call_1", action_id="a1")])
    ok, code, _reason = gate_action_against_plan(plan, action_id="a1:call_1", tool_name="status", arguments={"query": "q"})
    assert ok is True and code == ""
    # case 13: action not present in the ExecutionPlan
    ok, code, _ = gate_action_against_plan(plan, action_id="a9:call_9", tool_name="status", arguments={"query": "q"})
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value
    # case 14: arguments differ from the ExecutionPlan
    ok, code, _ = gate_action_against_plan(plan, action_id="a1:call_1", tool_name="status", arguments={"query": "changed"})
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value
    # case 15: tool differs from the ExecutionPlan
    ok, code, _ = gate_action_against_plan(plan, action_id="a1:call_1", tool_name="search", arguments={"query": "q"})
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value


def test_c4b_gate_rejects_tampered_plan_integrity(tmp_path):
    """A plan whose actions were mutated after construction is not executable."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    plan = derive_mission_execution_plan(mission, [ToolCallProposal.create("status", {}, mission_id=mission.mission_id, tool_call_id="call_1", action_id="a1")])
    tampered = plan.actions[0]
    object.__setattr__(tampered, "tool_name", "watch")
    ok, code, reason = gate_action_against_plan(plan, action_id="a1:call_1", tool_name="watch", arguments={})
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value
    assert "integrity" in reason


# ---------------------------------------------------------------------------
# Runtime: serial path
# ---------------------------------------------------------------------------


def test_c4b_happy_path_derives_binds_and_executes_against_plan(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("status", {}, "a1", "call_001")]]), tools=[], max_turns=3)
    assert result.status is MissionStatus.GOAL_COMPLETED
    assert [call["tool"] for call in calls] == ["status"]
    stored = result.progress["execution_plan"]
    assert stored["plan_fingerprint"] == canonical_plan_identity(result)
    assert calls[0]["proof"].plan_hash == stored["plan_fingerprint"]
    # INV-C4-3: the executed proposal maps to a concrete plan action.
    assert [action["action_id"] for action in stored["actions"]] == ["a1:call_001"]
    assert len(result.progress["execution_plans"]) == 1
    assert validate_stored_execution_plan(result) == (True, "authorized")


def test_c4b_inv1_tool_outside_owner_scope_never_executes(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime)
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("search", {"query": "q"}, "a1", "call_001")]]), tools=[], max_turns=1)
    assert calls == []
    tool_result = result.progress["model_loop"]["tool_results"][0]
    assert tool_result["ok"] is False
    assert tool_result["error"].startswith("TOOL_NOT_ALLOWED:")
    assert "execution_plan" not in result.progress


def test_c4b_inv2_authority_shaped_proposals_block_the_mission(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("status", {"owner_budget": ["watch"]}, "a1", "call_001")]]), tools=[], max_turns=1)
    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert result.progress["model_loop"]["tool_results"][0]["error"].startswith("TOOL_NOT_ALLOWED:")
    assert any(item["class"] == "AUTHORIZATION" for item in result.failures)
    assert any(item.get("event") == "ExecutionRejected" for item in result.trajectory)


def test_c4b_cross_run_proposal_is_rejected_without_execution(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = ToolCallProposal.create("status", {}, mission_id=mission.mission_id, run_id="another-run", tool_call_id="call_001", action_id="a1")
    model = ScriptedModel(mission.mission_id, [])
    model.complete = lambda messages, tools, **kw: ModelTurn(kw["turn_id"], tool_calls=(proposal,))
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)
    assert calls == []
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is False
    assert "another run" in result.progress["model_loop"]["tool_results"][0]["error"]


# ---------------------------------------------------------------------------
# Runtime: parallel path obeys the same plan gate (INV-C4-10)
# ---------------------------------------------------------------------------


def test_c4b_inv10_parallel_outside_allowlist_never_executes(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    model = ScriptedModel(mission.mission_id, [[("status", {}, "a1", "call_001"), ("search", {"query": "q"}, "a1", "call_002")]])
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=3)
    assert [call["tool"] for call in calls] == ["status"]
    blocked = [item for item in result.progress["model_loop"]["tool_results"] if item["tool_call_id"] == "call_002"]
    assert blocked and blocked[0]["ok"] is False
    assert blocked[0]["error"].startswith("TOOL_NOT_ALLOWED:")


def test_c4b_inv10_parallel_duplicate_tool_with_changed_arguments(tmp_path, monkeypatch):
    """Cases 4/13/14/15/27: a second same-tool call cannot widen the plan."""
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    model = ScriptedModel(mission.mission_id, [[("search", {"query": "first"}, "a1", "call_001"), ("search", {"query": "second"}, "a2", "call_002")]])
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=3)
    assert [call["tool"] for call in calls] == ["search"]
    assert calls[0]["argument"] == "first"
    blocked = [item for item in result.progress["model_loop"]["tool_results"] if item["tool_call_id"] == "call_002"]
    assert blocked and blocked[0]["ok"] is False
    assert blocked[0]["error"].startswith("PLAN_MISMATCH:")


# ---------------------------------------------------------------------------
# Replan (section 12): P1 immutable, P2 new identity, P1 proof cannot run P2
# ---------------------------------------------------------------------------


def test_c4b_inv6_inv9_replan_keeps_history_and_invalidates_p1_proofs(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    model = ScriptedModel(mission.mission_id, [
        [("status", {}, "a1", "call_001")],
        [("search", {"query": "q"}, "a2", "call_002")],
    ])
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=4)
    assert [call["tool"] for call in calls] == ["status", "search"]
    history = result.progress["execution_plans"]
    assert len(history) == 2
    p1, p2 = history
    assert p1["plan_fingerprint"] != p2["plan_fingerprint"]
    # P1 stays immutable history: the persisted entry still reconstructs.
    assert reconstruct_execution_plan(p1).plan_fingerprint == p1["plan_fingerprint"]
    assert canonical_plan_identity(result) == p2["plan_fingerprint"]
    # INV-C4-9: a proof minted for P1 cannot validate once P2 is bound.
    proof_p1 = calls[0]["proof"]
    assert proof_p1.plan_hash == p1["plan_fingerprint"]
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(proof_p1, result)
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value


# ---------------------------------------------------------------------------
# TOCTOU: stale stored plans, narrowed snapshots, entry-gate tamper checks
# ---------------------------------------------------------------------------


def test_c4b_inv7_tampered_stored_plan_blocks_at_entry(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    _prepared_bound_mission(runtime, mission, [ToolCallProposal.create("status", {}, mission_id=mission.mission_id, tool_call_id="call_1", action_id="a1")])
    loaded = runtime.store.load(mission.mission_id)
    loaded.progress["execution_plan"]["actions"][0]["tool_name"] = "watch"
    runtime.store.save(loaded)
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, []), tools=[], max_turns=2)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert calls == []


def test_c4b_case29_narrowed_owner_scope_blocks_stored_plan(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    _prepared_bound_mission(runtime, mission, [ToolCallProposal.create("search", {"query": "q"}, mission_id=mission.mission_id, tool_call_id="call_1", action_id="a1")])
    loaded = runtime.store.load(mission.mission_id)
    base = MissionAuthorizationSnapshot.from_dict(loaded.authorization_snapshot)
    narrowed = MissionAuthorizationSnapshot.create(
        owner_identity=base.owner_identity, mission_id=base.mission_id, target_identity=base.target_identity, scope=base.scope,
        allowed_actions=("status",), forbidden_actions=base.forbidden_actions, allowed_tools=("status",),
        time_window=base.time_window, max_duration=base.max_duration, rate_limits=base.rate_limits,
        network_boundary=base.network_boundary, data_boundary=base.data_boundary, credential_boundary=base.credential_boundary,
        workspace_boundary=base.workspace_boundary, policy_version=base.policy_version, owner_approval=base.owner_approval,
    )
    loaded.authorization_snapshot = narrowed.to_dict()
    loaded.provenance["authorization_snapshot_version"] = int(narrowed.version)
    runtime.store.save(loaded)
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, []), tools=[], max_turns=2)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert calls == []
    ok, reason = validate_stored_execution_plan(loaded)
    assert ok is False and "outside authorization snapshot" in reason


def test_c4b_inv12_plan_binding_is_mission_specific(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    plan = derive_mission_execution_plan(mission, [ToolCallProposal.create("status", {}, mission_id=mission.mission_id, tool_call_id="call_1")])
    other = _mission(runtime)
    assert plan.mission_fingerprint == mission_binding_fingerprint(mission)
    assert mission_binding_fingerprint(mission) != mission_binding_fingerprint(other)


# ---------------------------------------------------------------------------
# Resume (section 13): no widening; distinct plan identities fail closed
# ---------------------------------------------------------------------------


def test_c4b_inv13_resume_cannot_widen_and_slice_proof_fails_closed(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("status", {}, "a1", "call_001")]]), tools=[], max_turns=3)
    executed_before = len(calls)
    # The stored derived plan is the canonical identity, so a legacy
    # slice-path proof (bound to Plan.fingerprint) fails closed: the two
    # plan identities are intentionally distinct authority domains.
    stored_fp = canonical_plan_identity(result)
    assert stored_fp == result.progress["execution_plan"]["plan_fingerprint"]
    legacy_proof = ExecutionAuthorizationProof.derive(
        execution_class="MISSION_BOUND", mission_id=result.mission_id, request_id=result.request_id,
        tool="status", argument=None, snapshot=MissionAuthorizationSnapshot.from_dict(result.authorization_snapshot),
        tool_call_id="call_slice", plan_hash=result.plan.fingerprint, scope=result.scope_snapshot,
        mission_status=result.status.value, lifecycle_revision=len(result.transitions),
    )
    ok, _reason, code = ExecutionAuthorizationProof.validate_against_mission(legacy_proof, result)
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value
    # The Owner-minted snapshot still covers exactly the stored plan tools.
    assert validate_stored_execution_plan(result)[0] is True
    assert len(calls) == executed_before


def test_c4b_inv13_snapshot_renewal_keeps_plan_inside_owner_scope(tmp_path, monkeypatch):
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, request_id="req-test", authorization_context=make_test_authorization_context("req-test", tmp_path).to_dict())
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("status", {}, "a1", "call_001")]]), tools=[], max_turns=3)
    renewed = MissionAuthorizationSnapshot.from_dict(result.authorization_snapshot).amend(owner_approval="re-approval", changes={})
    result.authorization_snapshot = renewed.to_dict()
    result.provenance["authorization_snapshot_version"] = int(renewed.version)
    # Renewal changes snapshot identity, so old proofs fail closed, but the
    # stored plan itself remains inside the (unchanged) Owner allowlist.
    ok, _reason = validate_stored_execution_plan(result)
    assert ok is True
    assert calls


# ---------------------------------------------------------------------------
# Legacy Plan migration (section 16) and snapshot correspondence (section 7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("granted,requested,expected", [
    (["status"], ["status"], ["status"]),
    (["status", "search"], ["search", "status"], ["search", "status"]),
    (["status"], ["status", "watch"], ["status"]),
    (["watch"], ["status"], []),
    (["status", "watch"], ["unwatch", "nonexistent_tool", "status"], ["status"]),
    (["status"], ["Status", "status"], ["status"]),
])
def test_c4b_legacy_adapter_equals_owner_budget_intersection(granted, requested):
    budget = OwnerAuthorizedToolBudget(frozenset(granted))
    plan = Plan.initial("objective").replan(steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(requested, start=1)), reason="test")
    effective, derived = legacy_plan_effective_tools(budget, plan, request_id="req-legacy")
    assert list(effective) == expected
    assert set(effective) == set(budget.intersect(requested))
    if expected:
        assert derived is not None
        assert [action.tool_name for action in derived.actions] == list(effective)
    else:
        assert derived is None


def test_c4b_legacy_adapter_drops_authority_shaped_step_arguments():
    budget = OwnerAuthorizedToolBudget(frozenset({"status", "watch"}))
    steps = (
        PlanStep("s1", "objective", action="status"),
        PlanStep("s2", "objective", action="watch", retry_policy={"arguments": {"owner_budget": ["run_project_tests"]}}),
    )
    plan = Plan.initial("objective").replan(steps=steps, reason="test")
    effective, derived = legacy_plan_effective_tools(budget, plan, request_id="req-legacy")
    # The invalid step is dropped (narrowing only); the valid one survives.
    assert list(effective) == ["status"]


def test_c4b_inv5_legacy_step_cannot_execute_outside_derived_scope(tmp_path, monkeypatch):
    """A legacy PlanStep outside the derived effective scope never executes."""
    calls = _recording_registry(monkeypatch)
    runtime = _runtime(tmp_path, _restricted)
    mission = _mission(runtime, action="watch")
    result = runtime.run_model_loop(mission.mission_id, ScriptedModel(mission.mission_id, [[("watch", "x", "a1", "call_001")]]), tools=[], max_turns=1)
    assert calls == []
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


# ---------------------------------------------------------------------------
# Canonical plan identity (section 8) and registry enforcement (section 18)
# ---------------------------------------------------------------------------


def test_c4b_canonical_identity_unification(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    # No bound ExecutionPlan: the legacy Plan fingerprint remains canonical.
    assert canonical_plan_identity(mission) == mission.plan.fingerprint
    assert canonical_mission_plan_identity(mission) == mission.plan.fingerprint
    plan = derive_mission_execution_plan(mission, [ToolCallProposal.create("status", {}, mission_id=mission.mission_id, tool_call_id="call_1")])
    bind_execution_plan(mission, plan)
    # Bound ExecutionPlan: its fingerprint is the one canonical identity.
    assert canonical_plan_identity(mission) == plan.plan_fingerprint
    assert canonical_mission_plan_identity(mission) == plan.plan_fingerprint
    # A forged stored identity fails closed: it matches no derivable plan and
    # no longer reconstructs.
    mission.progress["execution_plan"]["plan_fingerprint"] = "f" * 64
    assert canonical_mission_plan_identity(mission) == "f" * 64
    with pytest.raises(Exception):
        reconstruct_execution_plan(mission.progress["execution_plan"])


def test_c4b_inv15_registry_proof_enforcement_remains_mandatory(tmp_path, monkeypatch):
    from tools.registry import ToolSpec
    import tools.registry
    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    from tools.registry import execute as registry_execute
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", mission_id="m1")
    assert str(excinfo.value).startswith("PROOF_REQUIRED:")


def test_c4b_inv14_owner_budget_view_never_widens(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    budget = owner_budget_from_snapshot(mission)
    snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    assert set(budget.tools) == set(snapshot.allowed_tools)
    # The model request can only narrow: an outside proposal never enters.
    assert budget.intersect(["watch", "status"]) == ("status",)
    assert "watch" not in budget.tools


__all__ = []
