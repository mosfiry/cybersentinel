"""Adversarial battery for the Owner tool budget (B-1 / INV-SCOPE-2).

Core invariant: EFFECTIVE_TOOLS = OWNER_AUTHORIZED_BUDGET intersect
MODEL_REQUESTED_TOOLS. The model may request tools; it may never grant,
widen, or redefine the authorization scope. Resume, replay, and mutation
paths fail closed. The Owner budget is granted authority recorded in Owner
Policy (optionally narrowed by an Owner declaration); it is never derived
from model output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
from security.owner_budget import OwnerAuthorizedToolBudget, OwnerBudgetError
from tools.registry import KNOWN_TOOLS


def _owner_context(tmp_path, monkeypatch, request_id="req-b1"):
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _plan(actions):
    return Plan.initial("objective").replan(
        steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(actions, start=1)),
        reason="b1",
    )


def _core(tmp_path, monkeypatch, actions, scope_context=None, request_id="req-b1"):
    plan = _plan(actions)
    core = AgentCore(router=object(), store=MissionStore(Path(tmp_path) / "missions.sqlite3"))
    context = _owner_context(tmp_path, monkeypatch, request_id=request_id)
    core._auth = lambda instruction, owner_token, request_id, owner_session_id, owner_challenge: (context, "policy-context")
    core._plan = lambda objective, observation=None, **kwargs: plan
    mission = core.run_owner_mission("objective", owner_token="stubbed-auth", run=False, scope_context=scope_context)
    return core, mission


# ---------------------------------------------------------------------------
# Core invariant: effective tools are the Owner budget intersected with the
# model request (never the model request alone, never a union).
# ---------------------------------------------------------------------------


def test_effective_tools_are_owner_budget_intersection_model_request(tmp_path, monkeypatch):
    core, mission = _core(
        tmp_path,
        monkeypatch,
        ("status", "refresh_intel", "run_project_tests"),
        scope_context={"owner_allowed_tools": ["status", "search"]},
    )
    snapshot = mission.authorization_snapshot
    owner_budget = set(mission.provenance["owner_budget"]["tools"])
    model_requested = set(mission.provenance["model_requested_tools"])
    effective = set(snapshot["allowed_tools"])
    assert effective == owner_budget & model_requested
    assert effective == {"status"}
    assert set(snapshot["allowed_actions"]) == effective
    assert set(snapshot["rate_limits"]) == effective


@pytest.mark.parametrize("granted,requested,expected", [
    (["status"], ["status"], ["status"]),
    (["status"], ["status", "refresh_intel"], ["status"]),
    (["status", "refresh_intel"], ["refresh_intel", "watch"], ["refresh_intel"]),
    (["status", "search", "refresh_intel"], ["refresh_intel", "status"], ["refresh_intel", "status"]),
    (["watch"], ["status"], []),
    (["status", "watch", "unwatch", "refresh_intel"], ["unwatch", "refresh_intel", "nonexistent_tool"], ["unwatch", "refresh_intel"]),
    (["status"], ["status", "status", "Status"], ["status"]),
])
def test_effective_tools_intersection_property(granted, requested, expected):
    budget = OwnerAuthorizedToolBudget(frozenset(granted))
    assert list(budget.intersect(requested)) == expected


def test_owner_budget_defaults_to_owner_policy_grant(tmp_path, monkeypatch):
    """Without a narrowing declaration, the budget is the Owner Policy grant;
    the model plan still only narrows it."""
    core, mission = _core(tmp_path, monkeypatch, ("status", "search"))
    assert mission.provenance["owner_budget"]["source"] == "owner_policy"
    assert set(mission.authorization_snapshot["allowed_tools"]) == {"status", "search"}


# ---------------------------------------------------------------------------
# B1-1..B1-5: unauthorized tools never enter the snapshot
# ---------------------------------------------------------------------------


def test_b1_1_unknown_model_tool_never_enters_scope(tmp_path, monkeypatch):
    core, mission = _core(tmp_path, monkeypatch, ("status", "definitely_not_a_tool"))
    assert "definitely_not_a_tool" not in KNOWN_TOOLS
    assert tuple(mission.authorization_snapshot["allowed_tools"]) == ("status",)
    assert "definitely_not_a_tool" in mission.provenance["model_requested_tools"]


@pytest.mark.parametrize("requested,granted,expected", [
    (("status", "refresh_intel"), ["status"], ["status"]),
    (("status", "watch"), ["status"], ["status"]),
    (("status", "refresh_intel"), ["status", "latest_intel"], ["status"]),
    (("run_project_tests",), ["status"], []),
    (("watch", "unwatch", "refresh_intel"), ["status"], []),
])
def test_b1_2_to_b1_5_unauthorized_tools_never_enter_snapshot(tmp_path, monkeypatch, requested, granted, expected):
    core, mission = _core(tmp_path, monkeypatch, requested, scope_context={"owner_allowed_tools": granted})
    assert list(mission.authorization_snapshot["allowed_tools"]) == expected
    assert set(mission.provenance["model_requested_tools"]) == set(requested)


def test_no_runtime_authority_minting_from_model_request(tmp_path, monkeypatch):
    """A model request outside the Owner budget authorizes nothing."""
    core, mission = _core(tmp_path, monkeypatch, ("watch", "unwatch", "refresh_intel"), scope_context={"owner_allowed_tools": ["status"]})
    assert tuple(mission.authorization_snapshot["allowed_tools"]) == ()
    assert set(mission.provenance["model_requested_tools"]) == {"watch", "unwatch", "refresh_intel"}


# ---------------------------------------------------------------------------
# B1-6: explicit forbidden constraints are never bypassed
# ---------------------------------------------------------------------------


def test_b1_6_forbidden_action_blocks_budget_authorized_tool(tmp_path, monkeypatch):
    core, mission = _core(tmp_path, monkeypatch, ("watch",), scope_context={"owner_allowed_tools": ["watch"], "forbidden_actions": ["watch"]})
    snap = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    ok, reason = snap.check(action="watch", tool_id="watch", target_identity="local-workspace")
    assert ok is False
    assert reason == "action outside authorization snapshot"


# ---------------------------------------------------------------------------
# B1-7: scope expansion attempts fail closed
# ---------------------------------------------------------------------------


def test_b1_7_scope_expansion_attempts_fail_closed(tmp_path, monkeypatch):
    with pytest.raises(OwnerBudgetError):
        OwnerAuthorizedToolBudget.from_owner_declaration({"owner_allowed_tools": ["*"]})
    with pytest.raises(OwnerBudgetError):
        OwnerAuthorizedToolBudget.from_owner_declaration({"owner_allowed_tools": ["status", "not_a_tool"]})
    with pytest.raises(OwnerBudgetError):
        OwnerAuthorizedToolBudget.from_owner_declaration({"owner_allowed_tools": "status"})
    with pytest.raises(OwnerBudgetError):
        OwnerAuthorizedToolBudget(frozenset({"status", "not_a_tool"}))
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    with pytest.raises(OwnerBudgetError):
        budget.narrowed_by(["status", "watch"])
    with pytest.raises(OwnerBudgetError):
        core_unused = OwnerAuthorizedToolBudget.from_owner_policy


def test_b1_7_renamed_or_malformed_model_tools_never_enter_scope(tmp_path, monkeypatch):
    core, mission = _core(tmp_path, monkeypatch, ("Status", "status", "status"), scope_context={"owner_allowed_tools": ["status"]})
    assert tuple(mission.authorization_snapshot["allowed_tools"]) == ("status",)


# ---------------------------------------------------------------------------
# B1-8: resume reuses documented authorization state
# ---------------------------------------------------------------------------


def test_b1_8_resume_reuses_documented_authorization_state(tmp_path, monkeypatch):
    import agent.agent_core as agent_core_module

    core, mission = _core(tmp_path, monkeypatch, ("status",), scope_context={"owner_allowed_tools": ["status"]}, request_id="req-b1-8")
    store = core.store
    monkeypatch.setattr(agent_core_module, "authenticate_owner", lambda text, token, request_id: owner_policy._issue_evidence("owner_token", request_id, "proof"))
    monkeypatch.setattr(agent_core_module, "get_snapshot", lambda snapshot_id: None)

    class _StubRuntime:
        def __init__(self, *args, **kwargs):
            pass

        def run_to_completion(self, mission_id, max_slices=None):
            return store.load(mission_id)

    monkeypatch.setattr(agent_core_module, "MissionRuntime", _StubRuntime)
    resumed = core.resume_mission(mission.mission_id, owner_token="stubbed-auth", max_slices=0)
    snap = MissionAuthorizationSnapshot.from_dict(resumed.authorization_snapshot)
    assert tuple(snap.allowed_tools) == ("status",)
    assert snap.version == 2


# ---------------------------------------------------------------------------
# B1-9: replay and cross-mission reuse are rejected
# ---------------------------------------------------------------------------


def test_b1_9_cross_mission_replay_rejected(tmp_path, monkeypatch):
    core_a, mission_a = _core(tmp_path, monkeypatch, ("status",), scope_context={"owner_allowed_tools": ["status"]}, request_id="req-a")
    core_b, mission_b = _core(Path(str(tmp_path) + "-b"), monkeypatch, ("status",), scope_context={"owner_allowed_tools": ["status"]}, request_id="req-b")
    snapshot_a = MissionAuthorizationSnapshot.from_dict(mission_a.authorization_snapshot)
    ok, reason = snapshot_a.validate_for_mission(mission_id=mission_b.mission_id, owner_identity=snapshot_a.owner_identity, target_identity="local-workspace")
    assert ok is False
    assert reason == "authorization snapshot mission mismatch"
    evidence = owner_policy._issue_evidence("owner_token", "req-a", "proof")
    assert evidence.is_valid("req-a") is True
    assert evidence.is_valid("req-b") is False


# ---------------------------------------------------------------------------
# B1-10: post-authorization mutation fails closed
# ---------------------------------------------------------------------------


def test_b1_10_post_authorization_mutation_fails_closed(tmp_path, monkeypatch):
    core, mission = _core(tmp_path, monkeypatch, ("status",), scope_context={"owner_allowed_tools": ["status"]})
    tampered = dict(mission.authorization_snapshot)
    tampered["allowed_tools"] = ["status", "watch"]
    with pytest.raises(MissionAuthorizationError):
        MissionAuthorizationSnapshot.from_dict(tampered)
    snap = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    ok_action, reason_action = snap.check(action="watch", tool_id="status", target_identity="local-workspace")
    assert ok_action is False
    assert reason_action == "action outside authorization snapshot"
    ok_tool, reason_tool = snap.check(action="status", tool_id="watch", target_identity="local-workspace")
    assert ok_tool is False
    assert reason_tool == "tool outside authorization snapshot"
    # A post-authorization plan mutation cannot widen the executed scope.
    mission.plan = _plan(("watch", "status"))
    ok_mutated, _ = snap.check(action="watch", tool_id="watch", target_identity="local-workspace")
    assert ok_mutated is False


# ---------------------------------------------------------------------------
# Fail-closed semantics for an empty effective scope
# ---------------------------------------------------------------------------


def test_empty_effective_scope_denies_at_snapshot_and_proof(tmp_path, monkeypatch):
    from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, ExecutionProofError

    core, mission = _core(tmp_path, monkeypatch, ("watch",), scope_context={"owner_allowed_tools": ["status"]})
    snap = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    assert tuple(snap.allowed_tools) == ()
    ok, _reason = snap.check(action="status", tool_id="status", target_identity="local-workspace")
    assert ok is False
    with pytest.raises(ExecutionProofError) as excinfo:
        ExecutionAuthorizationProof.derive(
            execution_class=ExecutionClass.MISSION_BOUND.value,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            tool="status",
            argument=None,
            snapshot=snap,
            mission_status="READY",
            plan_hash=mission.plan.fingerprint,
        )
    assert excinfo.value.code == "TOOL_NOT_ALLOWED"


__all__ = []
