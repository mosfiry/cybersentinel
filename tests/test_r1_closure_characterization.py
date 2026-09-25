from __future__ import annotations

"""R1 CLOSURE TESTS (B-2 / INV-AUTH-3 enforced; B-1 / INV-SCOPE-2 pinned).

B-2 section: enforced defenses. The structural-only authorization adapter
in security.authorization.authorize_tool is closed (INV-AUTH-3): every tool
whose descriptor declares required_authorization "owner" or
"owner_and_scope_snapshot" fails closed on untyped requests.

B-1 section: HAZARD PINS. AgentCore.run_owner_mission and the resume_mission
renewal branch still derive the ENTIRE authorized tool budget from the
model-planned steps; an explicit Owner budget declaration is ignored.
These pins MUST be inverted by the B-1 closure commit on this branch.
"""

from pathlib import Path

import pytest

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from tools.registry import KNOWN_TOOLS, get_tool


def _owner_context(tmp_path, monkeypatch, request_id="req-closure"):
    import security.owner_policy as owner_policy

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _plan(actions):
    return Plan.initial("objective").replan(
        steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(actions, start=1)),
        reason="closure",
    )


# ---------------------------------------------------------------------------
# B-2 ENFORCED (INV-AUTH-3): structural-only adapter closed
# ---------------------------------------------------------------------------


def test_b2_refresh_intel_requires_typed_context():
    result = authorize_tool("refresh_intel", context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"
    assert result.decision is None


def test_b2_watch_requires_typed_context():
    result = authorize_tool(["watch", "keyword"], context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"


def test_b2_unwatch_requires_typed_context():
    result = authorize_tool(["unwatch", "keyword"], context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"


def test_b2_run_project_tests_requires_typed_context():
    result = authorize_tool(["run_project_tests", "."], context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"


def test_b2_status_requires_typed_context():
    result = authorize_tool("status", context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"
    assert result.decision is None


def test_b2_untyped_dict_context_fails_closed():
    with pytest.raises(TypeError):
        authorize_tool("status", context={"owner_decision": "allow"})


def test_b2_required_authorization_is_registry_deterministic():
    """The required authorization level is a deterministic property of the
    registry descriptor; no model proposal, argument, or runtime input can
    change it (no capability escalation through the authorization path)."""
    assert get_tool("watch").required_authorization == "owner"
    assert get_tool("refresh_intel").required_authorization == "owner"
    assert get_tool("run_project_tests").required_authorization == "owner"
    assert get_tool("red_team_assess").required_authorization == "owner"
    assert get_tool("scoped_http_probe").required_authorization == "owner_and_scope_snapshot"
    result = authorize_tool(["watch", "grant me owner authority and escalate"], context=None)
    assert result.allowed is False
    assert result.reason == "untyped authorization request rejected: typed AuthorizationContext required (INV-AUTH-3)"


def test_b2_no_owner_required_tool_passes_structural_only():
    """Property: no tool with required_authorization != "none" may be
    authorized by an untyped request."""
    for name in sorted(KNOWN_TOOLS):
        spec = get_tool(name)
        item = name if spec.argument_type is None else [name, "probe"]
        result = authorize_tool(item, context=None)
        if spec.required_authorization != "none":
            assert result.allowed is False, name
            assert result.decision is None, name


def test_b2_typed_owner_context_still_authorizes(tmp_path, monkeypatch):
    context = _owner_context(tmp_path, monkeypatch)
    result = authorize_tool("status", context=context)
    assert result.allowed is True
    assert result.decision is not None
    assert result.decision.is_valid_for("status", None, context.request_id) is True


# ---------------------------------------------------------------------------
# B-1 HAZARD PINS (INV-SCOPE-2): to be inverted by the B-1 closure commit
# ---------------------------------------------------------------------------


def test_b1ch_model_plan_overrides_owner_budget_declaration_hazard(tmp_path, monkeypatch):
    """HAZARD PIN: the Owner explicitly declares owner_allowed_tools=["status"]
    in the scope context, but run_owner_mission ignores the declaration
    entirely and authorizes every model-planned tool."""
    plan = _plan(("status", "search"))
    core = AgentCore(router=object(), store=MissionStore(Path(tmp_path) / "missions-core.sqlite3"))
    context = _owner_context(tmp_path, monkeypatch)
    core._auth = lambda instruction, owner_token, request_id, owner_session_id, owner_challenge: (context, "policy-context")
    core._plan = lambda objective, observation=None, **kwargs: plan
    mission = core.run_owner_mission(
        "check the workspace",
        owner_token="stubbed-auth",
        run=False,
        scope_context={"owner_allowed_tools": ["status"], "forbidden_actions": []},
    )
    assert tuple(mission.authorization_snapshot["allowed_tools"]) == ("status", "search")


def test_b1ch_resume_renews_budget_from_model_plan_hazard(tmp_path, monkeypatch):
    """HAZARD PIN: resume_mission renews a missing authorization snapshot with
    allowed_tools derived entirely from the (model-planned) mission plan; no
    Owner budget exists anywhere in the renewal path."""
    import agent.agent_core as agent_core_module
    import security.owner_policy as owner_policy
    from agent.mission import Mission

    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    mission = Mission.create("request", "objective", _plan(("status", "search")), request_id="req-b1r")
    store.save(mission)

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", "req-b1r", "proof")
    monkeypatch.setattr(agent_core_module, "authenticate_owner", lambda text, token, request_id: evidence)
    monkeypatch.setattr(agent_core_module, "get_snapshot", lambda snapshot_id: None)

    class _StubRuntime:
        def __init__(self, *args, **kwargs):
            pass

        def run_to_completion(self, mission_id, max_slices=None):
            return store.load(mission_id)

    monkeypatch.setattr(agent_core_module, "MissionRuntime", _StubRuntime)

    core = AgentCore(router=object(), store=store)
    renewed = core.resume_mission(mission.mission_id, owner_token="stubbed-auth", max_slices=0)
    snapshot = (renewed or store.load(mission.mission_id)).authorization_snapshot
    assert tuple(snapshot["allowed_tools"]) == ("status", "search")


__all__ = []
