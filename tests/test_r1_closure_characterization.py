from __future__ import annotations

"""R1 CLOSURE CHARACTERIZATION TESTS (B-2 / INV-AUTH-3, B-1 / INV-SCOPE-2).

These tests characterize the two R1 blockers BEFORE their fix:

- B-2 (R1-C7 / INV-AUTH-3): security.authorization.authorize_tool still
  allows a structural-only path (context=None, no typed owner evidence)
  for tools whose descriptor declares required_authorization="owner".
- B-1 (R1-C10 / INV-SCOPE-2): AgentCore.run_owner_mission and the
  resume_mission renewal branch derive the ENTIRE authorized tool budget
  from the model-planned steps; an explicit Owner budget declaration is
  ignored.

Every test in this module is a HAZARD PIN: it documents CURRENT dangerous
behavior and MUST be inverted to an enforced defense by the R1 closure
commits on this branch.
"""

from pathlib import Path

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext


def _owner_context(tmp_path, monkeypatch, request_id="req-closure"):
    import security.owner_policy as owner_policy

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _plan(actions):
    return Plan.initial("objective").replan(
        steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(actions, start=1)),
        reason="characterization",
    )


# ---------------------------------------------------------------------------
# B-2 HAZARD PINS: structural-only authorization adapter (INV-AUTH-3)
# ---------------------------------------------------------------------------


def test_b2ch_refresh_intel_structural_only_hazard():
    """HAZARD PIN: refresh_intel (network-read, required_authorization
    "owner") passes the structural-only adapter with no typed context."""
    result = authorize_tool("refresh_intel", context=None)
    assert result.allowed is True
    assert result.decision is None


def test_b2ch_watch_structural_only_hazard():
    """HAZARD PIN: watch (state-write) passes the structural-only adapter."""
    result = authorize_tool(["watch", "keyword"], context=None)
    assert result.allowed is True
    assert result.decision is None


def test_b2ch_unwatch_structural_only_hazard():
    """HAZARD PIN: unwatch (state-write) passes the structural-only adapter."""
    result = authorize_tool(["unwatch", "keyword"], context=None)
    assert result.allowed is True
    assert result.decision is None


def test_b2ch_run_project_tests_structural_only_hazard():
    """HAZARD PIN: run_project_tests (bounded-exec) passes the structural-only
    adapter at the authorize_tool boundary (governed execution is still
    blocked later at the registry, but the authorization contract is not)."""
    result = authorize_tool(["run_project_tests", "."], context=None)
    assert result.allowed is True
    assert result.decision is None


def test_b2ch_status_structural_only_hazard():
    """HAZARD PIN: status (declared required_authorization "owner") passes
    the structural-only adapter with no owner authentication at all."""
    result = authorize_tool("status", context=None)
    assert result.allowed is True
    assert result.decision is None


def test_b2ch_typed_owner_context_still_authorizes(tmp_path, monkeypatch):
    """Positive pin: the legitimate typed owner path keeps working."""
    context = _owner_context(tmp_path, monkeypatch)
    result = authorize_tool("status", context=context)
    assert result.allowed is True
    assert result.decision is not None


# ---------------------------------------------------------------------------
# B-1 HAZARD PINS: model plan defines the entire tool budget (INV-SCOPE-2)
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
