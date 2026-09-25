from __future__ import annotations

"""B-3 characterization pins (HAZARD BASELINE - pre-implementation).

These tests document the CURRENT (pre-B-3) behavior of the planning
pipeline. They are hazard pins: every assertion below describes a gap that
the B-3 four-layer intent ladder must close. Commit 2 of B-3 inverts these
pins into enforced defenses:

    HAZARD B3-H1: no typed intent ladder module exists. MODEL_OUTPUT flows
    directly into Plan steps without typed MissionIntent / TaskIntent /
    ActionIntent layers or deterministic per-layer validators.

    HAZARD B3-H2: run_owner_mission records no typed ExecutionPlan bound to
    mission identity, run identity, snapshot hash, or authorization
    revision; the only plan binding is the legacy Plan fingerprint.

    HAZARD B3-H3: the legacy Plan contract carries no mission/run/
    authorization binding fields, so a plan object cannot be proven bound
    to one mission, one run, or one authorization revision.
"""

import importlib.util
from dataclasses import fields
from pathlib import Path

import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationContext


def _owner_context(tmp_path, monkeypatch, request_id="req-b3c"):
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _plan(actions):
    return Plan.initial("objective").replan(
        steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(actions, start=1)),
        reason="b3-characterization",
    )


def _core(tmp_path, monkeypatch, actions, scope_context=None, request_id="req-b3c"):
    plan = _plan(actions)
    core = AgentCore(router=object(), store=MissionStore(Path(tmp_path) / "missions.sqlite3"))
    context = _owner_context(tmp_path, monkeypatch, request_id=request_id)
    core._auth = lambda instruction, owner_token, request_id, owner_session_id, owner_challenge: (context, "policy-context")
    core._plan = lambda objective, observation=None, **kwargs: plan
    mission = core.run_owner_mission("objective", owner_token="stubbed-auth", run=False, scope_context=scope_context)
    return core, mission


def test_b3_h1_no_typed_intent_ladder_module_exists_yet():
    assert importlib.util.find_spec("security.intent_ladder") is None


def test_b3_h2_owner_mission_records_no_typed_execution_plan(tmp_path, monkeypatch):
    core, mission = _core(tmp_path, monkeypatch, ("status", "search"), scope_context={"owner_allowed_tools": ["status"]})
    provenance = dict(mission.provenance)
    assert "intent_ladder" not in provenance
    assert "execution_plan" not in provenance
    assert "mission_intent" not in provenance
    assert "task_intent" not in provenance
    assert "action_intents" not in provenance


def test_b3_h3_legacy_plan_contract_carries_no_authorization_binding():
    plan_field_names = {item.name for item in fields(Plan)}
    binding_fields = {"mission_id", "run_id", "snapshot_hash", "authorization_revision", "plan_hash"}
    assert not (plan_field_names & binding_fields), plan_field_names


def test_b3_h4_model_steps_outside_owner_budget_still_reach_the_plan(tmp_path, monkeypatch):
    """Pre-B-3: budget filtering happens only at the snapshot level; the
    legacy plan keeps out-of-budget steps (the runtime rejects them late).
    B-3 must reject/remove them deterministically inside the typed ladder."""
    core, mission = _core(tmp_path, monkeypatch, ("status", "definitely_not_a_tool"), scope_context={"owner_allowed_tools": ["status"]})
    assert "definitely_not_a_tool" in mission.provenance["model_requested_tools"]
    assert tuple(mission.authorization_snapshot["allowed_tools"]) == ("status",)
    assert "definitely_not_a_tool" not in mission.authorization_snapshot["allowed_tools"]
