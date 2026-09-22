from __future__ import annotations

from pathlib import Path

import pytest

import security.owner_policy as owner_policy
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.model_router import ModelRouter


def _mission(db: Path):
    store = MissionStore(db)
    runtime = MissionRuntime(store, executor=lambda *args, **kwargs: {"success": True, "criterion_id": "goal", "source": "fixture"})
    plan = Plan.initial("resume objective").replan(steps=(PlanStep("status", "status", action="status", authorization_requirement="owner"),), reason="test")
    mission = runtime.create("resume objective", "resume objective", plan, completion_criteria=[{"criterion_id": "goal"}], request_id="resume-request")
    return store, mission


def test_missing_owner_authentication_moves_restored_mission_to_owner_input(tmp_path, monkeypatch):
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "valid-owner")
    store, mission = _mission(Path(tmp_path) / "missions.sqlite3")
    core = AgentCore(ModelRouter([]), store=store)
    with pytest.raises(PermissionError):
        core.resume_mission(mission.mission_id, owner_token="wrong-owner", max_slices=1)
    restored = store.load(mission.mission_id)
    assert restored.status is MissionStatus.OWNER_INPUT_REQUIRED
    assert any(item.get("event") == "owner_revalidation_failed" for item in restored.recovery_events)


def test_valid_resume_replaces_stale_or_forged_authority(tmp_path, monkeypatch):
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "valid-owner")
    store, mission = _mission(Path(tmp_path) / "missions.sqlite3")
    forged = store.load(mission.mission_id)
    forged.authorization_context = {"owner_evidence": {"forged": True}, "scope_snapshot_id": None}
    forged.policy_snapshot = {"forged": True}
    store.save(forged)
    core = AgentCore(ModelRouter([]), store=store)
    resumed = core.resume_mission(mission.mission_id, owner_token="valid-owner", max_slices=1)
    assert resumed.authorization_context is not None
    assert resumed.authorization_context["owner_evidence"].get("forged") is not True
    assert resumed.policy_snapshot.get("forged") is not True
    assert any(item.get("event") == "owner_revalidated" for item in resumed.recovery_events)
