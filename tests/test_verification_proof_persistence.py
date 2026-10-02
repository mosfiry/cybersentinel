from __future__ import annotations

import sqlite3
from types import SimpleNamespace

from agent.evidence import MissionEvidenceChain
from agent.mission import Mission, MissionStore
from agent.mission_worker import MissionQueue
from agent.planning import GoalVerification, Plan, VerificationCriterion, evidence_for

BASE = "2026-01-01T00:00:00+00:00"


def test_current_claim_persists_goal_verification_state_with_evidence_not_a_separate_proof_store(tmp_path):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create(
        "owner request",
        "verify the goal",
        Plan.initial("verify the goal"),
        mission_id="verified-mission",
    )
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    claim = queue.claim_next(now=BASE, worker_id="worker-b", lease_seconds=30).lease_claim
    assert claim is not None
    completed = store.load(mission.mission_id)
    assert completed is not None

    mission_evidence = {
        "criterion_id": "goal",
        "passed": True,
        "source": "deterministic_fixture",
        "result": {"status": "complete"},
        "provenance": {"mission_id": mission.mission_id},
    }
    completed.evidence.append(mission_evidence)
    verification_evidence = evidence_for("goal", True, "deterministic_fixture", {"status": "complete"})
    report = GoalVerification.evaluate(
        completed.objective,
        [VerificationCriterion("goal", "goal", "fixture")],
        [verification_evidence],
    )
    completed.verification_state = {
        "verified": report.verified,
        "missing_criteria": list(report.missing_criteria),
        "evidence_count": len(report.evidence),
    }
    store.save(completed, claim=claim, now=BASE)

    reopened = MissionStore(authority).load(mission.mission_id)
    assert reopened is not None
    assert reopened.evidence == [mission_evidence]
    assert reopened.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    events = MissionEvidenceChain.list(authority, mission.mission_id)
    assert MissionEvidenceChain.verify(events)
    assert len(events) == 1 and events[0]["generation"] == claim.generation
    # VerificationReport has no persistent writer today; do not invent proof storage for it.
    with sqlite3.connect(authority) as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "verification_proofs" not in tables


def test_agent_core_preserves_legacy_workspace_chain_as_unfenced(tmp_path, monkeypatch):
    import agent.agent_core as agent_core
    from agent.evidence import EvidenceChainStore
    from agent.mission import Mission
    from agent.planning import Plan, PlanStep

    captured = {}
    monkeypatch.setattr(agent_core, "DB_PATH", tmp_path / "missions.sqlite3")
    monkeypatch.setattr(agent_core.AuthorizationContext, "from_dict", classmethod(lambda cls, data: object()))
    monkeypatch.setattr(agent_core.MissionAuthorizationSnapshot, "from_dict", classmethod(lambda cls, data: SimpleNamespace(workspace_boundary={"root": str(tmp_path)}, target_identity="test-target")))
    monkeypatch.setattr(agent_core, "authorize_tool", lambda *args, **kwargs: SimpleNamespace(allowed=True, decision=object(), reason=""))

    def fake_execute(*args, **kwargs):
        captured["evidence_store"] = kwargs.get("evidence_store")
        workspace = kwargs["workspace"]
        workspace.mission_id = kwargs["mission_id"]
        workspace.request_id = kwargs["request_id"]
        workspace.tool_id = "run_project_tests"
        workspace.evidence_store = kwargs.get("evidence_store")
        workspace._record("read", output_value={"ok": True})
        return {"ok": True}

    monkeypatch.setattr(agent_core, "execute_tool", fake_execute)
    mission = Mission.create(
        "owner request",
        "run a bounded check",
        Plan.initial("run a bounded check"),
        mission_id="workspace-mission",
        request_id="request-workspace",
        authorization_context={},
        authorization_snapshot={"workspace_boundary": {"root": str(tmp_path)}},
    )
    step = PlanStep("step-1", "run check", action="run_project_tests", retry_policy={"arguments": {"query": "."}})
    result = agent_core.AgentCore._executor(mission, step, "action-1")

    assert result["success"] is True
    legacy_store = captured["evidence_store"]
    assert isinstance(legacy_store, EvidenceChainStore)
    records = legacy_store.list(request_id=mission.request_id)
    assert legacy_store.verify() and len(records) == 1
    assert records[0]["source"] == "workspace:run_project_tests"
    assert records[0]["confidence"] == 10
    assert records[0]["evidence"]["mission_id"] == mission.mission_id
    assert records[0]["evidence"]["request_id"] == mission.request_id
    assert records[0]["evidence"]["operation"] == "read"
