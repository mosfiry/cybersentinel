from __future__ import annotations

import json
import sqlite3

import pytest

from agent.memory import MemoryItem, MemoryType, TrustClassification
from agent.mission import Mission, MissionStatus, MissionStore
from agent.planning import Plan
from agent.trajectory import verify_trajectory
from security.authorization_context import AuthorizationDecision
from security.authorization_context import AuthorizationContext
import security.owner_policy as owner_policy
from security.scope import ProgramAuthorization, ScopeError
from security.scope import TargetIdentity, make_snapshot
from security.scope_store import init_scope_store, save_snapshot
from security.scope_resolver import resolve
from tools.registry import execute


def test_forged_authorization_decision_cannot_cross_tool_boundary():
    forged = AuthorizationDecision(
        allowed=True,
        reason="forged",
        request_id="r1",
        tool="status",
        risk_class="read",
        owner_evidence_fingerprint="fake",
        policy_fingerprint="fake",
        scope_fingerprint="",
        decision_timestamp="2026-01-01T00:00:00+00:00",
        decision_source="model",
    )
    from security.execution_boundary import OwnerDirectBoundary
    from security.execution_proof import ExecutionProofError

    with pytest.raises(PermissionError, match="PROOF_REQUIRED"):
        execute("status", authorization_decision=forged)
    # A forged decision can never mint the proof the boundary requires.
    with pytest.raises(ExecutionProofError) as excinfo:
        OwnerDirectBoundary.derive(tool="status", argument=None, decision=forged, request_id="r1")
    assert excinfo.value.code in {"PROOF_BINDING_MISMATCH", "PROOF_INVALID"}


def test_authorization_decision_is_bound_to_request_identity():
    evidence = owner_policy._issue_evidence("owner_token", "mission-1", "test-proof")
    context = AuthorizationContext("mission-1", evidence, owner_policy.capture_policy_snapshot("mission-1", evidence))
    decision = AuthorizationDecision.issue(context, allowed=True, reason="authorized", tool="status", risk_class="read")
    from security.execution_boundary import OwnerDirectBoundary

    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision, request_id="mission-1")
    with pytest.raises(PermissionError, match="PROOF_BINDING_MISMATCH"):
        execute("status", authorization_decision=decision, request_id="mission-2", execution_proof=proof, execution_class="OWNER_DIRECT")


def test_program_authorization_rejects_crafted_evidence_hash():
    with pytest.raises(ScopeError, match="evidence_hash"):
        ProgramAuthorization(
            "p", "platform", "v1", "2026-01-01T00:00:00+00:00",
            ({"host": "target.example", "schemes": ["https"]},),
            evidence_hash="attacker-controlled-hash",
        )


def test_mission_persistence_detects_direct_database_tampering(tmp_path):
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-1")
    store.save(mission)
    with sqlite3.connect(tmp_path / "missions.sqlite3") as db:
        payload = json.loads(db.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()[0])
        payload["objective"] = "tampered objective"
        db.execute("UPDATE missions SET payload=? WHERE mission_id=?", (json.dumps(payload), mission.mission_id))
    with pytest.raises(ValueError, match="integrity"):
        store.load(mission.mission_id)


def test_mission_store_rejects_stale_writer(tmp_path):
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-stale")
    store.save(mission)
    first = store.load(mission.mission_id)
    second = store.load(mission.mission_id)
    first.error = "writer-a"
    store.save(first)
    second.error = "writer-b"
    with pytest.raises(ValueError, match="stale mission write"):
        store.save(second)


def test_trajectory_hash_chain_detects_reordering():
    mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-chain")
    events = list(mission.trajectory)
    assert verify_trajectory(events) is True
    reordered = list(reversed(events))
    assert verify_trajectory(reordered) is False


def test_terminal_and_recovery_transitions_are_closed():
    mission = Mission.create("owner", "objective", Plan.initial("objective"), request_id="req-2")
    mission.transition(MissionStatus.READY, "prepared")
    mission.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous")
    with pytest.raises(ValueError, match="reconciliation"):
        mission.transition(MissionStatus.GOAL_COMPLETED, "forged completion")
    mission.transition(MissionStatus.READY, "reconciled")
    mission.transition(MissionStatus.GOAL_COMPLETED, "verified", verification={"verified": True})
    with pytest.raises(ValueError, match="terminal"):
        mission.transition(MissionStatus.RUNNING, "forged resurrection")


def test_memory_restore_detects_content_tampering():
    item = MemoryItem.create("conversation", "original", MemoryType.FACT, TrustClassification.UNTRUSTED_DATA, "user", "message")
    payload = item.to_dict()
    payload["content"] = "tampered"
    with pytest.raises(ValueError, match="content_hash"):
        MemoryItem.from_dict(payload)


def test_scope_rejects_unbounded_redirect_chain():
    decision = resolve("missing", "target", "https://target.example/", redirect_chain=["https://target.example/"] * 11)
    assert decision.allowed is False
    assert decision.reason == "redirect_chain_too_long"


def test_scope_snapshot_id_cannot_be_replaced(monkeypatch, tmp_path):
    import security.owner_policy as owner_policy
    import security.scope_store as scope_store
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "scope-owner")
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", tmp_path / "scope.sqlite3")
    init_scope_store()
    first_auth = ProgramAuthorization("program", "test", "v1", "2026-01-01T00:00:00+00:00", ({"host": "one.example", "schemes": ["https"]},))
    second_auth = ProgramAuthorization("program", "test", "v2", "2026-01-01T00:00:00+00:00", ({"host": "two.example", "schemes": ["https"]},))
    save_snapshot(make_snapshot("immutable-id", first_auth, [TargetIdentity("one", "program", "one.example")]), owner_token="scope-owner")
    with pytest.raises(ValueError, match="already_exists"):
        save_snapshot(make_snapshot("immutable-id", second_auth, [TargetIdentity("two", "program", "two.example")]), owner_token="scope-owner")
