from __future__ import annotations

import json
import sqlite3

import pytest

from agent.evidence import EvidenceChainStore, MissionEvidenceChain
from agent.mission import Mission, MissionStore
from agent.mission_worker import LeaseLostError, MissionQueue
from agent.planning import GoalVerification, Plan, VerificationCriterion, evidence_for

BASE = "2026-01-01T00:00:00+00:00"


def _claim(queue: MissionQueue, *, now: str, worker_id: str, lease_seconds: int = 30):
    item = queue.claim_next(now=now, worker_id=worker_id, lease_seconds=lease_seconds)
    assert item is not None and item.lease_claim is not None
    return item.lease_claim


def _mission_row(db_path, mission_id: str):
    with sqlite3.connect(db_path) as db:
        return db.execute(
            "SELECT payload, revision FROM missions WHERE mission_id=?", (mission_id,)
        ).fetchone()


def _ownership_row(db_path, mission_id: str):
    with sqlite3.connect(db_path) as db:
        return db.execute(
            "SELECT state, attempts, lease_owner, lease_expires_at, lease_id, lease_generation, "
            "lease_acquired_at, lease_heartbeat_at FROM mission_queue WHERE mission_id=?",
            (mission_id,),
        ).fetchone()


def _evidence_record():
    return {
        "criterion_id": "goal",
        "passed": True,
        "source": "deterministic_fixture",
        "result": {"status": "verified"},
        "provenance": {"mission_id": "mission-1", "action_id": "action-1"},
    }


def test_stale_claim_cannot_append_mission_evidence_after_reclaim_and_current_claim_can(tmp_path):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create(
        "owner request",
        "verify goal",
        Plan.initial("verify goal"),
        mission_id="mission-1",
        completion_criteria=[{"criterion_id": "goal", "description": "goal", "check": "fixture"}],
    )
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)

    claim_a = _claim(queue, now=BASE, worker_id="worker-a", lease_seconds=1)
    queue.recover_expired(now="2026-01-01T00:00:01+00:00")
    claim_b = _claim(queue, now="2026-01-01T00:00:01+00:00", worker_id="worker-b")
    assert (claim_a.generation, claim_b.generation) == (1, 2)

    stale_a = store.load(mission.mission_id)
    assert stale_a is not None
    stale_a.evidence.append(_evidence_record())
    stale_a.verification_state = {"verified": True, "missing_criteria": [], "evidence_count": 1}
    before_mission = _mission_row(authority, mission.mission_id)
    before_ownership = _ownership_row(authority, mission.mission_id)
    with pytest.raises(LeaseLostError):
        store.save(stale_a, claim=claim_a, now="2026-01-01T00:00:01.500000+00:00")
    assert _mission_row(authority, mission.mission_id) == before_mission
    assert _ownership_row(authority, mission.mission_id) == before_ownership
    assert MissionEvidenceChain.list(authority, mission.mission_id) == []

    current_b = store.load(mission.mission_id)
    assert current_b is not None
    record = _evidence_record()
    current_b.evidence.append(record)
    verified_evidence = evidence_for("goal", True, "deterministic_fixture", {"status": "verified"}, provenance={"mission_id": mission.mission_id})
    verification = GoalVerification.evaluate(
        current_b.objective,
        [VerificationCriterion("goal", "goal", "fixture")],
        [verified_evidence],
    )
    assert verification.verified
    current_b.verification_state = {
        "verified": verification.verified,
        "missing_criteria": list(verification.missing_criteria),
        "evidence_count": len(verification.evidence),
    }
    store.save(current_b, claim=claim_b, now="2026-01-01T00:00:02+00:00")

    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None
    assert persisted.evidence == [record]
    assert persisted.verification_state == {"verified": True, "missing_criteria": [], "evidence_count": 1}
    events = MissionEvidenceChain.list(authority, mission.mission_id)
    assert len(events) == 1
    assert events[0]["evidence"] == record
    assert events[0]["generation"] == claim_b.generation
    assert MissionEvidenceChain.verify(events)
    assert _mission_row(authority, mission.mission_id)[1] == before_mission[1] + 1


def test_evidence_insert_is_rolled_back_when_mission_save_fails_after_it(tmp_path):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "verify goal", Plan.initial("verify goal"), mission_id="mission-rollback")
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-b")
    before_mission = _mission_row(authority, mission.mission_id)
    before_head = MissionEvidenceChain.list(authority, mission.mission_id)

    with sqlite3.connect(authority) as db:
        db.execute(
            "CREATE TRIGGER reject_mission_revision BEFORE UPDATE ON missions "
            "BEGIN SELECT RAISE(ABORT, 'injected failure after evidence insert'); END"
        )
    updated = store.load(mission.mission_id)
    assert updated is not None
    updated.evidence.append(_evidence_record())
    updated.verification_state = {"verified": True, "missing_criteria": [], "evidence_count": 1}
    with pytest.raises(sqlite3.IntegrityError, match="injected failure after evidence insert"):
        store.save(updated, claim=claim, now=BASE)

    assert _mission_row(authority, mission.mission_id) == before_mission
    assert MissionEvidenceChain.list(authority, mission.mission_id) == before_head == []
    reopened = MissionStore(authority).load(mission.mission_id)
    assert reopened is not None and reopened.evidence == [] and reopened.verification_state == {}


def test_additive_migration_is_idempotent_and_preserves_legacy_mission_and_chain(tmp_path):
    authority = tmp_path / "legacy-authority.sqlite3"
    legacy_chain_path = tmp_path / "evidence_chain.db"
    old_mission = Mission.create("old request", "old objective", Plan.initial("old objective"), mission_id="legacy-mission")
    old_mission.evidence.append({"criterion_id": "old", "passed": True, "source": "legacy", "result": {"kept": True}})
    legacy_payload = json.dumps(old_mission.to_dict(), ensure_ascii=False)
    with sqlite3.connect(authority) as db:
        db.execute("CREATE TABLE missions (mission_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        db.execute("INSERT INTO missions(mission_id,payload) VALUES(?,?)", (old_mission.mission_id, legacy_payload))

    legacy_chain = EvidenceChainStore(legacy_chain_path)
    legacy_chain.append({"claim": "preexisting event", "source": "legacy", "evidence": {"preserve": True}})
    legacy_hashes = [item["current_hash"] for item in legacy_chain.list()]
    legacy_file_hash = __import__("hashlib").sha256(legacy_chain_path.read_bytes()).hexdigest()

    first = MissionStore(authority)
    loaded = first.load(old_mission.mission_id)
    assert loaded is not None and loaded.revision == 0
    assert loaded.evidence == old_mission.evidence
    with sqlite3.connect(authority) as db:
        after_first = db.execute("SELECT payload FROM missions WHERE mission_id=?", (old_mission.mission_id,)).fetchone()[0]
        columns = {row[1] for row in db.execute("PRAGMA table_info(missions)")}
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert after_first == legacy_payload
    assert {"mission_id", "payload", "revision"} <= columns
    assert "mission_evidence_events" in tables

    second = MissionStore(authority)
    reopened = second.load(old_mission.mission_id)
    assert reopened is not None and reopened.revision == 0 and reopened.evidence == old_mission.evidence
    with sqlite3.connect(authority) as db:
        after_second = db.execute("SELECT payload FROM missions WHERE mission_id=?", (old_mission.mission_id,)).fetchone()[0]
    assert after_second == legacy_payload
    assert legacy_chain.verify()
    assert [item["current_hash"] for item in legacy_chain.list()] == legacy_hashes
    assert __import__("hashlib").sha256(legacy_chain_path.read_bytes()).hexdigest() == legacy_file_hash


def test_claimed_mission_runtime_persists_evidence_in_the_shared_authority_file(tmp_path):
    from agent.mission_runtime import MissionRuntime
    from agent.planning import PlanStep
    from runtime_authorization import make_test_snapshot

    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    plan = Plan.initial("run a deterministic observation").replan(
        steps=(PlanStep("observe", "observe fixture", action="fixture_action"),),
        reason="M2.b fixture",
    )
    runtime = MissionRuntime(
        store,
        executor=lambda mission, step, action_id: {
            "success": True,
            "criterion_id": "goal",
            "source": "deterministic_fixture",
            "result": {"action_id": action_id},
        },
        authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)),
    )
    mission = runtime.create("owner request", "run a deterministic observation", plan)
    queue.enqueue(mission.mission_id, available_at=BASE)
    claim = _claim(queue, now=BASE, worker_id="worker-b")
    runtime.store = store.with_claim(claim, now=BASE)

    completed = runtime.run_slice(mission.mission_id)
    assert completed.evidence and completed.evidence[0]["criterion_id"] == "goal"
    persisted = MissionStore(authority).load(mission.mission_id)
    assert persisted is not None and persisted.evidence == completed.evidence
    events = MissionEvidenceChain.list(authority, mission.mission_id)
    assert len(events) == 1 and events[0]["generation"] == claim.generation
    assert MissionEvidenceChain.verify(events)
