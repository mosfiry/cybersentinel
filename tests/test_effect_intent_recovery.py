from __future__ import annotations

import json
import sqlite3

import pytest

from agent.effect_intent import EffectIntentConflict, ExternalEffectState
from agent.mission import Mission, MissionStore
from agent.mission_worker import LeaseLostError, MissionQueue
from agent.planning import Plan


BASE = "2026-01-01T00:00:00+00:00"
AFTER_EXPIRY = "2026-01-01T00:00:01+00:00"


def _mission_and_claim(tmp_path, *, lease_seconds=30):
    authority = tmp_path / "mission-runtime.sqlite3"
    store = MissionStore(authority)
    queue = MissionQueue(authority)
    mission = Mission.create("owner request", "objective", Plan.initial("objective"), request_id="request-1")
    store.save(mission)
    queue.enqueue(mission.mission_id, available_at=BASE)
    item = queue.claim_next(now=BASE, worker_id="worker-a", lease_seconds=lease_seconds)
    assert item is not None and item.lease_claim is not None
    return authority, store, queue, mission, item.lease_claim


def _prepare(store, mission, claim, *, now=BASE, action="action-1", payload=None):
    return store.effect_intents.prepare(
        mission,
        logical_action_id=action,
        tool_id="watch",
        payload={"keyword": "sample"} if payload is None else payload,
        claim=claim,
        now=now,
    )


def _reclaim(queue, *, now=AFTER_EXPIRY):
    queue.recover_expired(now=now)
    item = queue.claim_next(now=now, worker_id="worker-b", lease_seconds=30)
    assert item is not None and item.lease_claim is not None
    return item.lease_claim


def test_prepared_intent_is_persisted_and_visible_after_store_restart(tmp_path):
    authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    mission.task_id = "task-42"

    prepared = _prepare(store, mission, claim)
    reopened = MissionStore(authority)
    loaded = reopened.effect_intents.get(prepared.effect_id)
    persisted_mission = reopened.load(mission.mission_id)

    assert loaded.state is ExternalEffectState.PREPARED
    assert persisted_mission is not None
    assert persisted_mission.checkpoint["effect_id"] == prepared.effect_id
    assert persisted_mission.checkpoint["claim_generation"] == claim.generation
    assert loaded.effect_id == prepared.effect_id
    assert loaded.idempotency_key == prepared.idempotency_key
    assert loaded.mission_id == mission.mission_id
    assert loaded.task_id == "task-42"
    assert loaded.request_id == "request-1"
    assert loaded.claim_generation == claim.generation == 1
    assert reopened.effect_intents.list_for_mission(mission.mission_id) == (loaded,)


def test_stale_claim_cannot_start_dispatch_or_record_outcome_after_reclaim(tmp_path):
    _authority, store, queue, mission, claim_a = _mission_and_claim(tmp_path, lease_seconds=1)
    prepared = _prepare(store, mission, claim_a)
    store.effect_intents.mark_dispatching(mission, prepared.effect_id, claim=claim_a, now=BASE)
    stale_mission_a = store.load(mission.mission_id)
    assert stale_mission_a is not None

    claim_b = _reclaim(queue)
    current_mission_b = store.load(mission.mission_id)
    assert current_mission_b is not None

    with pytest.raises(LeaseLostError):
        store.effect_intents.mark_dispatching(
            stale_mission_a, prepared.effect_id, claim=claim_a, now=AFTER_EXPIRY
        )
    with pytest.raises(LeaseLostError):
        store.effect_intents.mark_unknown(
            stale_mission_a,
            prepared.effect_id,
            claim=claim_a,
            reason="late result from stale A",
            now=AFTER_EXPIRY,
        )
    with pytest.raises(LeaseLostError):
        store.effect_intents.confirm(
            stale_mission_a,
            prepared.effect_id,
            {"success": True, "source": "fake"},
            claim=claim_a,
            now=AFTER_EXPIRY,
        )

    unchanged = store.effect_intents.get(prepared.effect_id)
    assert unchanged.state is ExternalEffectState.DISPATCHING
    assert unchanged.claim_generation == claim_a.generation
    assert current_mission_b.status is mission.status
    assert claim_b.generation == 2


def test_stale_mission_revision_cannot_create_or_change_an_intent(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    stale_mission = store.load(mission.mission_id)
    current_mission = store.load(mission.mission_id)
    assert stale_mission is not None and current_mission is not None
    current_mission.progress["revision_bump"] = "current"
    store.save(current_mission, claim=claim, now=BASE)

    with pytest.raises(ValueError, match="stale mission write rejected"):
        _prepare(store, stale_mission, claim)
    assert store.effect_intents.list_for_mission(mission.mission_id) == ()


def test_same_logical_retry_keeps_effect_key_and_records_reclaimed_generation(tmp_path):
    _authority, store, queue, mission, claim_a = _mission_and_claim(tmp_path, lease_seconds=1)
    first = _prepare(store, mission, claim_a)
    claim_b = _reclaim(queue)
    reloaded_mission = store.load(mission.mission_id)
    assert reloaded_mission is not None

    second = _prepare(store, reloaded_mission, claim_b, now=AFTER_EXPIRY)

    assert second.effect_id == first.effect_id
    assert second.idempotency_key == first.idempotency_key
    assert second.state is ExternalEffectState.PREPARED
    assert second.current_attempt == 2
    assert second.claim_generation == claim_b.generation == 2
    with sqlite3.connect(store.db_path) as db:
        attempts = db.execute(
            "SELECT attempt_number,claim_generation,state FROM external_effect_attempts "
            "WHERE effect_id=? ORDER BY attempt_number",
            (first.effect_id,),
        ).fetchall()
    assert attempts == [
        (1, 1, ExternalEffectState.DEFINITE_NOT_SENT.value),
        (2, 2, ExternalEffectState.PREPARED.value),
    ]


def test_claim_bound_facade_uses_latest_reclaimed_worker_claim(tmp_path):
    _authority, store, queue, mission, claim_a = _mission_and_claim(tmp_path, lease_seconds=1)
    bound_store = store.with_claim(claim_a, now=BASE)
    first = bound_store.effect_intents.prepare(
        mission,
        logical_action_id="action-bound",
        tool_id="watch",
        payload={"keyword": "sample"},
    )

    claim_b = _reclaim(queue)
    bound_store.set_claim(claim_b)
    reloaded = store.load(mission.mission_id)
    assert reloaded is not None
    second = bound_store.effect_intents.prepare(
        reloaded,
        logical_action_id="action-bound",
        tool_id="watch",
        payload={"keyword": "sample"},
    )

    assert second.effect_id == first.effect_id
    assert second.idempotency_key == first.idempotency_key
    assert second.claim_generation == claim_b.generation
    assert second.current_attempt == 2


def test_invalid_transitions_and_changed_payload_are_rejected(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    prepared = _prepare(store, mission, claim)
    with pytest.raises(EffectIntentConflict, match="different identity or payload"):
        _prepare(store, mission, claim, payload={"keyword": "different"})

    dispatching = store.effect_intents.mark_dispatching(mission, prepared.effect_id, claim=claim, now=BASE)
    assert dispatching.state is ExternalEffectState.DISPATCHING
    with pytest.raises(EffectIntentConflict, match="only this mission's PREPARED"):
        store.effect_intents.mark_dispatching(mission, prepared.effect_id, claim=claim, now=BASE)

    confirmed = store.effect_intents.confirm(
        mission,
        prepared.effect_id,
        {"success": True, "source": "fake", "criterion_id": "goal"},
        claim=claim,
        now=BASE,
    )
    assert confirmed.state is ExternalEffectState.CONFIRMED
    with pytest.raises(EffectIntentConflict, match="cannot confirm intent in CONFIRMED"):
        store.effect_intents.confirm(
            mission,
            prepared.effect_id,
            {"success": True},
            claim=claim,
            now=BASE,
        )


def test_definite_not_sent_retry_requires_proof_and_reuses_same_key(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    prepared = _prepare(store, mission, claim)
    store.effect_intents.mark_dispatching(mission, prepared.effect_id, claim=claim, now=BASE)

    with pytest.raises(ValueError, match="adapter proof"):
        store.effect_intents.mark_definitely_not_sent(
            mission, prepared.effect_id, claim=claim, proof="", now=BASE
        )
    definite = store.effect_intents.mark_definitely_not_sent(
        mission,
        prepared.effect_id,
        claim=claim,
        proof="fake adapter proves submit was never entered",
        reason="dispatch was cancelled before handler start",
        now=BASE,
    )
    assert definite.state is ExternalEffectState.DEFINITE_NOT_SENT

    with pytest.raises(EffectIntentConflict, match="only this mission's PREPARED"):
        store.effect_intents.mark_dispatching(mission, prepared.effect_id, claim=claim, now=BASE)
    rearmed = store.effect_intents.rearm_definitely_not_sent(
        mission,
        prepared.effect_id,
        claim=claim,
        proof="operator authorized a fresh attempt after definite-not-sent evidence",
        now=BASE,
    )
    assert rearmed.effect_id == prepared.effect_id
    assert rearmed.idempotency_key == prepared.idempotency_key
    assert rearmed.state is ExternalEffectState.PREPARED
    assert rearmed.current_attempt == 2
    assert rearmed.claim_generation == claim.generation


def test_known_failure_is_terminal_and_not_automatically_retried(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    intent = _prepare(store, mission, claim, action="action-failed")
    store.effect_intents.mark_dispatching(mission, intent.effect_id, claim=claim, now=BASE)
    failed = store.effect_intents.mark_failed(
        mission,
        intent.effect_id,
        claim=claim,
        reason="adapter returned a definitive final failure",
        now=BASE,
    )
    assert failed.state is ExternalEffectState.FAILED
    with pytest.raises(EffectIntentConflict, match="requires explicit reconciliation"):
        _prepare(store, mission, claim, action="action-failed")


def test_legacy_mission_schema_migration_is_additive_and_idempotent(tmp_path):
    db_path = tmp_path / "legacy.sqlite3"
    mission = Mission.create("owner request", "objective", Plan.initial("objective"))
    original_payload = json.dumps(mission.to_dict(), ensure_ascii=False)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE missions (mission_id TEXT PRIMARY KEY,payload TEXT NOT NULL)")
        db.execute(
            "INSERT INTO missions(mission_id,payload) VALUES(?,?)",
            (mission.mission_id, original_payload),
        )

    first = MissionStore(db_path)
    loaded = first.load(mission.mission_id)
    assert loaded is not None and loaded.revision == 0
    with sqlite3.connect(db_path) as db:
        preserved_first = db.execute(
            "SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()
        first_columns = {row[1] for row in db.execute("PRAGMA table_info(missions)")}
        intent_count = db.execute("SELECT COUNT(*) FROM external_effect_intents").fetchone()[0]

    MissionStore(db_path)
    with sqlite3.connect(db_path) as db:
        preserved_second = db.execute(
            "SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()
        second_columns = {row[1] for row in db.execute("PRAGMA table_info(missions)")}
        attempt_count = db.execute("SELECT COUNT(*) FROM external_effect_attempts").fetchone()[0]

    assert preserved_first == preserved_second == (original_payload, 0)
    assert first_columns == second_columns == {"mission_id", "payload", "revision"}
    assert intent_count == attempt_count == 0
