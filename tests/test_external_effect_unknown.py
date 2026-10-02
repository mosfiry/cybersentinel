from __future__ import annotations

import sqlite3

import pytest

from agent.effect_intent import EffectIntentConflict, ExternalEffectState
from agent.mission import MissionStatus, MissionStore
from agent.mission_worker import MissionQueue

from test_effect_intent_recovery import BASE, AFTER_EXPIRY, _mission_and_claim, _prepare, _reclaim


def test_crash_after_dispatching_reopens_as_unknown_and_never_re_dispatches(tmp_path):
    authority, store, queue, mission, claim_a = _mission_and_claim(tmp_path, lease_seconds=1)
    fake_adapter_calls = []

    def dispatch_with_local_fake(target_store, target_mission, target_claim, now):
        intent = _prepare(target_store, target_mission, target_claim, now=now)
        target_store.effect_intents.mark_dispatching(
            target_mission, intent.effect_id, claim=target_claim, now=now
        )
        fake_adapter_calls.append(intent.idempotency_key)
        return intent

    intent = dispatch_with_local_fake(store, mission, claim_a, BASE)

    # Simulated process death: only a new store/claim remains; no sleep or provider.
    claim_b = _reclaim(queue)
    restarted_store = MissionStore(authority)
    restarted_mission = restarted_store.load(mission.mission_id)
    assert restarted_mission is not None
    recovered = restarted_store.effect_intents.recover_dispatching(
        restarted_mission, claim=claim_b, now=AFTER_EXPIRY
    )

    assert len(recovered) == 1
    assert recovered[0].state is ExternalEffectState.UNKNOWN
    assert recovered[0].reconciliation_status == "OWNER_RECONCILIATION_REQUIRED"
    assert restarted_mission.status is MissionStatus.RECOVERY_REQUIRED
    assert restarted_mission.checkpoint["reconciliation_status"] == "OWNER_RECONCILIATION_REQUIRED"
    assert restarted_store.effect_intents.get(intent.effect_id).state is ExternalEffectState.UNKNOWN

    with pytest.raises(EffectIntentConflict, match="requires explicit reconciliation"):
        dispatch_with_local_fake(restarted_store, restarted_mission, claim_b, AFTER_EXPIRY)
    with pytest.raises(EffectIntentConflict, match="cannot confirm intent in UNKNOWN"):
        restarted_store.effect_intents.confirm(
            restarted_mission,
            intent.effect_id,
            {"success": True, "source": "fake"},
            claim=claim_b,
            now=AFTER_EXPIRY,
        )
    assert fake_adapter_calls == [intent.idempotency_key]


def test_confirmed_result_and_mission_evidence_commit_once_under_current_claim(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    intent = _prepare(store, mission, claim)
    store.effect_intents.mark_dispatching(mission, intent.effect_id, claim=claim, now=BASE)
    observation = {
        "success": True,
        "ok": True,
        "criterion_id": "goal",
        "source": "deterministic-fake-adapter",
        "receipt_id": "receipt-local-1",
    }

    confirmed = store.effect_intents.confirm(
        mission,
        intent.effect_id,
        observation,
        claim=claim,
        action_id="action-1",
        step_id="step-1",
        now=BASE,
    )
    persisted = store.load(mission.mission_id)
    assert persisted is not None
    assert confirmed.state is ExternalEffectState.CONFIRMED
    assert confirmed.receipt_metadata["receipt_id"] == "receipt-local-1"
    assert len([item for item in persisted.observations if item.get("effect_id") == intent.effect_id]) == 1
    effect_evidence = [
        item for item in persisted.evidence
        if item.get("provenance", {}).get("effect_id") == intent.effect_id
    ]
    assert len(effect_evidence) == 1 and effect_evidence[0]["passed"] is True
    assert len([item for item in persisted.action_history if item.get("action_id") == "action-1"]) == 1
    with sqlite3.connect(store.db_path) as db:
        ledger_count = db.execute(
            "SELECT COUNT(*) FROM mission_evidence_events WHERE mission_id=?",
            (mission.mission_id,),
        ).fetchone()[0]
    assert ledger_count == 1

    with pytest.raises(EffectIntentConflict, match="cannot confirm intent in CONFIRMED"):
        store.effect_intents.confirm(
            mission, intent.effect_id, observation, claim=claim, now=BASE
        )
    persisted_again = store.load(mission.mission_id)
    assert persisted_again is not None
    assert len([item for item in persisted_again.evidence if item.get("provenance", {}).get("effect_id") == intent.effect_id]) == 1
    with sqlite3.connect(store.db_path) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM mission_evidence_events WHERE mission_id=?",
            (mission.mission_id,),
        ).fetchone()[0] == 1


def test_injected_mission_write_failure_rolls_back_intent_receipt_and_evidence(tmp_path):
    _authority, store, _queue, mission, claim = _mission_and_claim(tmp_path)
    intent = _prepare(store, mission, claim)
    store.effect_intents.mark_dispatching(mission, intent.effect_id, claim=claim, now=BASE)
    before = store.load(mission.mission_id)
    assert before is not None
    with sqlite3.connect(store.db_path) as db:
        mission_row_before = db.execute(
            "SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()
        db.execute(
            "CREATE TRIGGER reject_effect_result BEFORE UPDATE ON missions "
            "BEGIN SELECT RAISE(ABORT,'injected effect-result rollback'); END"
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected effect-result rollback"):
        store.effect_intents.confirm(
            before,
            intent.effect_id,
            {"success": True, "source": "fake", "criterion_id": "goal"},
            claim=claim,
            now=BASE,
        )

    assert store.effect_intents.get(intent.effect_id).state is ExternalEffectState.DISPATCHING
    after = store.load(mission.mission_id)
    assert after is not None
    assert after.to_dict() == before.to_dict()
    with sqlite3.connect(store.db_path) as db:
        mission_row_after = db.execute(
            "SELECT payload,revision FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()
        ledger_count = db.execute(
            "SELECT COUNT(*) FROM mission_evidence_events WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()[0]
    assert mission_row_after == mission_row_before
    assert ledger_count == 0
