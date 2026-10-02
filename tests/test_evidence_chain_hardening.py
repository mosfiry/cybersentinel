from __future__ import annotations

"""Vibe V6.1 — evidence chain hardening battery.

Deterministic tests for evidence integrity: the hash-linked chain rejects
tampering, reordering and replay; evidence is isolated per request; and signed
system evidence is bound to the exact mission execution (action binding and
issuer signature) — substituted, transplanted or unsigned evidence can never
support a completion proof.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot

from agent.evidence import EvidenceChainStore, Evidence, observed, verify_chain
from agent.mission import MissionStatus, MissionStore
from agent.planning import Plan, PlanStep


def _completed_mission(tmp_path, monkeypatch):
    import core.engine
    import security.truthfulness as truthfulness
    from agent.mission_runtime import MissionRuntime

    monkeypatch.setattr(truthfulness, "PROVENANCE_KEY_PATH", Path(tmp_path) / "completion.key")
    monkeypatch.setattr(truthfulness, "_ISSUER", None)
    monkeypatch.setattr(core.engine, "status", lambda: {"service": "CyberSentinel X", "version": "test", "online": True})
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_: {"success": True, "source": "status", "result": {"online": False}},
        authorizer=lambda *_: (True, "test owner authorization"),
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("service online").replan(steps=(PlanStep("observe", "observe", action="status"),), reason="test")
    mission = runtime.create("request", "service online", plan, completion_criteria=[{"criterion_id": "service-online", "check": "system_online"}])
    completed = runtime.run_to_completion(mission.mission_id, max_slices=4)
    assert completed.status is MissionStatus.GOAL_COMPLETED
    return store, completed


def test_chain_rejects_payload_tampering(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    store.append(observed("claim-1", "tool", {"k": 1}, request_id="req-1"))
    store.append(observed("claim-2", "tool", {"k": 2}, request_id="req-1"))
    store.append(observed("claim-3", "tool", {"k": 3}, request_id="req-1"))
    assert store.verify() is True
    # attacker rewrites the middle payload directly in the database
    with sqlite3.connect(tmp_path / "evidence.sqlite3") as db:
        row = db.execute("SELECT payload FROM evidence_chain WHERE sequence=2").fetchone()
        forged = json.loads(row[0])
        forged["evidence"] = {"k": "forged"}
        db.execute("UPDATE evidence_chain SET payload=? WHERE sequence=2", (json.dumps(forged, sort_keys=True),))
    assert store.verify() is False


def test_chain_rejects_reordering_and_replay(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    store.append(observed("claim-1", "tool", {"k": 1}, request_id="req-1"))
    store.append(observed("claim-2", "tool", {"k": 2}, request_id="req-1"))
    records = store.list()
    assert verify_chain(records) is True
    # replaying a record as an extra slot breaks the expected sequence
    assert verify_chain(records + [records[0]]) is False
    # reordering breaks the chain linkage
    assert verify_chain(list(reversed(records))) is False
    # removing a record from the middle breaks linkage
    assert verify_chain([records[0], records[2]]) is False


def test_duplicate_append_is_sequenced_never_overwritten(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    item = observed("same claim", "tool", {"k": 1}, request_id="req-1")
    first = store.append(item)
    second = store.append(observed("same claim", "tool", {"k": 1}, request_id="req-1"))
    assert first["sequence"] == 1 and second["sequence"] == 2
    assert second["previous_hash"] == first["current_hash"]
    assert store.verify() is True
    records = store.list()
    assert len(records) == 2


def test_request_isolation_and_orphan_evidence_never_cross_leak(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    store.append(observed("a", "tool", {}, request_id="req-a"))
    store.append(observed("b", "tool", {}, request_id="req-b"))
    assert [r["claim"] for r in store.list(request_id="req-a")] == ["a"]
    assert [r["claim"] for r in store.list(request_id="req-b")] == ["b"]
    assert store.verify() is True


def test_unsigned_evidence_never_supports_a_completion_proof(tmp_path, monkeypatch):
    _store, mission = _completed_mission(tmp_path, monkeypatch)
    assert mission.completion_proof_is_valid() is True
    # strip the signed system evidence: the criterion is no longer covered
    stripped = json.loads(json.dumps(mission.evidence))
    stripped[0].pop("system_evidence", None)
    mission.evidence = stripped
    assert mission.completion_proof_is_valid() is False


def test_substituted_system_evidence_is_rejected(tmp_path, monkeypatch):
    _store, mission = _completed_mission(tmp_path, monkeypatch)
    # tamper the signed payload (action binding forgery)
    tampered = json.loads(json.dumps(mission.evidence))
    tampered[0]["system_evidence"]["payload"]["action_id"] = "call-forged"
    mission.evidence = tampered
    assert mission.completion_proof_is_valid() is False
    # tamper the signature itself
    resigned = json.loads(json.dumps(mission.evidence))
    resigned[0]["system_evidence"]["signature"] = "a" * 64
    mission.evidence = resigned
    assert mission.completion_proof_is_valid() is False


def test_evidence_transplant_across_missions_is_rejected(tmp_path, monkeypatch):
    _store, mission = _completed_mission(tmp_path, monkeypatch)
    _store2, other = _completed_mission(Path(tmp_path) / "second", monkeypatch)
    transplanted = json.loads(json.dumps(mission.evidence))
    other.evidence = transplanted
    assert other.completion_proof_is_valid() is False


def test_workspace_event_evidence_is_bound_to_mission_chain(tmp_path):
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    event = {
        "operation": "write",
        "tool_id": "write",
        "result": "success",
        "timestamp": 1780000000.0,
        "request_id": "req-w",
        "mission_id": "m-w",
    }
    record = store.append_workspace_event(event)
    assert record["chain"] == ("mission:m-w", "operation:write")
    assert record["request_id"] == "req-w"
    assert store.verify() is True


def test_evidence_hash_is_content_bound(tmp_path):
    base = observed("claim", "tool", {"k": 1}, request_id="req-1")
    altered = observed("claim", "tool", {"k": 2}, request_id="req-1")
    assert base["current_hash"] != altered["current_hash"]
    record = Evidence(**dict(base))
    assert record.verify() is True
    record.confidence = 99
    assert record.verify() is False
