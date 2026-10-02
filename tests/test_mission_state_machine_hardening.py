from __future__ import annotations

"""Vibe V5.1 — mission state machine hardening battery.

Deterministic, model-free adversarial tests for the mission lifecycle: no
shortcut may reach GOAL_COMPLETED, terminal states are absorbing except the
explicit reconciliation / owner-intervention paths, stale and concurrent
writes are rejected, and the system-signed completion proof binds to exactly
one mission (no forgery, no transplant, no replay-to-duplicate state).
"""

import json
from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot

from agent.mission import Mission, MissionStatus, MissionStore
from agent.planning import Plan, PlanStep


def _completed_mission(tmp_path, monkeypatch):
    """Produce one genuinely completed mission with a system-signed proof."""
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


def _fresh_mission(mission_id="m-fresh"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "status", action="status"),), reason="test")
    return Mission.create("request", "objective", plan, mission_id=mission_id, owner_identity_ref="owner-a")


def test_goal_completed_transition_requires_exact_verified_state(tmp_path, monkeypatch):
    store, mission = _completed_mission(tmp_path, monkeypatch)
    # missing verification data
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "replay without verification")
    # mismatched verification data
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "forged", verification={"verified": True})
    # the exact persisted verified state is accepted (replay is absorbed, not duplicated)
    before = mission.status
    mission.transition(MissionStatus.GOAL_COMPLETED, "replay", verification=mission.verification_state)
    assert mission.status is before


def test_forged_or_tampered_proof_never_completes_or_persists(tmp_path, monkeypatch):
    store, mission = _completed_mission(tmp_path, monkeypatch)
    tampered = json.loads(json.dumps(mission.completion_proof))
    tampered["payload"]["mission_id"] = "attacker-mission"
    mission.completion_proof = tampered
    assert mission.completion_proof_is_valid() is False
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "forged proof", verification=mission.verification_state)
    with pytest.raises(ValueError):
        store.save(mission)


def test_completion_proof_cannot_be_transplanted_across_missions(tmp_path, monkeypatch):
    store, mission = _completed_mission(tmp_path, monkeypatch)
    # a second, independently completed mission
    store2, other = _completed_mission(Path(tmp_path) / "second", monkeypatch)
    assert other.completion_proof_is_valid() is True
    other.completion_proof = json.loads(json.dumps(mission.completion_proof))
    assert other.completion_proof_is_valid() is False
    with pytest.raises(ValueError):
        store2.save(other)


def test_unsigned_goal_completed_state_cannot_be_persisted(tmp_path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    mission = _fresh_mission()
    mission.status = MissionStatus.GOAL_COMPLETED  # forged in-memory state
    with pytest.raises(ValueError):
        store.save(mission)


def test_integrity_hash_tamper_is_rejected_on_load(tmp_path, monkeypatch):
    store, mission = _completed_mission(tmp_path, monkeypatch)
    payload = mission.to_dict()
    payload["objective"] = "tampered objective"
    with pytest.raises(ValueError):
        Mission.from_dict(payload)


def test_terminal_states_are_absorbing_except_reconciliation_and_owner_paths(tmp_path, monkeypatch):
    _store, mission = _completed_mission(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.RUNNING, "shortcut from completed")
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.PLANNING, "reopen completed")

    blocked = _fresh_mission("m-blocked")
    blocked.transition(MissionStatus.AUTHORIZATION_BLOCKED, "authorization failed")
    with pytest.raises(ValueError):
        blocked.transition(MissionStatus.RUNNING, "blocked mission executes")
    blocked.transition(MissionStatus.READY, "owner renewed authorization")
    assert blocked.status is MissionStatus.READY

    recovering = _fresh_mission("m-recovering")
    recovering.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous external execution")
    with pytest.raises(ValueError):
        recovering.transition(MissionStatus.RUNNING, "skip reconciliation")
    with pytest.raises(ValueError):
        recovering.transition(MissionStatus.GOAL_COMPLETED, "shortcut through recovery")
    recovering.transition(MissionStatus.READY, "owner reconciled")
    assert recovering.status is MissionStatus.READY


def test_paused_mission_gate(tmp_path):
    mission = _fresh_mission("m-paused")
    mission.transition(MissionStatus.READY, "ready")
    mission.transition(MissionStatus.PAUSED, "owner paused")
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.RUNNING, "paused mission executes")
    mission.transition(MissionStatus.READY, "owner resumed")
    assert mission.status is MissionStatus.READY
    mission.transition(MissionStatus.PAUSED, "paused again")
    mission.transition(MissionStatus.CANCELLED, "owner cancelled")
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.READY, "cancelled resumes")


def test_stale_and_concurrent_writes_are_rejected(tmp_path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    mission = _fresh_mission("m-race")
    store.save(mission)
    worker_a = store.load("m-race")
    worker_b = store.load("m-race")
    worker_a.progress["note"] = "written by a"
    store.save(worker_a)
    worker_b.progress["note"] = "written by stale b"
    with pytest.raises(ValueError):
        store.save(worker_b)


def test_owner_isolation_on_load(tmp_path):
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    mission = _fresh_mission("m-owner")
    store.save(mission)
    assert store.load_for_owner("m-owner", "owner-a") is not None
    assert store.load_for_owner("m-owner", "owner-b") is None


def test_non_mission_status_transition_argument_is_a_type_error(tmp_path):
    mission = _fresh_mission("m-type")
    with pytest.raises(TypeError):
        mission.transition("GOAL_COMPLETED", "string status is not a status")
