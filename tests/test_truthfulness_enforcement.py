"""T2 production enforcement battery (integration + adversarial).

Proves the completion invariant and truth labeling on the PRODUCTION objects
(Mission state machine, MissionStore persistence, chat truth payload, web
frontend) - not only library helpers.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.mission import Mission, MissionStore, MissionStatus
from agent.planning import Plan
from security.truthfulness import (
    EvidenceRecord,
    EvidenceStatus,
    SystemEvidenceIssuer,
    mission_truth_payload,
)


def _plan() -> Plan:
    return Plan(version="v1", objective="o", assumptions=(), steps=(), dependencies=(), completion_criteria=(), risk="unknown", created_from="")


def _mission() -> Mission:
    return Mission.create("request", "objective", _plan())


# --- completion invariant: transition gate -----------------------------------

def test_mission_cannot_complete_by_assertion():
    mission = _mission()
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "model says complete")


def test_mission_completes_only_with_deterministic_verification_state():
    mission = _mission()
    mission.verification_state = {"verified": False, "missing_criteria": ["x"]}
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "claimed verification")
    mission.verification_state = {"verified": True, "missing_criteria": [], "evidence_count": 1}
    mission.transition(MissionStatus.GOAL_COMPLETED, "deterministic evidence")
    assert mission.status is MissionStatus.GOAL_COMPLETED


def test_model_final_text_cannot_complete_mission():
    # Adversarial: the model emits a "complete" final answer; truth payload
    # and the state machine both refuse completion without system evidence.
    mission = _mission()
    mission.progress["last_model_content"] = "all phases complete and verified"
    truth = mission_truth_payload(mission.status.value, mission.verification_state)
    assert truth["completion"] == "NOT_COMPLETE"
    assert truth["answer_authority"] == "MODEL_OUTPUT"
    with pytest.raises(ValueError):
        mission.transition(MissionStatus.GOAL_COMPLETED, "model final")


# --- persistence invariant: store gate ----------------------------------------

def test_store_refuses_persisting_unverified_completion():
    with tempfile.TemporaryDirectory() as tmp:
        store = MissionStore(pathlib.Path(tmp) / "missions.db")
        mission = _mission()
        # Simulate an alternate path bypassing transition() (direct assignment).
        mission.status = MissionStatus.GOAL_COMPLETED
        with pytest.raises(ValueError):
            store.save(mission)


def test_store_persishes_verified_completion():
    with tempfile.TemporaryDirectory() as tmp:
        store = MissionStore(pathlib.Path(tmp) / "missions.db")
        mission = _mission()
        mission.verification_state = {"verified": True, "missing_criteria": [], "evidence_count": 2}
        mission.transition(MissionStatus.GOAL_COMPLETED, "deterministic evidence")
        store.save(mission)
        loaded = store.load(mission.mission_id)
        assert loaded is not None
        assert loaded.status is MissionStatus.GOAL_COMPLETED


# --- truth payload semantics ---------------------------------------------------

def test_truth_payload_is_not_complete_without_verification():
    truth = mission_truth_payload("GOAL_COMPLETED", {"verified": False})
    assert truth["completion"] == "NOT_COMPLETE"
    assert truth["goal_verified"] is False


def test_truth_payload_complete_only_with_verified_state():
    truth = mission_truth_payload("GOAL_COMPLETED", {"verified": True, "evidence_count": 1, "missing_criteria": []})
    assert truth["completion"] == "COMPLETE"


# --- forged evidence cannot complete anything (system issuer) ------------------

def test_forged_evidence_record_is_claimed_provenance():
    issuer = SystemEvidenceIssuer(b"z" * 32 + b"prod-like-key-0001")
    forged = EvidenceRecord(origin="execution_runtime", kind="execution", payload={"ok": True}, provenance_token="f" * 64)
    assert not issuer.verify(forged)


# --- API + frontend wiring (source regression) ---------------------------------

def test_chat_api_attaches_server_truth():
    source = (ROOT / "api" / "chat.py").read_text(encoding="utf-8")
    assert "mission_truth_payload(mission.status.value, mission.verification_state)" in source
    assert '"truth"' in source


def test_frontend_cannot_fabricate_completion():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    # B7 regression: no invented completion status, no invented completion text.
    assert '||"completed"' not in source
    assert "اكتمل التحليل" not in source
    # Frontend must consume the server truth object.
    assert "d.truth" in source
    assert '||"UNKNOWN"' in source


def test_no_alternate_completion_writer_in_agent_layer():
    # The only production writer of GOAL_COMPLETED must be transition() after
    # deterministic verification; persistence additionally guards save().
    mission_source = (ROOT / "agent" / "mission.py").read_text(encoding="utf-8")
    assert "GOAL_COMPLETED is a system invariant" in mission_source
    assert "refusing to persist GOAL_COMPLETED" in mission_source
