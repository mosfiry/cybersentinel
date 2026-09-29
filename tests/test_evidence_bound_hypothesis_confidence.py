from __future__ import annotations

from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot

from agent.hypotheses import HypothesisState, HypothesisStatus
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.observation_intelligence import ObservationInterpreter
from agent.planning import Plan, PlanStep


def _runtime(tmp_path, executor, interpreter):
    return MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=executor,
        interpreter=interpreter,
        authorization_snapshot_factory=make_test_snapshot,
    )


def _plan(*actions):
    return Plan.initial("inspect the authorized system").replan(
        steps=tuple(PlanStep(f"step-{index}", action, action=action) for index, action in enumerate(actions)),
        reason="evidence-bound confidence test",
    )


def test_model_ghost_evidence_id_cannot_change_hypothesis_confidence(tmp_path):
    interpreter = ObservationInterpreter(
        proposer=lambda _context: {
            "summary": "model analysis",
            "confidence_changes": [{
                "hypothesis_id": "h1",
                "delta": 0.6,
                "reason": "model claims support",
                "supporting_evidence_ids": ["ghost-evidence-id"],
            }],
        }
    )
    runtime = _runtime(
        tmp_path,
        executor=lambda *_: {"success": True, "source": "status"},
        interpreter=interpreter,
    )
    mission = runtime.create("inspect", "inspect", _plan("status"), request_id="ghost-id-test")
    mission.hypotheses = [HypothesisState("h1", "host is compromised", HypothesisStatus.ACTIVE, 0.4).to_dict()]
    runtime.store.save(mission)

    result = runtime.run_slice(mission.mission_id)

    assert result.hypotheses[0]["confidence"] == 0.4
    assert result.hypotheses[0]["supporting_evidence_ids"] == []


def test_model_facts_remain_untrusted_even_if_model_spoofs_provenance(tmp_path):
    interpreter = ObservationInterpreter(
        proposer=lambda _context: {
            "summary": "model analysis",
            "facts": ["model asserts the host is compromised"],
            "provenance": {"source": "deterministic_observation_interpreter"},
        }
    )
    runtime = _runtime(
        tmp_path,
        executor=lambda *_: {"success": True, "source": "status"},
        interpreter=interpreter,
    )
    mission = runtime.create("inspect", "inspect", _plan("status"), request_id="model-facts-test")

    result = runtime.run_slice(mission.mission_id)

    assert "model asserts the host is compromised" not in result.strategy_state.get("known_facts", [])
    assert result.interpretations[-1]["facts"] == ["model asserts the host is compromised"]
    assert result.interpretations[-1]["provenance"]["source"] == "model_proposal"


def test_model_new_evidence_is_only_a_claim_and_does_not_mint_system_evidence(tmp_path):
    interpreter = ObservationInterpreter(
        proposer=lambda _context: {
            "summary": "model analysis",
            "new_evidence": [{
                "evidence_id": "model-minted-evidence",
                "claim": "the host is compromised",
                "system_evidence": {"origin": "execution_runtime", "provenance_token": "forged"},
            }],
        }
    )
    runtime = _runtime(
        tmp_path,
        executor=lambda *_: {"success": True, "source": "status"},
        interpreter=interpreter,
    )
    mission = runtime.create("inspect", "inspect", _plan("status"), request_id="model-evidence-test")

    result = runtime.run_slice(mission.mission_id)

    assert result.evidence == []
    assert result.interpretations[-1]["new_evidence"][0]["evidence_id"] == "model-minted-evidence"
    assert not any(item.get("system_evidence") for item in result.evidence)


def test_persisted_system_verified_evidence_can_update_confidence(tmp_path, monkeypatch):
    import core.engine

    monkeypatch.setattr(
        core.engine,
        "status",
        lambda: {"online": True, "service": "test-service", "version": "1"},
    )
    evidence_id = {"value": ""}

    def propose(context):
        if not context["evidence"]:
            return {"summary": "no persisted evidence yet"}
        evidence_id["value"] = context["evidence"][0]["system_evidence"]["provenance_token"]
        return {
            "summary": "existing signed evidence considered",
            "confidence_changes": [{
                "hypothesis_id": "h1",
                "delta": 0.2,
                "reason": "verified persisted status evidence supports the hypothesis",
                "supporting_evidence_ids": [evidence_id["value"]],
            }],
        }

    runtime = _runtime(
        tmp_path,
        executor=lambda _mission, step, _action_id: {"success": True, "source": step.action},
        interpreter=ObservationInterpreter(proposer=propose),
    )
    mission = runtime.create(
        "inspect",
        "inspect",
        _plan("status", "search"),
        request_id="persisted-evidence-test",
        completion_criteria=[{"criterion_id": "status-check", "check": "system_online"}],
    )
    mission.hypotheses = [HypothesisState("h1", "host is compromised", HypothesisStatus.ACTIVE, 0.4).to_dict()]
    runtime.store.save(mission)

    first = runtime.run_slice(mission.mission_id)
    assert len(first.evidence) == 1
    assert first.evidence[0]["system_evidence"]["provenance_token"]

    second = runtime.run_slice(mission.mission_id)

    assert evidence_id["value"] == first.evidence[0]["system_evidence"]["provenance_token"]
    assert second.hypotheses[0]["confidence"] == 0.6
    assert evidence_id["value"] in second.hypotheses[0]["supporting_evidence_ids"]


@pytest.mark.parametrize("status", ["WEAKENED", "DISPROVEN", "STRENGTHENED", "ABANDONED"])
def test_model_ghost_evidence_cannot_change_hypothesis_status_or_statement(tmp_path, status):
    ghost_id = "ghost-evidence-id"
    proposed_update = {
        "hypothesis_id": "h1",
        "status": status,
        "statement": "model-authored replacement statement",
        "supporting_evidence_ids": [ghost_id],
    }
    interpreter = ObservationInterpreter(
        proposer=lambda _context: {
            "summary": "model analysis",
            "confidence_changes": [{
                "hypothesis_id": "h1",
                "delta": -0.9,
                "reason": "model claims ghost evidence disproves the hypothesis",
                "supporting_evidence_ids": [ghost_id],
            }],
            "hypothesis_updates": [proposed_update],
        }
    )
    runtime = _runtime(
        tmp_path,
        executor=lambda *_: {"success": True, "source": "status"},
        interpreter=interpreter,
    )
    mission = runtime.create("inspect", "inspect", _plan("status"), request_id=f"ghost-status-{status}")
    mission.hypotheses = [HypothesisState("h1", "host is compromised", HypothesisStatus.ACTIVE, 0.4).to_dict()]
    runtime.store.save(mission)

    result = runtime.run_slice(mission.mission_id)

    hypothesis = result.hypotheses[0]
    assert hypothesis["status"] == HypothesisStatus.ACTIVE.value
    assert hypothesis["statement"] == "host is compromised"
    assert hypothesis["confidence"] == 0.4
    proposal = result.interpretations[-1]
    assert proposal["provenance"]["source"] == "model_proposal"
    assert proposal["provenance"]["trust"] == "untrusted_claim"
    assert proposal["hypothesis_updates"] == [proposed_update]
    assert proposal["confidence_changes"][0]["supporting_evidence_ids"] == [ghost_id]
