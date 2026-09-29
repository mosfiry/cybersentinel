from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_intelligence.context import ContextAssembler
from agent.model_protocol import ModelTurn
from agent.observation_intelligence import ObservationInterpreter
from agent.planning import Plan, PlanStep


def _runtime(tmp_path, *, executor=None, interpreter=None):
    return MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=executor or (lambda *_: {"success": True, "source": "status"}),
        interpreter=interpreter or ObservationInterpreter(),
        authorization_snapshot_factory=make_test_snapshot,
    )


def _mission(runtime, *, completion_criteria=()):
    plan = Plan.initial("inspect the authorized system").replan(
        steps=(PlanStep("inspect", "inspect the authorized system", action="status"),),
        reason="reasoning pipeline test",
    )
    return runtime.create(
        "inspect the authorized system",
        "inspect the authorized system",
        plan,
        completion_criteria=list(completion_criteria),
        request_id="reasoning-pipeline-test",
    )


def _interpret(runtime, mission, observation):
    mission.record_observation(observation)
    runtime._interpret_observation(mission, mission.plan.steps[0], observation, success=True)
    runtime.store.save(mission)
    return mission.reasoning_cases[-1]


def test_untrusted_model_claims_and_invented_evidence_ids_stay_unverified(tmp_path):
    ghost_support = "invented-support-id"
    ghost_counter = "invented-counter-id"
    interpreter = ObservationInterpreter(
        proposer=lambda _context: {
            "summary": "model claims compromise",
            "facts": ["the host is compromised"],
            "hypothesis_updates": [{
                "hypothesis_id": "h-1",
                "statement": "the host is compromised",
                "status": "CANDIDATE",
                "assumptions": ["the scanner label is accurate"],
                "supporting_evidence_ids": [ghost_support],
            }],
            "supporting_evidence_ids": [ghost_support],
            "counter_evidence_ids": [ghost_counter],
            "confidence_changes": [{
                "hypothesis_id": "h-1",
                "delta": 0.9,
                "reason": "the model claims a decisive signal",
                "supporting_evidence_ids": [ghost_support],
            }],
            "required_next_evidence": [],
        }
    )
    runtime = _runtime(tmp_path, interpreter=interpreter)
    mission = _mission(runtime)

    record = _interpret(runtime, mission, {
        "type": "tool_observation",
        "source": "status",
        "action_id": "status-1",
        "success": True,
        "confidence": 0.99,
        "summary": "raw tool claim: compromised",
    })

    assert record["record_type"] == "REASONING_CASE"
    assert record["observations"] == ("model claims compromise",)
    assert record["supporting_evidence"] == ()
    assert record["contradicting_evidence"] == ()
    assert record["candidate_hypotheses"][0]["record_type"] == "HYPOTHESIS_CANDIDATE"
    assert record["candidate_hypotheses"][0]["status"] == "UNVALIDATED"
    assert record["alternative_explanations"]
    assert record["confidence_rationale"].startswith("NOT_ASSESSED")
    assert set(record["evidence_reference_audit"]["rejected_ids"]) == {ghost_support, ghost_counter}
    assert record["system_validation"]["state"] == "UNVALIDATED"
    assert record["confidence"] == 0.0
    assert record["model_confidence"] == {
        "claimed_value": 0.99,
        "source": "raw_observation",
        "trust": "untrusted_claim",
    }
    assert "unsupported_claim" in {item["category"] for item in record["critic"]["findings"]}
    assert "missing_evidence" in {item["category"] for item in record["critic"]["findings"]}
    assert "tool_result_interpretation" in {item["category"] for item in record["critic"]["findings"]}
    assert "reasoning_gap" in {item["category"] for item in record["critic"]["findings"]}
    assert "invalid_assumption" in {item["category"] for item in record["critic"]["findings"]}
    assert "invalid_evidence_reference" in {item["category"] for item in record["critic"]["findings"]}
    assert "confidence_inflation" in {item["category"] for item in record["critic"]["findings"]}
    assert mission.interpretations[-1]["proposal_trust"] == "untrusted_claim"
    assert mission.interpretations[-1]["record_type"] == "INTERPRETED_OBSERVATION"
    assert mission.interpretations[-1]["facts"] == ["the host is compromised"]
    assert mission.evidence == []
    assert mission.verification_state.get("verified") is not True


def test_high_model_confidence_is_diagnostic_not_an_evidence_score(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)

    record = _interpret(runtime, mission, {
        "type": "tool_observation",
        "source": "status",
        "action_id": "status-confidence",
        "success": True,
        "confidence": 0.97,
        "summary": "the tool returned an observation",
    })

    assert record["model_confidence"]["claimed_value"] == 0.97
    assert record["confidence"] == 0.0
    assert record["confidence_rationale"].startswith("NOT_ASSESSED")
    assert record["evidence_confidence"] == {
        "value": None,
        "state": "NOT_ASSESSED",
        "rationale": "This slice does not derive confidence from evidence quality; see system_validation separately.",
    }
    assert record["critic"]["confidence_inflation"] >= 1
    assert record["critic"]["authority"] == "diagnostic_only"
    assert record["critic"]["confidence_changed"] is False
    assert record["system_validation"]["state"] == "UNVALIDATED"


def test_conflicting_verified_evidence_references_are_surfaced_without_adjudication(tmp_path, monkeypatch):
    import core.engine
    import security.truthfulness as truthfulness

    monkeypatch.setenv("CYBERSENTINEL_PROVENANCE_KEY", str(Path(tmp_path) / "system-evidence.key"))
    monkeypatch.setattr(truthfulness, "_ISSUER", None)
    monkeypatch.setattr(core.engine, "status", lambda: {"online": True, "service": "test", "version": "1"})

    runtime = _runtime(tmp_path)
    mission = _mission(runtime, completion_criteria=(
        {"criterion_id": "status-a", "check": "system_online"},
        {"criterion_id": "status-b", "check": "system_online"},
    ))
    mission.record_action("prior-status", "inspect", "completed", {"source": "status"}, plan_fingerprint=mission.plan.fingerprint)
    runtime._record_verified_criterion_evidence(mission, "prior-status")
    verified_ids = [str(item["evidence_id"]) for item in mission._verified_system_evidence()]
    assert len(verified_ids) == 2

    runtime.interpreter = ObservationInterpreter(proposer=lambda _context: {
        "summary": "references evidence on both sides",
        "supporting_evidence_ids": [verified_ids[0]],
        "counter_evidence_ids": [verified_ids[1]],
        "required_next_evidence": ["independent resolution of the conflict"],
    })
    record = _interpret(runtime, mission, {
        "type": "tool_observation",
        "source": "status",
        "action_id": "status-conflict",
        "success": True,
        "summary": "observation with conflicting citations",
    })

    assert set(record["supporting_evidence"]) == {verified_ids[0]}
    assert set(record["contradicting_evidence"]) == {verified_ids[1]}
    assert record["evidence_reference_audit"]["rejected_ids"] == []
    assert record["required_next_evidence"] == ("independent resolution of the conflict",)
    assert "contradictory_evidence" in {item["category"] for item in record["critic"]["findings"]}
    assert record["critic"]["semantic_truth_claimed"] is False
    assert record["system_validation"]["state"] == "UNVALIDATED"


def test_reasoning_case_survives_reload_model_switch_and_reaches_provider_messages(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.record_action("status-durable", "inspect", "completed", {"source": "status"}, plan_fingerprint=mission.plan.fingerprint)
    mission.checkpoint = {"status": "completed", "step_id": "inspect", "action_id": "status-durable"}
    mission.recovery_events.append({"event": "resumed_after_restart", "reason": "test fixture", "action_id": "status-durable"})
    _interpret(runtime, mission, {
        "type": "tool_observation",
        "source": "status",
        "action_id": "status-durable",
        "success": True,
        "summary": "durable observation claim",
    })

    reloaded_store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    reloaded = reloaded_store.load(mission.mission_id)
    assert reloaded is not None
    reloaded.model_selection = {"provider": "secondary-test-provider", "model": "switched-model"}
    reloaded_store.save(reloaded)

    switched_runtime = MissionRuntime(reloaded_store, executor=lambda *_: {})

    class CapturingModel:
        messages = ()

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.messages = tuple(messages)
            return ModelTurn(turn_id, content="received durable state", provider="test", model="switched-model")

    model = CapturingModel()
    switched_runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)

    state_message = next(message.content for message in model.messages if message.content.startswith("DURABLE_STATE\n"))
    provider_state = json.loads(state_message.removeprefix("DURABLE_STATE\n"))
    assert provider_state["mission"]["mission_id"] == mission.mission_id
    assert provider_state["reasoning_cases"][-1]["case_id"] == reloaded.reasoning_cases[-1]["case_id"]
    assert provider_state["reasoning_cases"][-1]["observations"] == ["durable observation claim"]
    assert provider_state["reasoning_cases"][-1]["system_validation"]["state"] == "UNVALIDATED"
    assert provider_state["reasoning_cases"][-1]["evidence_confidence"]["state"] == "NOT_ASSESSED"
    assert provider_state["completed_steps"][-1]["record_type"] == "COMPLETED_ACTION"
    assert provider_state["completed_steps"][-1]["step_id"] == "inspect"
    assert provider_state["recovery_state"]["record_type"] == "RECOVERY_STATE"
    assert provider_state["recovery_state"]["checkpoint"]["status"] == "completed"
    assert provider_state["recovery_state"]["events"][-1]["event"] == "resumed_after_restart"
    assert reloaded.model_selection["model"] == "switched-model"


def test_critic_diagnostic_cannot_complete_mission(tmp_path):
    runtime = _runtime(
        tmp_path,
        executor=lambda *_: {
            "success": True,
            "source": "status",
            "summary": "model says the objective is complete",
            "confidence": 0.99,
        },
        interpreter=ObservationInterpreter(proposer=lambda _context: {
            "summary": "model says the objective is complete",
            "facts": ["goal satisfied"],
        }),
    )
    mission = _mission(runtime, completion_criteria=(
        {"criterion_id": "independently-verified-goal", "check": "unsupported-check"},
    ))

    after_observation = runtime.run_slice(mission.mission_id)
    assert after_observation.reasoning_cases[-1]["critic"]["authority"] == "diagnostic_only"
    completed = runtime.run_slice(mission.mission_id)

    assert completed.status is MissionStatus.OWNER_INPUT_REQUIRED
    assert completed.status is not MissionStatus.GOAL_COMPLETED
    assert completed.verification_state["verified"] is False
    assert completed.completion_proof is None
    assert completed.reasoning_cases[-1]["system_validation"]["state"] == "UNVALIDATED"
