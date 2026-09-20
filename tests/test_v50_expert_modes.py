import pytest

from core.expert_modes import analyze_expert_case, attacker_reasoning, defender_reasoning


def test_attacker_reasoning_is_path_analysis_not_execution():
    result = attacker_reasoning("php-fpm spawned a shell-like process")
    assert result["mode"] == "attacker_reasoning"
    assert len(result["candidate_hypotheses"]) >= 2
    assert result["required_evidence"]
    assert any("does not generate payloads" in item for item in result["limitations"])


def test_defender_reasoning_requests_telemetry_and_scope():
    result = defender_reasoning("unexpected outbound connection during deployment")
    assert result["mode"] == "defender_reasoning"
    assert result["detection"]
    assert result["required_next_evidence"]
    assert any("No containment" in item for item in result["limitations"])


def test_combined_case_is_uncertain_and_rejects_empty_observation():
    result = analyze_expert_case("service process changed unexpectedly")
    assert result["attacker_reasoning"]["mode"] == "attacker_reasoning"
    assert result["defender_reasoning"]["mode"] == "defender_reasoning"
    assert result["confidence"] < 0.5
    with pytest.raises(ValueError):
        analyze_expert_case(" ")
