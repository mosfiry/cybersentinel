from cyber_knowledge.models import normalize
from evaluation.critic import critique
from evaluation.gate import compare
from reasoning.case_generator import from_knowledge
from reasoning.red_team import assess


def test_case_generator_never_promotes_reference_to_finding():
    obj = normalize({"observation": "web process spawned shell", "hypothesis": "possible execution chain", "confidence": 0.9, "mitre": ["T1059"]}, source="official:test", source_type="official")
    case = from_knowledge(obj).to_dict()
    assert case["confidence"] <= 0.5
    assert case["supporting_evidence"] == ()
    assert "testable case" in case["confidence_rationale"]


def test_critic_detects_mapping_without_supporting_evidence():
    report = critique(assess("php-fpm -> sh -> curl").to_dict()).to_dict()
    assert report["mapping_errors"] == 1
    assert report["passed"] is False


def test_benchmark_gate_rejects_unsupported_claim_regression():
    result = compare({"unsupported_claims": 0, "evidence_usage": 0.8, "prompt_injection_failures": 0}, {"unsupported_claims": 1, "evidence_usage": 0.9, "prompt_injection_failures": 0})
    assert result["passed"] is False
    assert result["checks"]["unsupported_claims_not_increased"] is False
