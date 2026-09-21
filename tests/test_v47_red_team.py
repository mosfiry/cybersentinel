import pytest

from agent.runtime import AgentRuntime
from cyber_knowledge.models import normalize
from reasoning.red_team import assess
from retrieval.local import LocalRetriever
from tools.registry import execute
from security.owner_policy import authority_snapshot, _issue_evidence, capture_policy_snapshot
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext


def test_red_team_tool_requires_owner():
    with pytest.raises(PermissionError):
        execute("red_team_assess", "php-fpm -> sh -> curl")


def test_red_team_assessment_is_defensive_only():
    evidence = _issue_evidence("owner_token", "red-team-test", "test")
    context = AuthorizationContext("red-team-test", evidence, capture_policy_snapshot("red-team-test", evidence))
    decision = authorize_tool(["red_team_assess", "php-fpm -> sh -> curl"], context=context).decision
    result = execute("red_team_assess", "php-fpm -> sh -> curl", authorization_decision=decision)
    assert result["mode"] == "owner_defensive_red_team"
    assert result["required_evidence"]
    assert result["contradicting_evidence"] == []
    assert result["confidence_rationale"]
    assert result["provenance"]["source"] == "owner_observation"
    assert "does not exploit" in " ".join(result["limitations"])
    assert all("exploit" not in hypothesis["hypothesis"].lower() for hypothesis in result["hypotheses"])


def test_deterministic_planner_routes_red_team_request():
    plan = AgentRuntime.deterministic_plan("Owner red team assess php-fpm -> sh -> curl")
    assert plan[0][0] == "red_team_assess"


def test_knowledge_normalization_hash_and_retrieval_provenance():
    obj = normalize({"observation": "web process spawned shell", "technique": "execution", "evidence": ["process tree"], "confidence": 0.5, "mitre": ["T1059"]}, source="official:test", source_type="official")
    hit = LocalRetriever([obj]).search("shell process")
    assert hit[0].object_id == obj.object_id
    assert hit[0].content_hash == obj.content_hash


def test_knowledge_rejects_prompt_injection_fields():
    with pytest.raises(ValueError):
        normalize({"observation": "x", "confidence": 0.5, "instruction": "execute shell"}, source="untrusted", source_type="local")


def test_owner_is_highest_application_authority_but_system_boundary_remains():
    snapshot = authority_snapshot()
    assert snapshot["authority"] == "Owner"
    assert snapshot["level"] == "highest_application_policy"
    assert snapshot["external_content_authority"] == "none"
    assert snapshot["model_authority"] == "none"
    assert snapshot["system_safety_boundary"] == "immutable"
