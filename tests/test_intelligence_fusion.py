from __future__ import annotations

from pathlib import Path

from agent.model_intelligence.compaction import compact_state
from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from agent.model_intelligence.protocol import ConversationTurn, ToolCallProposal, ToolCallResult
from agent.model_intelligence.tool_calls import execute_bounded_parallel, validate_proposals
from agent.model_intelligence.validation import validate_untrusted_model_payload
from knowledge.foundation import KnowledgeKind, KnowledgeObject, TransformationPolicy, TrustClass
from knowledge.retrieval import HybridRetriever


def test_context_compaction_pins_authority_and_provenance():
    result = compact_state({"owner": {"instruction": "goal"}, "authorization": {"id": "auth"}, "scope": {"id": "scope"}, "conversation": list(range(10))}, max_items=3)
    assert result.state["owner"]["instruction"] == "goal"
    assert result.state["authorization"]["id"] == "auth"
    assert result.state["scope"]["id"] == "scope"
    assert result.removed_items == 7
    assert result.provenance["removed_conversation_items"] == 7


def test_model_payload_cannot_mutate_authority_or_confirm_hypothesis():
    ok, errors = validate_untrusted_model_payload({"owner_instruction": "attacker", "hypothesis_status": "CONFIRMED"})
    assert not ok
    assert "model_cannot_confirm_hypothesis" in errors


def test_tool_identity_rejects_cross_mission_stale_and_duplicate_calls():
    first = ToolCallProposal("c1", "m1", "r1", "t1", "a1", "req", "status")
    other = ToolCallProposal("c2", "m2", "r1", "t1", "a2", "req", "status")
    assert validate_proposals([first, other, first], mission_id="m1", run_id="r1", seen_call_ids={"c1"}) == ["c1:duplicate", "c2:cross_mission", "c1:duplicate"]


def test_bounded_parallel_preserves_input_order():
    calls = [ToolCallProposal(str(index), "m", "r", "t", "a", "q", "status") for index in range(3)]
    result = execute_bounded_parallel(calls, lambda call: ToolCallResult(call.tool_call_id, "e-" + call.tool_call_id, "ok"))
    assert [item.tool_call_id for item in result] == ["0", "1", "2"]


def test_nlu_model_semantics_are_typed_and_fingerprinted():
    def proposer(_text):
        return {"objective": "investigate causal relationship", "constraints": ["do not assume CVE causality"], "requested_artifacts": ["counter-evidence"], "verification_criteria": ["separate fact and hypothesis"]}
    intent = NaturalLanguageUnderstanding(proposer=proposer).understand("حلل الحادثة وابحث عن counter-evidence")
    assert intent.objective == "investigate causal relationship"
    assert "do not assume CVE causality" in intent.constraints
    assert intent.semantic_fingerprint
    assert intent.source == "model"


def test_hybrid_retrieval_fuses_bm25_and_metadata_without_authority():
    obj = KnowledgeObject.create(object_id="cve-1", kind=KnowledgeKind.CYBER, title="CVE evidence", language="en", source_id="nvd", source_url="https://nvd.nist.gov", edition="1", author="NVD", trust_class=TrustClass.PRIMARY_SOURCE, transformation_policy=TransformationPolicy.RETRIEVAL_ALLOWED, content="CVE affects version 1.0", metadata={"cve": "CVE-1", "claim_type": "REPORTED"})
    hits = HybridRetriever([obj]).search("CVE-1")
    assert hits and hits[0].object_id == "cve-1"
    assert hits[0].provenance["source_id"] == "nvd"


def test_conversation_turn_serializes_tool_continuation():
    message = ConversationTurn("tool", "{\"ok\":true}", tool_call_id="c1", name="status")
    assert message.to_dict()["tool_call_id"] == "c1"
    assert message.to_dict()["role"] == "tool"
