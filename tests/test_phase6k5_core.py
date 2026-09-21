from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent.conversation import (
    ConversationActionProposal,
    ConversationContext,
    ConversationInput,
    ConversationParser,
    ConversationResponse,
    IntentType,
)
from agent.memory import MemoryDomain, MemoryItem, MemoryType, TrustClassification
from security.owner_policy import capture_policy_snapshot, owner_instruction_fingerprint, set_current_owner_instruction
from security.authorization import authorize_plan


def test_owner_evidence_is_request_bound_and_replay_protected(monkeypatch, tmp_path):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "state.json")
    evidence = policy._issue_evidence("owner_token", "request-a", "proof")
    set_current_owner_instruction("Owner instruction A", auth_evidence=evidence, request_id="request-a")
    with pytest.raises(PermissionError, match="replay"):
        set_current_owner_instruction("Owner instruction B", auth_evidence=evidence, request_id="request-a")
    other_request = policy._issue_evidence("owner_token", "request-a", "proof-other")
    with pytest.raises(PermissionError, match="request-mismatched"):
        set_current_owner_instruction("Owner instruction B", auth_evidence=other_request, request_id="request-b")


def test_session_evidence_requires_manager_issued_proof(monkeypatch):
    import security.owner_policy as policy
    import security.owner_session as sessions
    monkeypatch.setattr(sessions, "verify_owner", lambda text, token: (True, "test"))
    manager = sessions.OwnerSessionManager(ttl_seconds=30)
    session = manager.create("token")
    context = manager.consume(session.session_id, session.challenge, f"CS {session.challenge}", "request-session")
    monkeypatch.setattr(sessions, "DEFAULT_OWNER_SESSIONS", manager)
    evidence = policy.authentication_from_session(context, "request-session")
    assert evidence.session_id == session.session_id
    fake = dict(context, session_proof="fake")
    with pytest.raises(PermissionError, match="proof"):
        policy.authentication_from_session(fake, "request-session")


def test_tampered_and_stale_evidence_is_deterministically_rejected(monkeypatch, tmp_path):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "state.json")
    evidence = policy._issue_evidence("owner_token", "request-a", "proof")
    tampered = replace(evidence, proof_fingerprint="changed")
    with pytest.raises(PermissionError, match="stale|forged|mismatched"):
        set_current_owner_instruction("Owner instruction", auth_evidence=tampered, request_id="request-a")
    expired = replace(evidence, expires_at="2000-01-01T00:00:00+00:00")
    with pytest.raises(PermissionError, match="stale|forged|mismatched"):
        set_current_owner_instruction("Owner instruction", auth_evidence=expired, request_id="request-a")


def test_policy_snapshot_does_not_change_when_current_instruction_changes(monkeypatch, tmp_path):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "state.json")
    first = policy._issue_evidence("owner_token", "request-a", "first")
    set_current_owner_instruction("Owner instruction A", auth_evidence=first, request_id="request-a")
    snapshot = capture_policy_snapshot("request-a", first)
    second = policy._issue_evidence("owner_token", "request-b", "second")
    set_current_owner_instruction("Owner instruction B", auth_evidence=second, request_id="request-b")
    assert snapshot.owner_instruction == "Owner instruction A"
    assert snapshot.owner_instruction_fingerprint == owner_instruction_fingerprint("Owner instruction A")
    assert snapshot.request_id == "request-a"


def test_tool_firewall_requires_valid_evidence_for_sensitive_plan(monkeypatch, tmp_path):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "state.json")
    evidence = policy._issue_evidence("owner_token", "request-firewall", "firewall")
    accepted, errors = authorize_plan([["red_team_assess", "assess safely"]], owner_evidence=evidence, request_id="request-firewall")
    assert accepted == [("red_team_assess", "assess safely")]
    assert errors == []
    forged = replace(evidence, signature="0" * len(evidence.signature))
    accepted, errors = authorize_plan([["red_team_assess", "assess safely"]], owner_evidence=forged, request_id="request-firewall")
    assert accepted == []
    assert any("evidence" in error for error in errors)
    accepted, errors = authorize_plan([["search", {"query": "bad"}]], owner_evidence=evidence, request_id="request-firewall")
    assert accepted == []
    assert errors


def test_concurrent_owner_updates_leave_valid_state_and_history(monkeypatch, tmp_path):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "state.json")

    def update(index: int):
        request_id = f"race-{index}"
        evidence = policy._issue_evidence("owner_token", request_id, f"race-proof-{index}")
        return set_current_owner_instruction(f"Owner race instruction {index}", auth_evidence=evidence, request_id=request_id)

    with ThreadPoolExecutor(max_workers=4) as pool:
        states = list(pool.map(update, range(4)))
    final_state = policy.load_state()
    assert final_state["current_owner_instruction"].startswith("Owner race instruction")
    assert len(final_state["previous_owner_instructions"]) >= 1
    assert all(isinstance(state["current_owner_instruction"], str) for state in states)


@pytest.mark.parametrize("text, expected", [
    ("حلل هذه الحادثة بالتفصيل.", IntentType.ANALYZE_INCIDENT),
    ("علمني SQL injection من الصفر.", IntentType.LEARN),
    ("اشرح لي لماذا رفض النظام الطلب.", IntentType.EXPLAIN_REJECTION),
    ("لدي CVE-2026-1234 وأريد فهم تأثيرها.", IntentType.EXPLAIN_EVIDENCE),
    ("افحص هذا الكود وابحث عن نقاط الضعف.", IntentType.ANALYZE_CODE),
    ("اختبر الهدف الموجود داخل النطاق المصرح به.", IntentType.SCOPED_TEST),
    ("What evidence is missing?", IntentType.EXPLAIN_EVIDENCE),
    ("Explain this CVE and tell me what evidence is missing.", IntentType.EXPLAIN_EVIDENCE),
    ("علمني الفرق بين SQLi وcommand injection.", IntentType.LEARN),
])
def test_bilingual_conversation_understanding_is_not_authorization(text, expected):
    parser = ConversationParser()
    intent = parser.understand(text)
    assert intent.intent_type is expected
    assert intent.authority_granted is False
    response = parser.respond(ConversationInput(text, "conv-1", "req-1"), ConversationContext("conv-1", "req-1"))
    assert isinstance(response, ConversationResponse)
    assert "authority_granted" not in response.public()
    if expected is IntentType.SCOPED_TEST:
        assert isinstance(response.action_proposal, ConversationActionProposal)
        assert response.action_proposal.status == "PROPOSED"
        assert response.action_proposal.authorization_required is True
        assert response.tool_calls == ()


def test_memory_domains_carry_provenance_but_cannot_be_policy_or_evidence():
    item = MemoryItem.create(
        conversation_id="conv-1",
        content="research note",
        memory_type=MemoryType.INVESTIGATION,
        trust_classification=TrustClassification.UNTRUSTED_DATA,
        source="user",
        provenance="request:req-1",
        domain=MemoryDomain.RESEARCH,
        request_id="req-1",
    )
    data = item.to_dict()
    assert data["domain"] == "research"
    assert data["request_id"] == "req-1"
    with pytest.raises(ValueError):
        MemoryItem.create("conv-1", "policy", MemoryType.FACT, TrustClassification.VALIDATED, "tool", "x", domain=MemoryDomain.CONVERSATION, metadata={"classification": "evidence"})
