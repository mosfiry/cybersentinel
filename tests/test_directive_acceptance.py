from __future__ import annotations

from unittest.mock import patch

from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from core.engine import summarize
from search.ssrf import check_url_ssrf
from security.authority import AuthorityTier, authority_snapshot


def test_owner_instruction_is_highest_application_authority():
    assert AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_POLICY
    snapshot = authority_snapshot()
    assert snapshot["application_policy_order"][:3] == ["OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY"]


def test_local_fallback_is_honest_and_does_not_claim_model_execution():
    text = summarize(["status"], [{"tool": "status", "ok": True, "result": {"event_counts": {}}}], "local", "provider unavailable")
    assert "الوضع المحلي المحدود" in text
    assert "خطة دفاعية فعلية" not in text
    assert "provider unavailable" not in text


def test_dns_resolution_is_checked_at_ssrf_boundary():
    with patch("search.ssrf.get_ip_addresses", return_value=["127.0.0.1"]):
        assert check_url_ssrf("https://public.example", raise_on_block=False) is False
    with patch("search.ssrf.get_ip_addresses", return_value=[]):
        assert check_url_ssrf("https://unresolvable.example", raise_on_block=False) is False


def test_arabic_and_english_incident_intents_share_semantic_type():
    class Unavailable:
        def __call__(self, _text):
            raise RuntimeError("no model")

    nlu = NaturalLanguageUnderstanding(proposer=Unavailable())
    arabic = nlu.understand("حلل الحادثة وحدد السبب الجذري")
    english = nlu.understand("analyze the incident and identify the root cause")
    assert arabic.intent_type == "MISSION_REQUEST"
    assert english.intent_type == "MISSION_REQUEST"
    assert arabic.source == english.source == "deterministic_fallback"
