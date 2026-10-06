from __future__ import annotations

import socket
from unittest.mock import patch

from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from core.engine import summarize
from search.ssrf import check_url_ssrf, validate_url
from security.authority import AuthorityTier, authority_snapshot


def test_system_platform_is_outer_authority_and_owner_is_highest_application_authority():
    assert AuthorityTier.SYSTEM_PLATFORM > AuthorityTier.OWNER_INSTRUCTION > AuthorityTier.OWNER_POLICY
    snapshot = authority_snapshot()
    assert snapshot["authority_order"][:3] == ["SYSTEM_PLATFORM", "OWNER_INSTRUCTION", "OWNER_POLICY"]
    assert snapshot["application_policy_order"][:2] == ["OWNER_INSTRUCTION", "OWNER_POLICY"]


def test_local_fallback_is_honest_and_does_not_claim_model_execution():
    text = summarize(["status"], [{"tool": "status", "ok": True, "result": {"event_counts": {}}}], "local", "provider unavailable")
    assert "الوضع المحلي المحدود" in text
    assert "خطة دفاعية فعلية" not in text
    assert "provider unavailable" not in text


def test_dns_resolution_is_checked_at_ssrf_boundary():
    private_answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]
    with patch("security.pinned_http.socket.getaddrinfo", return_value=private_answer):
        assert check_url_ssrf("https://public.example", raise_on_block=False) is False
    with patch("security.pinned_http.socket.getaddrinfo", side_effect=socket.gaierror("not found")):
        assert check_url_ssrf("https://unresolvable.example", raise_on_block=False) is False


def test_ssrf_preflight_rejects_malformed_and_scheme_mismatched_ports():
    assert validate_url("https://public.example:70000")[0] is False
    assert validate_url("https://public.example:80")[0] is False
    assert validate_url("http://public.example:443")[0] is False


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
