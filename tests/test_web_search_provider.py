from __future__ import annotations

import hashlib

import pytest

from search.exceptions import (
    InvalidRequestError,
    ParseError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    RateLimitError,
    ResponseTooLargeError,
    SSRFError,
)
from search.providers import ProviderStatus, SearchRequest, SearchScope
from search.web_provider import WebSearchProvider
from security.pinned_http import PinnedHTTPResponse, PinnedRequestError


class FakePinnedSession:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def response(body: bytes, *, status: int = 200, content_type: str = "text/html; charset=utf-8"):
    return PinnedHTTPResponse(status, {"content-type": content_type}, body)


def result_page(*results: tuple[str, str]) -> bytes:
    items = []
    for href, snippet in results:
        items.append(
            '<div class="result">'
            f'<a class="result__a" href="{href}">Example <b>result</b></a>'
            f'<a class="result__snippet">{snippet}</a>'
            '</div>'
        )
    return ("<!doctype html><html><body>" + "".join(items) + "</body></html>").encode()


def test_search_uses_pinned_transport_and_returns_bounded_untrusted_results():
    html = result_page(
        ("https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Freport", "A public report with independently checkable evidence."),
    )
    session = FakePinnedSession(response(html))
    provider = WebSearchProvider(session=session)

    assert provider.check_availability() is ProviderStatus.IMPLEMENTED
    assert session.calls == []
    result = provider.search(SearchRequest("  incident response  ", scope=SearchScope.WEB, max_results=3, timeout=5))

    assert session.calls == [(provider.ENDPOINT, {"params": {"q": "incident response", "kl": "us-en"}, "timeout": 5.0})]
    assert result.success and result.total_results == 1
    item = result.results[0]
    assert item.url == "https://example.com/report"
    assert item.content.startswith("[UNTRUSTED_WEB_RESULT]")
    assert item.provenance["trust"] == "untrusted_data"
    assert len(item.content_hash) == 64
    assert item.content_hash == hashlib.sha256((item.title + "\n" + item.content).encode()).hexdigest()
    assert result.metadata["remote_fetch_performed"] is False


def test_search_caps_results_and_discards_unsafe_or_empty_links():
    body = result_page(
        ("javascript:alert(1)", "bad scheme"),
        ("https://user:password@example.com/private", "userinfo must not be cited"),
        ("https://example.org/safe", "safe result"),
    )
    session = FakePinnedSession(response(body))
    provider = WebSearchProvider(session=session)

    result = provider.search(SearchRequest("query", scope=SearchScope.WEB, max_results=100))

    assert len(result.results) == 1
    assert result.results[0].url == "https://example.org/safe"


def test_invalid_query_and_scope_fail_before_network_request():
    session = FakePinnedSession(response(result_page(("https://example.com", "snippet"))))
    provider = WebSearchProvider(session=session)

    with pytest.raises(InvalidRequestError):
        provider.search(SearchRequest("   ", scope=SearchScope.WEB))
    with pytest.raises(InvalidRequestError):
        provider.search(SearchRequest("query", scope=SearchScope.NVD))
    with pytest.raises(InvalidRequestError):
        provider.search(SearchRequest("q" * (provider.max_query_chars + 1), scope=SearchScope.WEB))
    assert session.calls == []


def test_rate_limit_and_http_provider_failure_are_typed():
    for code, error in ((429, RateLimitError), (503, ProviderError)):
        provider = WebSearchProvider(session=FakePinnedSession(response(b"", status=code)))
        with pytest.raises(error):
            provider.search(SearchRequest("query", scope=SearchScope.WEB))

    provider = WebSearchProvider(session=FakePinnedSession(response(b"challenge", status=202)))
    with pytest.raises(ProviderUnavailableError, match="anti-automation"):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))


def test_non_html_invalid_utf8_and_oversized_responses_fail_closed():
    provider = WebSearchProvider(session=FakePinnedSession(response(b"{}", content_type="application/json")))
    with pytest.raises(ParseError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))

    provider = WebSearchProvider(session=FakePinnedSession(response(b"\xff")))
    with pytest.raises(ParseError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))

    provider = WebSearchProvider(session=FakePinnedSession(response(b"x" * 100_001)))
    with pytest.raises(ResponseTooLargeError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))


def test_pinned_transport_policy_failures_are_typed_and_never_fall_back():
    provider = WebSearchProvider(session=FakePinnedSession(error=PinnedRequestError("hostname resolved to a non-public address")))
    with pytest.raises(SSRFError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))

    provider = WebSearchProvider(session=FakePinnedSession(error=PinnedRequestError("HTTP response exceeds the configured size limit")))
    with pytest.raises(ResponseTooLargeError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))

    provider = WebSearchProvider(session=FakePinnedSession(error=TimeoutError("timed out")))
    with pytest.raises(ProviderTimeoutError):
        provider.search(SearchRequest("query", scope=SearchScope.WEB))


def test_search_service_routes_web_requests_to_the_real_provider(monkeypatch):
    from search.service import search_service
    from tools.registry import REGISTRY

    provider = search_service.get_provider("web")
    assert isinstance(provider, WebSearchProvider)
    assert REGISTRY["search"].risk_class == "network-read"
    assert REGISTRY["search"].network_access == "allowlisted_search_provider"
    assert REGISTRY["search"].effect_provider == "cybersentinel.search-aggregate"
    session = FakePinnedSession(response(result_page(("https://example.com/advisory", "untrusted advisory snippet"))))
    monkeypatch.setattr(provider, "_session", session)

    result = search_service.search("security advisory", scope=SearchScope.WEB, max_results=2, use_cache=False)

    assert result.success
    assert result.provider == "search_service"
    assert result.results[0].url == "https://example.com/advisory"
