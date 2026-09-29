from __future__ import annotations

import pytest

from search.exceptions import InvalidRequestError, ProviderUnavailableError
from search.providers import ProviderStatus, SearchRequest, SearchScope
from search.service import SearchService
from search.web_provider import (
    WEB_SEARCH_UNAVAILABLE,
    WebSearchProvider,
    WebSearchProviderUnavailable,
)


@pytest.mark.parametrize("provider_type", [WebSearchProvider, WebSearchProviderUnavailable])
def test_public_web_provider_fails_closed_without_http_or_gh_cli(provider_type):
    provider = provider_type()
    request = SearchRequest("cybersentinel web availability check", scope=SearchScope.WEB)

    assert provider.check_availability() is ProviderStatus.NOT_CONFIGURED
    assert provider.get_status()["status"] == ProviderStatus.NOT_CONFIGURED.value
    with pytest.raises(ProviderUnavailableError, match="General web search is not configured") as exc:
        provider.search(request)
    assert exc.value.message == WEB_SEARCH_UNAVAILABLE


def test_web_provider_rejects_a_non_web_scope():
    provider = WebSearchProvider()
    request = SearchRequest("not a web search", scope=SearchScope.GITHUB)

    with pytest.raises(InvalidRequestError, match="only supports WEB scope"):
        provider.search(request)


def test_search_service_does_not_report_unavailable_web_as_empty_success():
    service = SearchService()
    response = service.search(
        "cybersentinel unavailable web provider regression",
        scope=SearchScope.WEB,
        use_cache=False,
    )

    assert response.success is False
    assert response.empty is False
    assert response.results == []
    assert response.total_results == 0
    assert response.error_type == "provider_errors"
    assert "unavailable" in (response.error or "").lower()
