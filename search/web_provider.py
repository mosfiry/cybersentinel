"""Explicitly unavailable general-web search provider.

CyberSentinel does not currently have a configured general-web search connector.
This provider deliberately performs no network or CLI calls and never reports an
empty result set as a successful search. GitHub repository search is exposed by
the separate GitHub provider, not under the general-web scope.
"""

from __future__ import annotations

from .exceptions import InvalidRequestError, ProviderUnavailableError
from .providers import (
    ProviderCapability,
    ProviderStatus,
    SearchProvider,
    SearchRequest,
    SearchResponse,
    SearchScope,
)


WEB_SEARCH_UNAVAILABLE = "General web search is not configured; no web request was made."


class WebSearchProvider(SearchProvider):
    """Compatibility provider that always fails closed until a real connector exists."""

    name = "web"
    scope = SearchScope.WEB
    capabilities = frozenset({ProviderCapability.SEARCH, ProviderCapability.READ_ONLY})
    status = ProviderStatus.NOT_CONFIGURED

    def check_availability(self) -> ProviderStatus:
        """Return the truthful, fixed availability state without probing the network."""
        return ProviderStatus.NOT_CONFIGURED

    def search(self, request: SearchRequest) -> SearchResponse:
        """Reject every request; never synthesize an empty successful result."""
        if request.scope is not None and request.scope is not SearchScope.WEB:
            raise InvalidRequestError(
                f"Web provider only supports WEB scope, got {request.scope}",
                provider=self.name,
            )
        raise ProviderUnavailableError(WEB_SEARCH_UNAVAILABLE, provider=self.name)


class WebSearchProviderUnavailable(WebSearchProvider):
    """Backward-compatible explicit name for the unavailable web provider."""
