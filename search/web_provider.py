"""
Web Search Provider

Web search provider for general web searches.
All results are UNTRUSTED_DATA.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from .providers import (
    SearchProvider,
    SearchRequest,
    SearchResponse,
    SearchResult,
    SearchScope,
    ProviderStatus,
    ProviderCapability,
)
from .exceptions import (
    ProviderUnavailableError,
    ProviderTimeoutError,
    RateLimitError,
    InvalidRequestError,
    ParseError,
    NetworkError,
    ResponseTooLargeError,
    SSRFError,
)
from .ssrf import check_url_ssrf, validate_url, is_safe_url


class WebSearchProvider(SearchProvider):
    """Web search provider with read-only capabilities.
    
    This provider performs web searches using available connectors.
    All results are UNTRUSTED_DATA.
    All operations are READ-ONLY in Phase 4.
    
    Note: This provider requires a real web search connector to be available.
    If no connector is available, it will be marked as UNAVAILABLE.
    """
    
    name = "web"
    scope = SearchScope.WEB
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.READ_ONLY,
    })
    
    # Configuration
    # Try to use gh CLI if available, otherwise fall back to HTTP
    USE_GH_CLI = True
    
    # Limits
    max_results = 10
    max_response_bytes = 100000  # 100KB
    max_result_chars = 10000
    timeout = 30.0
    
    def __init__(self):
        """Initialize provider."""
        self._session = None
        self._status = self._check_availability()
    
    def _get_session(self) -> Any:
        """Get or create HTTP session with proper headers."""
        if self._session is None:
            try:
                import httpx
                headers = {
                    "Accept": "application/json",
                    "User-Agent": "CyberSentinel-X/1.0",
                }
                self._session = httpx.Client(
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            except ImportError:
                try:
                    import requests
                    from requests.adapters import HTTPAdapter
                    from urllib3.util.retry import Retry
                    
                    headers = {
                        "Accept": "application/json",
                        "User-Agent": "CyberSentinel-X/1.0",
                    }
                    
                    retry = Retry(
                        total=3,
                        backoff_factor=0.5,
                        status_forcelist=[429, 500, 502, 503, 504],
                    )
                    adapter = HTTPAdapter(max_retries=retry)
                    self._session = requests.Session()
                    self._session.mount("https://", adapter)
                    self._session.mount("http://", adapter)
                    self._session.headers.update(headers)
                except ImportError:
                    raise ProviderUnavailableError(
                        "No HTTP library available (neither httpx nor requests)",
                        provider=self.name,
                    )
        return self._session
    
    def _check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        # Check if gh CLI is available
        if self.USE_GH_CLI:
            try:
                import subprocess
                result = subprocess.run(
                    ["gh", "--version"],
                    capture_output=True,
                    timeout=5.0,
                )
                if result.returncode == 0:
                    return ProviderStatus.AVAILABLE
            except Exception:
                pass
        
        # Local, dependency-free capability check: constructing the HTTP
        # session proves an HTTP client library is usable. No third-party
        # endpoint is contacted during availability probing (SSRF posture:
        # no outbound request is needed to answer "is a client library present").
        try:
            session = self._get_session()
        except Exception:
            return ProviderStatus.UNAVAILABLE
        if session is not None and hasattr(session, "get"):
            return ProviderStatus.AVAILABLE
        return ProviderStatus.UNAVAILABLE
    
    def check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        self._status = self._check_availability()
        return self._status
    
    def _search_with_gh_cli(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search using gh CLI."""
        results = []
        
        try:
            import subprocess
            import json
            
            # Use gh search command
            # Note: gh search requires authentication
            cmd = [
                "gh",
                "search",
                "repos",
                query,
                "--limit",
                str(min(max_results, 100)),
                "--json",
                "name,description,htmlUrl,stargazerCount,updatedAt",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True,
            )
            
            if result.returncode != 0:
                # Try without authentication
                cmd = [
                    "gh",
                    "search",
                    "repos",
                    query,
                    "--limit",
                    str(min(max_results, 100)),
                    "--json",
                    "name,description,htmlUrl",
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.timeout,
                    text=True,
                )
            
            if result.returncode == 0:
                repos = json.loads(result.stdout)
                for repo in repos[:max_results]:
                    result_item = self._normalize_gh_result(repo, "repository")
                    if result_item:
                        results.append(result_item)
        except Exception:
            pass
        
        return results
    
    def _search_with_http(
        self,
        query: str,
        max_results: int,
    ) -> list[SearchResult]:
        """Search using HTTP requests.
        
        This is a fallback method that uses a mock/search simulation.
        For real web search, a proper API key would be needed.
        """
        results = []
        
        # For Phase 4, we mark web search as unavailable
        # since we don't have a real web search API configured
        # This is intentional - we don't want to create fake implementations
        
        return results
    
    def _normalize_gh_result(
        self,
        data: dict[str, Any],
        source_type: str,
    ) -> SearchResult | None:
        """Normalize a GitHub CLI result into SearchResult."""
        try:
            name = data.get("name", "")
            description = data.get("description", "") or ""
            html_url = data.get("htmlUrl", "") or data.get("html_url", "")
            
            content = f"{name}\n{description}"
            content = self.truncate_result(content)
            content = self.sanitize_content(content)
            
            # Calculate hash
            content_bytes = content.encode('utf-8')
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            
            return SearchResult(
                result_id=f"web:{source_type}:{html_url}",
                title=name or "Untitled",
                content=content,
                source="web",
                source_type=source_type,
                url=html_url,
                provenance={
                    "source": "web",
                    "type": source_type,
                    "provider": self.name,
                    "via": "gh_cli",
                },
                metadata={
                    "url": html_url,
                    "content_hash": content_hash,
                },
            )
        except Exception:
            return None
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute a web search request.
        
        This provider is intentionally limited in Phase 4.
        Real web search requires proper API configuration.
        """
        # Validate scope
        if request.scope and request.scope != SearchScope.WEB:
            raise InvalidRequestError(
                f"Web provider only supports WEB scope, got {request.scope}",
                provider=self.name,
            )
        
        # Check availability
        self.check_availability()
        
        # For Phase 4, web search is marked as unavailable
        # This is intentional per the requirements
        if self._status != ProviderStatus.CONFIGURED:
            raise ProviderUnavailableError(
                "Web search provider requires API configuration. "
                "Not available in Phase 4 without explicit connector.",
                provider=self.name,
            )
        
        query = request.query.strip()
        
        # Try gh CLI first
        if self.USE_GH_CLI:
            results = self._search_with_gh_cli(query, request.max_results)
        else:
            results = self._search_with_http(query, request.max_results)
        
        return SearchResponse(
            request=request,
            results=results[:request.max_results],
            total_results=len(results),
            provider=self.name,
            metadata={
                "query": query,
                "status": self._status.value,
            },
        )


class WebSearchProviderUnavailable(WebSearchProvider):
    """Web search provider that is explicitly unavailable.
    
    This is the actual implementation for Phase 4, as we don't have
    a real web search connector configured.
    """
    
    name = "web"
    scope = SearchScope.WEB
    capabilities = frozenset({
        ProviderCapability.SEARCH,
        ProviderCapability.READ_ONLY,
    })
    
    status = ProviderStatus.NOT_CONFIGURED
    
    def __init__(self):
        """Initialize provider as unavailable."""
        pass
    
    def check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        return self.status
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute a web search request - always unavailable in Phase 4."""
        raise ProviderUnavailableError(
            "Web search provider is not configured in Phase 4. "
            "Real web search requires explicit API connector configuration.",
            provider=self.name,
        )


# Provider error for compatibility
class ProviderError(Exception):
    """Generic provider error."""
    def __init__(self, message: str, provider: str | None = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
