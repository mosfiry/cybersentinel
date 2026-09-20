"""
Search Service

Central service for routing search requests to appropriate providers.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
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
    SearchError,
    ProviderUnavailableError,
    InvalidRequestError,
    RateLimitError,
    ProviderTimeoutError,
    NetworkError,
    SSRFError,
)
from .local_knowledge import LocalKnowledgeProvider
from .github_provider import GitHubProvider
from .nvd_provider import NVDProvider
from .mitre_provider import MITREProvider
from .web_provider import WebSearchProviderUnavailable

logger = logging.getLogger(__name__)


@dataclass
class SearchConfig:
    """Configuration for SearchService."""
    max_requests_per_task: int = 10
    max_requests_per_minute: int = 30
    cache_enabled: bool = True
    cache_ttl: int = 300  # 5 minutes
    default_timeout: float = 30.0
    max_total_results: int = 100


@dataclass
class SearchCacheEntry:
    """Cache entry for search results."""
    query: str
    scope: SearchScope | None
    results: list[SearchResult]
    timestamp: float
    ttl: int
    content_hash: str
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        return time.time() - self.timestamp > self.ttl


class SearchCache:
    """Simple in-memory cache for search results."""
    
    def __init__(self, ttl: int = 300):
        self._cache: dict[str, SearchCacheEntry] = {}
        self._ttl = ttl
    
    def _make_key(self, query: str, scope: SearchScope | None) -> str:
        """Generate cache key."""
        scope_str = scope.value if scope else "none"
        return f"{scope_str}:{query}"
    
    def get(self, query: str, scope: SearchScope | None) -> SearchCacheEntry | None:
        """Get cached results."""
        key = self._make_key(query, scope)
        entry = self._cache.get(key)
        if entry and not entry.is_expired():
            return entry
        return None
    
    def set(
        self,
        query: str,
        scope: SearchScope | None,
        results: list[SearchResult],
    ) -> None:
        """Store results in cache."""
        key = self._make_key(query, scope)
        content = "".join([r.content for r in results])
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        self._cache[key] = SearchCacheEntry(
            query=query,
            scope=scope,
            results=results,
            timestamp=time.time(),
            ttl=self._ttl,
            content_hash=content_hash,
        )
    
    def invalidate(self, query: str, scope: SearchScope | None) -> bool:
        """Invalidate cache entry."""
        key = self._make_key(query, scope)
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()


class SearchService:
    """Central search service that routes requests to providers.
    
    This service:
    - Routes search requests to appropriate providers
    - Handles provider selection and failover
    - Manages rate limiting
    - Handles caching
    - Tracks provenance
    
    All external data returned is UNTRUSTED_DATA.
    """
    
    def __init__(self, config: SearchConfig | None = None):
        """Initialize search service."""
        self.config = config or SearchConfig()
        self._providers: dict[str, SearchProvider] = {}
        self._cache = SearchCache(ttl=self.config.cache_ttl)
        self._request_count = 0
        self._last_minute_requests: list[float] = []
        self._init_providers()
    
    def _init_providers(self) -> None:
        """Initialize all available providers."""
        # Local knowledge provider (always available)
        self._providers["local"] = LocalKnowledgeProvider()
        
        # GitHub provider
        try:
            self._providers["github"] = GitHubProvider()
        except Exception as e:
            logger.warning(f"Failed to initialize GitHub provider: {e}")
            # Use a placeholder
            self._providers["github"] = _UnavailableProvider("github")
        
        # NVD provider
        try:
            self._providers["nvd"] = NVDProvider()
        except Exception as e:
            logger.warning(f"Failed to initialize NVD provider: {e}")
            self._providers["nvd"] = _UnavailableProvider("nvd")
        
        # MITRE provider
        try:
            self._providers["mitre"] = MITREProvider()
        except Exception as e:
            logger.warning(f"Failed to initialize MITRE provider: {e}")
            self._providers["mitre"] = _UnavailableProvider("mitre")
        
        # Web provider (unavailable in Phase 4)
        self._providers["web"] = WebSearchProviderUnavailable()
    
    def get_provider(self, name: str) -> SearchProvider | None:
        """Get a provider by name."""
        return self._providers.get(name)
    
    def get_all_providers(self) -> dict[str, SearchProvider]:
        """Get all registered providers."""
        return self._providers.copy()
    
    def _check_rate_limit(self) -> bool:
        """Check if rate limit is exceeded."""
        now = time.time()
        
        # Remove old requests
        self._last_minute_requests = [
            t for t in self._last_minute_requests
            if now - t < 60
        ]
        
        if len(self._last_minute_requests) >= self.config.max_requests_per_minute:
            return False
        
        return True
    
    def _record_request(self) -> None:
        """Record a request for rate limiting."""
        self._request_count += 1
        self._last_minute_requests.append(time.time())
    
    def _select_providers(
        self,
        scope: SearchScope | None,
    ) -> list[SearchProvider]:
        """Select appropriate providers for a search scope."""
        providers = []
        
        if scope is None or scope == SearchScope.LOCAL:
            # Default to local knowledge
            if "local" in self._providers:
                providers.append(self._providers["local"])
        
        if scope == SearchScope.GITHUB:
            if "github" in self._providers:
                providers.append(self._providers["github"])
        
        if scope in (SearchScope.NVD, SearchScope.CVE):
            if "nvd" in self._providers:
                providers.append(self._providers["nvd"])
        
        if scope == SearchScope.MITRE:
            if "mitre" in self._providers:
                providers.append(self._providers["mitre"])
        
        if scope == SearchScope.WEB:
            if "web" in self._providers:
                providers.append(self._providers["web"])
        
        # If no specific scope, try all available providers
        if not providers:
            for name, provider in self._providers.items():
                if provider.check_availability() in (
                    ProviderStatus.AVAILABLE,
                    ProviderStatus.CONFIGURED,
                ):
                    providers.append(provider)
        
        return providers
    
    def search(
        self,
        query: str,
        scope: SearchScope | None = None,
        max_results: int = 10,
        timeout: float | None = None,
        use_cache: bool = True,
    ) -> SearchResponse:
        """Execute a search request.
        
        Args:
            query: Search query string
            scope: Search scope (LOCAL, GITHUB, NVD, MITRE, WEB)
            max_results: Maximum number of results to return
            timeout: Request timeout in seconds
            use_cache: Whether to use cached results
            
        Returns:
            SearchResponse with results from appropriate providers
        """
        # Validate query
        if not query or not isinstance(query, str):
            raise InvalidRequestError("Query must be a non-empty string")
        
        # Check rate limit
        if not self._check_rate_limit():
            raise RateLimitError(
                f"Rate limit exceeded: {self.config.max_requests_per_minute} requests per minute",
                provider="search_service",
            )
        
        # Create request
        request = SearchRequest(
            query=query,
            scope=scope,
            max_results=min(max_results, self.config.max_total_results),
            timeout=timeout or self.config.default_timeout,
        )
        
        # Check cache
        if use_cache:
            cache_entry = self._cache.get(query, scope)
            if cache_entry:
                logger.debug(f"Cache hit for query: {query}")
                self._record_request()
                return SearchResponse(
                    request=request,
                    results=cache_entry.results[:request.max_results],
                    total_results=len(cache_entry.results),
                    provider="search_service",
                    metadata={
                        "cached": True,
                        "cache_hit": True,
                        "content_hash": cache_entry.content_hash,
                    },
                )
        
        # Select providers
        providers = self._select_providers(scope)
        
        if not providers:
            raise ProviderUnavailableError(
                f"No providers available for scope {scope}",
                provider="search_service",
            )
        
        # Execute search across providers
        all_results: list[SearchResult] = []
        errors: list[str] = []
        
        for provider in providers:
            try:
                self._record_request()
                response = provider.search(request)
                
                if response.success:
                    all_results.extend(response.results)
                elif response.error:
                    errors.append(f"{provider.name}: {response.error}")
            except ProviderUnavailableError as e:
                errors.append(f"{provider.name}: unavailable - {e.message}")
            except RateLimitError as e:
                errors.append(f"{provider.name}: rate limited - {e.message}")
            except ProviderTimeoutError as e:
                errors.append(f"{provider.name}: timeout - {e.message}")
            except NetworkError as e:
                errors.append(f"{provider.name}: network error - {e.message}")
            except SSRFError as e:
                errors.append(f"{provider.name}: SSRF blocked - {e.message}")
            except Exception as e:
                errors.append(f"{provider.name}: error - {str(e)}")
        
        # Sort results by relevance (provider order for now)
        # In a real implementation, we'd have a proper ranking algorithm
        
        # Cache results
        if use_cache and all_results:
            self._cache.set(query, scope, all_results)
        
        # Return response
        error_message = "; ".join(errors) if errors else None
        
        return SearchResponse(
            request=request,
            results=all_results[:request.max_results],
            total_results=len(all_results),
            provider="search_service",
            error=error_message,
            error_type="provider_errors" if errors else None,
            metadata={
                "providers_tried": [p.name for p in providers],
                "cached": False,
                "errors": errors,
            },
        )
    
    def search_local(
        self,
        query: str,
        max_results: int = 10,
    ) -> SearchResponse:
        """Search local knowledge only."""
        return self.search(
            query=query,
            scope=SearchScope.LOCAL,
            max_results=max_results,
        )
    
    def search_github(
        self,
        query: str,
        max_results: int = 10,
    ) -> SearchResponse:
        """Search GitHub only."""
        return self.search(
            query=query,
            scope=SearchScope.GITHUB,
            max_results=max_results,
        )
    
    def search_nvd(
        self,
        query: str,
        max_results: int = 10,
    ) -> SearchResponse:
        """Search NVD/CVE only."""
        return self.search(
            query=query,
            scope=SearchScope.NVD,
            max_results=max_results,
        )
    
    def search_mitre(
        self,
        query: str,
        max_results: int = 10,
    ) -> SearchResponse:
        """Search MITRE ATT&CK only."""
        return self.search(
            query=query,
            scope=SearchScope.MITRE,
            max_results=max_results,
        )
    
    def get_status(self) -> dict[str, Any]:
        """Get status of all providers."""
        status = {}
        for name, provider in self._providers.items():
            try:
                provider_status = provider.check_availability()
                status[name] = {
                    "status": provider_status.value,
                    "capabilities": [c.value for c in provider.capabilities],
                    "scope": provider.scope.value if provider.scope else None,
                }
            except Exception as e:
                status[name] = {
                    "status": "error",
                    "error": str(e),
                }
        
        return {
            "service": "search",
            "providers": status,
            "requests_this_minute": len(self._last_minute_requests),
            "total_requests": self._request_count,
            "cache_enabled": self.config.cache_enabled,
            "cache_size": len(self._cache._cache),
        }
    
    def clear_cache(self) -> None:
        """Clear search cache."""
        self._cache.clear()
        logger.info("Search cache cleared")


class _UnavailableProvider(SearchProvider):
    """Placeholder for unavailable providers."""
    
    name: str = "unavailable"
    scope: SearchScope | None = None
    capabilities: set[ProviderCapability] = set()
    status: ProviderStatus = ProviderStatus.UNAVAILABLE
    
    def __init__(self, name: str):
        self.name = name
    
    def check_availability(self) -> ProviderStatus:
        return self.status
    
    def search(self, request: SearchRequest) -> SearchResponse:
        raise ProviderUnavailableError(
            f"Provider {self.name} is unavailable",
            provider=self.name,
        )


# Global search service instance
search_service = SearchService()


def get_search_service() -> SearchService:
    """Get the global search service instance."""
    return search_service
