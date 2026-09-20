"""
Search Provider Abstraction

Unified interface for all search providers.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ProviderStatus(Enum):
    """Current status of a search provider."""
    IMPLEMENTED = "implemented"
    AVAILABLE = "available"
    CONFIGURED = "configured"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"


class ProviderCapability(Enum):
    """Capabilities supported by a provider."""
    SEARCH = "search"
    SEARCH_MANY = "search_many"
    GET_BY_ID = "get_by_id"
    LIST = "list"
    READ_ONLY = "read_only"


class SearchScope(Enum):
    """Valid search scopes."""
    LOCAL = "local"
    WEB = "web"
    GITHUB = "github"
    CVE = "cve"
    NVD = "nvd"
    MITRE = "mitre"
    THREAT_INTEL = "threat_intel"
    
    @classmethod
    def from_string(cls, scope: str) -> SearchScope | None:
        """Parse scope from string."""
        try:
            return cls[scope.upper()]
        except KeyError:
            return None


@dataclass(frozen=True)
class SearchRequest:
    """Request for search operation."""
    query: str
    scope: SearchScope | None = None
    provider: str | None = None
    max_results: int = 10
    timeout: float = 30.0
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Validate scope
        if self.scope is not None and not isinstance(self.scope, SearchScope):
            raise ValueError(f"Invalid scope: {self.scope}")
        
        # Validate query
        if not self.query or not isinstance(self.query, str):
            raise ValueError("Query must be a non-empty string")
        
        # Validate max_results
        if self.max_results <= 0 or self.max_results > 100:
            raise ValueError("max_results must be between 1 and 100")
        
        # Validate timeout
        if self.timeout <= 0 or self.timeout > 120:
            raise ValueError("timeout must be between 0 and 120 seconds")


@dataclass
class SearchResult:
    """Single search result with full provenance.
    
    All external data is UNTRUSTED_DATA regardless of source.
    This object carries provenance, not authorization.
    """
    result_id: str
    title: str
    content: str
    source: str
    source_type: str
    url: str | None = None
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    content_hash: str = field(default="")
    provenance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        # Ensure content_hash is set
        if not self.content_hash:
            content_bytes = f"{self.title}{self.content}".encode('utf-8')
            self.content_hash = hashlib.sha256(content_bytes).hexdigest()
        # Ensure provenance has at least source and type
        if not self.provenance:
            self.provenance = {"source": self.source, "type": self.source_type}
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "result_id": self.result_id,
            "title": self.title,
            "content": self.content,
            "source": self.source,
            "source_type": self.source_type,
            "url": self.url,
            "retrieved_at": self.retrieved_at,
            "content_hash": self.content_hash,
            "provenance": self.provenance,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SearchResult:
        """Create from dictionary."""
        return cls(**data)


@dataclass(frozen=True)
class SearchResponse:
    """Response from a search operation."""
    request: SearchRequest
    results: list[SearchResult] = field(default_factory=list)
    total_results: int = 0
    provider: str = ""
    retrieved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str | None = None
    error_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def success(self) -> bool:
        """Check if search was successful."""
        return self.error is None
    
    @property
    def empty(self) -> bool:
        """Check if search returned no results (but was successful)."""
        return self.success and self.total_results == 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request": {
                "query": self.request.query,
                "scope": self.request.scope.value if self.request.scope else None,
                "provider": self.request.provider,
                "max_results": self.request.max_results,
            },
            "results": [r.to_dict() for r in self.results],
            "total_results": self.total_results,
            "provider": self.provider,
            "retrieved_at": self.retrieved_at,
            "error": self.error,
            "error_type": self.error_type,
            "metadata": self.metadata,
        }


class SearchProvider(ABC):
    """Abstract base class for all search providers.
    
    All external data returned is UNTRUSTED_DATA.
    Providers must not expose credentials in results.
    """
    
    # Provider metadata
    name: str = ""
    scope: SearchScope | None = None
    capabilities: set[ProviderCapability] = set()
    status: ProviderStatus = ProviderStatus.NOT_CONFIGURED
    
    # Limits
    max_results: int = 10
    max_response_bytes: int = 100000  # 100KB
    max_result_chars: int = 10000
    timeout: float = 30.0
    
    @abstractmethod
    def search(self, request: SearchRequest) -> SearchResponse:
        """Execute a search request."""
        pass
    
    @abstractmethod
    def check_availability(self) -> ProviderStatus:
        """Check if provider is available."""
        pass
    
    def get_status(self) -> dict[str, Any]:
        """Get current provider status."""
        return {
            "name": self.name,
            "scope": self.scope.value if self.scope else None,
            "status": self.status.value,
            "capabilities": [c.value for c in self.capabilities],
            "max_results": self.max_results,
            "max_response_bytes": self.max_response_bytes,
            "max_result_chars": self.max_result_chars,
            "timeout": self.timeout,
        }
    
    def validate_response_size(self, content: str | bytes) -> bool:
        """Validate response size against limits."""
        size = len(content) if isinstance(content, bytes) else len(content.encode('utf-8'))
        return size <= self.max_response_bytes
    
    def truncate_result(self, content: str, max_chars: int | None = None) -> str:
        """Truncate result content to max length."""
        max_chars = max_chars or self.max_result_chars
        if len(content) <= max_chars:
            return content
        return content[:max_chars] + "...[TRUNCATED]"
    
    def sanitize_content(self, content: str) -> str:
        """Sanitize content to remove sensitive data."""
        # Remove potential credentials or secrets
        import re
        sensitive_patterns = [
            r'[A-Za-z0-9_-]{32,}',  # API keys, tokens
            r'ghp_[A-Za-z0-9]{36}',  # GitHub tokens
            r'github_pat_[A-Za-z0-9]{22}',  # GitHub PAT
            r'[A-Za-z0-9+/=]{40,}',  # Base64 encoded secrets
        ]
        for pattern in sensitive_patterns:
            content = re.sub(pattern, '[REDACTED]', content)
        return content
