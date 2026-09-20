"""
CyberSentinel X - Phase 4: Search & External Integrations

Search abstraction layer providing unified interface for:
- Local Knowledge
- GitHub (read-only)
- NVD/CVE
- MITRE ATT&CK
- Threat Intelligence

Architecture:
    Tool
        ↓
    SearchService
        ↓
    SearchProvider (Local/GitHub/NVD/MITRE/Web/TI)
        ↓
    External API

All external data is UNTRUSTED_DATA regardless of source.
"""

from .providers import (
    SearchProvider,
    SearchRequest,
    SearchResponse,
    SearchResult,
    SearchScope,
    ProviderStatus,
    ProviderCapability,
)
from .local_knowledge import LocalKnowledgeProvider
from .github_provider import GitHubProvider
from .nvd_provider import NVDProvider
from .mitre_provider import MITREProvider
from .web_provider import WebSearchProvider, WebSearchProviderUnavailable
from .service import SearchService, SearchConfig, SearchCache
from .ssrf import SSRFProtection, validate_url, is_safe_url, check_url_ssrf
from .exceptions import (
    SearchError,
    ProviderUnavailableError,
    ProviderTimeoutError,
    RateLimitError,
    AuthenticationError,
    InvalidRequestError,
    SSRFError,
    ResponseTooLargeError,
    ParseError,
    NetworkError,
    ProviderError,
    SearchErrorType,
)
from .evidence import (
    Evidence,
    EvidenceBuilder,
    EvidenceStore,
    EvidenceGenerator,
    generate_evidence,
)

__all__ = [
    # Core abstractions
    "SearchProvider",
    "SearchRequest",
    "SearchResponse",
    "SearchResult",
    "SearchScope",
    "ProviderStatus",
    "ProviderCapability",
    # Providers
    "LocalKnowledgeProvider",
    "GitHubProvider",
    "NVDProvider",
    "MITREProvider",
    "WebSearchProvider",
    "WebSearchProviderUnavailable",
    # Service
    "SearchService",
    "SearchConfig",
    "SearchCache",
    # SSRF Protection
    "SSRFProtection",
    "validate_url",
    "is_safe_url",
    "check_url_ssrf",
    # Exceptions
    "SearchError",
    "ProviderUnavailableError",
    "ProviderTimeoutError",
    "RateLimitError",
    "AuthenticationError",
    "InvalidRequestError",
    "SSRFError",
    "ResponseTooLargeError",
    "ParseError",
    "NetworkError",
    "ProviderError",
    "SearchErrorType",
    # Evidence
    "Evidence",
    "EvidenceBuilder",
    "EvidenceStore",
    "EvidenceGenerator",
    "generate_evidence",
]
