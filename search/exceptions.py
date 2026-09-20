"""
Search Exception Hierarchy

Custom exceptions for search providers with clear categorization.
"""

from __future__ import annotations


class SearchError(Exception):
    """Base exception for all search-related errors."""
    
    def __init__(self, message: str, provider: str | None = None, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.details = details or {}
    
    def to_dict(self) -> dict:
        return {
            "error": self.message,
            "provider": self.provider,
            **self.details,
        }


class ProviderUnavailableError(SearchError):
    """Provider is not configured or unavailable."""
    pass


class ProviderTimeoutError(SearchError):
    """Provider request timed out."""
    pass


class RateLimitError(SearchError):
    """Rate limit exceeded for provider."""
    pass


class AuthenticationError(SearchError):
    """Authentication failed for provider."""
    pass


class InvalidRequestError(SearchError):
    """Request is invalid (malformed query, invalid scope, etc.)."""
    pass


class SSRFError(SearchError):
    """SSRF protection blocked the request."""
    pass


class ResponseTooLargeError(SearchError):
    """Response exceeds maximum allowed size."""
    pass


class ParseError(SearchError):
    """Failed to parse provider response."""
    pass


class NetworkError(SearchError):
    """Network-level error (DNS, connection, etc.)."""
    pass


class ProviderError(SearchError):
    """Generic provider error (5xx, etc.)."""
    pass


# Error type classification for Agent
class SearchErrorType:
    """Error type classification."""
    SUCCESS_EMPTY = "success_empty"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMEOUT = "timeout"
    AUTHENTICATION_FAILURE = "authentication_failure"
    RATE_LIMITED = "rate_limited"
    INVALID_REQUEST = "invalid_request"
    NETWORK_POLICY_DENIED = "network_policy_denied"
    PARSE_FAILURE = "parse_failure"
    RESPONSE_TOO_LARGE = "response_too_large"
    PROVIDER_ERROR = "provider_error"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_exception(cls, exc: SearchError) -> str:
        """Classify error type from exception."""
        mapping = {
            ProviderUnavailableError: cls.PROVIDER_UNAVAILABLE,
            ProviderTimeoutError: cls.TIMEOUT,
            RateLimitError: cls.RATE_LIMITED,
            AuthenticationError: cls.AUTHENTICATION_FAILURE,
            InvalidRequestError: cls.INVALID_REQUEST,
            SSRFError: cls.NETWORK_POLICY_DENIED,
            ResponseTooLargeError: cls.RESPONSE_TOO_LARGE,
            ParseError: cls.PARSE_FAILURE,
            NetworkError: cls.NETWORK_POLICY_DENIED,
            ProviderError: cls.PROVIDER_ERROR,
        }
        for exc_type, error_type in mapping.items():
            if isinstance(exc, exc_type):
                return error_type
        return cls.UNKNOWN
