"""Best-effort redaction for recognizable credential forms at persistence boundaries.

This is deliberately not a secret vault and cannot identify arbitrary opaque values.
Callers must not treat pattern matching as a guarantee that every secret is found.
"""

from __future__ import annotations

import re
from typing import Any


_REDACTED = "[REDACTED]"
_SECRET_TEXT_PATTERNS = (
    # Credential-bearing URL userinfo; retain the scheme and host for diagnostics.
    (re.compile(r"(?i)\b((?:https?|ftp)://)[^/@\s]+(?::[^/@\s]*)?@"), r"\1[REDACTED]@"),
    # Header values are credential material regardless of whether they use Bearer or Basic.
    (re.compile(r"(?i)(\bauthorization\b\s*[:=]\s*(?:bearer|basic)\s+)[^\s,;\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), lambda match: match.group(0).split()[0] + " [REDACTED]"),
    # Cookie headers are treated as a unit so every cookie value/attribute is removed.
    (re.compile(r"(?im)(\b(?:set-cookie|cookie)\s*:\s*)[^\r\n]*"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([\"'](?:set-cookie|cookie)[\"']\s*:\s*[\"'])[^\"']*([\"'])"), r"\1[REDACTED]\2"),
    # Keep unrelated URL query parameters while removing known credential parameters.
    (re.compile(r"(?i)([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|password|secret|authorization)=)[^&#\s\"']+"), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Common key/value forms in prose, headers, and serialized JSON-like text.
    (re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|password|secret|authorization|credentials?)\b[\"']?\s*[:=]\s*[\"']?)[^\s,;&\"']+"), r"\1[REDACTED]"),
)

_SENSITIVE_KEY_MARKERS = (
    "apikey", "password", "secret", "credential", "sessionid", "ownersession",
    "accesstoken", "refreshtoken", "privatekey",
)
_SAFE_TOKEN_COUNT_KEYS = frozenset(
    {
        "inputtokensestimated", "inputtokens", "inputtokensreported",
        "outputtokens", "outputtokensreported", "prompttokens", "completiontokens",
        "maxtotaltokens",
    }
)
_SENSITIVE_EXACT_KEYS = frozenset(
    {
        "auth", "authcontext", "ownerauth", "ownerauthorization", "authorization",
        "authorizationcontext", "authorizationheader", "authorizationtoken", "authorizationvalue",
        "httpauthorization", "session", "sessiontoken", "sessioncookie", "ownertoken",
        "ownersessiontoken", "token", "bearer", "basic", "cookie", "setcookie", "idtoken",
        "oauthtoken", "privatekey",
    }
)
_OPAQUE_REFERENCE_KEYS = frozenset(
    {"secretref", "secretreference", "credentialref", "vaultref"}
)
# This is structural authorization policy, not a credential value. Its children are
# still recursively redacted, but the boundary itself must survive snapshot hashing.
_SAFE_STRUCTURAL_KEYS = frozenset({"credentialboundary"})
_SAFE_DERIVATIVE_SUFFIXES = ("hash", "fingerprint")


def sanitize_sensitive_text(value: str) -> str:
    """Redact common recognizable credential forms in text, preserving other evidence.

    This cannot recognize an arbitrary secret that has no credential label or known
    token structure. No registered-value source or vault is available in this slice.
    """
    result = str(value)
    for pattern, replacement in _SECRET_TEXT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_sensitive_data(value: Any) -> Any:
    """Recursively redact credential-named fields and recognizable text values.

    Stable opaque reference keys (for example ``secret_ref``) are preserved, while
    recognizable credential material inside their values is still redacted.
    """
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            compact = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            safe_derivative = compact.endswith(_SAFE_DERIVATIVE_SUFFIXES)
            if compact in _SAFE_TOKEN_COUNT_KEYS and (
                item is None or (type(item) is int and item >= 0)
            ):
                result[str(key)] = item
            elif compact in _OPAQUE_REFERENCE_KEYS or compact in _SAFE_STRUCTURAL_KEYS:
                result[str(key)] = sanitize_sensitive_data(item)
            elif compact in _SENSITIVE_EXACT_KEYS or (
                not safe_derivative and any(marker in compact for marker in _SENSITIVE_KEY_MARKERS)
            ):
                result[str(key)] = _REDACTED
            else:
                result[str(key)] = sanitize_sensitive_data(item)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, str):
        return sanitize_sensitive_text(value)
    return value


__all__ = ["sanitize_sensitive_data", "sanitize_sensitive_text"]
