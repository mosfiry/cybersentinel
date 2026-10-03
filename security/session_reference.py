from __future__ import annotations

import hashlib
import re
from typing import Any


_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_REFERENCE_KEYS = frozenset({"session_id", "owner_session_id", "session_token", "owner_session_token"})


def is_session_reference(value: Any) -> bool:
    return isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None


def session_reference(token_or_reference: Any) -> str:
    """Return the stable, non-bearer reference for a high-entropy session token.

    Existing 64-character SHA-256 references are preserved, making this helper
    idempotent at API and persistence boundaries.
    """
    if not isinstance(token_or_reference, str) or not token_or_reference:
        return ""
    if is_session_reference(token_or_reference):
        return token_or_reference
    return hashlib.sha256(token_or_reference.encode("utf-8")).hexdigest()


def normalize_persisted_session_fields(value: Any) -> Any:
    """Recursively migrate session identifiers in structured legacy records."""
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if key in _SESSION_REFERENCE_KEYS and isinstance(item, str) and item:
                normalized[key] = session_reference(item)
            else:
                normalized[key] = normalize_persisted_session_fields(item)
        return normalized
    if isinstance(value, list):
        return [normalize_persisted_session_fields(item) for item in value]
    if isinstance(value, tuple):
        return tuple(normalize_persisted_session_fields(item) for item in value)
    return value
