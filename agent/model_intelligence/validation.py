from __future__ import annotations

from typing import Any

FORBIDDEN_AUTHORITY_KEYS = frozenset({"owner", "owner_instruction", "owner_policy", "authorization", "scope", "identity", "objective", "policy"})


def validate_untrusted_model_payload(payload: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    errors = []
    for key in payload:
        if str(key).casefold() in FORBIDDEN_AUTHORITY_KEYS:
            errors.append(f"model_output_cannot_mutate:{key}")
    if payload.get("hypothesis_status") == "CONFIRMED":
        errors.append("model_cannot_confirm_hypothesis")
    return not errors, tuple(errors)


__all__ = ["FORBIDDEN_AUTHORITY_KEYS", "validate_untrusted_model_payload"]
