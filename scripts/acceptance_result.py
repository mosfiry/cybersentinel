"""Shared final-status checks for local acceptance evidence."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def apply_cleanup_gate(result: dict[str, Any], cleanup_checks: Mapping[str, Any]) -> bool:
    """Record required teardown outcomes and prevent PASS when any cleanup failed."""
    if not isinstance(result, dict) or not isinstance(cleanup_checks, Mapping) or not cleanup_checks:
        raise ValueError("acceptance result and at least one cleanup check are required")
    normalized: dict[str, bool] = {}
    for name, value in cleanup_checks.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("cleanup check names must be non-empty strings")
        normalized[name] = value is True

    checks = result.setdefault("checks", {})
    if not isinstance(checks, dict):
        raise ValueError("acceptance checks must be an object")
    for name, passed in normalized.items():
        checks[f"cleanup_{name}"] = passed
    result["cleanup_checks"] = normalized

    failures = [name for name, passed in normalized.items() if not passed]
    if failures:
        was_pass = result.get("status") == "PASS"
        result["status"] = "FAIL"
        result["cleanup_failures"] = failures
        if was_pass:
            result.setdefault("failure_phase", "cleanup")
    else:
        result["cleanup_verified"] = True
    return not failures
