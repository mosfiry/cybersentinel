from __future__ import annotations

import hashlib
import json
from typing import Any

ALLOWED_PLAN_FIELDS = frozenset({"tools", "rationale"})


def validate_plan_object(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("planner response must be an object")
    unknown = set(payload) - ALLOWED_PLAN_FIELDS
    if unknown:
        raise ValueError("planner response contains unknown fields")
    if "tools" not in payload or not isinstance(payload["tools"], list):
        raise ValueError("planner JSON must contain a tools array")
    return payload


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_plan(plan: list) -> str:
    return canonical_json(plan)


def plan_hash(plan: list) -> str:
    return hashlib.sha256(canonical_plan(plan).encode("utf-8")).hexdigest()
