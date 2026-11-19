"""Guard: the legacy OWNER_TOKEN-era policy schema keys are gone completely.

Mission 1 contract: username+password is the ONLY Owner authentication and
OWNER_TOKEN-era mechanisms are removed with no fallback and no compatibility
mode. The inert dataclass fields require_owner_token / owner_phrase had
ZERO consumers in live code; they were removed in session 11 (unit X-K.1)
and must never reappear in the policy schema.
"""
from __future__ import annotations

import json

from security import owner_policy

LEGACY_KEYS = ("require_owner_token", "owner_phrase")


def test_owner_policy_schema_has_no_legacy_keys():
    fields = set(owner_policy.OwnerPolicy.__dataclass_fields__)
    for key in LEGACY_KEYS:
        assert key not in fields


def test_owner_policy_json_has_no_legacy_keys():
    data = json.loads(owner_policy.POLICY_PATH.read_text(encoding="utf-8"))
    for key in LEGACY_KEYS:
        assert key not in data


def test_load_policy_still_loads_canonical_schema():
    policy = owner_policy.load_policy()
    assert policy.version == "2.0"
    assert policy.evidence_required is True
    assert policy.model_authority == "none"
    assert policy.external_content_authority == "none"
    assert policy.system_safety_boundary == "immutable"
    assert policy.runtime_limits.get("max_tool_calls") == 10
