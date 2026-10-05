"""Owner-scoped episodic memory over the existing schema-v4 MemoryStore.

Mission episodes contain only bounded structured outcome metadata. They are never
policy, authorization, evidence, or trusted instructions. Approved procedures
remain in the separate Owner-controlled SkillRegistry.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any


def memory_scope_ref(owner_identity_ref: str, scope_snapshot_id: str) -> str:
    owner = str(owner_identity_ref).strip()
    snapshot = str(scope_snapshot_id).strip()
    if not owner or not snapshot or len(owner) > 256 or len(snapshot) > 256:
        raise ValueError("canonical_owner_scope_required")
    digest = hashlib.sha256(f"mission-memory-scope-v1\0{owner}\0{snapshot}".encode("utf-8")).hexdigest()
    return f"owner_scope_sha256:{digest}"


def live_scope_snapshot_id(authorization_context: Any) -> str:
    """Return a scope ID only for the active Owner session and an unexpired snapshot."""
    snapshot = getattr(authorization_context, "scope_snapshot", None)
    authorization = getattr(snapshot, "authorization", None)
    snapshot_id = str(getattr(snapshot, "snapshot_id", "") or "").strip()
    scope_session = str(getattr(authorization, "owner_session_id", "") or "")
    active_session = str(getattr(authorization_context, "session_id", "") or "")
    if not snapshot_id or not scope_session or not active_session or not hmac.compare_digest(scope_session, active_session):
        return ""
    expires_at = getattr(snapshot, "expires_at", None)
    if expires_at:
        if not isinstance(expires_at, str):
            return ""
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return ""
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return ""
    return snapshot_id


def provider_for_scope(
    owner_identity_ref: str,
    scope_snapshot_id: str,
    *,
    exclude_mission_id: str | None = None,
):
    """Build a provider that can read only exact Owner + approved-scope episodes."""
    from agent.context import DurableMemoryProvider
    from agent.memory import MemoryDomain

    scope_ref = memory_scope_ref(owner_identity_ref, scope_snapshot_id)
    return DurableMemoryProvider(
        conversation_id="owner-scoped-mission-memory",
        owner_identity_ref=str(owner_identity_ref),
        scope=(scope_ref,),
        domain=MemoryDomain.LEARNING,
        strict_scope=True,
        exclude_mission_id=exclude_mission_id,
        max_age_days=90,
        minimum_confidence=0.0,
    )


def _scope_snapshot_id(mission: Any) -> str:
    for candidate in (getattr(mission, "scope_snapshot", None), getattr(mission, "authorization_context", None)):
        if not isinstance(candidate, dict):
            continue
        for key in ("scope_snapshot_id", "snapshot_id"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        nested = candidate.get("scope_snapshot")
        if isinstance(nested, dict):
            value = nested.get("snapshot_id", nested.get("scope_snapshot_id"))
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def persist_terminal_episode(mission: Any):
    """Idempotently persist a small UNTRUSTED episodic record after Mission save.

    No prompt, observation, tool arguments/results, target address, credentials,
    exception text, or provider response is copied into this record.
    """
    if not bool(getattr(mission, "is_terminal", False)):
        return None
    owner = str(getattr(mission, "owner_identity_ref", "") or "").strip()
    mission_id = str(getattr(mission, "mission_id", "") or "").strip()
    scope_snapshot_id = _scope_snapshot_id(mission)
    integrity_hash = str(getattr(mission, "integrity_hash", "") or "").strip().lower()
    verifier = getattr(mission, "verify_integrity", None)
    try:
        integrity_valid = callable(verifier) and verifier() is True
    except Exception:
        integrity_valid = False
    if not re.fullmatch(r"owner:[1-9][0-9]*", owner) or not mission_id or not scope_snapshot_id or not re.fullmatch(r"[0-9a-f]{64}", integrity_hash) or not integrity_valid:
        return None
    expected_scope_ref = memory_scope_ref(owner, scope_snapshot_id)
    provenance = getattr(mission, "provenance", {})
    if not isinstance(provenance, dict) or provenance.get("mission_memory_scope_ref") != expected_scope_ref:
        return None

    status = getattr(getattr(mission, "status", None), "value", "")
    if not isinstance(status, str) or not re.fullmatch(r"[A-Z_]{1,48}", status):
        return None
    plan = getattr(mission, "plan", None)
    steps = getattr(plan, "steps", ())
    tool_names: list[str] = []
    try:
        from tools.registry import get_tool
        for step in steps:
            name = str(getattr(step, "action", ""))
            if name and name != "__planning_failure__" and get_tool(name) is not None and name not in tool_names:
                tool_names.append(name)
            if len(tool_names) >= 12:
                break
    except Exception:
        tool_names = []

    verification = getattr(mission, "verification_state", {})
    verified = isinstance(verification, dict) and verification.get("verified") is True
    evidence = getattr(mission, "evidence", ())
    evidence_count = min(len(evidence), 1000) if isinstance(evidence, (list, tuple)) else 0
    failures = getattr(mission, "failures", ())
    failure_classes: list[str] = []
    if isinstance(failures, (list, tuple)):
        for failure in failures[:32]:
            if not isinstance(failure, dict):
                continue
            value = str(failure.get("class", "")).upper()
            if re.fullmatch(r"[A-Z_]{1,32}", value) and value not in failure_classes:
                failure_classes.append(value)
            if len(failure_classes) >= 8:
                break

    content = "\n".join((
        "[UNTRUSTED_MISSION_EPISODE]",
        f"outcome_status: {status}",
        f"verification_recorded: {'yes' if verified else 'no'}",
        f"tool_names: {', '.join(tool_names) if tool_names else 'none'}",
        f"evidence_record_count: {evidence_count}",
        f"failure_classes: {', '.join(failure_classes) if failure_classes else 'none'}",
    ))
    if len(content.encode("utf-8")) > 2048:
        return None

    provenance_payload = {
        "record_type": "mission_episode_v1",
        "mission_integrity_hash": integrity_hash,
        "plan_fingerprint": str(getattr(plan, "fingerprint", ""))[:128],
        "status": status,
        "verified": verified,
        "tool_names": tool_names,
        "evidence_count": evidence_count,
        "failure_classes": failure_classes,
    }
    source_digest = hashlib.sha256(
        json.dumps(provenance_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    memory_id = hashlib.sha256(
        f"mission-episode-v1\0{owner}\0{mission_id}\0{source_digest}".encode("utf-8")
    ).hexdigest()

    from agent.memory import (
        MemoryDomain,
        MemoryItem,
        MemoryProvider,
        MemorySensitivity,
        MemoryType,
        MemoryValidationState,
        TrustClassification,
    )

    item = MemoryItem.create(
        conversation_id="owner-mission-episodes:" + hashlib.sha256(owner.encode("utf-8")).hexdigest(),
        content=content,
        memory_type=MemoryType.INVESTIGATION,
        trust_classification=TrustClassification.UNTRUSTED_DATA,
        source="mission_runtime_episode",
        provenance=f"sha256:{source_digest}",
        metadata={
            "record_type": "UNTRUSTED_MISSION_EPISODE",
            "episode_schema": 1,
            "source_digest": source_digest,
            "tool_names": tool_names,
        },
        domain=MemoryDomain.LEARNING,
        request_id=str(getattr(mission, "request_id", "") or "")[:128],
        owner_identity_ref=owner,
        mission_id=mission_id,
        agent_id="mission-coordinator",
        scope=(expected_scope_ref,),
        confidence=0.95 if verified else 0.5,
        sensitivity=MemorySensitivity.INTERNAL,
        validation_state=MemoryValidationState.UNVERIFIED,
    )
    item = replace(item, memory_id=memory_id)
    return MemoryProvider.store_idempotent_memory(item)
