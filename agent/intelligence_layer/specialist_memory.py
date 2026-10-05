"""Bounded, untrusted specialist memory on the existing schema-v4 MemoryStore.

This module never creates a database. It delegates persistence to
``agent.memory.MemoryProvider`` and stores no specialist prompt/context, tools,
credentials, evidence, or authority-bearing data.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from .models import AgentLifecycle, TaskLifecycle

MAX_SPECIALIST_MEMORY_RECORD_BYTES = 4096
MAX_SPECIALIST_MEMORY_INPUT_BYTES = 8192
MAX_SPECIALIST_MEMORY_PARENT_BYTES = 8192
MAX_SPECIALIST_MEMORY_PARENT_RECORDS = 4
MAX_SPECIALIST_MEMORY_CHILD_RECORDS = 4
MAX_SPECIALIST_MEMORY_CHILD_BYTES = 2048
SPECIALIST_MEMORY_MAX_AGE_SECONDS = 30 * 24 * 60 * 60

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|passwd|secret|authorization|credential|private[_ -]?key)\b\s*[:=]\s*(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_PEM_SECRET = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
_RAW_TOKEN_SECRET = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class SpecialistMemoryError(ValueError):
    """A specialist memory record or authorization binding is invalid."""


def redact_specialist_text(value: str) -> str:
    """Remove common credential formats before any text enters durable memory."""
    text = _PEM_SECRET.sub("[REDACTED_PRIVATE_KEY]", value)
    text = _BEARER_SECRET.sub("Bearer [REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(
        lambda match: match.group(0)[:match.start(1) - match.start(0)] + "[REDACTED]",
        text,
    )
    return _RAW_TOKEN_SECRET.sub("[REDACTED_TOKEN]", text)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _scope(owner: str, mission: str, agent: str, task: str) -> tuple[str, ...]:
    return (f"owner:{owner}", f"mission:{mission}", f"agent:{agent}", f"task:{task}")


def _source_digest(*, owner: str, mission: str, agent: str, task: str, step: str,
                   plan_fingerprint: str, provider: str, model: str) -> str:
    return _sha256(_canonical({
        "owner_identity_ref": owner,
        "mission_id": mission,
        "agent_id": agent,
        "task_id": task,
        "step_id": step,
        "plan_fingerprint": plan_fingerprint,
        "provider": provider,
        "model": model,
        "tool_identity": "none",
    }))


def _identity_text(value: Any, *, limit: int, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise SpecialistMemoryError(f"{field}_invalid")
    cleaned = redact_specialist_text(value.strip())
    if not cleaned or len(cleaned) > limit or cleaned != value.strip():
        raise SpecialistMemoryError(f"{field}_invalid")
    return cleaned


def _bounded_proposal(proposal: Any, *, task_id: str, provider: str, model: str,
                      source_digest: str) -> tuple[dict[str, Any], str, bool]:
    if not isinstance(proposal, dict) or set(proposal) != {"summary", "recommendations", "open_questions"}:
        raise SpecialistMemoryError("proposal_schema_invalid")
    raw_bytes = _canonical(proposal)
    if len(raw_bytes) > MAX_SPECIALIST_MEMORY_INPUT_BYTES:
        raise SpecialistMemoryError("proposal_input_too_large")
    clean: dict[str, Any] = {}
    for key in ("summary", "recommendations", "open_questions"):
        value = proposal[key]
        if key == "summary":
            if not isinstance(value, str):
                raise SpecialistMemoryError("proposal_summary_invalid")
            clean[key] = redact_specialist_text(value.strip())[:1200]
            if not clean[key]:
                clean[key] = "[empty after credential filtering]"
            continue
        if not isinstance(value, list) or len(value) > 3:
            raise SpecialistMemoryError("proposal_list_invalid")
        entries = []
        for entry in value:
            if not isinstance(entry, str):
                raise SpecialistMemoryError("proposal_item_invalid")
            safe = redact_specialist_text(entry.strip())[:800]
            if safe:
                entries.append(safe)
        clean[key] = entries

    truncated = False
    while True:
        result_digest = _sha256(_canonical(clean))
        envelope = {
            "record_type": "UNTRUSTED_SPECIALIST_CHILD_MEMORY",
            "trust": "untrusted_data",
            "authority": "none",
            "task_id": task_id,
            "provider": provider,
            "model": model,
            "tool_identity": "none",
            "source_digest": source_digest,
            "result_digest": result_digest,
            "truncated": truncated,
            "proposal": clean,
        }
        content = _canonical(envelope).decode("utf-8")
        if len(content.encode("utf-8")) <= MAX_SPECIALIST_MEMORY_RECORD_BYTES:
            return clean, content, truncated
        candidates: list[tuple[int, str, int | None]] = []
        summary = clean["summary"]
        if len(summary) > 1:
            candidates.append((len(summary.encode("utf-8")), "summary", None))
        for key in ("recommendations", "open_questions"):
            for index, entry in enumerate(clean[key]):
                if len(entry) > 1:
                    candidates.append((len(entry.encode("utf-8")), key, index))
        if not candidates:
            raise SpecialistMemoryError("proposal_cannot_fit_memory_limit")
        _, key, index = max(candidates)
        value = clean[key] if index is None else clean[key][index]
        # Remove a bounded fraction of Unicode code points per pass; byte length
        # is checked again after every edit, so no invalid UTF-8 is produced.
        remove = max(1, len(value) // 8)
        shortened = value[:-remove].rstrip() or "[truncated]"
        truncated = True
        if index is None:
            clean[key] = shortened
        else:
            clean[key][index] = shortened


class SpecialistChildMemoryStore:
    """Create and retrieve strictly scoped child memories in schema-v4 storage."""

    @staticmethod
    def _authorized_graph(mission: Any, snapshot: Any, graph: Any, authorization_version: int) -> None:
        if not getattr(mission, "verify_integrity", lambda: False)():
            raise SpecialistMemoryError("mission_integrity_invalid")
        if (
            graph.mission_id != mission.mission_id
            or graph.owner_identity_ref != mission.owner_identity_ref
            or snapshot.mission_id != mission.mission_id
            or snapshot.owner_identity != mission.owner_identity_ref
            or graph.authorization_hash != snapshot.authorization_hash
        ):
            raise SpecialistMemoryError("memory_mission_binding_invalid")
        valid, _reason = snapshot.validate_for_mission(
            mission_id=mission.mission_id,
            owner_identity=mission.owner_identity_ref,
            target_identity=graph.target_identity,
            version=authorization_version,
        )
        if not valid:
            raise SpecialistMemoryError("memory_authorization_invalid")
        graph.validate_current_authorization(snapshot, authorization_version=authorization_version)

    def persist_proposal(
        self,
        *,
        mission: Any,
        snapshot: Any,
        graph: Any,
        task_id: str,
        step_id: str,
        proposal: dict[str, Any],
        provider: str,
        model: str,
        authorization_version: int,
    ) -> dict[str, Any]:
        from agent.memory import (
            MemoryDomain,
            MemoryItem,
            MemoryProvider,
            MemorySensitivity,
            MemoryType,
            MemoryValidationState,
            TrustClassification,
        )

        self._authorized_graph(mission, snapshot, graph, authorization_version)
        task = graph.tasks.get(task_id)
        if task is None or task.mission_id != mission.mission_id:
            raise SpecialistMemoryError("memory_task_binding_invalid")
        agent = graph.agents.get(task.assigned_agent_id)
        if agent is None or agent.mission_id != mission.mission_id or agent.owner_identity_ref != mission.owner_identity_ref:
            raise SpecialistMemoryError("memory_agent_binding_invalid")
        if (
            agent.role != "mission_specialist_analyst"
            or agent.parent_task_id != task_id
            or not {"untrusted_analysis_only", "no_tools", "no_evidence", "no_owner_authority"}.issubset(set(agent.capabilities))
            or agent.permission_scope.allowed_tools
            or agent.permission_scope.allowed_actions
            or agent.permission_scope.allowed_networks
            or agent.permission_scope.allowed_credentials
            or agent.permission_scope.workspace_root
            or agent.permission_scope.scope
        ):
            raise SpecialistMemoryError("memory_child_scope_invalid")
        if task.lifecycle not in {TaskLifecycle.RUNNING, TaskLifecycle.COMPLETED}:
            raise SpecialistMemoryError("memory_task_not_active")
        if task.lifecycle is TaskLifecycle.COMPLETED and task.result_validation_state != "UNTRUSTED_PROPOSAL":
            raise SpecialistMemoryError("memory_task_result_not_untrusted")

        owner = _identity_text(mission.owner_identity_ref, limit=512, field="owner")
        mission_id = _identity_text(mission.mission_id, limit=512, field="mission")
        agent_id = _identity_text(agent.agent_id, limit=512, field="agent")
        task_id = _identity_text(task_id, limit=512, field="task")
        step_id = _identity_text(step_id, limit=256, field="step")
        if task_id != "specialist:" + hashlib.sha256(step_id.encode("utf-8")).hexdigest()[:24]:
            raise SpecialistMemoryError("memory_task_step_binding_invalid")
        provider = _identity_text(provider, limit=80, field="provider")
        model = _identity_text(model, limit=120, field="model")
        initial = mission.progress.get("initial_model_response", {})
        if not isinstance(initial, dict) or initial.get("provider") != provider or initial.get("model") != model:
            raise SpecialistMemoryError("memory_provider_binding_invalid")
        plan_fingerprint = str(mission.plan.fingerprint)
        if not _DIGEST.fullmatch(plan_fingerprint):
            raise SpecialistMemoryError("memory_plan_fingerprint_invalid")
        source_digest = _source_digest(
            owner=owner, mission=mission_id, agent=agent_id, task=task_id, step=step_id,
            plan_fingerprint=plan_fingerprint, provider=provider, model=model,
        )
        clean_proposal, content, truncated = _bounded_proposal(
            proposal, task_id=task_id, provider=provider, model=model, source_digest=source_digest,
        )
        result_digest = _sha256(_canonical(clean_proposal))
        idempotency_key = _sha256(_canonical({
            "owner_identity_ref": owner,
            "mission_id": mission_id,
            "agent_id": agent_id,
            "task_id": task_id,
            "source_digest": source_digest,
        }))
        memory_id = "specialist-memory:" + idempotency_key
        if task.lifecycle is TaskLifecycle.COMPLETED and task.memory_refs != (memory_id,):
            raise SpecialistMemoryError("memory_reference_recovery_mismatch")

        metadata = {
            "record_type": "UNTRUSTED_SPECIALIST_CHILD_MEMORY",
            "authority": "none",
            "task_id": task_id,
            "step_id": step_id,
            "provider": provider,
            "model": model,
            "tool_identity": "none",
            "plan_fingerprint": plan_fingerprint,
            "source_digest": source_digest,
            "result_digest": result_digest,
            "idempotency_key": idempotency_key,
            "truncated": truncated,
        }
        item = MemoryItem.create(
            conversation_id=f"mission:{mission_id}",
            content=content,
            memory_type=MemoryType.REASONING_CASE,
            trust_classification=TrustClassification.UNTRUSTED_DATA,
            source="tool_less_specialist",
            provenance=f"mission:{mission_id}:task:{task_id}:source_sha256:{source_digest}",
            metadata=metadata,
            domain=MemoryDomain.TASK_STATE,
            request_id="",
            owner_identity_ref=owner,
            mission_id=mission_id,
            agent_id=agent_id,
            scope=_scope(owner, mission_id, agent_id, task_id),
            confidence=0.0,
            sensitivity=MemorySensitivity.INTERNAL,
            validation_state=MemoryValidationState.UNVERIFIED,
        )
        item = replace(item, memory_id=memory_id)
        persisted = MemoryProvider.store_idempotent_memory(item)
        # Return only the opaque ref and non-secret digests to graph persistence.
        return {
            "memory_ref": persisted.memory_id,
            "source_digest": source_digest,
            "result_digest": result_digest,
            "provider": provider,
            "model": model,
            "truncated": truncated,
        }

    def retrieve_for_child(
        self,
        *,
        memory_ref: str,
        owner_identity_ref: str,
        mission_id: str,
        agent_id: str,
        task_id: str,
        expected_plan_fingerprint: str,
    ) -> dict[str, Any] | None:
        """Return one record only when all four exact scope identities match."""
        return self._read_and_validate(
            memory_ref=memory_ref,
            owner_identity_ref=owner_identity_ref,
            mission_id=mission_id,
            agent_id=agent_id,
            task_id=task_id,
            expected_plan_fingerprint=expected_plan_fingerprint,
        )

    def retrieve_for_child_task(
        self,
        *,
        mission: Any,
        snapshot: Any,
        graph: Any,
        task_id: str,
        step_id: str,
        authorization_version: int,
    ) -> list[dict[str, Any]]:
        """Read only recent records for this currently running child/task scope."""
        from agent.memory import MemoryProvider

        self._authorized_graph(mission, snapshot, graph, authorization_version)
        task = graph.tasks.get(task_id)
        agent = graph.agents.get(task.assigned_agent_id) if task is not None else None
        if (
            task is None
            or task.mission_id != mission.mission_id
            or task.lifecycle is not TaskLifecycle.RUNNING
            or agent is None
            or agent.mission_id != mission.mission_id
            or agent.owner_identity_ref != mission.owner_identity_ref
            or agent.role != "mission_specialist_analyst"
            or agent.parent_task_id != task_id
            or agent.memory_scope != f"task:{step_id}"
            or task_id != "specialist:" + hashlib.sha256(step_id.encode("utf-8")).hexdigest()[:24]
            or not {"untrusted_analysis_only", "no_tools", "no_evidence", "no_owner_authority"}.issubset(set(agent.capabilities))
            or agent.permission_scope.allowed_tools
            or agent.permission_scope.allowed_actions
            or agent.permission_scope.allowed_networks
            or agent.permission_scope.allowed_credentials
            or agent.permission_scope.workspace_root
            or agent.permission_scope.scope
        ):
            return []

        rows = MemoryProvider.get_specialist_memory_items(
            owner_identity_ref=mission.owner_identity_ref,
            mission_id=mission.mission_id,
            agent_id=agent.agent_id,
            task_id=task.task_id,
            limit=MAX_SPECIALIST_MEMORY_CHILD_RECORDS,
        )
        records: list[dict[str, Any]] = []
        total_bytes = 0
        for item in rows:
            try:
                record = self._read_and_validate(
                    memory_ref=item.memory_id,
                    owner_identity_ref=mission.owner_identity_ref,
                    mission_id=mission.mission_id,
                    agent_id=agent.agent_id,
                    task_id=task.task_id,
                    expected_plan_fingerprint=str(mission.plan.fingerprint),
                    expected_step_id=step_id,
                )
            except SpecialistMemoryError:
                # Bad, stale, unknown-schema, or tampered records are excluded;
                # they never become prompt content or grant Mission authority.
                continue
            if record is None:
                continue
            record_bytes = len(_canonical(record))
            if record_bytes > MAX_SPECIALIST_MEMORY_CHILD_BYTES:
                continue
            if total_bytes + record_bytes > MAX_SPECIALIST_MEMORY_CHILD_BYTES:
                break
            records.append(record)
            total_bytes += record_bytes
        return records

    def retrieve_for_parent(
        self,
        *,
        mission: Any,
        snapshot: Any,
        graph: Any,
        task_id: str,
        step_id: str,
        memory_ref: str,
        authorization_version: int,
    ) -> dict[str, Any]:
        """Explicitly retrieve a child record only through a validated Mission graph."""
        self._authorized_graph(mission, snapshot, graph, authorization_version)
        task = graph.tasks.get(task_id)
        if (
            task is None
            or task.lifecycle is not TaskLifecycle.COMPLETED
            or task.result_validation_state != "UNTRUSTED_PROPOSAL"
            or task.memory_refs != (memory_ref,)
            or task.evidence_refs
            or task.artifacts
        ):
            raise SpecialistMemoryError("parent_memory_reference_not_authorized")
        agent = graph.agents.get(task.assigned_agent_id)
        if (
            agent is None or agent.role != "mission_specialist_analyst" or agent.parent_task_id != task_id
            or task_id != "specialist:" + hashlib.sha256(step_id.encode("utf-8")).hexdigest()[:24]
        ):
            raise SpecialistMemoryError("parent_memory_agent_binding_invalid")
        return self._read_and_validate(
            memory_ref=memory_ref,
            owner_identity_ref=mission.owner_identity_ref,
            mission_id=mission.mission_id,
            agent_id=agent.agent_id,
            task_id=task.task_id,
            expected_plan_fingerprint=str(mission.plan.fingerprint),
            expected_step_id=step_id,
        ) or self._raise_missing()

    @staticmethod
    def _raise_missing():
        raise SpecialistMemoryError("specialist_memory_reference_missing")

    def _read_and_validate(
        self,
        *,
        memory_ref: str,
        owner_identity_ref: str,
        mission_id: str,
        agent_id: str,
        task_id: str,
        expected_plan_fingerprint: str,
        expected_step_id: str | None = None,
    ) -> dict[str, Any] | None:
        from agent.memory import MemoryProvider, MemoryValidationState, MemoryDomain, MemorySensitivity, TrustClassification

        if not all(isinstance(value, str) and value for value in (memory_ref, owner_identity_ref, mission_id, agent_id, task_id)):
            return None
        try:
            item = MemoryProvider.get_specialist_memory_item(
                memory_id=memory_ref,
                owner_identity_ref=owner_identity_ref,
                mission_id=mission_id,
                agent_id=agent_id,
                task_id=task_id,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SpecialistMemoryError("specialist_memory_record_corrupt") from exc
        if item is None:
            return None
        if (
            item.conversation_id != f"mission:{mission_id}"
            or item.domain is not MemoryDomain.TASK_STATE
            or item.trust_classification is not TrustClassification.UNTRUSTED_DATA
            or item.validation_state is not MemoryValidationState.UNVERIFIED
            or item.sensitivity is not MemorySensitivity.INTERNAL
            or item.superseded_by is not None
            or item.source != "tool_less_specialist"
            or item.scope != _scope(owner_identity_ref, mission_id, agent_id, task_id)
            or len(item.content.encode("utf-8")) > MAX_SPECIALIST_MEMORY_RECORD_BYTES
        ):
            raise SpecialistMemoryError("specialist_memory_scope_or_trust_invalid")
        try:
            created_at = datetime.fromisoformat(item.created_at.replace("Z", "+00:00"))
            if created_at.tzinfo is None:
                raise ValueError("memory_timestamp_timezone_missing")
            age_seconds = (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds()
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistMemoryError("specialist_memory_timestamp_invalid") from exc
        if age_seconds < -300 or age_seconds > SPECIALIST_MEMORY_MAX_AGE_SECONDS:
            raise SpecialistMemoryError("specialist_memory_expired")
        metadata = item.metadata
        if not isinstance(metadata, dict) or set(metadata) != {
            "record_type", "authority", "task_id", "step_id", "provider", "model", "tool_identity",
            "plan_fingerprint", "source_digest", "result_digest", "idempotency_key", "truncated",
        }:
            raise SpecialistMemoryError("specialist_memory_metadata_invalid")
        if (
            metadata.get("record_type") != "UNTRUSTED_SPECIALIST_CHILD_MEMORY"
            or metadata.get("authority") != "none"
            or metadata.get("task_id") != task_id
            or metadata.get("tool_identity") != "none"
            or metadata.get("plan_fingerprint") != expected_plan_fingerprint
            or (expected_step_id is not None and metadata.get("step_id") != expected_step_id)
            or not isinstance(metadata.get("step_id"), str)
            or not isinstance(metadata.get("provider"), str)
            or not isinstance(metadata.get("model"), str)
            or not isinstance(metadata.get("truncated"), bool)
            or not all(_DIGEST.fullmatch(str(metadata.get(key, ""))) for key in ("plan_fingerprint", "source_digest", "result_digest", "idempotency_key"))
        ):
            raise SpecialistMemoryError("specialist_memory_metadata_binding_invalid")
        expected_source = _source_digest(
            owner=owner_identity_ref,
            mission=mission_id,
            agent=agent_id,
            task=task_id,
            step=metadata["step_id"],
            plan_fingerprint=expected_plan_fingerprint,
            provider=metadata["provider"],
            model=metadata["model"],
        )
        expected_idempotency = _sha256(_canonical({
            "owner_identity_ref": owner_identity_ref,
            "mission_id": mission_id,
            "agent_id": agent_id,
            "task_id": task_id,
            "source_digest": expected_source,
        }))
        if metadata["source_digest"] != expected_source or metadata["idempotency_key"] != expected_idempotency:
            raise SpecialistMemoryError("specialist_memory_source_digest_mismatch")
        try:
            envelope = json.loads(item.content)
        except (TypeError, json.JSONDecodeError) as exc:
            raise SpecialistMemoryError("specialist_memory_content_invalid") from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "record_type", "trust", "authority", "task_id", "provider", "model", "tool_identity",
            "source_digest", "result_digest", "truncated", "proposal",
        }:
            raise SpecialistMemoryError("specialist_memory_content_schema_invalid")
        proposal = envelope.get("proposal")
        if (
            envelope.get("record_type") != "UNTRUSTED_SPECIALIST_CHILD_MEMORY"
            or envelope.get("trust") != "untrusted_data"
            or envelope.get("authority") != "none"
            or envelope.get("task_id") != task_id
            or envelope.get("provider") != metadata["provider"]
            or envelope.get("model") != metadata["model"]
            or envelope.get("tool_identity") != "none"
            or envelope.get("source_digest") != expected_source
            or envelope.get("truncated") is not metadata["truncated"]
            or not isinstance(proposal, dict)
            or _sha256(_canonical(proposal)) != metadata["result_digest"]
            or envelope.get("result_digest") != metadata["result_digest"]
            or item.content_hash != _sha256(item.content.encode("utf-8"))
        ):
            raise SpecialistMemoryError("specialist_memory_content_digest_mismatch")
        # Redact again on read; tampered legacy data is never returned verbatim.
        safe_proposal, _safe_content, _was_truncated = _bounded_proposal(
            proposal,
            task_id=task_id,
            provider=metadata["provider"],
            model=metadata["model"],
            source_digest=expected_source,
        )
        if safe_proposal != proposal:
            raise SpecialistMemoryError("specialist_memory_secret_scrub_validation_failed")
        return {
            "record_type": "UNTRUSTED_SPECIALIST_CHILD_MEMORY",
            "trust": "untrusted_data",
            "validation_state": "unverified",
            "authority": "none",
            "memory_ref": item.memory_id,
            "task_id": task_id,
            "step_id": metadata["step_id"],
            "provider": metadata["provider"],
            "model": metadata["model"],
            "tool_identity": "none",
            "source_digest": expected_source,
            "result_digest": metadata["result_digest"],
            "truncated": metadata["truncated"],
            "proposal": safe_proposal,
        }
