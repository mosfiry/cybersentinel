from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

import security.owner_policy as owner_policy
from security.scope import ScopeSnapshot


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthorizationContext:
    """The sole immutable bridge from authenticated request to sensitive execution."""

    request_id: str
    owner_evidence: Any
    policy_snapshot: Any
    scope_snapshot: ScopeSnapshot | None = None
    session_id: str | None = None
    authorization_source: str = "security.authorization_context"
    task_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("authorization context requires request_id")
        if not isinstance(self.owner_evidence, owner_policy.OwnerAuthenticationEvidence):
            raise TypeError("authorization context requires typed OwnerAuthenticationEvidence")
        if not isinstance(self.policy_snapshot, owner_policy.OwnerPolicySnapshot):
            raise TypeError("authorization context requires typed OwnerPolicySnapshot")
        if self.owner_evidence.request_id != self.request_id or self.policy_snapshot.request_id != self.request_id:
            raise ValueError("authorization context request binding mismatch")
        if not self.owner_evidence.is_valid(self.request_id, self.session_id):
            raise PermissionError("authorization context contains stale or invalid Owner evidence")
        if self.scope_snapshot is not None:
            if not isinstance(self.scope_snapshot, ScopeSnapshot):
                raise TypeError("scope_snapshot must be a persisted ScopeSnapshot")
            if self.scope_snapshot.authorization.owner_session_id and self.session_id != self.scope_snapshot.authorization.owner_session_id:
                raise ValueError("authorization context scope/session binding mismatch")

    @property
    def owner_evidence_fingerprint(self) -> str:
        return _fingerprint(self.owner_evidence.to_dict())

    @property
    def policy_fingerprint(self) -> str:
        return self.policy_snapshot.owner_policy_fingerprint

    @property
    def instruction_fingerprint(self) -> str:
        return self.policy_snapshot.owner_instruction_fingerprint

    @property
    def scope_fingerprint(self) -> str:
        return _fingerprint(self.scope_snapshot.to_dict()) if self.scope_snapshot else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "owner_evidence": self.owner_evidence.to_dict(),
            "policy_snapshot": self.policy_snapshot.to_dict(),
            "scope_snapshot": self.scope_snapshot.to_dict() if self.scope_snapshot else None,
            "scope_snapshot_id": self.scope_snapshot.snapshot_id if self.scope_snapshot else None,
            "session_id": self.session_id,
            "authorization_source": self.authorization_source,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "owner_evidence_fingerprint": self.owner_evidence_fingerprint,
            "instruction_fingerprint": self.instruction_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "scope_fingerprint": self.scope_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorizationContext":
        evidence = owner_policy.OwnerAuthenticationEvidence(**dict(data["owner_evidence"]))
        policy_data = dict(data["policy_snapshot"])
        policy = owner_policy.OwnerPolicySnapshot(
            request_id=str(policy_data["request_id"]),
            owner_instruction=str(policy_data.get("owner_instruction", "")),
            owner_instruction_fingerprint=str(policy_data.get("owner_instruction_fingerprint", "")),
            owner_policy_fingerprint=str(policy_data.get("owner_policy_fingerprint", "")),
            authority_snapshot=dict(policy_data.get("authority_snapshot", {})),
            authentication=dict(policy_data.get("authentication", {})),
            captured_at=str(policy_data.get("captured_at", "")),
            instruction_record=dict(policy_data.get("instruction_record", {})),
        )
        scope = None
        scope_id = data.get("scope_snapshot_id")
        if scope_id:
            from security.scope_store import get_snapshot
            scope = get_snapshot(str(scope_id))
            if scope is None:
                raise ValueError("authorization context scope snapshot not found")
        return cls(
            request_id=str(data["request_id"]),
            owner_evidence=evidence,
            policy_snapshot=policy,
            scope_snapshot=scope,
            session_id=data.get("session_id"),
            authorization_source=str(data.get("authorization_source", "security.authorization_context")),
            task_id=data.get("task_id"),
            created_at=str(data.get("created_at") or datetime.now(timezone.utc).isoformat()),
        )


@dataclass(frozen=True)
class AuthorizationDecision:
    """Immutable security decision; model output cannot create a trusted instance."""

    allowed: bool
    reason: str
    request_id: str
    tool: str
    risk_class: str | None
    owner_evidence_fingerprint: str
    policy_fingerprint: str
    scope_fingerprint: str
    decision_timestamp: str
    decision_source: str
    arguments_hash: str = ""

    @classmethod
    def issue(cls, context: AuthorizationContext, *, allowed: bool, reason: str, tool: str, risk_class: str | None, argument: Any = None) -> "AuthorizationDecision":
        if not isinstance(context, AuthorizationContext):
            raise TypeError("only AuthorizationContext may issue AuthorizationDecision")
        return cls(
            allowed=bool(allowed), reason=str(reason), request_id=context.request_id, tool=str(tool), risk_class=risk_class,
            owner_evidence_fingerprint=context.owner_evidence_fingerprint, policy_fingerprint=context.policy_fingerprint,
            scope_fingerprint=context.scope_fingerprint, decision_timestamp=datetime.now(timezone.utc).isoformat(),
            decision_source="security.authorization_context", arguments_hash=_fingerprint(argument) if argument is not None else "",
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


__all__ = ["AuthorizationContext", "AuthorizationDecision"]
