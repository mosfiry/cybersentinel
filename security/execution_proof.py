from __future__ import annotations

"""Proof-carrying execution boundary.

An ExecutionAuthorizationProof is DERIVED EVIDENCE of an existing
authorization. It is never a source of authority: authority comes from the
Owner policy and the deterministic authorization machinery (Owner evidence ->
AuthorizationContext -> authorize_tool -> MissionAuthorizationSnapshot).

A proof binds exactly one execution to:

- mission identity and request identity
- the Owner-minted mission authorization snapshot (hash + version, embedded
  for boundary re-validation)
- the plan fingerprint and the scope snapshot fingerprint
- the exact tool name and canonical argument fingerprint
- the authorization decision fingerprint (when a decision exists)
- the mission lifecycle status and lifecycle revision

The tool registry verifies the proof at the execution boundary (validation,
never policy creation). The runtime re-validates it against the live mission
immediately before execution, so replans, cancellations, recoveries, scope or
snapshot changes invalidate previously derived proofs deterministically.

Model output, tool output, and external data can never construct a valid
proof: the proof signature is an HMAC over the binding hash under the same
process secret that signs AuthorizationDecision objects.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from typing import Any

from security.authorization_context import _DECISION_SECRET, _fingerprint
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot

PROOF_TTL_SECONDS = 300
EXECUTION_ALLOWED_MISSION_STATUSES = frozenset({"READY", "RUNNING"})


class RejectionCode(str, Enum):
    """Deterministic rejection taxonomy shared by gates, runtime, and registry."""

    SNAPSHOT_MISSING = "SNAPSHOT_MISSING"
    SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
    SNAPSHOT_EXPIRED = "SNAPSHOT_EXPIRED"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    FORBIDDEN_ACTION = "FORBIDDEN_ACTION"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    NETWORK_BOUNDARY_MISMATCH = "NETWORK_BOUNDARY_MISMATCH"
    WORKSPACE_BOUNDARY_MISMATCH = "WORKSPACE_BOUNDARY_MISMATCH"
    CREDENTIAL_BOUNDARY_MISMATCH = "CREDENTIAL_BOUNDARY_MISMATCH"
    PLAN_MISMATCH = "PLAN_MISMATCH"
    LIFECYCLE_MISMATCH = "LIFECYCLE_MISMATCH"
    PROOF_REQUIRED = "PROOF_REQUIRED"
    PROOF_INVALID = "PROOF_INVALID"
    PROOF_EXPIRED = "PROOF_EXPIRED"
    PROOF_REPLAY = "PROOF_REPLAY"
    PROOF_BINDING_MISMATCH = "PROOF_BINDING_MISMATCH"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def canonical_execution_fingerprint(value: Any) -> str:
    """Deterministic canonical fingerprint (key order and whitespace insensitive)."""
    return _fingerprint(value)


def classify_snapshot_reason(reason: str) -> RejectionCode:
    """Map a snapshot validation message to a deterministic rejection code."""
    text = str(reason)
    if "expired" in text or "not active" in text:
        return RejectionCode.SNAPSHOT_EXPIRED
    if "actions or tools outside" in text:
        return RejectionCode.TOOL_NOT_ALLOWED
    if "workspace boundary mismatch" in text:
        return RejectionCode.WORKSPACE_BOUNDARY_MISMATCH
    if "network boundary mismatch" in text:
        return RejectionCode.NETWORK_BOUNDARY_MISMATCH
    if "credential boundary mismatch" in text:
        return RejectionCode.CREDENTIAL_BOUNDARY_MISMATCH
    if "target mismatch" in text:
        return RejectionCode.TARGET_MISMATCH
    if "mission mismatch" in text or "owner mismatch" in text or "version invalid" in text:
        return RejectionCode.SNAPSHOT_MISMATCH
    return RejectionCode.SNAPSHOT_INVALID


class ExecutionProofError(PermissionError):
    """Raised when proof derivation cannot bind an execution to its authorization."""

    def __init__(self, code: str, reason: str):
        super().__init__(f"{code}: {reason}")
        self.code = str(code)
        self.reason = str(reason)


@dataclass(frozen=True)
class ExecutionAuthorizationProof:
    """Immutable derived evidence binding one execution to its authorization."""

    mission_id: str
    request_id: str
    tool: str
    arguments_hash: str
    snapshot_hash: str
    snapshot_version: int
    mission_status: str
    lifecycle_revision: int
    created_at: str
    expires_at: str
    execution_binding_hash: str = ""
    tool_call_id: str = ""
    plan_hash: str = ""
    scope_hash: str = ""
    policy_fingerprint: str = ""
    decision_fingerprint: str = ""
    proof_signature: str = ""
    snapshot: dict[str, Any] = field(default_factory=dict)

    def _binding_payload(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "tool": self.tool,
            "tool_call_id": self.tool_call_id,
            "arguments_hash": self.arguments_hash,
            "plan_hash": self.plan_hash,
            "snapshot_hash": self.snapshot_hash,
            "snapshot_version": self.snapshot_version,
            "scope_hash": self.scope_hash,
            "policy_fingerprint": self.policy_fingerprint,
            "decision_fingerprint": self.decision_fingerprint,
            "mission_status": self.mission_status,
            "lifecycle_revision": self.lifecycle_revision,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def _computed_binding_hash(self) -> str:
        return hashlib.sha256(_canonical(self._binding_payload()).encode("utf-8")).hexdigest()

    @property
    def proof_fingerprint(self) -> str:
        return self.execution_binding_hash

    def is_expired(self, *, at: str | None = None) -> bool:
        moment = _parse(at or _now())
        return not (_parse(self.created_at) <= moment < _parse(self.expires_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "tool": self.tool,
            "tool_call_id": self.tool_call_id,
            "arguments_hash": self.arguments_hash,
            "plan_hash": self.plan_hash,
            "snapshot_hash": self.snapshot_hash,
            "snapshot_version": self.snapshot_version,
            "scope_hash": self.scope_hash,
            "policy_fingerprint": self.policy_fingerprint,
            "decision_fingerprint": self.decision_fingerprint,
            "mission_status": self.mission_status,
            "lifecycle_revision": self.lifecycle_revision,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "execution_binding_hash": self.execution_binding_hash,
            "proof_signature": self.proof_signature,
            "snapshot": dict(self.snapshot),
        }

    @classmethod
    def derive(cls, *, mission_id: str, request_id: str, tool: str, argument: Any, snapshot: MissionAuthorizationSnapshot, decision: Any = None, tool_call_id: str = "", plan_hash: str = "", scope: Any = None, mission_status: str = "", lifecycle_revision: int = 0, policy_fingerprint: str = "", ttl_seconds: int = PROOF_TTL_SECONDS, at: str | None = None) -> "ExecutionAuthorizationProof":
        """Derive a proof for exactly one execution. Never creates authority."""
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise ExecutionProofError(RejectionCode.SNAPSHOT_INVALID.value, "execution proof requires a typed MissionAuthorizationSnapshot")
        moment = _parse(at or _now())
        if not snapshot.is_active(at=at):
            raise ExecutionProofError(RejectionCode.SNAPSHOT_EXPIRED.value, "authorization snapshot expired or not active")
        if tool in snapshot.forbidden_actions:
            raise ExecutionProofError(RejectionCode.FORBIDDEN_ACTION.value, f"tool {tool} is forbidden by authorization snapshot")
        if tool not in snapshot.allowed_tools or tool not in snapshot.allowed_actions:
            raise ExecutionProofError(RejectionCode.TOOL_NOT_ALLOWED.value, f"tool {tool} outside authorization snapshot allowlist")
        decision_fingerprint = ""
        effective_policy_fingerprint = str(policy_fingerprint or "")
        if decision is not None:
            from security.authorization_context import AuthorizationDecision
            if not isinstance(decision, AuthorizationDecision):
                raise ExecutionProofError(RejectionCode.PROOF_INVALID.value, "execution proof requires a typed AuthorizationDecision")
            if not decision.is_valid_for(tool, argument, request_id):
                raise ExecutionProofError(RejectionCode.PROOF_BINDING_MISMATCH.value, "authorization decision does not match tool, arguments, or request")
            decision_fingerprint = decision.decision_signature
            effective_policy_fingerprint = decision.policy_fingerprint
        expiry = _parse(snapshot.expires_at)
        bounded = moment + timedelta(seconds=max(1, int(ttl_seconds)))
        expires_at = (expiry if expiry <= bounded else bounded).isoformat()
        proof = cls(
            mission_id=str(mission_id),
            request_id=str(request_id or ""),
            tool=str(tool),
            arguments_hash=_fingerprint(argument),
            snapshot_hash=snapshot.authorization_hash,
            snapshot_version=int(snapshot.version),
            mission_status=str(mission_status),
            lifecycle_revision=int(lifecycle_revision),
            created_at=moment.isoformat(),
            expires_at=expires_at,
            tool_call_id=str(tool_call_id or ""),
            plan_hash=str(plan_hash or ""),
            scope_hash=_fingerprint(scope or {}),
            policy_fingerprint=effective_policy_fingerprint,
            decision_fingerprint=decision_fingerprint,
            snapshot=snapshot.to_dict(),
        )
        object.__setattr__(proof, "execution_binding_hash", proof._computed_binding_hash())
        object.__setattr__(proof, "proof_signature", hmac.new(_DECISION_SECRET, proof.execution_binding_hash.encode("utf-8"), hashlib.sha256).hexdigest())
        return proof

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionAuthorizationProof":
        values = dict(data)
        values["snapshot"] = dict(values.get("snapshot") or {})
        return cls(**values)

    @classmethod
    def verify(cls, proof: Any, *, name: str, argument: Any = None, mission_id: str | None = None, request_id: str | None = None, tool_call_id: str | None = None, at: str | None = None) -> tuple[bool, str, str]:
        """Validate a proof at the execution boundary. Validation only; no policy creation."""
        if not isinstance(proof, ExecutionAuthorizationProof):
            return False, "execution proof is not a typed ExecutionAuthorizationProof", RejectionCode.PROOF_INVALID.value
        if proof._computed_binding_hash() != proof.execution_binding_hash:
            return False, "execution binding hash mismatch", RejectionCode.PROOF_INVALID.value
        expected = hmac.new(_DECISION_SECRET, proof.execution_binding_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, proof.proof_signature):
            return False, "execution proof signature mismatch", RejectionCode.PROOF_INVALID.value
        if proof.is_expired(at=at):
            return False, "execution proof expired", RejectionCode.PROOF_EXPIRED.value
        if str(name) != proof.tool:
            return False, "execution proof is bound to a different tool", RejectionCode.PROOF_BINDING_MISMATCH.value
        if mission_id is not None and str(mission_id) != proof.mission_id:
            return False, "execution proof belongs to another mission", RejectionCode.PROOF_BINDING_MISMATCH.value
        if request_id is not None and str(request_id) != proof.request_id:
            return False, "execution proof belongs to another request", RejectionCode.PROOF_BINDING_MISMATCH.value
        if tool_call_id is not None and str(tool_call_id) != proof.tool_call_id:
            return False, "execution proof belongs to another tool call", RejectionCode.PROOF_BINDING_MISMATCH.value
        if not hmac.compare_digest(proof.arguments_hash, _fingerprint(argument)):
            return False, "execution proof argument binding mismatch", RejectionCode.PROOF_BINDING_MISMATCH.value
        try:
            embedded = MissionAuthorizationSnapshot.from_dict(dict(proof.snapshot or {}))
        except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError):
            return False, "embedded authorization snapshot invalid", RejectionCode.PROOF_INVALID.value
        if embedded.authorization_hash != proof.snapshot_hash or int(embedded.version) != proof.snapshot_version:
            return False, "embedded authorization snapshot does not match proof binding", RejectionCode.SNAPSHOT_MISMATCH.value
        if not embedded.is_active(at=at):
            return False, "authorization snapshot expired or not active", RejectionCode.SNAPSHOT_EXPIRED.value
        if proof.tool in embedded.forbidden_actions:
            return False, f"tool {proof.tool} is forbidden by authorization snapshot", RejectionCode.FORBIDDEN_ACTION.value
        if proof.tool not in embedded.allowed_tools or proof.tool not in embedded.allowed_actions:
            return False, f"tool {proof.tool} outside authorization snapshot allowlist", RejectionCode.TOOL_NOT_ALLOWED.value
        return True, "authorized", ""

    @classmethod
    def validate_against_mission(cls, proof: Any, mission: Any, *, at: str | None = None) -> tuple[bool, str, str]:
        """Re-validate a proof against the live mission right before execution (TOCTOU bound)."""
        if not isinstance(proof, ExecutionAuthorizationProof):
            return False, "execution proof is not a typed ExecutionAuthorizationProof", RejectionCode.PROOF_INVALID.value
        if str(mission.mission_id) != proof.mission_id:
            return False, "execution proof belongs to another mission", RejectionCode.PROOF_BINDING_MISMATCH.value
        if getattr(mission, "request_id", "") and proof.request_id != str(mission.request_id):
            return False, "execution proof belongs to another request", RejectionCode.PROOF_BINDING_MISMATCH.value
        if proof.plan_hash and proof.plan_hash != mission.plan.fingerprint:
            return False, "mission plan changed after proof derivation", RejectionCode.PLAN_MISMATCH.value
        if proof.scope_hash != _fingerprint(mission.scope_snapshot or {}):
            return False, "mission scope snapshot changed after proof derivation", RejectionCode.SCOPE_MISMATCH.value
        if str(getattr(mission.status, "value", str(mission.status))) != proof.mission_status or len(mission.transitions) != proof.lifecycle_revision:
            return False, "mission lifecycle changed after proof derivation", RejectionCode.LIFECYCLE_MISMATCH.value
        if proof.mission_status not in EXECUTION_ALLOWED_MISSION_STATUSES:
            return False, f"mission status {proof.mission_status} cannot execute tools", RejectionCode.LIFECYCLE_MISMATCH.value
        try:
            current = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError):
            return False, "mission authorization snapshot invalid", RejectionCode.SNAPSHOT_INVALID.value
        if current.authorization_hash != proof.snapshot_hash or int(current.version) != proof.snapshot_version:
            return False, "mission authorization snapshot changed after proof derivation", RejectionCode.SNAPSHOT_MISMATCH.value
        if not current.is_active(at=at):
            return False, "authorization snapshot expired or not active", RejectionCode.SNAPSHOT_EXPIRED.value
        return True, "authorized", ""


__all__ = [
    "EXECUTION_ALLOWED_MISSION_STATUSES",
    "ExecutionAuthorizationProof",
    "ExecutionProofError",
    "PROOF_TTL_SECONDS",
    "RejectionCode",
    "canonical_execution_fingerprint",
    "classify_snapshot_reason",
]
