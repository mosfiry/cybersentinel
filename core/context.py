from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any


@dataclass(frozen=True)
class ExecutionContext:
    """Execution metadata plus an optional, non-serializable Mission tool capability.

    The capability fields are populated only by ``tools.registry.execute`` after
    its normal Owner, Mission, scope, delegation, and execution-fence checks.
    They are deliberately omitted from ``to_dict`` and are injected only into
    ToolSpecs that explicitly declare ``execution_context_required``.
    """

    request_id: str
    owner_authenticated: bool
    owner_identity: str
    policy_snapshot: str
    provider: str = "local"
    model: str = "deterministic"
    authority: dict[str, Any] = field(default_factory=dict)
    owner_session_id: str | None = None
    authentication_method: str = "username_password"
    authenticated_at: str | None = None
    owner_instruction_snapshot: str = ""
    owner_instruction_fingerprint: str = ""
    policy_snapshot_details: dict[str, Any] = field(default_factory=dict)
    scope_snapshot: dict[str, Any] = field(default_factory=dict)
    authorization_context: dict[str, Any] = field(default_factory=dict)
    authorization_decisions: tuple[dict[str, Any], ...] = ()

    # Live capabilities: never serialize these into a provider prompt or event.
    mission_id: str = ""
    execution_id: str = ""
    target_identity: str = ""
    tool_id: str = ""
    tool_argument: Any = field(default=None, repr=False, compare=False)
    owner_authorization: Any = field(default=None, repr=False, compare=False)
    mission_authorization: Any = field(default=None, repr=False, compare=False)
    mission_authorization_version: int | None = field(default=None, repr=False, compare=False)
    authorization_decision: Any = field(default=None, repr=False, compare=False)
    execution_fence: Any = field(default=None, repr=False, compare=False)
    evidence_store: Any = field(default=None, repr=False, compare=False)
    artifact_store: Any = field(default=None, repr=False, compare=False)
    cancellation_event: Event | None = field(default=None, repr=False, compare=False)
    delegation_scope: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Return public execution metadata, excluding live authority objects."""
        result = {
            "request_id": self.request_id,
            "owner_authenticated": self.owner_authenticated,
            "owner_identity": self.owner_identity,
            "policy_snapshot": self.policy_snapshot,
            "provider": self.provider,
            "model": self.model,
            "authority": dict(self.authority),
            "owner_session_id": self.owner_session_id,
            "authentication_method": self.authentication_method,
            "authenticated_at": self.authenticated_at,
            "owner_instruction_snapshot": self.owner_instruction_snapshot,
            "owner_instruction_fingerprint": self.owner_instruction_fingerprint,
            "policy_snapshot_details": dict(self.policy_snapshot_details),
            "scope_snapshot": dict(self.scope_snapshot),
            "authorization_context": dict(self.authorization_context),
            "authorization_decisions": tuple(dict(item) for item in self.authorization_decisions),
        }
        if self.mission_id:
            result.update({
                "mission_id": self.mission_id,
                "execution_id": self.execution_id,
                "target_identity": self.target_identity,
                "tool_id": self.tool_id,
            })
            if self.mission_authorization_version is not None:
                result["mission_authorization_version"] = self.mission_authorization_version
        return result

    def assert_active(self) -> None:
        """Revalidate the exact Owner/Mission/tool/fence binding at use time."""
        from agent.execution_fence import ExecutionFenceError
        from security.authorization_context import AuthorizationContext, AuthorizationDecision
        from security.mission_authorization import MissionAuthorizationSnapshot

        if self.cancellation_event is not None and self.cancellation_event.is_set():
            raise PermissionError("tool execution cancelled")
        if not self.owner_authenticated or not self.request_id or not self.mission_id or not self.execution_id or not self.tool_id:
            raise PermissionError("a fully bound Owner/Mission execution context is required")
        if not isinstance(self.owner_authorization, AuthorizationContext):
            raise PermissionError("canonical Owner authorization context is required")
        if not isinstance(self.mission_authorization, MissionAuthorizationSnapshot):
            raise PermissionError("integrity-bound Mission authorization is required")
        if not isinstance(self.authorization_decision, AuthorizationDecision):
            raise PermissionError("signed tool authorization decision is required")
        if self.owner_authorization.request_id != self.request_id or self.owner_authorization.session_id != self.owner_session_id:
            raise PermissionError("Owner authorization request/session binding mismatch")
        evidence = self.owner_authorization.owner_evidence
        if not evidence.is_valid(self.request_id, self.owner_session_id) and not evidence.is_valid_for_active_session(
            self.request_id, self.owner_session_id
        ):
            raise PermissionError("Owner session is no longer active")
        if self.owner_authorization.scope_snapshot is None:
            raise PermissionError("canonical persisted Owner scope snapshot is required")
        if not self.authorization_decision.is_valid_for(self.tool_id, self.tool_argument, self.request_id):
            raise PermissionError("tool authorization expired or no longer matches its arguments")

        active_owner = None
        try:
            from security.owner_password import authenticated_owner
            active_owner = authenticated_owner(str(self.owner_session_id or ""))
        except Exception:
            active_owner = None
        if not isinstance(active_owner, dict) or active_owner.get("owner_id") is None:
            raise PermissionError("canonical active Owner identity is unavailable")
        canonical_owner = f"owner:{int(active_owner['owner_id'])}"
        if self.owner_identity != canonical_owner or self.mission_authorization.owner_identity != canonical_owner:
            raise PermissionError("canonical Owner identity does not match the Mission")

        expected_version = self.mission_authorization_version
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version != self.mission_authorization.version
        ):
            raise PermissionError("Mission authorization snapshot version is not bound to the current Mission")
        valid, reason = self.mission_authorization.validate_for_mission(
            mission_id=self.mission_id,
            owner_identity=canonical_owner,
            target_identity=self.target_identity,
            version=expected_version,
        )
        if not valid:
            raise PermissionError("Mission authorization is not current: " + reason)
        allowed, reason = self.mission_authorization.check(
            action=self.tool_id,
            tool_id=self.tool_id,
            target_identity=self.target_identity,
        )
        if not allowed:
            raise PermissionError("Mission authorization blocked tool use: " + reason)
        if self.delegation_scope is not None:
            from agent.intelligence_layer.models import DelegationScope

            if not isinstance(self.delegation_scope, DelegationScope):
                raise PermissionError("delegated execution context requires a typed DelegationScope")
            self.delegation_scope.validate_current(
                self.mission_authorization,
                authorization_version=expected_version,
            )
            if (
                not self.delegation_scope.is_within_owner_authorization(self.mission_authorization)
                or self.tool_id not in self.delegation_scope.allowed_tools
                or self.tool_id not in self.delegation_scope.allowed_actions
                or self.target_identity != self.delegation_scope.target_identity
            ):
                raise PermissionError("delegated execution context exceeds its Owner-bound task grant")
        if not self.authorization_context:
            raise PermissionError("integrity-bound Owner authorization record is required")
        expected_fingerprints = {
            "owner_evidence_fingerprint": self.owner_authorization.owner_evidence_fingerprint,
            "policy_fingerprint": self.owner_authorization.policy_fingerprint,
            "scope_fingerprint": self.owner_authorization.scope_fingerprint,
        }
        if any(self.authorization_context.get(name) != value for name, value in expected_fingerprints.items()):
            raise PermissionError("persisted Owner authorization fingerprints do not match canonical records")

        scope = self.scope_snapshot
        canonical_scope = self.owner_authorization.scope_snapshot
        if not isinstance(scope, dict) or not {"program_id", "target_id", "scope_snapshot_id", "url"}.issubset(scope):
            raise PermissionError("complete Mission scope context is required")
        if (
            scope.get("scope_snapshot_id") != canonical_scope.snapshot_id
            or scope.get("program_id") != canonical_scope.authorization.program_id
            or canonical_scope.target(str(scope.get("target_id"))) is None
        ):
            raise PermissionError("Mission scope context differs from the canonical Owner snapshot")
        if canonical_scope.authorization.owner_session_id and canonical_scope.authorization.owner_session_id != self.owner_session_id:
            raise PermissionError("scope snapshot belongs to a different Owner session")

        fence = self.execution_fence
        if fence is None:
            raise ExecutionFenceError("active execution fence is required")
        fence.assert_dispatch(
            mission_id=self.mission_id,
            request_id=self.request_id,
            execution_id=self.execution_id,
            authorization_snapshot=self.mission_authorization,
        )
        evidence_store = self.evidence_store
        if (
            evidence_store is None
            or not bool(getattr(evidence_store, "require_execution_fence", False))
            or getattr(evidence_store, "mission_store", None) is not getattr(fence.queue, "mission_store", None)
            or str(getattr(getattr(evidence_store, "mission", None), "mission_id", "")) != self.mission_id
            or getattr(evidence_store, "execution_fence", None) != fence
        ):
            raise ExecutionFenceError("strict Mission evidence store bound to the current fence is required")
        if self.artifact_store is not None:
            evidence_path = Path(str(getattr(evidence_store, "db_path", ""))).resolve()
            artifact_path = Path(str(getattr(self.artifact_store, "db_path", ""))).resolve()
            if evidence_path.parent != artifact_path.parent:
                raise PermissionError("artifact store is outside the Mission data boundary")
