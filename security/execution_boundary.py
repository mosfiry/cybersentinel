from __future__ import annotations

"""Canonical execution boundary.

This module is the single canonical point where governed tool execution is
bound to its authorization. Every production caller reaches the tool registry
through the same sequence:

    AuthorizationDecision
        + canonical arguments
        + execution identity (mission / request / tool call)
        + Owner-minted snapshot (mission class) or AuthorizationDecision (owner-direct class)
        + plan / scope / policy / lifecycle (mission class)
        -> ExecutionAuthorizationProof.derive()
        -> ExecutionAuthorizationProof.validate_against_mission()
        -> registry final verification
        -> handler

The boundary derives and validates evidence of authorization that ALREADY
exists. It never creates, widens, or repairs authority, and model output or
external data can never supply any of its inputs. The registry remains
defense-in-depth: it independently re-verifies the proof, the execution
class, the decision binding and the live snapshot agreement.
"""

from typing import Any

from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass
from security.mission_authorization import MissionAuthorizationSnapshot


class MissionExecutionBoundary:
    """Canonical boundary for mission-bound tool execution."""

    @staticmethod
    def derive(mission: Any, *, tool: str, argument: Any, decision: Any = None, tool_call_id: str = "", plan_hash: str | None = None, scope: Any = None, scope_context: Any = None) -> ExecutionAuthorizationProof:
        """Derive the MISSION_BOUND proof for exactly one execution.

        All bindings come from the live Mission object and the Owner-minted
        snapshot; none of them can be supplied by model output.
        """
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        return ExecutionAuthorizationProof.derive(
            execution_class=ExecutionClass.MISSION_BOUND.value,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            tool=tool,
            argument=argument,
            snapshot=snapshot,
            decision=decision,
            tool_call_id=tool_call_id,
            plan_hash=plan_hash if plan_hash is not None else mission.plan.fingerprint,
            scope=scope if scope is not None else mission.scope_snapshot,
            scope_context=scope_context,
            mission_status=mission.status.value,
            lifecycle_revision=len(mission.transitions),
        )

    @staticmethod
    def scope_context_for_call(mission: Any, *, tool: str, argument: Any, authorization_context: Any) -> Any:
        """Project validated mission authority into a tool's per-call context.

        This projection is passed to the registry separately from the execution
        proof. The proof remains bound to the durable mission scope snapshot.
        """
        from tools.registry import get_tool

        spec = get_tool(tool)
        if spec is None or not spec.scope_required:
            return mission.scope_snapshot
        if tool != "scoped_http_probe":
            raise PermissionError("scope context derivation is unavailable for this tool")

        from security.authorization_context import AuthorizationContext
        from tools.scoped_http_probe import validate_scope_context_fields

        if not isinstance(authorization_context, AuthorizationContext):
            raise PermissionError("scope-required tool needs a typed Owner AuthorizationContext")
        binding = mission.scope_snapshot if isinstance(mission.scope_snapshot, dict) else {}
        persisted_scope = authorization_context.scope_snapshot
        target_id = str(binding.get("target_id") or "")
        selected_target = persisted_scope.target(target_id) if persisted_scope is not None and target_id else None
        bound_fingerprint = str(binding.get("scope_snapshot_fingerprint") or "")
        if (
            persisted_scope is None
            or selected_target is None
            or authorization_context.session_id != persisted_scope.authorization.owner_session_id
            or persisted_scope.snapshot_id != str(binding.get("scope_snapshot_id") or "")
            or persisted_scope.authorization.program_id != str(binding.get("program_id") or "")
            or not bound_fingerprint
            or authorization_context.scope_fingerprint != bound_fingerprint
        ):
            raise PermissionError("mission scope binding differs from the persisted Owner snapshot")

        return validate_scope_context_fields({
            "program_id": persisted_scope.authorization.program_id,
            "target_id": selected_target.target_id,
            "scope_snapshot_id": persisted_scope.snapshot_id,
            "url": argument,
        })

    @staticmethod
    def validate(proof: Any, mission: Any) -> tuple[bool, str, str]:
        """Re-validate the proof against the live mission right before execution."""
        return ExecutionAuthorizationProof.validate_against_mission(proof, mission)

    @staticmethod
    def execute(mission: Any, *, tool: str, argument: Any, decision: Any = None, tool_call_id: str = "", scope_context: Any = None, execute: Any = None, **governed: Any) -> Any:
        """derive -> validate against live mission -> registry execution."""
        from tools.registry import execute as registry_execute
        proof = MissionExecutionBoundary.derive(mission, tool=tool, argument=argument, decision=decision, tool_call_id=tool_call_id, scope_context=scope_context)
        ok, reason, code = MissionExecutionBoundary.validate(proof, mission)
        if not ok:
            raise PermissionError(f"{code}: {reason}")
        return (execute or registry_execute)(tool, argument, authorization_decision=decision, scope_context=scope_context, execution_proof=proof, execution_class=ExecutionClass.MISSION_BOUND.value, tool_call_id=tool_call_id, mission_id=mission.mission_id, request_id=mission.request_id, **governed)


class OwnerDirectBoundary:
    """Canonical boundary for owner-authenticated non-mission execution.

    This is an explicit execution class, not an implicit "mission_bound=False"
    escape: the proof is derived from the typed AuthorizationDecision that
    authorized the execution, binds its canonical decision signature and
    policy fingerprint, and cannot exist without them.
    """

    @staticmethod
    def derive(*, tool: str, argument: Any, decision: Any, request_id: str, tool_call_id: str = "", scope_context: Any = None) -> ExecutionAuthorizationProof:
        return ExecutionAuthorizationProof.derive(
            execution_class=ExecutionClass.OWNER_DIRECT.value,
            mission_id="",
            request_id=request_id,
            tool=tool,
            argument=argument,
            snapshot=None,
            decision=decision,
            tool_call_id=tool_call_id,
            scope=scope_context,
            scope_context=scope_context,
        )

    @staticmethod
    def execute(*, tool: str, argument: Any, decision: Any, request_id: str, tool_call_id: str = "", scope_context: Any = None, execute: Any = None, **kwargs: Any) -> Any:
        from tools.registry import execute as registry_execute
        proof = OwnerDirectBoundary.derive(tool=tool, argument=argument, decision=decision, request_id=request_id, tool_call_id=tool_call_id, scope_context=scope_context)
        return (execute or registry_execute)(tool, argument, authorization_decision=decision, scope_context=scope_context, request_id=request_id, tool_call_id=tool_call_id, execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value, **kwargs)


__all__ = ["MissionExecutionBoundary", "OwnerDirectBoundary"]
