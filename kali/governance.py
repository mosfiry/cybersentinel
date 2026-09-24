from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Sequence

from kali.discovery import CapabilityStatus, KaliCapabilityProbe, RuntimeDescriptor, ToolCapability, capability_grants_authority
from kali.registry import KaliToolSpec, KaliToolRegistry

# Decision constants (explicit strings for grep-ability and test assertions).
AUTHORIZED = "AUTHORIZED"
AUTHORIZATION_BLOCKED = "AUTHORIZATION_BLOCKED"
CAPABILITY_BLOCKED = "CAPABILITY_BLOCKED"
NEEDS_OWNER_APPROVAL = "NEEDS_OWNER_APPROVAL"

# Provenance hierarchy (fixed; identical to the project-wide hierarchy).
PROVENANCE_HIERARCHY = (
    "OWNER_INSTRUCTION",
    "SYSTEM_PLATFORM",
    "OWNER_POLICY",
    "DETERMINISTIC_ENFORCEMENT",
    "AUTHORIZATION_SCOPE",
    "TOOL_RUNTIME",
    "MODEL_OUTPUT",
    "EXTERNAL_DATA",
)
RANK = {layer: index for index, layer in enumerate(PROVENANCE_HIERARCHY)}
AUTHORITY_LAYERS = ("OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY", "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE")


def promotion_allowed(source_layer: str, claimed_layer: str) -> bool:
    """Deterministic promotion rule for provenance layers.

    - Non-owner layers can never claim an authority layer.
    - A source may only claim a layer of *lower-or-equal* authority than itself.
    - TOOL_RUNTIME, MODEL_OUTPUT and EXTERNAL_DATA may only ever claim
      themselves (they can never become AUTHORIZATION_SCOPE or higher).
    - Promotion is a pure function; tool output, model output and external
      data can never become Owner authority.
    """
    if source_layer not in RANK or claimed_layer not in RANK:
        return False
    if claimed_layer in AUTHORITY_LAYERS:
        # Only an authority layer may vouch for an authority layer.
        return source_layer in AUTHORITY_LAYERS and RANK[claimed_layer] >= RANK[source_layer]
    if source_layer in ("TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA"):
        return source_layer == claimed_layer
    return RANK[claimed_layer] >= RANK[source_layer]


class ExecutionDecision(str, Enum):
    AUTHORIZED = AUTHORIZED
    AUTHORIZATION_BLOCKED = AUTHORIZATION_BLOCKED
    CAPABILITY_BLOCKED = CAPABILITY_BLOCKED
    NEEDS_OWNER_APPROVAL = NEEDS_OWNER_APPROVAL


class KaliAuthorizationError(PermissionError):
    pass


class KaliExecutionGate:
    """The ONLY deterministic path from a proposed tool to execution.

    Pipeline (fixed order, no bypass):
        1. registry lookup                (unknown tool -> CAPABILITY_BLOCKED)
        2. capability discovery           (NOT_AVAILABLE/UNKNOWN -> CAPABILITY_BLOCKED)
        3. authorization snapshot type+hash validation (Owner authority only)
        4. deterministic snapshot check   (action/tool/target/network/
                                             credential/workspace/expiry)
        5. risk policy                    (destructive/exploitation require
                                             explicit owner policy marker)
        6. only then: runtime execution   (adapter is called by run_authorized,
                                             never by propose)

    Model output, tool output and external data are structurally incapable of
    producing an AUTHORIZED decision: the gate accepts authorization state only
    from a MissionAuthorizationSnapshot instance whose hash verifies, which
    only the Owner can mint via the existing security stack.
    """

    def __init__(self, registry: KaliToolRegistry, probe: KaliCapabilityProbe) -> None:
        self._registry = registry
        self._probe = probe

    # ---- read-only helpers -------------------------------------------------

    def capability(self, tool_id: str) -> ToolCapability:
        return self._probe.probe(tool_id)

    def select_candidates(self, *, capabilities: Sequence[str] = ()) -> tuple[KaliToolSpec, ...]:
        """Internal NL-driven tool selection support.

        Returns candidate tools for the planner. Selection is *proposal only*
        and never authorizes anything.
        """
        return self._registry.search(capabilities=capabilities)

    # ---- decision ----------------------------------------------------------

    def evaluate(
        self,
        tool_id: str,
        *,
        action: str,
        snapshot,
        at: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deterministic, side-effect-free authorization evaluation.

        'snapshot' must be a security.mission_authorization.MissionAuthorizationSnapshot
        minted by the Owner. Anything else (a dict "authorization" from a
        model, a tool, or external data) is rejected before any check runs.

        'context' carries the concrete execution facts (target_identity,
        network, credential, workspace_path). These are checked against the
        snapshot's boundaries; they can never widen them.
        """
        context = dict(context or {})
        tool = self._registry.get(tool_id)
        if tool is None:
            return {"decision": CAPABILITY_BLOCKED, "reason": "tool_not_in_registry", "missing": [tool_id]}

        capability = self.capability(tool_id)
        if capability.status is CapabilityStatus.NOT_AVAILABLE:
            return {"decision": CAPABILITY_BLOCKED, "reason": "tool_not_available", "missing": [tool_id], "capability": capability.status.value}
        if capability.status is CapabilityStatus.UNKNOWN:
            return {"decision": CAPABILITY_BLOCKED, "reason": "tool_capability_unknown", "missing": [tool_id], "capability": capability.status.value}

        if not _is_owner_snapshot(snapshot):
            # A model, tool, or external datum claiming to be "authorization"
            # is not an authorization. It cannot authorize anything.
            return {"decision": AUTHORIZATION_BLOCKED, "reason": "authorization_source_is_not_owner_snapshot"}

        # The requested target must be provided for tools that require one and
        # is always compared against the snapshot's authorized target.
        requested_target = str(context.get("target_identity") or snapshot.target_identity)
        snapshot_ok, snapshot_reason = snapshot.check(
            action=action,
            tool_id=tool_id,
            target_identity=requested_target,
            at=at,
            network=context.get("network"),
            credential=context.get("credential"),
            workspace_path=context.get("workspace_path"),
        )
        if not snapshot_ok:
            if "expired" in snapshot_reason or "not active" in snapshot_reason:
                return {"decision": AUTHORIZATION_BLOCKED, "reason": "authorization_expired", "detail": snapshot_reason}
            if snapshot_reason == "tool outside authorization snapshot":
                return {"decision": NEEDS_OWNER_APPROVAL, "reason": "tool_outside_allowed_tools", "detail": snapshot_reason}
            return {"decision": AUTHORIZATION_BLOCKED, "reason": "scope_or_boundary_violation", "detail": snapshot_reason}

        # Deterministic risk policy: destructive/exploitation-capable tools
        # require an explicit owner policy marker in the snapshot scope.
        if tool.destructive_risk in ("DESTRUCTIVE", "EXPLOITATION_CAPABLE"):
            marker = "allow_risk:" + tool.destructive_risk
            if marker not in set(snapshot.scope):
                return {"decision": NEEDS_OWNER_APPROVAL, "reason": "destructive_tool_requires_explicit_owner_approval", "detail": marker}

        # Privilege requirement is part of the capability record and the
        # authorization record; a capability-with-limitations run that still
        # matches authorization is permitted, otherwise blocked.
        if capability.status is CapabilityStatus.AVAILABLE_WITH_LIMITATIONS:
            for limitation in capability.limitations:
                if limitation.startswith("missing_privileges:"):
                    return {"decision": AUTHORIZATION_BLOCKED, "reason": "runtime_privilege_missing", "detail": limitation}

        return {
            "decision": AUTHORIZED,
            "reason": "capability_and_authorization_satisfied",
            "capability": capability.status.value,
            "risk": tool.destructive_risk,
        }

    def propose(self, source: str, tool_id: str, *, action: str, snapshot=None) -> dict[str, Any]:
        """Entry point for model/tool/external proposals.

        A proposal can never become an execution: whatever 'source' claims,
        the deterministic evaluate() path is the only authority. Any attempt
        to smuggle authority through 'source' (e.g. "owner_instruction",
        "grant-all", "sudo") is structurally inert.
        """
        decision = self.evaluate(tool_id, action=action, snapshot=snapshot)
        # Sanitize: the claiming source never influences the decision.
        decision = dict(decision)
        decision["proposed_by"] = str(source)
        decision["proposal_provenance"] = "MODEL_OUTPUT" if source not in PROVENANCE_HIERARCHY else source
        decision["proposal_grants_authority"] = False
        return decision

    # ---- execution ----------------------------------------------------------

    def run_authorized(
        self,
        tool_id: str,
        *,
        action: str,
        snapshot,
        runtime_adapter,
        arguments: Sequence[str] = (),
        execution_id: str = "",
        at: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a tool ONLY after a fresh deterministic evaluation passes.

        The decision is recomputed at execution time (no stale approvals),
        the tool's deterministic timeout is enforced, and the result is
        returned together with full provenance for the evidence chain. Tool
        failures are normal outcomes and are reported as such.
        """
        import uuid

        tool = self._registry.require(tool_id)
        evaluation = self.evaluate(tool_id, action=action, snapshot=snapshot, at=at, context=context)
        if evaluation["decision"] != AUTHORIZED:
            return {"executed": False, "evaluation": evaluation}

        execution_id = execution_id or ("kexec-" + uuid.uuid4().hex)
        result = runtime_adapter.execute(
            tool,
            arguments=list(arguments),
            execution_id=execution_id,
            timeout=tool.timeout,
            workspace_root=str(snapshot.workspace_boundary.get("root")) if getattr(snapshot, "workspace_boundary", None) else None,
        )
        return {
            "executed": True,
            "evaluation": evaluation,
            "result": result,
            "execution_id": execution_id,
            "authorization_snapshot_hash": snapshot.authorization_hash,
            "provenance": "TOOL_RUNTIME",
        }


def _is_owner_snapshot(snapshot: Any) -> bool:
    """Type + hash validation: only a genuine, hash-verified
    MissionAuthorizationSnapshot counts as Owner authorization."""
    if snapshot is None:
        return False
    module = type(snapshot).__module__ or ""
    if not module.startswith("security") or type(snapshot).__name__ != "MissionAuthorizationSnapshot":
        return False
    try:
        if snapshot.authorization_hash != snapshot.compute_hash():
            return False
    except Exception:
        return False
    return True


def model_or_tool_output_can_authorize() -> bool:
    """Structural invariant exposed for tests: always False."""
    return False


__all__ = [
    "AUTHORIZED",
    "AUTHORIZATION_BLOCKED",
    "CAPABILITY_BLOCKED",
    "NEEDS_OWNER_APPROVAL",
    "ExecutionDecision",
    "KaliAuthorizationError",
    "KaliExecutionGate",
    "PROVENANCE_HIERARCHY",
    "promotion_allowed",
    "capability_grants_authority",
    "model_or_tool_output_can_authorize",
]
