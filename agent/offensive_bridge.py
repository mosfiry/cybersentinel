"""Offensive Capability Layer: the live typed reasoning-to-execution bridge.

P0 of the Offensive Capability Activation mission. This module is the
DETERMINISTIC BRIDGE that makes the previously isolated offensive reasoning
layer (agent/offensive_mind.py: OffensiveMind) and the authorization-bound
offensive planning layer (cyber/offensive.py: ScopeGuard,
OffensiveExecutionPlanner) LIVE parts of the executed runtime:

    Owner-authenticated mission (Owner Policy -> MissionAuthorizationSnapshot)
        |
        v
    OffensiveActionProposal  (typed, untrusted until validated)
        |
        v
    1. deterministic proposal validation (fail closed)
    2. tool registration check (catalog definition is NOT execution)
    3. mission identity binding (proposal must match the live mission:
       mission_id, request_id, live execution run id, plan fingerprint)
    4. SCOPE FIREWALL (ScopeGuard over a typed ScopeSnapshot; the guard's
       CANONICAL url becomes the tool argument — the proposal can never
       smuggle a raw url, and DNS/redirect observations can never widen scope)
    5. proof derivation through the EXISTING owner chain
       (ExecutionAuthorizationProof.derive over the mission snapshot)
    6. ToolAdapter.run — the EXISTING nine-phase contract; execution happens
       ONLY through tools.registry.execute (INV-ADP-2)
    7. structured record + evidence (the existing adapter evidence envelope)

INVARIANTS (INV-OFF-1..7):

- INV-OFF-1 (proposal is not authority): a proposal is untrusted input. It
  can only DESCRIBE a desired action; every binding decision (scope,
  authorization, plan, run) is recomputed from typed owner-side state.
- INV-OFF-2 (scope firewall is mandatory for network actions): a network
  proposal without a typed ScopeSnapshot, or outside the snapshot's
  authorized assets, is rejected BEFORE any proof derivation or execution.
  The executed argument is the guard's canonical url, never the raw
  proposal text. Observed endpoints (redirects, DNS results) can never
  become authorized targets — only the typed snapshot decides.
- INV-OFF-3 (single execution path): the bridge has NO execution surface of
  its own. It composes ScopeGuard + ExecutionAuthorizationProof.derive +
  ToolAdapter.run. The only way to reach a handler remains
  tools.registry.execute.
- INV-OFF-4 (no authority creation): the bridge never mints authority. The
  proof is derived from the mission's owner-authorized snapshot via the
  existing derive() path; the adapter only VERIFIES it (INV-ADP-1).
- INV-OFF-5 (feedback is not authorization): feedback_event() maps an
  execution record to an OffensiveMind.adapt event. A next hypothesis is
  reasoning, never authority — any next action must re-enter this bridge and
  pass validation, scope, and authorization again.
- INV-OFF-6 (fail closed): every rejection is returned as a REJECTED record
  with a deterministic reason; no partial execution, no fallback.
- INV-OFF-7 (dry-run is real): dry_run=True flows to the adapter contract;
  validation, scope, authorization, and preparation run, nothing executes.

The authority hierarchy is unchanged and unchangeable here:
OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY > DETERMINISTIC_ENFORCEMENT
> AUTHORIZATION_SCOPE > TOOL_RUNTIME > MODEL_OUTPUT > EXTERNAL_DATA.
Model output (a proposal's rationale), tool output (observations), and
external data can never widen scope or mint authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import tools.registry
from cyber.offensive import GuardDecision, OffensiveAction, ScopeGuard
from security.authorization_context import AuthorizationDecision
from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, RejectionCode
from security.mission_authorization import MissionAuthorizationSnapshot
from security.tool_adapter import (
    AdapterErrorCode,
    AdapterPhase,
    LocalProcessInfoAdapter,
    ToolAdapter,
    ToolAdapterError,
    ToolAdapterRequest,
    _classify_rejection,
    _rejection_code_from_message,
)

__all__ = [
    "LOCAL_PROCESS_INFO_ADAPTER",
    "OffensiveActionProposal",
    "OffensiveActionRejected",
    "OffensiveActionBridge",
    "OffensiveExecutionRecord",
    "ScopedHttpProbeAdapter",
    "ScopedDnsLookupAdapter",
]

# Target kinds: "local" = local read-only analysis (no network surface, the
# scope firewall is not applicable); "network" = the scope firewall is
# MANDATORY (typed ScopeSnapshot + in-scope target identity).
TARGET_KINDS = ("local", "network")


@dataclass(frozen=True)
class OffensiveActionProposal:
    """A typed offensive action proposal. UNTRUSTED until the bridge validates it.

    The proposal DESCRIBES a desired action. It carries no authority: every
    binding (scope, authorization, plan, run) is recomputed by the bridge
    from typed owner-side state (INV-OFF-1).
    """

    proposal_id: str
    mission_id: str
    request_id: str
    tool_id: str
    plan_hash: str
    target_kind: str = "local"
    target_url: str = ""
    target_id: str = ""
    argument: Any = None
    hypothesis_id: str = ""
    required_evidence: tuple[str, ...] = ()
    risk_class: str = ""
    source_step_id: str = ""
    execution_run_id: str = ""
    rationale: str = ""


class OffensiveActionRejected(Exception):
    """Deterministic bridge rejection. Never a source of authority; never success."""

    def __init__(self, reason: str, *, guard: GuardDecision | None = None) -> None:
        super().__init__(reason)
        self.reason = str(reason)
        self.guard = guard


@dataclass(frozen=True)
class OffensiveExecutionRecord:
    """Structured bridge outcome: proposal identity, scope decision, result."""

    status: str  # EXECUTED | DRY_RUN | REJECTED
    proposal: OffensiveActionProposal | None
    reason: str = ""
    guard_decision: dict[str, Any] = field(default_factory=dict)
    proof_fingerprint: str = ""
    executed: bool = False
    result: Any = None  # AdapterResult when not REJECTED


class ScopedHttpProbeAdapter(ToolAdapter):
    """Adapter for the registered scoped_http_probe observation tool.

    The tool executes ONLY through tools.registry.execute behind the full
    proof chain; this adapter adds the contract phases, not a new path.
    """

    tool_name = "scoped_http_probe"
    timeout_seconds = 10
    # The registry demands a typed Owner AuthorizationDecision for
    # scope_required tools; the decision is owner-side authority, verified —
    # never minted — here (INV-OFF-4).
    requires_authorization_decision = True

    def __init__(self) -> None:
        super().__init__()
        self._bound_scope_context: dict[str, Any] | None = None
        self._bound_decision: AuthorizationDecision | None = None

    def bind_authorization(self, decision: AuthorizationDecision) -> "ScopedHttpProbeAdapter":
        """Bind the typed Owner AuthorizationDecision for the NEXT execution."""
        if not isinstance(decision, AuthorizationDecision) or not decision.allowed:
            raise OffensiveActionRejected("scope-bound execution requires an allowed typed Owner AuthorizationDecision")
        self._bound_decision = decision
        return self

    def bind_scope(self, scope_context: dict[str, Any]) -> "ScopedHttpProbeAdapter":
        """Bind the typed owner-side scope context for the NEXT execution.

        The context is composed ONLY from typed owner-side state (the scope
        snapshot's program identity, the proposal's target identity, the
        guard's canonical url). It is never derived from tool output or
        model output (INV-OFF-2).
        """
        required = {"program_id", "target_id", "scope_snapshot_id", "url"}
        if not isinstance(scope_context, dict) or not required.issubset(scope_context):
            raise OffensiveActionRejected("scope-bound tool requires a complete typed scope context")
        self._bound_scope_context = dict(scope_context)
        return self

    def execute(self, request: ToolAdapterRequest, authorization: Any, prepared: Any) -> Any:
        """Execute through the canonical registry boundary WITH the scope context.

        scoped_http_probe is a scope_required registry tool: tools.registry.execute
        re-resolves the request against the typed scope snapshot store before the
        handler is reachable. Without a bound context the tool fails closed.
        """
        context = getattr(self, "_bound_scope_context", None)
        decision = getattr(self, "_bound_decision", None)
        if context is None:
            raise ToolAdapterError(
                AdapterPhase.EXECUTE,
                AdapterErrorCode.AUTHORIZATION_DENIED,
                "scope-bound execution requires a bound typed scope context",
                tool=str(request.tool or ""),
                rejection_code=RejectionCode.SCOPE_MISMATCH.value,
            )
        if decision is None:
            raise ToolAdapterError(
                AdapterPhase.EXECUTE,
                AdapterErrorCode.AUTHORIZATION_DENIED,
                "scope-bound execution requires a bound typed Owner AuthorizationDecision",
                tool=str(request.tool or ""),
                rejection_code=RejectionCode.PROOF_REQUIRED.value,
            )
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(request.mission, "authorization_snapshot", None) or {}))
        except Exception as exc:
            raise ToolAdapterError(
                AdapterPhase.EXECUTE,
                AdapterErrorCode.AUTHORIZATION_DENIED,
                "live mission authorization snapshot is invalid: " + str(exc),
                tool=str(request.tool or ""),
                rejection_code=RejectionCode.SNAPSHOT_INVALID.value,
            ) from None
        try:
            return tools.registry.execute(
                request.tool,
                request.argument,
                mission_id=request.mission_id,
                request_id=request.request_id,
                mission_authorization=snapshot,
                execution_proof=request.execution_proof,
                execution_class=ExecutionClass.MISSION_BOUND.value,
                execution_run_id=request.run_id,
                timeout=prepared.timeout,
                scope_context=dict(context),
                authorization_decision=decision,
            )
        except PermissionError as exc:
            code = _rejection_code_from_message(str(exc))
            raise ToolAdapterError(AdapterPhase.EXECUTE, _classify_rejection(code), str(exc), tool=str(request.tool or ""), rejection_code=code) from None
        except TimeoutError as exc:
            raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.TIMEOUT, str(exc), tool=str(request.tool or "")) from None
        except ValueError as exc:
            raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.INPUT_INVALID, str(exc), tool=str(request.tool or "")) from None


class ScopedDnsLookupAdapter(ScopedHttpProbeAdapter):
    """Adapter for the registered scoped_dns_lookup observation tool (P1).

    Same contract as the scoped probe adapter, for the DNS observation
    family: the typed Owner AuthorizationDecision and the typed owner-side
    scope context are bound BEFORE execution, and the tool executes ONLY
    through tools.registry.execute, which re-resolves the scope snapshot and
    re-verifies the decision binding (INV-OFF-3/INV-OFF-4). Resolved
    addresses are OBSERVED data — they can never become authorized targets
    (INV-OFF-2).
    """

    tool_name = "scoped_dns_lookup"
    timeout_seconds = 10


LOCAL_PROCESS_INFO_ADAPTER = LocalProcessInfoAdapter()


def _live_run_id(mission: Any) -> str:
    progress = getattr(mission, "progress", None) or {}
    return str(progress.get("execution_run_id") or progress.get("model_run_id") or "")


class OffensiveActionBridge:
    """Composes scope firewall + existing proof chain + existing adapter contract.

    The bridge is deterministic and authority-free (INV-OFF-3, INV-OFF-4):
    it validates, composes typed owner-side state, and delegates. It has no
    registry write access, no proof minting, and no handler access.
    """

    def __init__(self, guard: ScopeGuard | None = None) -> None:
        self.guard = guard or ScopeGuard()

    # -- Phase 1: deterministic proposal validation (fail closed) ----------

    def validate_proposal(self, proposal: OffensiveActionProposal) -> None:
        if not isinstance(proposal, OffensiveActionProposal):
            raise OffensiveActionRejected("proposal must be a typed OffensiveActionProposal")
        for required in ("proposal_id", "mission_id", "tool_id", "plan_hash", "risk_class"):
            if not str(getattr(proposal, required, "") or ""):
                raise OffensiveActionRejected("proposal field is required: " + required)
        if proposal.target_kind not in TARGET_KINDS:
            raise OffensiveActionRejected("unknown target kind: {!r}".format(proposal.target_kind))
        if proposal.target_kind == "network":
            if not proposal.target_url or not proposal.target_id:
                raise OffensiveActionRejected("network proposals require target_url and target_id")
        else:
            if proposal.target_url or proposal.target_id:
                raise OffensiveActionRejected("local proposals must not carry network targets")

    # -- Phase 2: mission identity binding (proposal must match live state) -

    def _bind_mission(self, proposal: OffensiveActionProposal, mission: Any) -> str:
        if str(proposal.mission_id) != str(mission.mission_id):
            raise OffensiveActionRejected("proposal mission does not match the live mission")
        if str(proposal.request_id) != str(mission.request_id):
            raise OffensiveActionRejected("proposal request does not match the live mission")
        if str(proposal.plan_hash) != str(mission.plan.fingerprint):
            raise OffensiveActionRejected("proposal plan hash does not match the live mission plan (stale or tampered proposal)")
        live_run_id = _live_run_id(mission)
        if proposal.execution_run_id and str(proposal.execution_run_id) != live_run_id:
            raise OffensiveActionRejected("proposal execution run does not match the live execution run")
        return live_run_id

    # -- Phase 3: scope firewall (network actions only; typed snapshot) ---

    def _enforce_scope(self, proposal: OffensiveActionProposal, scope_snapshot: Any) -> tuple[GuardDecision | None, Any]:
        if proposal.target_kind != "network":
            return None, proposal.argument
        action = OffensiveAction(method="GET", url=proposal.target_url, target_id=proposal.target_id, rationale=proposal.rationale)
        decision = self.guard.evaluate(action, scope_snapshot)
        if not decision.allowed:
            raise OffensiveActionRejected(decision.reason, guard=decision)
        # The GUARD's canonical url is the executed argument: the raw
        # proposal url never reaches execution, and observed endpoints can
        # never widen scope (INV-OFF-2).
        return decision, decision.canonical_url

    # -- Phase 4/5/6: proof derivation through the existing owner chain ----

    def _derive_proof(self, proposal: OffensiveActionProposal, mission: Any, argument: Any, live_run_id: str, decision: Any = None) -> ExecutionAuthorizationProof:
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        return ExecutionAuthorizationProof.derive(
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            tool=proposal.tool_id,
            argument=argument,
            snapshot=snapshot,
            decision=decision,
            tool_call_id=proposal.proposal_id,
            run_id=live_run_id,
            plan_hash=mission.plan.fingerprint,
            scope=mission.scope_snapshot,
            mission_status=mission.status.value,
            lifecycle_revision=len(mission.transitions),
        )

    # -- Orchestration ------------------------------------------------------

    def run(
        self,
        proposal: OffensiveActionProposal,
        *,
        mission: Any,
        adapter: ToolAdapter,
        scope_snapshot: Any = None,
        authorization_decision: Any = None,
        dry_run: bool = False,
    ) -> OffensiveExecutionRecord:
        """Validate → bind → scope → authorize → execute → record. Fail closed."""
        self.validate_proposal(proposal)
        if tools.registry.get_tool(proposal.tool_id) is None:
            raise OffensiveActionRejected("tool is not registered in the runtime registry: " + str(proposal.tool_id))
        if getattr(adapter, "tool_name", "") != proposal.tool_id:
            raise OffensiveActionRejected("adapter does not wrap the proposed tool")
        if getattr(adapter, "requires_authorization_decision", False):
            if authorization_decision is None:
                raise OffensiveActionRejected("scope-bound tool execution requires a typed Owner AuthorizationDecision")
            binder_decision = getattr(adapter, "bind_authorization", None)
            if binder_decision is None:
                raise OffensiveActionRejected("adapter does not accept a bound AuthorizationDecision")
            binder_decision(authorization_decision)
        live_run_id = self._bind_mission(proposal, mission)
        guard_decision, argument = self._enforce_scope(proposal, scope_snapshot)
        if proposal.target_kind == "network":
            binder = getattr(adapter, "bind_scope", None)
            if binder is None:
                raise OffensiveActionRejected("network tool adapter does not support bound scope contexts")
            binder({
                "program_id": str(getattr(getattr(scope_snapshot, "authorization", None), "program_id", "")),
                "target_id": str(proposal.target_id),
                "scope_snapshot_id": str(getattr(scope_snapshot, "snapshot_id", "")),
                "url": str(argument),
                "method": "GET",
            })
        proof = self._derive_proof(proposal, mission, argument, live_run_id, decision=authorization_decision)
        request = ToolAdapterRequest(
            tool=proposal.tool_id,
            argument=argument,
            execution_class="MISSION_BOUND",
            execution_proof=proof,
            mission=mission,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            run_id=live_run_id,
        )
        result = adapter.run(request, dry_run=dry_run)
        return OffensiveExecutionRecord(
            status="DRY_RUN" if dry_run else ("EXECUTED" if result.ok else "REJECTED"),
            proposal=proposal,
            guard_decision=(guard_decision.to_dict() if guard_decision is not None else {}),
            proof_fingerprint=str(proof.execution_binding_hash),
            executed=bool(result.executed),
            result=result,
        )

    # -- Phase 7: reasoning feedback (NOT authorization) --------------------

    @staticmethod
    def feedback_event(record: OffensiveExecutionRecord) -> dict[str, Any]:
        """Map a record to an OffensiveMind.adapt event (INV-OFF-5).

        The event is reasoning input only. Any next action derived from it
        must re-enter the bridge and pass validation, scope, and authorization
        again — a hypothesis is never authority.
        """
        proposal = record.proposal
        if proposal is None:
            return {"type": "OBSERVATION", "note": "bridge rejected an unbindable proposal"}
        result = record.result
        outcome = "COMPLETED" if record.status == "EXECUTED" else "FAILED"
        note = ""
        if result is not None:
            normalized = getattr(result, "normalized_output", None)
            if isinstance(normalized, dict):
                note = " ".join(str(k) for k in sorted(normalized)[:16])
        event: dict[str, Any] = {
            "type": "STEP_RESULT",
            "step_id": proposal.source_step_id,
            "outcome": outcome,
            "tool": proposal.tool_id,
            "hypothesis_id": proposal.hypothesis_id,
        }
        if note:
            event["observation"] = note
        return event
