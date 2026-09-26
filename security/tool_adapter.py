from __future__ import annotations

"""Stage B (Security Tooling Expansion): the Tool Adapter contract (Layer 2).

A ToolAdapter is a STRICT ORCHESTRATION LAYER above the existing execution
chain. It never creates authority and never creates a second execution path:

    Owner Policy -> Authorization -> ExecutionPlan -> Proof -> Registry
                                                             -> ToolAdapter (this module)
                                                             -> Handler (via tools.registry.execute only)

Invariants (INV-ADP-1..8):

- INV-ADP-1 (adapter is not authority): the adapter VALIDATES existing
  authority; it never creates, widens, or repairs authorization. It cannot
  mint ExecutionAuthorizationProof objects (proof derivation stays in the
  runtime/authorization layers), cannot mint AuthorizationDecision objects,
  and cannot modify any snapshot, policy, or registry entry.
- INV-ADP-2 (single execution path): the ONLY way a adapter reaches a tool
  handler is tools.registry.execute with the full chain arguments
  (mission binding, typed proof, execution class, live run id). There is no
  direct handler call, no subprocess fallback, and no alternate registry.
- INV-ADP-3 (reject before execution): every authorization, plan, proof,
  scope, and availability rejection happens BEFORE tools.registry.execute is
  invoked, therefore before any handler can run. Post-execution failures
  (timeout, handler crash, normalization, evidence) are classified, never
  turned into false success.
- INV-ADP-4 (fail closed): a missing external binary, an unknown tool, a
  missing proof, a class confusion, or a malformed request fails closed with
  a classified error. Unavailability never degrades into a fallback path.
- INV-ADP-5 (dry-run is real): dry_run=True performs validation,
  authorization, and preparation but NEVER invokes tools.registry.execute,
  a handler, or a subprocess.
- INV-ADP-6 (evidence is structured, output is untrusted): raw tool output is
  UNTRUSTED DATA. Evidence is a separate structured record of bindings and
  output hashes; it can never carry authority, and no adapter output field
  can shape itself like authority (defense in depth: authority-shaped
  top-level output keys are rejected).
- INV-ADP-7 (cleanup always, cleanup is inert): cleanup runs exactly once
  per run() on every path (success, dry-run, and every failure). Cleanup is
  a side-effect-free hook: it receives no authorization, cannot re-execute
  the tool, and a cleanup failure can never convert an error into success.
- INV-ADP-8 (deterministic classification): every failure maps to exactly
  one (phase, code) pair, and security rejections carry the underlying
  RejectionCode from the existing chain. Model output, tool output, and
  external data can never select or alter a classification.

This module imports nothing from agent.* and never writes to
tools.registry.REGISTRY, security.owner_*, or any authorization store.
The dependency and no-minting rules are enforced by tests/test_tool_adapter.py.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
import shutil
from typing import Any

import tools.registry
from security.authorization_context import AuthorizationDecision
from security.execution_proof import (
    ExecutionAuthorizationProof,
    ExecutionClass,
    RejectionCode,
    canonical_execution_fingerprint,
)
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot


__all__ = [
    "ADAPTER_PHASES",
    "AdapterAuthorization",
    "AdapterErrorCode",
    "AdapterPhase",
    "AdapterResult",
    "LOCAL_SYSTEM_INFO_ADAPTER",
    "LocalSystemInfoAdapter",
    "PreparedExecution",
    "ToolAdapter",
    "ToolAdapterError",
    "ToolAdapterRequest",
]


class AdapterPhase(str, Enum):
    VALIDATE_INPUT = "VALIDATE_INPUT"
    AUTHORIZE = "AUTHORIZE"
    PREPARE = "PREPARE"
    DRY_RUN = "DRY_RUN"
    EXECUTE = "EXECUTE"
    NORMALIZE_OUTPUT = "NORMALIZE_OUTPUT"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    CLEANUP = "CLEANUP"


ADAPTER_PHASES = tuple(phase for phase in AdapterPhase)


class AdapterErrorCode(str, Enum):
    """Deterministic adapter error taxonomy (INV-ADP-8).

    Security rejections additionally carry the underlying chain RejectionCode
    in ToolAdapterError.rejection_code; they are never flattened into a
    generic success or a silent skip.
    """

    INPUT_INVALID = "INPUT_INVALID"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    PLAN_MISMATCH = "PLAN_MISMATCH"
    PROOF_FAILURE = "PROOF_FAILURE"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    TIMEOUT = "TIMEOUT"
    NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


_REJECTION_TO_ADAPTER: dict[str, AdapterErrorCode] = {
    RejectionCode.PROOF_REQUIRED.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PROOF_INVALID.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PROOF_EXPIRED.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PROOF_REPLAY.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PROOF_BINDING_MISMATCH.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PROOF_INCOMPLETE.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.RUN_MISMATCH.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.EXECUTION_CLASS_MISMATCH.value: AdapterErrorCode.PROOF_FAILURE,
    RejectionCode.PLAN_MISMATCH.value: AdapterErrorCode.PLAN_MISMATCH,
    RejectionCode.SNAPSHOT_MISSING.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.SNAPSHOT_INVALID.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.SNAPSHOT_EXPIRED.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.SNAPSHOT_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.TOOL_NOT_ALLOWED.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.ACTION_NOT_ALLOWED.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.FORBIDDEN_ACTION.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.SCOPE_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.TARGET_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.NETWORK_BOUNDARY_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.WORKSPACE_BOUNDARY_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.CREDENTIAL_BOUNDARY_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
    RejectionCode.LIFECYCLE_MISMATCH.value: AdapterErrorCode.AUTHORIZATION_DENIED,
}


def _classify_rejection(code: str) -> AdapterErrorCode:
    """Map a chain RejectionCode to the adapter taxonomy; unknown -> denied (fail closed)."""
    return _REJECTION_TO_ADAPTER.get(str(code), AdapterErrorCode.AUTHORIZATION_DENIED)


def _rejection_code_from_message(message: str) -> str:
    text = str(message)
    head = text.split(":", 1)[0].strip()
    return head if head in {item.value for item in RejectionCode} else ""


TOOL_NAME_PATTERN = re.compile(r"^[a-z0-9_]+$")

AUTHORITY_OUTPUT_TOKENS = (
    "authorization", "authorisation", "owner_token", "owner_evidence",
    "execution_proof", "proof_signature", "authorization_decision",
    "permission", "grant", "allowed_tools", "scope_expansion",
    "credential", "secret", "password", "token",
)


def _is_authority_shaped_key(name: Any) -> bool:
    folded = str(name).casefold()
    return any(token in folded for token in AUTHORITY_OUTPUT_TOKENS)


class ToolAdapterError(Exception):
    """Classified adapter failure. Never a source of authority; never success."""

    def __init__(self, phase: AdapterPhase, code: AdapterErrorCode, reason: str, *, tool: str = "", rejection_code: str = "") -> None:
        super().__init__(f"{phase.value}/{code.value}: {reason}")
        self.phase = AdapterPhase(phase)
        self.code = AdapterErrorCode(code)
        self.reason = str(reason)
        self.tool = str(tool)
        self.rejection_code = str(rejection_code or "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "code": self.code.value,
            "reason": self.reason,
            "tool": self.tool,
            "rejection_code": self.rejection_code,
        }


@dataclass(frozen=True)
class ToolAdapterRequest:
    """One adapter invocation request. Authority must ALREADY exist.

    The proof and (for owner-direct runs) the typed AuthorizationDecision are
    supplied by the caller (the runtime / owner-authenticated path), derived
    from the existing authorization layers. The adapter verifies them; it
    never derives them (INV-ADP-1).
    """

    tool: str
    argument: Any = None
    execution_class: str = ExecutionClass.MISSION_BOUND.value
    execution_proof: Any = None
    mission: Any = None
    mission_id: str = ""
    request_id: str = ""
    run_id: str = ""
    authorization_decision: Any = None


@dataclass(frozen=True)
class AdapterAuthorization:
    """Record that existing authority was VERIFIED (never created)."""

    tool: str
    execution_class: str
    proof_fingerprint: str
    snapshot_hash: str
    snapshot_version: int
    decision_fingerprint: str
    verified: bool = True


@dataclass(frozen=True)
class PreparedExecution:
    """Deterministic preparation record; no side effects."""

    tool: str
    timeout: int
    required_binary: str | None
    handler_source: str = "tools.registry"


@dataclass(frozen=True)
class AdapterResult:
    """Full separated result envelope.

    raw output, normalized output, evidence, metadata, and error state are
    DISTINCT fields (INV-ADP-6): raw output is untrusted data, evidence is a
    structured binding record, and a failure can never masquerade as success.
    """

    tool: str
    execution_class: str
    status: str  # SUCCESS | DRY_RUN | ERROR
    dry_run: bool
    executed: bool
    raw_output: Any = None
    normalized_output: Any = None
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    error_state: dict[str, Any] = field(default_factory=dict)
    cleanup_ran: bool = False
    cleanup_error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "SUCCESS"


class ToolAdapter:
    """Base adapter contract: validate_input, authorize, prepare, dry_run,
    execute, normalize_output, collect_evidence, cleanup, error classification.

    Subclasses describe a tool (tool_name, optional required_binary, optional
    timeout_seconds) and may override the pure hooks (_validate_argument,
    _normalize, _collect, cleanup). They must NEVER override execute() to
    bypass tools.registry.execute, and must NEVER call a handler directly.
    """

    tool_name: str = ""
    required_binary: str | None = None
    timeout_seconds: int | None = None

    # -- Phase 1: input validation (fail closed, before anything else) ------

    def validate_input(self, request: ToolAdapterRequest) -> None:
        tool = str(request.tool or "")
        if not isinstance(request.tool, str) or not TOOL_NAME_PATTERN.match(tool):
            raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "tool name must be a lowercase registry identifier", tool=tool)
        if request.execution_class not in {ExecutionClass.MISSION_BOUND.value, ExecutionClass.OWNER_DIRECT.value}:
            raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "unknown execution class: " + str(request.execution_class), tool=tool)
        spec = tools.registry.get_tool(tool)
        if spec is None:
            raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.TOOL_UNAVAILABLE, "tool is not registered in the runtime registry", tool=tool)
        valid, reason = spec.validate(request.argument)
        if not valid:
            raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, reason, tool=tool)
        if isinstance(request.argument, dict) and any(_is_authority_shaped_key(key) for key in request.argument):
            raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "authority-shaped argument keys rejected", tool=tool)
        if request.execution_class == ExecutionClass.MISSION_BOUND.value:
            if request.mission is None:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "mission-bound execution requires the live mission object", tool=tool)
            if not str(request.mission_id or ""):
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "mission-bound execution requires the mission identity", tool=tool)
        else:
            if request.mission is not None:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution must not carry mission bindings", tool=tool)
            if request.authorization_decision is None:
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution requires the typed AuthorizationDecision that authorized it", tool=tool)
            if not str(request.request_id or ""):
                raise ToolAdapterError(AdapterPhase.VALIDATE_INPUT, AdapterErrorCode.INPUT_INVALID, "owner-direct execution requires the request identity", tool=tool)
        self._validate_argument(request)

    def _validate_argument(self, request: ToolAdapterRequest) -> None:
        """Pure hook: additional tool-specific input checks. No side effects."""

    # -- Phase 2: authorization VERIFICATION (never creation) ---------------

    def authorize(self, request: ToolAdapterRequest) -> AdapterAuthorization:
        """Verify existing authority through the existing chain validators.

        INV-ADP-1: this method only calls ExecutionAuthorizationProof.verify
        and ExecutionAuthorizationProof.validate_against_mission — the same
        validators the registry and runtime use. It cannot mint, widen, or
        repair any authorization, and a missing/invalid proof fails closed.
        """
        proof = request.execution_proof
        if not isinstance(proof, ExecutionAuthorizationProof):
            code = RejectionCode.PROOF_REQUIRED.value if proof is None else RejectionCode.PROOF_INVALID.value
            raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), "typed ExecutionAuthorizationProof required", tool=request.tool, rejection_code=code)
        if str(getattr(proof, "execution_class", "")) != str(request.execution_class):
            raise ToolAdapterError(
                AdapterPhase.AUTHORIZE,
                AdapterErrorCode.PROOF_FAILURE,
                "proof execution class does not match the request execution class",
                tool=request.tool,
                rejection_code=RejectionCode.EXECUTION_CLASS_MISMATCH.value,
            )
        mission_bound = request.execution_class == ExecutionClass.MISSION_BOUND.value
        ok, reason, code = ExecutionAuthorizationProof.verify(
            proof,
            name=request.tool,
            argument=request.argument,
            mission_id=request.mission_id if mission_bound else None,
            request_id=request.request_id or None,
            run_id=request.run_id if mission_bound else None,
        )
        if not ok:
            raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), reason, tool=request.tool, rejection_code=code)
        if mission_bound:
            ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, request.mission)
            if not ok:
                raise ToolAdapterError(AdapterPhase.AUTHORIZE, _classify_rejection(code), reason, tool=request.tool, rejection_code=code)
        else:
            decision = request.authorization_decision
            if not isinstance(decision, AuthorizationDecision):
                raise ToolAdapterError(AdapterPhase.AUTHORIZE, AdapterErrorCode.AUTHORIZATION_DENIED, "typed AuthorizationDecision required for owner-direct execution", tool=request.tool)
            if not decision.is_valid_for(request.tool, request.argument, request.request_id):
                raise ToolAdapterError(AdapterPhase.AUTHORIZE, AdapterErrorCode.AUTHORIZATION_DENIED, "authorization decision does not match tool, argument, or request", tool=request.tool)
            if str(decision.decision_signature) != str(proof.decision_fingerprint):
                raise ToolAdapterError(
                    AdapterPhase.AUTHORIZE,
                    AdapterErrorCode.PROOF_FAILURE,
                    "execution proof is not bound to the supplied AuthorizationDecision",
                    tool=request.tool,
                    rejection_code=RejectionCode.PROOF_BINDING_MISMATCH.value,
                )
            if str(decision.policy_fingerprint) != str(proof.policy_fingerprint):
                raise ToolAdapterError(
                    AdapterPhase.AUTHORIZE,
                    AdapterErrorCode.PROOF_FAILURE,
                    "execution proof policy binding does not match the authorization decision policy",
                    tool=request.tool,
                    rejection_code=RejectionCode.PROOF_BINDING_MISMATCH.value,
                )
        return AdapterAuthorization(
            tool=request.tool,
            execution_class=str(request.execution_class),
            proof_fingerprint=str(proof.execution_binding_hash),
            snapshot_hash=str(proof.snapshot_hash),
            snapshot_version=int(proof.snapshot_version),
            decision_fingerprint=str(proof.decision_fingerprint),
        )

    # -- Phase 3: preparation and availability (fail closed, no fallback) ---

    def prepare(self, request: ToolAdapterRequest, authorization: AdapterAuthorization) -> PreparedExecution:
        spec = tools.registry.get_tool(request.tool)
        if spec is None:
            raise ToolAdapterError(AdapterPhase.PREPARE, AdapterErrorCode.TOOL_UNAVAILABLE, "tool is not registered in the runtime registry", tool=request.tool)
        if self.required_binary is not None and shutil.which(self.required_binary) is None:
            raise ToolAdapterError(
                AdapterPhase.PREPARE,
                AdapterErrorCode.TOOL_UNAVAILABLE,
                "required runtime binary is unavailable: " + str(self.required_binary) + " (fail closed; no fallback execution)",
                tool=request.tool,
            )
        timeout = int(self.timeout_seconds) if self.timeout_seconds is not None else int(spec.timeout)
        return PreparedExecution(tool=request.tool, timeout=timeout, required_binary=self.required_binary)

    # -- Phase 4: dry run (never executes anything) --------------------------

    def dry_run(self, request: ToolAdapterRequest, authorization: AdapterAuthorization, prepared: PreparedExecution) -> dict[str, Any]:
        plan = {
            "tool": request.tool,
            "argument_fingerprint": canonical_execution_fingerprint(request.argument),
            "execution_class": request.execution_class,
            "proof_fingerprint": authorization.proof_fingerprint,
            "timeout": prepared.timeout,
            "required_binary": prepared.required_binary,
            "handler_source": prepared.handler_source,
            "would_execute": True,
        }
        return plan

    # -- Phase 5: execution (ONLY through tools.registry.execute) -----------

    def execute(self, request: ToolAdapterRequest, authorization: AdapterAuthorization, prepared: PreparedExecution) -> Any:
        """Invoke the tool through the canonical registry boundary.

        INV-ADP-2: the only call path to a handler is tools.registry.execute
        with the full chain arguments. The adapter passes the typed proof, the
        live mission snapshot, the execution class, and the live run id; the
        registry remains the last line of defense and re-checks everything.
        """
        mission_bound = request.execution_class == ExecutionClass.MISSION_BOUND.value
        if mission_bound:
            try:
                snapshot = MissionAuthorizationSnapshot.from_dict(dict(getattr(request.mission, "authorization_snapshot", None) or {}))
            except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError) as exc:
                raise ToolAdapterError(
                    AdapterPhase.EXECUTE,
                    AdapterErrorCode.AUTHORIZATION_DENIED,
                    "live mission authorization snapshot is invalid: " + str(exc),
                    tool=request.tool,
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
                )
            except PermissionError as exc:
                code = _rejection_code_from_message(str(exc))
                raise ToolAdapterError(AdapterPhase.EXECUTE, _classify_rejection(code), str(exc), tool=request.tool, rejection_code=code) from None
            except TimeoutError as exc:
                # The handler was submitted before the timeout fired.
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.TIMEOUT, str(exc), tool=request.tool) from None
            except ValueError as exc:
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.INPUT_INVALID, str(exc), tool=request.tool) from None
            except Exception as exc:  # handler-side failure after submission
                raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.EXECUTION_FAILED, str(exc), tool=request.tool) from None
        try:
            return tools.registry.execute(
                request.tool,
                request.argument,
                request_id=request.request_id,
                authorization_decision=request.authorization_decision,
                execution_proof=request.execution_proof,
                execution_class=ExecutionClass.OWNER_DIRECT.value,
                timeout=prepared.timeout,
            )
        except PermissionError as exc:
            code = _rejection_code_from_message(str(exc))
            raise ToolAdapterError(AdapterPhase.EXECUTE, _classify_rejection(code), str(exc), tool=request.tool, rejection_code=code) from None
        except TimeoutError as exc:
            raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.TIMEOUT, str(exc), tool=request.tool) from None
        except ValueError as exc:
            raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.INPUT_INVALID, str(exc), tool=request.tool) from None
        except Exception as exc:  # handler-side failure after submission
            raise ToolAdapterError(AdapterPhase.EXECUTE, AdapterErrorCode.EXECUTION_FAILED, str(exc), tool=request.tool) from None

    # -- Phase 6: deterministic normalization (output is untrusted) ---------

    def normalize_output(self, raw: Any) -> dict[str, Any]:
        try:
            normalized = self._normalize(raw)
        except ToolAdapterError:
            raise
        except Exception as exc:
            raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "output normalization failed: " + str(exc), tool=self.tool_name) from None
        if not isinstance(normalized, dict):
            raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "normalized output must be a dict", tool=self.tool_name)
        for key in normalized:
            if _is_authority_shaped_key(key):
                raise ToolAdapterError(
                    AdapterPhase.NORMALIZE_OUTPUT,
                    AdapterErrorCode.NORMALIZATION_FAILED,
                    "tool output attempted to carry an authority-shaped key (rejected as untrusted data): " + str(key),
                    tool=self.tool_name,
                )
        return dict(normalized)

    def _normalize(self, raw: Any) -> dict[str, Any]:
        """Deterministic normalization hook. Output is UNTRUSTED DATA."""
        if isinstance(raw, dict):
            return dict(raw)
        if raw is None or isinstance(raw, (str, int, float, bool)):
            return {"value": raw}
        if isinstance(raw, (list, tuple)):
            return {"items": list(raw)}
        raise ToolAdapterError(AdapterPhase.NORMALIZE_OUTPUT, AdapterErrorCode.NORMALIZATION_FAILED, "tool output cannot be normalized deterministically", tool=self.tool_name)

    # -- Phase 7: structured evidence (bindings and hashes, never authority) -

    def collect_evidence(
        self,
        request: ToolAdapterRequest,
        authorization: AdapterAuthorization | None,
        raw: Any,
        normalized: dict[str, Any] | None,
        error: ToolAdapterError | None,
        *,
        status: str,
        executed: bool,
    ) -> dict[str, Any]:
        try:
            proof = request.execution_proof if isinstance(request.execution_proof, ExecutionAuthorizationProof) else None
            record: dict[str, Any] = {
                "record_type": "TOOL_ADAPTER_EVIDENCE",
                "provenance": "TOOL_ADAPTER",
                "classification": "UNTRUSTED_TOOL_OUTPUT",
                "tool": str(request.tool),
                "execution_class": str(request.execution_class),
                "status": str(status),
                "executed": bool(executed),
                "mission_id": str(getattr(proof, "mission_id", "") or "") if proof is not None else "",
                "request_id": str(getattr(proof, "request_id", "") or "") if proof is not None else str(request.request_id or ""),
                "run_id": str(getattr(proof, "run_id", "") or "") if proof is not None else str(request.run_id or ""),
                "tool_call_id": str(getattr(proof, "tool_call_id", "") or "") if proof is not None else "",
                "lifecycle_revision": int(getattr(proof, "lifecycle_revision", 0) or 0) if proof is not None else 0,
                "proof_fingerprint": str(authorization.proof_fingerprint) if authorization is not None else "",
                "snapshot_hash": str(authorization.snapshot_hash) if authorization is not None else "",
                "snapshot_version": int(authorization.snapshot_version) if authorization is not None else 0,
                "argument_fingerprint": canonical_execution_fingerprint(request.argument),
                "raw_output_sha256": _sha256(raw),
                "result_hash": _sha256(normalized),
                "error_code": str(error.code.value) if error is not None else "",
                "error_phase": str(error.phase.value) if error is not None else "",
            }
            return self._collect(request, record)
        except ToolAdapterError:
            raise
        except Exception as exc:
            raise ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, "evidence collection failed: " + str(exc), tool=self.tool_name) from None

    def _collect(self, request: ToolAdapterRequest, record: dict[str, Any]) -> dict[str, Any]:
        """Pure evidence hook; subclasses may add descriptive fields only."""
        return dict(record)

    # -- Phase 8: cleanup (always runs; inert by contract) -------------------

    def cleanup(self, request: ToolAdapterRequest) -> None:
        """Inert cleanup hook. Runs exactly once per run() on every path.

        INV-ADP-7: cleanup receives no authorization, must never invoke the
        tool, the registry, or any handler, and must never repair a failure.
        """

    def _evidence_safe(
        self,
        request: ToolAdapterRequest,
        authorization: AdapterAuthorization | None,
        raw: Any,
        normalized: dict[str, Any] | None,
        error: ToolAdapterError | None,
        *,
        status: str,
        executed: bool,
    ) -> tuple[dict[str, Any], str]:
        """Collect evidence without ever raising (evidence failure is classified).

        A failing evidence hook must never crash the envelope, mask a primary
        error, or silently pass: on the success path the caller converts the
        returned error string into an EVIDENCE_FAILED result state.
        """
        try:
            return self.collect_evidence(request, authorization, raw, normalized, error, status=status, executed=executed), ""
        except ToolAdapterError as exc:
            return {}, str(exc)
        except Exception as exc:  # a misbehaving evidence hook is classified, never fatal
            return {}, str(ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, str(exc), tool=str(request.tool or "")))

    # -- Orchestration -------------------------------------------------------

    def run(self, request: ToolAdapterRequest, *, dry_run: bool = False) -> AdapterResult:
        """Run the full contract in order. Returns a classified envelope.

        Every pre-execution rejection happens before tools.registry.execute;
        every failure is classified; cleanup always runs; no failure can be
        reported as success (INV-ADP-3, INV-ADP-7, INV-ADP-8).
        """
        authorization: AdapterAuthorization | None = None
        raw: Any = None
        normalized: dict[str, Any] | None = None
        executed = False
        error: ToolAdapterError | None = None
        evidence: dict[str, Any] = {}
        evidence_error = ""
        cleanup_ran = False
        cleanup_error = ""
        dry_run_plan: dict[str, Any] | None = None
        metadata: dict[str, Any] = {"adapter": type(self).__name__, "tool": str(request.tool or ""), "required_binary": self.required_binary}
        try:
            self.validate_input(request)
            authorization = self.authorize(request)
            prepared = self.prepare(request, authorization)
            if dry_run:
                dry_run_plan = self.dry_run(request, authorization, prepared)
                evidence, evidence_error = self._evidence_safe(request, authorization, None, None, None, status="DRY_RUN", executed=False)
                if evidence_error and error is None:
                    error = ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, evidence_error, tool=str(request.tool))
                    evidence_error = ""
            else:
                try:
                    raw = self.execute(request, authorization, prepared)
                    executed = True
                except ToolAdapterError as exc:
                    if exc.code is AdapterErrorCode.TIMEOUT or exc.code is AdapterErrorCode.EXECUTION_FAILED:
                        executed = True  # the handler was submitted before the failure
                    raise
                normalized = self.normalize_output(raw)
                evidence, evidence_error = self._evidence_safe(request, authorization, raw, normalized, None, status="SUCCESS", executed=executed)
                if evidence_error and error is None:
                    error = ToolAdapterError(AdapterPhase.COLLECT_EVIDENCE, AdapterErrorCode.EVIDENCE_FAILED, evidence_error, tool=str(request.tool))
                    evidence_error = ""
        except ToolAdapterError as exc:
            error = exc
            evidence, evidence_retry_error = self._evidence_safe(request, authorization, raw, normalized, exc, status="ERROR", executed=executed)
            if evidence_retry_error:
                evidence_error = (evidence_error + " | " if evidence_error else "") + evidence_retry_error
        finally:
            try:
                self.cleanup(request)
                cleanup_ran = True
            except ToolAdapterError as exc:
                cleanup_error = str(exc)
            except Exception as exc:
                cleanup_error = "CLEANUP_FAILED: " + str(exc)
        if error is None and cleanup_error:
            error = ToolAdapterError(AdapterPhase.CLEANUP, AdapterErrorCode.CLEANUP_FAILED, cleanup_error, tool=str(request.tool))
        if error is not None:
            status = "ERROR"
        elif dry_run:
            status = "DRY_RUN"
        else:
            status = "SUCCESS"
        return AdapterResult(
            tool=str(request.tool),
            execution_class=str(request.execution_class),
            status=status,
            dry_run=bool(dry_run),
            executed=executed,
            raw_output=raw,
            normalized_output=normalized,
            evidence=dict(evidence),
            metadata=dict(metadata, dry_run_plan=dict(dry_run_plan)) if dry_run_plan is not None else dict(metadata, evidence_error=evidence_error),
            error_state=dict(error.to_dict()) if error is not None else {},
            cleanup_ran=cleanup_ran,
            cleanup_error=cleanup_error,
        )


def _sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LocalSystemInfoAdapter(ToolAdapter):
    """First concrete adapter: the registered local_system_info tool.

    Local, informational, read-only, non-destructive. Pure local runtime
    (required_binary is None): the tool reads local system information through
    its existing registry handler. It reaches execution only through
    tools.registry.execute with a mission-bound or owner-direct proof.
    """

    tool_name = "local_system_info"


LOCAL_SYSTEM_INFO_ADAPTER = LocalSystemInfoAdapter()
