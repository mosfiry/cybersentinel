"""Truthfulness and anti-hallucination invariants for CyberSentinel.

System truth = authoritative runtime state + verified evidence + provenance.
Model output is NEVER evidence by itself: the model can propose, explain,
summarize, infer, and plan, but it cannot manufacture test results, CI
results, git state, execution results, security findings, or authorization
facts.

Machine-readable states (no ambiguous "success" wording):
    OBSERVED       directly measured by a system layer
    VERIFIED       checked against authoritative evidence
    INFERRED       derived by reasoning; NOT a fact until verified
    PLANNED        intended but not executed
    CLAIMED        asserted by a model or report without evidence
    UNVERIFIED     no matching evidence found
    FAILED         executed and failed
    NOT_RUN        never executed
    INTERRUPTED    started but did not finish
    UNKNOWN        outcome cannot be determined
    NOT_APPLICABLE gate or claim does not apply here

Core invariant:
    NO EVIDENCE -> NO VERIFIED CLAIM -> NO FALSE COMPLETION
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Sequence


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    PLANNED = "PLANNED"
    CLAIMED = "CLAIMED"
    UNVERIFIED = "UNVERIFIED"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"
    INTERRUPTED = "INTERRUPTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Statuses a claim may never be silently upgraded to without authoritative evidence.
_PROTECTED_STATUSES = frozenset({
    EvidenceStatus.VERIFIED,
    EvidenceStatus.OBSERVED,
})

# Origins that can produce authoritative evidence. "model_output" is NOT among them.
TRUSTED_EVIDENCE_ORIGINS = frozenset({
    "test_runner",
    "ci_runner",
    "git",
    "filesystem",
    "database",
    "execution_runtime",
    "authorization_layer",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceRecord:
    """A single piece of evidence produced by a SYSTEM layer (never by the model)."""
    origin: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    commit_sha: str = ""
    created_at: str = field(default_factory=lambda: _iso(_now()))

    def is_authoritative(self) -> bool:
        return self.origin in TRUSTED_EVIDENCE_ORIGINS


@dataclass(frozen=True)
class ExecutionRecord:
    """Proof that something actually ran (command, exit code, timestamps)."""
    command: str
    started_at: str
    finished_at: str
    exit_code: int | None
    environment: str = ""
    commit_sha: str = ""
    stdout_ref: str = ""
    stderr_ref: str = ""

    @property
    def outcome(self) -> EvidenceStatus:
        if self.exit_code is None:
            return EvidenceStatus.INTERRUPTED
        return EvidenceStatus.VERIFIED if self.exit_code == 0 else EvidenceStatus.FAILED


@dataclass(frozen=True)
class Claim:
    """A statement about system state, bound to evidence and provenance."""
    statement: str
    status: EvidenceStatus = EvidenceStatus.CLAIMED
    claim_id: str = ""
    request_id: str = ""
    mission_id: str = ""
    source: str = ""
    source_type: str = ""
    timestamp: str = field(default_factory=lambda: _iso(_now()))
    commit_sha: str = ""
    file_path: str = ""
    test_name: str = ""
    test_run_id: str = ""
    execution_id: str = ""
    evidence_hash: str = ""
    evidence: tuple[EvidenceRecord, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "status": self.status.value,
            "request_id": self.request_id,
            "mission_id": self.mission_id,
            "source": self.source,
            "source_type": self.source_type,
            "timestamp": self.timestamp,
            "commit_sha": self.commit_sha,
            "file_path": self.file_path,
            "test_name": self.test_name,
            "test_run_id": self.test_run_id,
            "execution_id": self.execution_id,
            "evidence_hash": self.evidence_hash,
            "evidence_count": len(self.evidence),
        }


def classify_claim(claim: Claim, evidence: Sequence[EvidenceRecord]) -> Claim:
    """Classify a claim STRICTLY. A protected status requires authoritative evidence.

    The model can say anything; this function decides what the claim IS.
    - No evidence at all -> UNVERIFIED (never VERIFIED).
    - Only model-origin evidence -> stays CLAIMED/UNVERIFIED, never VERIFIED.
    - An interrupted execution -> INTERRUPTED, never COMPLETED/VERIFIED.
    """
    authoritative = [item for item in evidence if item.is_authoritative()]
    if claim.status in _PROTECTED_STATUSES and not authoritative:
        return replace(claim, status=EvidenceStatus.UNVERIFIED)
    if claim.status in _PROTECTED_STATUSES and not any(
        item.kind == claim.source_type or not claim.source_type for item in authoritative
    ):
        return replace(claim, status=EvidenceStatus.UNVERIFIED)
    return claim


def execution_outcome(record: ExecutionRecord | None) -> EvidenceStatus:
    """Test/CI results come only from real execution records.

    No execution record -> NOT_RUN (never PASSED).
    Interrupted execution  -> INTERRUPTED (never COMPLETED).
    """
    if record is None:
        return EvidenceStatus.NOT_RUN
    return record.outcome


def verify_test_claim(statement: str, execution: ExecutionRecord | None, *, commit_sha: str = "") -> Claim:
    """Refuse 'tests passed' without an execution record on the SAME commit."""
    if execution is None:
        return Claim(statement=statement, status=EvidenceStatus.NOT_RUN, commit_sha=commit_sha)
    if commit_sha and execution.commit_sha and execution.commit_sha != commit_sha:
        return Claim(statement=statement, status=EvidenceStatus.UNVERIFIED, commit_sha=commit_sha)
    status = execution_outcome(execution)
    return Claim(
        statement=statement,
        status=status,
        commit_sha=execution.commit_sha or commit_sha,
        evidence=(EvidenceRecord(origin="test_runner", kind="execution", payload={"exit_code": execution.exit_code}),),
    )


def verify_ci_claim(statement: str, *, workflow_run_id: str, conclusion: str, commit_sha: str) -> Claim:
    """A CI claim is VERIFIED only with a real run id bound to the SAME commit SHA."""
    if not workflow_run_id or not commit_sha:
        return Claim(statement=statement, status=EvidenceStatus.UNVERIFIED, commit_sha=commit_sha)
    if conclusion == "success":
        return Claim(
            statement=statement,
            status=EvidenceStatus.VERIFIED,
            commit_sha=commit_sha,
            test_run_id=workflow_run_id,
            evidence=(EvidenceRecord(origin="ci_runner", kind="workflow_run", payload={"conclusion": conclusion, "commit_sha": commit_sha}),),
        )
    return Claim(
        statement=statement,
        status=EvidenceStatus.FAILED if conclusion == "failure" else EvidenceStatus.UNKNOWN,
        commit_sha=commit_sha,
        test_run_id=workflow_run_id,
        evidence=(EvidenceRecord(origin="ci_runner", kind="workflow_run", payload={"conclusion": conclusion, "commit_sha": commit_sha}),),
    )


# ---------------------------------------------------------------------------
# Completion gate: COMPLETE is impossible without proven gates.
# ---------------------------------------------------------------------------

class CompletionGate(str, Enum):
    CODE_PRESENT = "CODE_PRESENT"
    TESTS_PRESENT = "TESTS_PRESENT"
    TESTS_EXECUTED = "TESTS_EXECUTED"
    TESTS_PASS = "TESTS_PASS"
    CI_PASS = "CI_PASS"
    SECURITY_CHECK_PASS = "SECURITY_CHECK_PASS"
    DOCUMENTATION_ALIGNED = "DOCUMENTATION_ALIGNED"
    RUNTIME_PATH_VERIFIED = "RUNTIME_PATH_VERIFIED"
    EVIDENCE_COMPLETE = "EVIDENCE_COMPLETE"


REQUIRED_GATES: tuple[CompletionGate, ...] = (
    CompletionGate.CODE_PRESENT,
    CompletionGate.TESTS_PRESENT,
    CompletionGate.TESTS_EXECUTED,
    CompletionGate.TESTS_PASS,
    CompletionGate.CI_PASS,
    CompletionGate.SECURITY_CHECK_PASS,
    CompletionGate.DOCUMENTATION_ALIGNED,
    CompletionGate.RUNTIME_PATH_VERIFIED,
    CompletionGate.EVIDENCE_COMPLETE,
)


def evaluate_completion(claims: Iterable[Claim]) -> dict[str, Any]:
    """Return COMPLETE only when EVERY required gate is VERIFIED with evidence.

    Any missing, claimed-only, or unverified gate forces NOT_COMPLETE.
    Text in a report can never override this result.
    """
    verified_gates: set[CompletionGate] = set()
    gate_status: dict[str, str] = {}
    for gate in REQUIRED_GATES:
        matching = [c for c in claims if gate.value == c.claim_id or gate.value in c.statement]
        if not matching:
            gate_status[gate.value] = EvidenceStatus.NOT_APPLICABLE.value if gate not in REQUIRED_GATES else EvidenceStatus.UNVERIFIED.value
            continue
        best = matching[0]
        for c in matching:
            if c.status == EvidenceStatus.VERIFIED and c.evidence and all(e.is_authoritative() for e in c.evidence):
                best = c
                break
        gate_status[gate.value] = best.status.value
        if best.status == EvidenceStatus.VERIFIED and best.evidence and all(e.is_authoritative() for e in best.evidence):
            verified_gates.add(gate)
    complete = verified_gates == set(REQUIRED_GATES)
    return {
        "result": "COMPLETE" if complete else "NOT_COMPLETE",
        "gates": gate_status,
        "verified": sorted(g.value for g in verified_gates),
        "missing": sorted(g.value for g in REQUIRED_GATES if g not in verified_gates),
    }


__all__ = [
    "EvidenceStatus",
    "EvidenceRecord",
    "ExecutionRecord",
    "Claim",
    "CompletionGate",
    "REQUIRED_GATES",
    "TRUSTED_EVIDENCE_ORIGINS",
    "classify_claim",
    "execution_outcome",
    "verify_test_claim",
    "verify_ci_claim",
    "evaluate_completion",
]
