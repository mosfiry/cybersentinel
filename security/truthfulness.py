"""Truthfulness and anti-hallucination invariants for CyberSentinel.

System truth = authoritative runtime state + verified evidence + provenance.
Model output is NEVER evidence by itself: the model can propose, explain,
summarize, infer, and plan, but it cannot manufacture test results, CI
results, git state, execution results, security findings, or authorization
facts.

PROVENANCE MODEL (T1/T2):
    An EvidenceRecord carries CLAIMED provenance by default. It becomes
    VERIFIED provenance only when its provenance_token is a valid keyed
    HMAC minted by SystemEvidenceIssuer - a SYSTEM-only boundary whose key
    never reaches the model, HTTP callers, or untrusted sources. A record
    that merely NAMES a trusted origin ("test_runner", "ci_runner") is a
    claim, not evidence.

Core invariant:
    NO EVIDENCE -> NO VERIFIED CLAIM -> NO FALSE COMPLETION
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    INFERRED = "INFERRED"
    PLANNED = "PLANNED"
    CLAIMED = "CLAIMED"
    UNVERIFIED = "UNVERIFIED"
    CONTRADICTED = "CONTRADICTED"
    MISSING = "MISSING"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"
    INTERRUPTED = "INTERRUPTED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# API semantics for every machine-readable status: no serialization path may
# turn a non-verified status into success/completed.
EVIDENCE_STATUS_SEMANTICS: dict[EvidenceStatus, dict[str, Any]] = {
    EvidenceStatus.OBSERVED: {"ok": True, "display": "observed", "completed": True},
    EvidenceStatus.VERIFIED: {"ok": True, "display": "verified", "completed": True},
    EvidenceStatus.PARTIAL: {"ok": False, "display": "partial", "completed": False},
    EvidenceStatus.INFERRED: {"ok": False, "display": "inferred", "completed": False},
    EvidenceStatus.PLANNED: {"ok": False, "display": "planned", "completed": False},
    EvidenceStatus.CLAIMED: {"ok": False, "display": "claimed", "completed": False},
    EvidenceStatus.UNVERIFIED: {"ok": False, "display": "unverified", "completed": False},
    EvidenceStatus.CONTRADICTED: {"ok": False, "display": "contradicted", "completed": False},
    EvidenceStatus.MISSING: {"ok": False, "display": "missing", "completed": False},
    EvidenceStatus.FAILED: {"ok": False, "display": "failed", "completed": False},
    EvidenceStatus.NOT_RUN: {"ok": False, "display": "not_run", "completed": False},
    EvidenceStatus.INTERRUPTED: {"ok": False, "display": "interrupted", "completed": False},
    EvidenceStatus.UNKNOWN: {"ok": False, "display": "unknown", "completed": False},
    EvidenceStatus.NOT_APPLICABLE: {"ok": False, "display": "not_applicable", "completed": False},
}

# Statuses a claim may never be silently upgraded to without authoritative evidence.
_PROTECTED_STATUSES = frozenset({
    EvidenceStatus.VERIFIED,
    EvidenceStatus.OBSERVED,
})

# Statuses that actively BLOCK a gate (contradiction), not merely fail to prove it.
_CONTRADICTING_STATUSES = frozenset({
    EvidenceStatus.FAILED,
    EvidenceStatus.CONTRADICTED,
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

# Default SYSTEM key store (same local directory family as the application DB).
PROVENANCE_KEY_PATH = Path(
    os.environ.get("CYBERSENTINEL_PROVENANCE_KEY")
    or (Path.home() / ".cybersentinel-x" / "evidence_provenance.key")
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


class SystemEvidenceIssuer:
    """SYSTEM-only evidence minting boundary (verified provenance).

    The HMAC key lives in a local system file (0600) created once. Only system
    code paths that possess the key can mint records with a valid
    provenance_token. Any other constructor of EvidenceRecord - model code,
    HTTP handlers, external data - produces claimed provenance that never
    verifies. What an attacker (model/caller) can forge: origin names,
    payloads, run ids, conclusions, commit SHAs. What they cannot forge: a
    valid provenance_token without the system key.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ValueError("provenance key must be at least 32 bytes")
        self._key = bytes(key)

    @classmethod
    def from_key_file(cls, path: str | os.PathLike = PROVENANCE_KEY_PATH) -> "SystemEvidenceIssuer":
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            key = p.read_bytes()
        else:
            key = secrets.token_bytes(32)
            p.write_bytes(key)
            os.chmod(p, 0o600)
        return cls(key)

    @staticmethod
    def _canonical(origin: str, kind: str, payload: dict[str, Any], commit_sha: str, created_at: str) -> bytes:
        return json.dumps(
            {"origin": origin, "kind": kind, "payload": payload, "commit_sha": commit_sha, "created_at": created_at},
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")

    def _token(self, origin: str, kind: str, payload: dict[str, Any], commit_sha: str, created_at: str) -> str:
        return hmac.new(self._key, self._canonical(origin, kind, payload, commit_sha, created_at), hashlib.sha256).hexdigest()

    def mint(self, origin: str, kind: str, payload: dict[str, Any] | None = None, *, commit_sha: str = "") -> "EvidenceRecord":
        if origin not in TRUSTED_EVIDENCE_ORIGINS:
            raise ValueError("issuer refuses to mint untrusted origin")
        created_at = _iso(_now())
        token = self._token(origin, kind, dict(payload or {}), commit_sha, created_at)
        return EvidenceRecord(
            origin=origin, kind=kind, payload=dict(payload or {}),
            commit_sha=commit_sha, created_at=created_at, provenance_token=token,
        )

    def verify(self, record: "EvidenceRecord") -> bool:
        if not isinstance(record, EvidenceRecord):
            return False
        if record.origin not in TRUSTED_EVIDENCE_ORIGINS:
            return False
        expected = self._token(record.origin, record.kind, record.payload, record.commit_sha, record.created_at)
        return hmac.compare_digest(expected, str(record.provenance_token))


_ISSUER: SystemEvidenceIssuer | None = None


def system_issuer() -> SystemEvidenceIssuer:
    """Process-wide SYSTEM issuer (key from the local system key file)."""
    global _ISSUER
    if _ISSUER is None:
        _ISSUER = SystemEvidenceIssuer.from_key_file()
    return _ISSUER


@dataclass(frozen=True)
class EvidenceRecord:
    """A single piece of evidence. Provenance is CLAIMED until the token verifies."""
    origin: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    commit_sha: str = ""
    created_at: str = field(default_factory=lambda: _iso(_now()))
    provenance_token: str = ""

    def is_authoritative(self) -> bool:
        """CLAIMED provenance check: trusted origin NAME plus a provenance token.

        Full VERIFIED provenance requires SystemEvidenceIssuer.verify() -
        the token must be a valid keyed HMAC. A bare trusted name is NOT
        sufficient (T0 finding B2).
        """
        return self.origin in TRUSTED_EVIDENCE_ORIGINS and bool(self.provenance_token)


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
            "evidence_verified": sum(1 for e in self.evidence if e.is_authoritative()),
        }


def _verified_evidence(evidence: Sequence[EvidenceRecord], issuer: SystemEvidenceIssuer | None) -> list[EvidenceRecord]:
    """Only records with VERIFIED provenance count as authoritative."""
    if issuer is None:
        return []
    return [item for item in evidence if issuer.verify(item)]


def classify_claim(claim: Claim, evidence: Sequence[EvidenceRecord], *, issuer: SystemEvidenceIssuer | None = None) -> Claim:
    """Classify a claim STRICTLY. A protected status requires verified provenance.

    - No issuer or no verified evidence -> UNVERIFIED (never VERIFIED).
    - Name-only "trusted" records without a valid token -> UNVERIFIED.
    - The model can say anything; this function decides what the claim IS.
    """
    authoritative = _verified_evidence(evidence, issuer)
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


def verify_test_claim(statement: str, execution: ExecutionRecord | None, *, commit_sha: str = "", issuer: SystemEvidenceIssuer | None = None) -> Claim:
    """Refuse 'tests passed' without a system-minted execution record.

    VERIFIED requires an issuer: the system layer that actually ran the tests
    mints the evidence. Without an issuer the best achievable states are
    NOT_RUN / INTERRUPTED / FAILED / UNVERIFIED - never VERIFIED.
    """
    if execution is None:
        return Claim(statement=statement, status=EvidenceStatus.NOT_RUN, commit_sha=commit_sha)
    if commit_sha and execution.commit_sha and execution.commit_sha != commit_sha:
        return Claim(statement=statement, status=EvidenceStatus.UNVERIFIED, commit_sha=commit_sha)
    outcome = execution_outcome(execution)
    if issuer is None:
        # Caller-supplied execution data can describe failure/interruption,
        # but it can never certify success (no verified provenance).
        status = EvidenceStatus.UNVERIFIED if outcome == EvidenceStatus.VERIFIED else outcome
        return Claim(statement=statement, status=status, commit_sha=execution.commit_sha or commit_sha)
    evidence = (issuer.mint("test_runner", "execution", {"exit_code": execution.exit_code, "command": execution.command}, commit_sha=execution.commit_sha or commit_sha),)
    return Claim(statement=statement, status=outcome, commit_sha=execution.commit_sha or commit_sha, evidence=evidence)


def verify_ci_claim(statement: str, ci_evidence: EvidenceRecord | None, *, issuer: SystemEvidenceIssuer, commit_sha: str = "") -> Claim:
    """A CI claim is VERIFIED only with a system-minted ci_runner record.

    Caller-supplied workflow_run_id / conclusion / commit_sha strings are NOT
    evidence (T0 finding B3). The trusted CI provider boundary that would
    mint ci_runner records at runtime (a CI job signing its own result with a
    system/repository secret) does not exist in this deployment yet, so CI
    claims fail closed to UNVERIFIED.
    """
    if ci_evidence is None:
        return Claim(statement=statement, status=EvidenceStatus.MISSING, commit_sha=commit_sha)
    if not issuer.verify(ci_evidence):
        return Claim(statement=statement, status=EvidenceStatus.UNVERIFIED, commit_sha=commit_sha)
    payload_commit = str(ci_evidence.payload.get("commit_sha", ""))
    if commit_sha and payload_commit and payload_commit != commit_sha:
        return Claim(statement=statement, status=EvidenceStatus.UNVERIFIED, commit_sha=commit_sha)
    conclusion = str(ci_evidence.payload.get("conclusion", ""))
    if conclusion == "success":
        return Claim(
            statement=statement,
            status=EvidenceStatus.VERIFIED,
            commit_sha=commit_sha or payload_commit,
            test_run_id=str(ci_evidence.payload.get("workflow_run_id", "")),
            evidence=(ci_evidence,),
        )
    status = EvidenceStatus.FAILED if conclusion == "failure" else EvidenceStatus.UNKNOWN
    return Claim(statement=statement, status=status, commit_sha=commit_sha or payload_commit, test_run_id=str(ci_evidence.payload.get("workflow_run_id", "")), evidence=(ci_evidence,))


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


def evaluate_completion(claims: Iterable[Claim], *, issuer: SystemEvidenceIssuer) -> dict[str, Any]:
    """Return COMPLETE only when EVERY required gate is VERIFIED with issuer-verified evidence.

    Gates match by EXACT claim_id (no substring matching - T0 finding B6).
    A gate whose best claim is FAILED/CONTRADICTED is reported CONTRADICTED
    and can never contribute to COMPLETE. Text in a report can never override
    this result.
    """
    claim_list = list(claims)
    verified_gates: set[CompletionGate] = set()
    gate_status: dict[str, str] = {}
    contradicted: list[str] = []
    for gate in REQUIRED_GATES:
        matching = [c for c in claim_list if c.claim_id == gate.value]
        if not matching:
            gate_status[gate.value] = EvidenceStatus.MISSING.value
            continue
        best: Claim | None = None
        for c in matching:
            evidence_ok = bool(c.evidence) and all(issuer.verify(e) for e in c.evidence)
            if c.status == EvidenceStatus.VERIFIED and evidence_ok:
                best = c
                break
        if best is not None:
            gate_status[gate.value] = EvidenceStatus.VERIFIED.value
            verified_gates.add(gate)
            continue
        statuses = [c.status for c in matching]
        if any(s in _CONTRADICTING_STATUSES for s in statuses):
            gate_status[gate.value] = EvidenceStatus.CONTRADICTED.value
            contradicted.append(gate.value)
        else:
            non_missing = [s for s in statuses if s != EvidenceStatus.MISSING]
            gate_status[gate.value] = (non_missing[0].value if non_missing else EvidenceStatus.MISSING.value)
    complete = verified_gates == set(REQUIRED_GATES)
    return {
        "result": "COMPLETE" if complete else "NOT_COMPLETE",
        "gates": gate_status,
        "verified": sorted(g.value for g in verified_gates),
        "missing": sorted(g.value for g in REQUIRED_GATES if g not in verified_gates),
        "contradicted": sorted(set(contradicted)),
    }


def mission_truth_payload(mission_status_value: str, verification_state: dict[str, Any] | None) -> dict[str, Any]:
    """Canonical API truth object for a mission (used by /api/chat and /api/command).

    The model answer is always MODEL_OUTPUT (a claim). Completion truth
    comes exclusively from the deterministic goal verification state that the
    MissionRuntime wrote - never from the answer text.
    """
    state = dict(verification_state or {})
    verified = state.get("verified") is True
    completed = mission_status_value == "GOAL_COMPLETED" and verified
    return {
        "mission_status": mission_status_value,
        "goal_verified": verified,
        "completion": "COMPLETE" if completed else "NOT_COMPLETE",
        "answer_authority": "MODEL_OUTPUT",
        "evidence_count": int(state.get("evidence_count") or 0),
        "missing_criteria": list(state.get("missing_criteria") or []),
    }


__all__ = [
    "EvidenceStatus",
    "EVIDENCE_STATUS_SEMANTICS",
    "EvidenceRecord",
    "ExecutionRecord",
    "Claim",
    "CompletionGate",
    "REQUIRED_GATES",
    "TRUSTED_EVIDENCE_ORIGINS",
    "SystemEvidenceIssuer",
    "PROVENANCE_KEY_PATH",
    "system_issuer",
    "classify_claim",
    "execution_outcome",
    "verify_test_claim",
    "verify_ci_claim",
    "evaluate_completion",
    "mission_truth_payload",
]
