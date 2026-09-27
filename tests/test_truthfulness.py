"""Adversarial battery for the truthfulness / anti-hallucination invariants.

These tests prove the SYSTEM refuses to convert model output into system
truth: claims without evidence stay UNVERIFIED/NOT_RUN, model-generated
evidence is non-authoritative, and COMPLETE is impossible without proven
completion gates.
"""
from __future__ import annotations

from security.truthfulness import (
    Claim,
    CompletionGate,
    EvidenceRecord,
    EvidenceStatus,
    ExecutionRecord,
    classify_claim,
    evaluate_completion,
    execution_outcome,
    verify_ci_claim,
    verify_test_claim,
)


# --- 1. a claim never becomes a fact without evidence -----------------------

def test_claim_without_evidence_is_never_verified():
    claim = Claim(statement="tests passed", status=EvidenceStatus.VERIFIED, claim_id="C1")
    result = classify_claim(claim, evidence=[])
    assert result.status == EvidenceStatus.UNVERIFIED


def test_model_says_tests_passed_without_execution_record():
    # The model asserts success; no execution record exists.
    result = verify_test_claim("pytest passed", None, commit_sha="abc123")
    assert result.status == EvidenceStatus.NOT_RUN
    assert result.status != EvidenceStatus.VERIFIED


def test_planned_tool_call_without_execution_is_not_run():
    planned = Claim(statement="planned tool call", status=EvidenceStatus.PLANNED, claim_id="P1")
    assert planned.status == EvidenceStatus.PLANNED
    assert execution_outcome(None) == EvidenceStatus.NOT_RUN


def test_interrupted_execution_is_never_completed():
    record = ExecutionRecord(command="pytest -q", started_at="t0", finished_at="t1", exit_code=None)
    assert execution_outcome(record) == EvidenceStatus.INTERRUPTED


def test_failed_execution_is_failed_not_success():
    record = ExecutionRecord(command="pytest -q", started_at="t0", finished_at="t1", exit_code=1)
    assert execution_outcome(record) == EvidenceStatus.FAILED


def test_successful_execution_record_verifies_only_same_commit():
    record = ExecutionRecord(command="pytest -q", started_at="t0", finished_at="t1", exit_code=0, commit_sha="sha-A")
    same = verify_test_claim("pytest passed", record, commit_sha="sha-A")
    assert same.status == EvidenceStatus.VERIFIED
    other = verify_test_claim("pytest passed", record, commit_sha="sha-B")
    assert other.status == EvidenceStatus.UNVERIFIED


# --- 2. model output is not evidence ----------------------------------------

def test_model_generated_evidence_is_non_authoritative():
    model_evidence = EvidenceRecord(origin="model_output", kind="execution", payload={"result": "passed"})
    claim = Claim(statement="tests passed", status=EvidenceStatus.VERIFIED, claim_id="C2")
    result = classify_claim(claim, evidence=[model_evidence])
    assert result.status == EvidenceStatus.UNVERIFIED
    assert not model_evidence.is_authoritative()


def test_trusted_origin_evidence_is_authoritative():
    runner = EvidenceRecord(origin="test_runner", kind="execution", payload={"exit_code": 0})
    assert runner.is_authoritative()


def test_fake_ci_claim_without_run_id_is_rejected():
    claim = verify_ci_claim("CI GREEN", workflow_run_id="", conclusion="success", commit_sha="sha-A")
    assert claim.status == EvidenceStatus.UNVERIFIED


def test_ci_claim_must_bind_commit_sha():
    claim = verify_ci_claim("CI GREEN", workflow_run_id="run-1", conclusion="success", commit_sha="")
    assert claim.status == EvidenceStatus.UNVERIFIED


def test_real_ci_claim_is_verified():
    claim = verify_ci_claim("CI GREEN", workflow_run_id="run-1", conclusion="success", commit_sha="sha-A")
    assert claim.status == EvidenceStatus.VERIFIED
    assert claim.test_run_id == "run-1"


# --- 3. completion gate ------------------------------------------------------

def _verified_gate(gate: CompletionGate) -> Claim:
    return Claim(
        statement=f"{gate.value} proven",
        status=EvidenceStatus.VERIFIED,
        claim_id=gate.value,
        evidence=(EvidenceRecord(origin="ci_runner", kind="gate", payload={"gate": gate.value}),),
    )


def test_completion_requires_all_gates():
    partial = [_verified_gate(g) for g in list(CompletionGate)[:-1]]
    result = evaluate_completion(partial)
    assert result["result"] == "NOT_COMPLETE"
    assert result["missing"] == [list(CompletionGate)[-1].value]


def test_completion_impossible_with_claimed_only_gate():
    gates = [_verified_gate(g) for g in list(CompletionGate)[:-1]]
    gates.append(Claim(statement="EVIDENCE_COMPLETE (model says so)", status=EvidenceStatus.VERIFIED, claim_id=CompletionGate.EVIDENCE_COMPLETE.value))
    result = evaluate_completion(gates)
    assert result["result"] == "NOT_COMPLETE"
    assert "EVIDENCE_COMPLETE" in result["missing"]


def test_full_completion_with_all_verified_gates():
    gates = [_verified_gate(g) for g in CompletionGate]
    result = evaluate_completion(gates)
    assert result["result"] == "COMPLETE"
    assert result["missing"] == []


def test_no_claims_means_not_complete():
    result = evaluate_completion([])
    assert result["result"] == "NOT_COMPLETE"
    assert len(result["missing"]) == len(list(CompletionGate))


# --- 4. serialization exposes machine-readable status -----------------------

def test_claim_dict_exposes_status_explicitly():
    claim = Claim(statement="s", status=EvidenceStatus.UNVERIFIED, claim_id="C9")
    d = claim.to_dict()
    assert d["status"] == "UNVERIFIED"
    assert "evidence_count" in d
