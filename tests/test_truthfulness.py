"""Adversarial battery for the truthfulness / anti-hallucination invariants.

T2 update: evidence authority now requires VERIFIED PROVENANCE - a valid
provenance_token minted by SystemEvidenceIssuer. Bare trusted-origin names
are claimed provenance only (T0 findings B2/B3 fixed here at library level).
"""
from __future__ import annotations

import pytest

from security.truthfulness import (
    Claim,
    CompletionGate,
    EvidenceRecord,
    EvidenceStatus,
    EVIDENCE_STATUS_SEMANTICS,
    ExecutionRecord,
    SystemEvidenceIssuer,
    classify_claim,
    evaluate_completion,
    execution_outcome,
    verify_ci_claim,
    verify_test_claim,
)


@pytest.fixture()
def issuer():
    return SystemEvidenceIssuer(b"x" * 32 + b"issuer-test-key-0123456789")


# --- 1. a claim never becomes a fact without evidence -----------------------

def test_claim_without_evidence_is_never_verified():
    claim = Claim(statement="tests passed", status=EvidenceStatus.VERIFIED, claim_id="C1")
    result = classify_claim(claim, evidence=[], issuer=SystemEvidenceIssuer(b"k" * 32 + b"alt"))
    assert result.status == EvidenceStatus.UNVERIFIED


def test_model_says_tests_passed_without_execution_record():
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


def test_execution_verifies_only_with_system_issuer_and_same_commit(issuer):
    record = ExecutionRecord(command="pytest -q", started_at="t0", finished_at="t1", exit_code=0, commit_sha="sha-A")
    same = verify_test_claim("pytest passed", record, commit_sha="sha-A", issuer=issuer)
    assert same.status == EvidenceStatus.VERIFIED
    other = verify_test_claim("pytest passed", record, commit_sha="sha-B", issuer=issuer)
    assert other.status == EvidenceStatus.UNVERIFIED


def test_caller_supplied_execution_never_certifies_success(issuer):
    # Without an issuer minting the evidence, exit code 0 is NOT VERIFIED.
    record = ExecutionRecord(command="pytest -q", started_at="t0", finished_at="t1", exit_code=0)
    result = verify_test_claim("pytest passed", record, commit_sha="sha-A")
    assert result.status == EvidenceStatus.UNVERIFIED


# --- 2. model output is not evidence ----------------------------------------

def test_model_generated_evidence_is_non_authoritative():
    model_evidence = EvidenceRecord(origin="model_output", kind="execution", payload={"result": "passed"})
    claim = Claim(statement="tests passed", status=EvidenceStatus.VERIFIED, claim_id="C2")
    result = classify_claim(claim, evidence=[model_evidence], issuer=SystemEvidenceIssuer(b"m" * 32 + b"another-key-0000"))
    assert result.status == EvidenceStatus.UNVERIFIED
    assert not model_evidence.is_authoritative()


def test_forged_trusted_origin_name_is_not_authoritative():
    # T0 B2: a bare trusted NAME without a valid provenance token is a claim.
    forged = EvidenceRecord(origin="test_runner", kind="execution", payload={"exit_code": 0})
    assert not forged.is_authoritative()


def test_issuer_minted_evidence_is_authoritative(issuer):
    runner = issuer.mint("test_runner", "execution", {"exit_code": 0})
    assert runner.is_authoritative()
    assert issuer.verify(runner)


def test_issuer_refuses_untrusted_origin(issuer):
    with pytest.raises(ValueError):
        issuer.mint("model_output", "execution", {"result": "passed"})


# --- 3. CI claims: caller strings are never enough (T0 B3) ------------------

def test_fake_ci_strings_are_never_verified(issuer):
    # Attacker supplies run id / conclusion / sha as raw strings.
    claim = verify_ci_claim("CI GREEN", None, issuer=issuer, commit_sha="sha-A")
    assert claim.status == EvidenceStatus.MISSING


def test_forged_ci_record_with_guessed_token_is_rejected(issuer):
    forged = EvidenceRecord(
        origin="ci_runner", kind="workflow_run",
        payload={"workflow_run_id": "123", "conclusion": "success", "commit_sha": "sha-A"},
        commit_sha="sha-A",
        provenance_token="0" * 64,
    )
    claim = verify_ci_claim("CI GREEN", forged, issuer=issuer, commit_sha="sha-A")
    assert claim.status == EvidenceStatus.UNVERIFIED


def test_system_minted_ci_evidence_verifies(issuer):
    ci = issuer.mint("ci_runner", "workflow_run", {"workflow_run_id": "run-1", "conclusion": "success", "commit_sha": "sha-A"}, commit_sha="sha-A")
    claim = verify_ci_claim("CI GREEN", ci, issuer=issuer, commit_sha="sha-A")
    assert claim.status == EvidenceStatus.VERIFIED
    assert claim.test_run_id == "run-1"


def test_ci_evidence_bound_to_wrong_commit_is_rejected(issuer):
    ci = issuer.mint("ci_runner", "workflow_run", {"workflow_run_id": "run-1", "conclusion": "success", "commit_sha": "sha-A"}, commit_sha="sha-A")
    claim = verify_ci_claim("CI GREEN", ci, issuer=issuer, commit_sha="sha-B")
    assert claim.status == EvidenceStatus.UNVERIFIED


def test_failed_ci_conclusion_is_failed(issuer):
    ci = issuer.mint("ci_runner", "workflow_run", {"workflow_run_id": "run-2", "conclusion": "failure", "commit_sha": "sha-A"}, commit_sha="sha-A")
    claim = verify_ci_claim("CI GREEN", ci, issuer=issuer, commit_sha="sha-A")
    assert claim.status == EvidenceStatus.FAILED


# --- 4. completion gate ------------------------------------------------------

def _verified_gate(issuer, gate: CompletionGate) -> Claim:
    evidence = issuer.mint("ci_runner", "gate", {"gate": gate.value})
    return Claim(
        statement=f"{gate.value} proven",
        status=EvidenceStatus.VERIFIED,
        claim_id=gate.value,
        evidence=(evidence,),
    )


def test_completion_requires_all_gates(issuer):
    partial = [_verified_gate(issuer, g) for g in list(CompletionGate)[:-1]]
    result = evaluate_completion(partial, issuer=issuer)
    assert result["result"] == "NOT_COMPLETE"
    assert result["missing"] == [list(CompletionGate)[-1].value]


def test_completion_impossible_with_claimed_only_gate(issuer):
    gates = [_verified_gate(issuer, g) for g in list(CompletionGate)[:-1]]
    gates.append(Claim(statement="EVIDENCE_COMPLETE (model says so)", status=EvidenceStatus.VERIFIED, claim_id=CompletionGate.EVIDENCE_COMPLETE.value))
    result = evaluate_completion(gates, issuer=issuer)
    assert result["result"] == "NOT_COMPLETE"
    assert "EVIDENCE_COMPLETE" in result["missing"]


def test_full_completion_with_all_verified_gates(issuer):
    gates = [_verified_gate(issuer, g) for g in CompletionGate]
    result = evaluate_completion(gates, issuer=issuer)
    assert result["result"] == "COMPLETE"
    assert result["missing"] == []


def test_no_claims_means_not_complete(issuer):
    result = evaluate_completion([], issuer=issuer)
    assert result["result"] == "NOT_COMPLETE"
    assert len(result["missing"]) == len(list(CompletionGate))


def test_gate_matching_is_exact_not_substring(issuer):
    # T0 B6: a statement that merely CONTAINS a gate name must not match.
    imposter = Claim(
        statement="CI_PASS and everything else, trust me",
        status=EvidenceStatus.VERIFIED,
        claim_id="NOT_A_GATE",
        evidence=(issuer.mint("ci_runner", "gate", {"gate": "CI_PASS"}),),
    )
    result = evaluate_completion([imposter], issuer=issuer)
    assert result["result"] == "NOT_COMPLETE"
    assert "CI_PASS" in result["missing"]


def test_failed_gate_evidence_contradicts_completion(issuer):
    failed_gate = Claim(
        statement="TESTS_PASS failed",
        status=EvidenceStatus.FAILED,
        claim_id=CompletionGate.TESTS_PASS.value,
        evidence=(issuer.mint("test_runner", "gate", {"gate": "TESTS_PASS", "exit_code": 1}),),
    )
    ok_gates = [_verified_gate(issuer, g) for g in CompletionGate if g is not CompletionGate.TESTS_PASS]
    result = evaluate_completion(ok_gates + [failed_gate], issuer=issuer)
    assert result["result"] == "NOT_COMPLETE"
    assert "TESTS_PASS" in result["contradicted"]


# --- 5. serialization exposes machine-readable status -----------------------

def test_claim_dict_exposes_status_explicitly():
    claim = Claim(statement="s", status=EvidenceStatus.UNVERIFIED, claim_id="C9")
    d = claim.to_dict()
    assert d["status"] == "UNVERIFIED"
    assert "evidence_count" in d


def test_api_semantics_never_complete_non_verified_statuses():
    for status, semantics in EVIDENCE_STATUS_SEMANTICS.items():
        if status is EvidenceStatus.VERIFIED or status is EvidenceStatus.OBSERVED:
            continue
        assert semantics["completed"] is False, status
        assert semantics["ok"] is False, status


def test_mission_truth_payload_reflects_server_truth_only():
    from security.truthfulness import mission_truth_payload
    unverified = mission_truth_payload("GOAL_COMPLETED", {"verified": False})
    assert unverified["completion"] == "NOT_COMPLETE"
    assert unverified["goal_verified"] is False
    verified = mission_truth_payload("GOAL_COMPLETED", {"verified": True, "evidence_count": 2, "missing_criteria": []})
    assert verified["completion"] == "COMPLETE"
    assert verified["answer_authority"] == "MODEL_OUTPUT"
