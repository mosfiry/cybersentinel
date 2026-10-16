"""Benchmark contract: multi-dimensional scoring, no single number, holdout discipline."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import cyber.benchmark as benchmark
from cyber.benchmark import DEV_CASES, run_benchmark, Case


def test_benchmark_runs_all_dev_dimensions():
    result = run_benchmark()
    assert result["cases_run"] == len(DEV_CASES)
    assert result["cases_passed"] == result["cases_run"]
    assert result["unsupported_claims"] == 0
    for dim in ("uncertainty", "chain", "conflict", "antihalluc"):
        assert dim in result["by_dimension"]
        assert result["by_dimension"][dim]["passed"] == result["by_dimension"][dim]["total"]


def test_benchmark_exposes_holdout_discipline_not_a_single_score():
    result = run_benchmark()
    assert "score" not in result
    assert "holdout" in result


def test_benchmark_case_failure_is_recorded_not_hidden():
    def failing_case() -> tuple[bool, int, list[str]]:
        return False, 2, ["declared winner from non-discriminating evidence"]

    result = run_benchmark([Case("dev-uncertainty-bad", "uncertainty_calibration", failing_case)])
    assert result["cases_passed"] == 0
    assert result["unsupported_claims"] == 2
    assert result["by_dimension"]["uncertainty"]["unsupported_claims"] == 2


@pytest.mark.parametrize(
    ("helper", "patch_target", "method", "replacement", "expected_note"),
    [
        (
            benchmark._case_uncertainty_calibration,
            benchmark.MultiHypothesisEngine,
            "dominant",
            lambda self: SimpleNamespace(hypothesis_id="premature"),
            "non-discriminating evidence",
        ),
        (
            benchmark._case_attack_chain_reconstruction,
            benchmark.AttackChainReconstructor,
            "reconstruct",
            lambda self, edges: {"status": "SUPPORTED", "missing_transitions": []},
            "fabricated into a conclusion",
        ),
        (
            benchmark._case_source_conflict,
            benchmark.SourceConflictEngine,
            "evaluate",
            lambda self, claims: {"status": "SUPPORTED", "values": ["critical"]},
            "auto-resolved",
        ),
    ],
)
def test_benchmark_cases_report_guardrail_failures(
    monkeypatch, helper, patch_target, method, replacement, expected_note
):
    monkeypatch.setattr(patch_target, method, replacement)

    passed, unsupported, notes = helper()

    assert passed is False
    assert unsupported == 1
    assert expected_note in notes[0]


@pytest.mark.parametrize(
    "fake_result,known_result,expected_note",
    [
        (("KNOWN", 0), ("SUPPORTED", 0), "fabricated IOC"),
        (("UNKNOWN", 0), ("HYPOTHESIS", 1), "known IOC"),
    ],
)
def test_anti_hallucination_case_reports_gate_failures(
    monkeypatch, fake_result, known_result, expected_note
):
    def classify(self, entity_id, statement):
        if entity_id == "IOC-FAKE-123":
            classification, source_count = fake_result
        else:
            classification, source_count = known_result
        return {"classification": classification, "source_count": source_count}

    monkeypatch.setattr(benchmark.CyberClaimGate, "classify", classify)

    passed, unsupported, notes = benchmark._case_anti_hallucination()

    assert passed is False
    assert unsupported == 1
    assert expected_note in notes[0]
