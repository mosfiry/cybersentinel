"""Benchmark contract: multi-dimensional scoring, no single number, holdout discipline."""

from __future__ import annotations

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
