"""Behavioral tests for the generalization benchmark.

The benchmark must stay honest:
* metrics are computed only on the fixture probe set
* refusal probes map to UNKNOWN (the engine is rewarded for refusing)
* every mapped probe produces only TENTATIVE hypotheses
* the result carries its scoped-no-claims disclaimer
"""

from cyber.generalization_benchmark import run_generalization_benchmark


class TestGeneralizationBenchmark:
    def test_benchmark_runs_and_reports_scoped_metrics(self):
        result = run_generalization_benchmark()
        d = result.to_dict()
        assert d["probe_count"] == 12
        assert "no real-world or comparative claim" in d["scope"]
        for key in ("top1_accuracy", "top5_recall", "refusal_honesty"):
            assert 0.0 <= d[key] <= 1.0

    def test_refusal_probes_are_all_unknown(self):
        result = run_generalization_benchmark()
        assert result.refusal_probes_total == 3
        assert result.refusal_probes_unknown == 3
        assert result.refusal_honesty == 1.0

    def test_mapped_probes_produce_only_tentative_hypotheses(self):
        result = run_generalization_benchmark()
        assert result.tentative_probes + result.unknown_probes == 12
        for probe in result.per_probe:
            if probe["status"] == "TENTATIVE":
                assert probe["ranked"]

    def test_top5_recall_is_nonzero_over_the_fixtures(self):
        result = run_generalization_benchmark()
        # fixture-scoped expectation, hand-verified for these probes only
        assert result.top5_hits >= 10
