from __future__ import annotations

from pathlib import Path

from evaluation.adversarial_benchmarks import ADVERSARIAL_BENCHMARK_VERSION, ADVERSARIAL_CASES


def test_adversarial_catalog_has_stable_coverage_for_all_fourteen_required_scenarios():
    expected = {
        "prompt-injection",
        "web-injection",
        "memory-poisoning",
        "skill-poisoning",
        "malicious-mcp",
        "cross-mission-leakage",
        "scope-escalation",
        "tool-privilege-escalation",
        "fake-evidence",
        "provider-failure",
        "browser-failure",
        "runtime-crash",
        "mission-interruption",
        "restart-resume",
    }
    assert ADVERSARIAL_BENCHMARK_VERSION == "cybersentinel-adversarial-control-plane-v1"
    assert {case.case_id for case in ADVERSARIAL_CASES} == expected
    assert len(ADVERSARIAL_CASES) == len(expected)
    assert len({case.test_nodeid for case in ADVERSARIAL_CASES}) == len(expected)


def test_every_adversarial_case_maps_to_a_repository_local_pytest_target():
    root = Path(__file__).resolve().parents[1]
    for case in ADVERSARIAL_CASES:
        path_text = case.test_nodeid.split("::", 1)[0]
        path = (root / path_text).resolve()
        assert path.is_relative_to(root)
        assert path.is_file()
        assert case.description
        assert len(case.description) <= 200
