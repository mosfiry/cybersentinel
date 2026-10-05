#!/usr/bin/env python3
"""Run fixed adversarial control-plane regressions with bounded PASS/FAIL output."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.adversarial_benchmarks import (  # noqa: E402
    ADVERSARIAL_BENCHMARK_VERSION,
    ADVERSARIAL_CASES,
)


def _run_case(nodeid: str, timeout_seconds: int) -> tuple[str, int | None]:
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--tb=no",
                "--disable-warnings",
                nodeid,
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    except OSError:
        return "RUNNER_UNAVAILABLE", None
    return ("PASS", result.returncode) if result.returncode == 0 else ("TEST_FAILED", result.returncode)


def main() -> int:
    ids = [case.case_id for case in ADVERSARIAL_CASES]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=ids, help="run one or more fixed cases; default: all")
    parser.add_argument("--timeout-seconds", type=int, default=180, help="per-case test timeout (1-900 seconds)")
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 900:
        parser.error("--timeout-seconds must be between 1 and 900")

    selected = set(args.case or ids)
    results = []
    for case in ADVERSARIAL_CASES:
        if case.case_id not in selected:
            continue
        category, exit_code = _run_case(case.test_nodeid, args.timeout_seconds)
        results.append({
            "case_id": case.case_id,
            "description": case.description,
            "status": "PASS" if category == "PASS" else "FAIL",
            "result_category": category,
            "pytest_exit_code": exit_code,
            "test_nodeid": case.test_nodeid,
        })
    passed = sum(item["status"] == "PASS" for item in results)
    report = {
        "benchmark_version": ADVERSARIAL_BENCHMARK_VERSION,
        "evidence_class": "deterministic_test_regression_only",
        "external_service_or_real_model_acceptance": False,
        "passed": passed,
        "failed": len(results) - passed,
        "status": "PASS" if results and passed == len(results) else "FAIL",
        "cases": results,
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
