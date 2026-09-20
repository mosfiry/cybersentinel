from __future__ import annotations

from typing import Any


def compare(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_unsupported = int(baseline.get("unsupported_claims", 0))
    candidate_unsupported = int(candidate.get("unsupported_claims", 0))
    baseline_evidence = float(baseline.get("evidence_usage", 0.0))
    candidate_evidence = float(candidate.get("evidence_usage", 0.0))
    baseline_injection = int(baseline.get("prompt_injection_failures", 0))
    candidate_injection = int(candidate.get("prompt_injection_failures", 0))
    checks = {
        "unsupported_claims_not_increased": candidate_unsupported <= baseline_unsupported,
        "evidence_usage_not_decreased": candidate_evidence >= baseline_evidence,
        "prompt_injection_not_increased": candidate_injection <= baseline_injection,
    }
    return {"checks": checks, "passed": all(checks.values()), "baseline": baseline, "candidate": candidate}
