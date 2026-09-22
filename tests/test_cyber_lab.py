"""Behavioral tests for the offensive reasoning evaluation lab.

The lab itself must be honest: synthetic targets are FIXTURE-class, the
engine finds seeded findings only through evidence support, decoy assets
never win, and effort scaling is measured, not claimed.
"""

from __future__ import annotations

from cyber.lab import (
    COMMERCE,
    GOV_PORTAL,
    LAB_TARGETS,
    UNIVERSITY,
    compare_effort_levels,
    evidence_for_asset,
    knowledge_fixture,
    run_lab_evaluation,
)
from cyber.reasoning_engine import ReasoningEffort


def test_lab_targets_are_synthetic_not_real_organizations():
    for target in LAB_TARGETS:
        assert target.target_id.startswith("synth-")
    # no real hostname appears anywhere in the lab module
    import cyber.lab as lab_module
    source = open(lab_module.__file__, encoding="utf-8").read().lower()
    for forbidden in ("amazon", "google", "microsoft", "yale", "harvard", "whitehouse", "defense.gov", ".mil", ".gov", ".edu"):
        assert forbidden not in source.replace("gov-portal", "").replace("synthetic", ""), "real-world reference leaked: " + forbidden


def test_engine_finds_seeded_findings_through_evidence():
    result = run_lab_evaluation(effort=ReasoningEffort.DEEP)
    assert result["seeded_findings_found"] == len(LAB_TARGETS)
    for entry in result["per_target"]:
        assert entry["found_seeded_finding"] is True
        assert entry["winner"] == entry["seeded_finding"]


def test_decoy_nonexistent_asset_never_wins():
    result = run_lab_evaluation(effort=ReasoningEffort.DEEP)
    assert result["fabricated_winners"] == 0
    for entry in result["per_target"]:
        assert entry["winner"] != "nonexistent-asset"


def test_unknown_technique_critique_is_raised_for_decoys():
    result = run_lab_evaluation(effort=ReasoningEffort.DEEP)
    assert result["unknown_technique_critiques_raised"] == len(LAB_TARGETS)
    for entry in result["per_target"]:
        assert "unverified_technique" in entry["critique_kinds"]


def test_evidence_lookup_separates_existing_from_nonexistent():
    assert evidence_for_asset(COMMERCE, "a-api") is not None
    assert evidence_for_asset(COMMERCE, "nonexistent-asset") is None


def test_effort_scaling_is_measured_across_levels():
    scaling = compare_effort_levels()
    assert set(scaling) == {"fast", "standard", "deep", "exhaustive"}
    # deeper effort must at least match shallower effort on seeded findings
    values = [scaling[k]["seeded_findings_found"] for k in ("fast", "standard", "deep", "exhaustive")]
    assert all(later >= earlier for earlier, later in zip(values, values[1:]))


def test_lab_results_are_fixture_classified():
    result = run_lab_evaluation()
    assert result["lab_classification"] == "FIXTURE"
    assert "NOT an operational-effectiveness claim" in result["note"]


def test_all_three_profiles_are_covered():
    assert {t.profile for t in LAB_TARGETS} == {"ecommerce", "gov-portal", "university"}
    assert COMMERCE.seeded_finding == "a-api"
    assert GOV_PORTAL.seeded_finding == "g-docs"
    assert UNIVERSITY.seeded_finding == "u-sso"


def test_knowledge_fixture_is_fixture_not_real():
    graph = knowledge_fixture()
    data = graph.to_dict()
    for edge in data["edges"]:
        assert edge["provenance"]["source_class"] == "FIXTURE"
