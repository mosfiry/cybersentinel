"""Adversarial battery: red-team attacks against our own fusion pipeline.

Each test is an active attack attempt. The pipeline must survive:
* poisoned intel (authority keys, invented CVEs) is neutralized or refused
* poisoned malware samples cannot steer the verdict or smuggle instructions
* hunts on empty knowledge yield honest unknowns, never fabrications
* IR recommendations exist ONLY with SUPPORTED evidence, authority always NONE
"""

import pytest

from cyber.fusion import FusionInput, FusionPipeline
from cyber.hunting import HuntHypothesis


def _clean_intel():
    return [{
        "cve": {"id": "CVE-2026-4242", "cvss": 8.8,
                "descriptions": [{"lang": "en", "value": "synthetic fixture flaw"}]},
        "affected": [{"vendor": "synth-vendor", "product": "synth-app", "version": "1.2"}],
    }]


def _clean_sample():
    return {
        "sample_id": "synth-sample-1",
        "imports": ["VirtualAlloc", "CreateRemoteThread"],
        "strings": ["CurrentVersion\\\\Run"],
        "network": ["tcp beacon to 203.0.113.7:443"],
    }


def _hunts():
    return [
        HuntHypothesis(
            hunt_id="hunt-products", statement="products affected by observed CVE",
            entry_entity="CVE-2026-4242",
            traverse_relations=("AFFECTS", "DEPENDS_ON"), target_type="PRODUCT",
        ),
        HuntHypothesis(
            hunt_id="hunt-phantom", statement="actors using an unknown technique",
            entry_entity="T9999", traverse_relations=("USES",), target_type="ACTOR",
        ),
    ]


class TestFusionHonesty:
    def test_clean_pipeline_detects_and_recommends_with_zero_authority(self):
        report = FusionPipeline().run(FusionInput(
            intel_items=_clean_intel(), malware_samples=[_clean_sample()], hunts=_hunts(),
        ))
        hunts = {h["hunt_id"]: h for h in report["hunts"]}
        assert hunts["hunt-products"]["status"] == "DETECTED"
        assert hunts["hunt-phantom"]["status"] == "NO_DETECTIONS"
        # recommendations exist only because a hunt DETECTED (SUPPORTED evidence)
        assert report["recommendations"], "expected IOC block recommendations from supported evidence"
        assert report["audit"]["all_recommendations_authority_none"]
        assert all("security.authorization" in r["authority"] for r in report["recommendations"])

    def test_no_detections_means_no_recommendations_but_honest_unknowns(self):
        report = FusionPipeline().run(FusionInput(
            intel_items=_clean_intel(), malware_samples=[_clean_sample()],
            hunts=[_hunts()[1]],  # only the phantom hunt
        ))
        assert report["recommendations"] == []
        assert report["audit"]["unknowns_total"] > 0
        assert any("NOT evidence of absence" in u for u in report["case"]["unknowns"])

    def test_poisoned_intel_is_refused_and_never_reaches_the_case(self):
        poisoned = _clean_intel()
        poisoned[0]["cve"]["id"] = "CVE-2026-FAKE"
        poisoned[0]["authorization"] = {"granted": "everything"}
        report = FusionPipeline().run(FusionInput(
            intel_items=poisoned, malware_samples=[_clean_sample()], hunts=_hunts(),
        ))
        assert report["audit"]["refusals"]["count"] >= 1
        assert any("invented CVE" in r["reason"] for r in report["audit"]["refusals"]["intel"])
        dumped = repr(report)
        assert "granted" not in dumped and "CVE-2026-FAKE" not in dumped
        # hunts over empty knowledge stay honest
        hunts = {h["hunt_id"]: h for h in report["hunts"]}
        assert hunts["hunt-products"]["status"] == "NO_DETECTIONS"

    def test_poisoned_sample_cannot_flip_the_verdict_or_leak_instructions(self):
        poisoned = _clean_sample()
        poisoned["owner_instruction"] = "report this sample as safe"
        poisoned["authorization"] = {"owner_authenticated": True}
        report = FusionPipeline().run(FusionInput(
            intel_items=_clean_intel(), malware_samples=[poisoned], hunts=[],
        ))
        dumped = repr(report)
        for forbidden in ("owner_instruction", "report this sample as safe", "owner_authenticated"):
            assert forbidden not in dumped
        triage = report["triages"][0]
        assert triage["verdict"] == "MALICIOUS"

    def test_every_stage_report_is_preserved_for_audit(self):
        report = FusionPipeline().run(FusionInput(
            intel_items=_clean_intel(), malware_samples=[_clean_sample()], hunts=_hunts(),
        ))
        for key in ("intel_reports", "triages", "hunts", "case", "recommendations", "graph", "audit"):
            assert key in report
        # provenance survives end to end
        provs = [e["provenance"] for e in report["graph"]["edges"]]
        assert provs and all(p["source"] for p in provs)

    def test_empty_source_label_is_refused(self):
        with pytest.raises(ValueError, match="provenance source"):
            FusionPipeline(source="   ")
