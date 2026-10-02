from __future__ import annotations

import pytest

from cyber_data.poc_validation import PocClass, classify_poc


def test_missing_or_empty_poc_is_no_poc():
    assert classify_poc(None) is PocClass.NO_POC
    assert classify_poc("text record") is PocClass.NO_POC
    assert classify_poc({}) is PocClass.NO_POC
    assert classify_poc({"poc": None}) is PocClass.NO_POC
    assert classify_poc({"poc": {}}) is PocClass.NO_POC
    assert classify_poc({"poc": {"kind": "none"}}) is PocClass.NO_POC


def test_structural_kinds_map_deterministically():
    assert classify_poc({"poc": {"kind": "reference", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}}) is PocClass.REFERENCE_ONLY
    assert classify_poc({"poc": {"kind": "non_executable", "steps": ["describe payload"]}}) is PocClass.NON_EXECUTABLE
    assert classify_poc({"poc": {"kind": "lab_reproducer", "steps": ["step one", "step two"], "expected": "crash"}}) is PocClass.LAB_REPRODUCER


def test_verified_lab_poc_requires_complete_lab_evidence():
    complete = {"lab_id": "lab-01", "verified_at": "2026-10-02T00:00:00+00:00", "evidence_hash": "a" * 64}
    assert classify_poc({"poc": {"kind": "verified_lab_poc", "lab_evidence": dict(complete)}}) is PocClass.VERIFIED_LAB_POC
    for missing in ("lab_id", "verified_at", "evidence_hash"):
        partial = dict(complete)
        partial[missing] = ""
        assert classify_poc({"poc": {"kind": "verified_lab_poc", "lab_evidence": partial}}) is PocClass.LAB_REPRODUCER
    assert classify_poc({"poc": {"kind": "verified_lab_poc"}}) is PocClass.LAB_REPRODUCER
    assert classify_poc({"poc": {"kind": "verified_lab_poc", "lab_evidence": "self-declared"}}) is PocClass.LAB_REPRODUCER


@pytest.mark.parametrize("bad_kind", ["PoC", "exploit", "verified", "lab", "VERIFIED_LAB_POC", "", None, 5])
def test_unknown_kind_is_rejected_fail_closed(bad_kind):
    with pytest.raises(ValueError):
        classify_poc({"poc": {"kind": bad_kind}})


def test_prose_mentions_never_upgrade_classification():
    # The brief forbids treating a mention, a link, or the word exploit as a PoC.
    assert classify_poc({"poc": {"kind": "reference", "text": "exploit available, full PoC at link, weaponized"}}) is PocClass.REFERENCE_ONLY
    assert classify_poc({"text": "this is a working PoC with exploit code", "poc": {"kind": "none"}}) is PocClass.NO_POC


def test_no_classification_grants_execution():
    assert classify_poc({"poc": {"kind": "verified_lab_poc", "lab_evidence": {"lab_id": "l", "verified_at": "t", "evidence_hash": "h"}}}).value == "VERIFIED_LAB_POC"
    # The classifier returns a label only; it exposes no execution capability of any kind.
    assert set(PocClass) == {PocClass.NO_POC, PocClass.REFERENCE_ONLY, PocClass.NON_EXECUTABLE, PocClass.LAB_REPRODUCER, PocClass.VERIFIED_LAB_POC}
