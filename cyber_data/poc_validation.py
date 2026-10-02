from __future__ import annotations

"""PoC classification for training-data governance (V11).

Deterministic, STRUCTURAL classification only. Mentions of "PoC", "exploit",
CVE identifiers, or links NEVER upgrade a record: the mission brief explicitly
forbids treating a mention, a link, or the word exploit as a PoC. The validator
classifies records supplied to it; it never collects, constructs, or executes
PoCs, and no classification grants execution permission.
"""

from enum import Enum


class PocClass(str, Enum):
    NO_POC = "NO_POC"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    NON_EXECUTABLE = "NON_EXECUTABLE"
    LAB_REPRODUCER = "LAB_REPRODUCER"
    VERIFIED_LAB_POC = "VERIFIED_LAB_POC"


_KIND_FIELD = "kind"
_ALLOWED_KINDS = frozenset({"none", "reference", "non_executable", "lab_reproducer", "verified_lab_poc"})
_VERIFICATION_FIELDS = ("lab_id", "verified_at", "evidence_hash")


def classify_poc(record: object) -> PocClass:
    """Classify one training record's PoC field structurally, fail-closed.

    Rules (deterministic; no prose inference):
    - non-dict record, missing/empty poc, or kind "none"      -> NO_POC
    - kind "reference"                                         -> REFERENCE_ONLY
    - kind "non_executable"                                    -> NON_EXECUTABLE
    - kind "lab_reproducer"                                    -> LAB_REPRODUCER
    - kind "verified_lab_poc" WITHOUT complete lab evidence    -> LAB_REPRODUCER (never self-declared)
    - kind "verified_lab_poc" WITH complete lab evidence       -> VERIFIED_LAB_POC
    - unknown kind                                             -> ValueError (fail-closed)
    """
    if not isinstance(record, dict):
        return PocClass.NO_POC
    poc = record.get("poc")
    if poc is None or poc == {} or poc == "":
        return PocClass.NO_POC
    if not isinstance(poc, dict):
        raise ValueError("invalid_poc_field")
    kind = poc.get(_KIND_FIELD)
    if not isinstance(kind, str) or kind not in _ALLOWED_KINDS:
        raise ValueError("invalid_poc_kind")
    if kind == "none":
        return PocClass.NO_POC
    if kind == "reference":
        return PocClass.REFERENCE_ONLY
    if kind == "non_executable":
        return PocClass.NON_EXECUTABLE
    if kind == "lab_reproducer":
        return PocClass.LAB_REPRODUCER
    evidence = poc.get("lab_evidence")
    if not isinstance(evidence, dict) or any(
        not isinstance(evidence.get(field), str) or not evidence.get(field, "").strip()
        for field in _VERIFICATION_FIELDS
    ):
        return PocClass.LAB_REPRODUCER
    return PocClass.VERIFIED_LAB_POC


__all__ = ["PocClass", "classify_poc"]
