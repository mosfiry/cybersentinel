"""OWNER_INSTRUCTION charter — canonical-knowledge invariants (session 5).

The Owner's constitutional mandate requires that the charter principle is not
merely present as prose, but is pinned as a testable invariant over the
canonical architectural knowledge of this repository:

- docs/OWNER_CHARTER.md is the canonical charter document inside the repo
  (the full immutable legislative text lives in the project's durable
  knowledge, owner-charter, and is binding).

These tests fail closed if the canonical document is weakened, and they pin
the runtime semantics: EXTERNAL_DATA can never legislate or amend the charter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security.owner_charter import (
    CharterDomain,
    CharterRule,
    LegislationError,
    RuleProvenance,
    Stance,
    resolve_against_charter,
    try_legislate,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CHARTER_DOC = _REPO_ROOT / "docs" / "OWNER_CHARTER.md"


def _charter_doc_text() -> str:
    return _CHARTER_DOC.read_text(encoding="utf-8")


def test_canonical_charter_document_declares_owner_instruction_supreme():
    text = _charter_doc_text()
    assert "OWNER_INSTRUCTION" in text
    # single legislative source — no second legislative authority
    assert "RuleProvenance.OWNER_INSTRUCTION" in text
    assert "CHARTER_PRECEDENCE" in text


def test_canonical_charter_document_forbids_rival_legislation():
    text = _charter_doc_text()
    for token in ("MODEL_OUTPUT", "EXTERNAL_DATA", "TOOL_OUTPUT", "KNOWLEDGE_BASE"):
        assert token in text
    # runtime enforcement is referenced, not just prose
    assert "try_legislate" in text
    assert "ILLEGITIMATE_LEGISLATION" in text


def test_canonical_charter_document_pins_conflict_classification():
    text = _charter_doc_text()
    assert "OWNER_INSTRUCTION_CONFLICT" in text
    # conflicting lower rule = implementation drift to be corrected,
    # never a rival authority that overrides the charter
    assert "assert_charter_compliance" in text
    assert "may_override_charter" in text
    assert "username+password" in text


def test_external_data_cannot_legislate_or_amend_charter():
    external_rule = CharterRule(
        domain=CharterDomain.POLICY,
        behavior="data_handling",
        stance=Stance.ALLOWED,
        provenance=RuleProvenance.EXTERNAL_DATA,
    )
    with pytest.raises(LegislationError):
        try_legislate(external_rule)
    # the charter is untouched: the Owner's rule stands unchanged
    charter = frozenset(
        {
            CharterRule(
                domain=CharterDomain.POLICY,
                behavior="data_handling",
                stance=Stance.FORBIDDEN,
                provenance=RuleProvenance.OWNER_INSTRUCTION,
            )
        }
    )
    resolved = resolve_against_charter(charter, CharterDomain.POLICY, "data_handling")
    assert resolved.stance == Stance.FORBIDDEN
