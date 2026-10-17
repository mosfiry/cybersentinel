"""Contract tests for the documented Owner policy reference model.

The live authorization boundary is implemented separately by owner_policy,
AuthorizationContext, authorize_tool, and the governed execution runtime.
These tests must not imply that owner_charter.py itself grants runtime access.
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


def test_canonical_charter_document_declares_owner_rank_and_separate_gates():
    text = _charter_doc_text()
    assert "OWNER_INSTRUCTION" in text
    assert "900" in text
    assert "800" in text
    assert "RuleProvenance.OWNER_INSTRUCTION" in text
    assert "CHARTER_PRECEDENCE" in text
    assert "NON_OVERRIDABLE_EXECUTION_GATES" in text
    assert "لا يمنح إذن تنفيذ" in text


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
    assert "ليست جزءًا من مسار التفويض الحي" in text


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
