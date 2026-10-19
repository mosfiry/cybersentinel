"""Deterministic, read-only routing to an Owner's active approved Skills.

This module selects a descriptive skill reference only. It never executes a
skill, consults a model or external API, loads skill files, or grants authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import unicodedata
from typing import Any, Iterable

from .skills import SkillError, SkillStatus, validate_skill_definition


_MAX_OBJECTIVE_CHARS = 12_000
_MAX_OWNER_CHARS = 256
_MAX_INPUT_ITEMS = 500
_MAX_ITEM_CHARS = 256
_MAX_ACTIVE_SKILLS = 500


@dataclass(frozen=True)
class SkillRoutingDecision:
    """Bounded result of routing; only a selected result binds a Skill."""

    outcome: str
    reason_code: str
    skill_id: str | None = None
    version: int | None = None
    content_hash: str | None = None
    score: int = 0
    catalog_count: int = 0
    eligible_count: int = 0
    matched_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return stable, bounded metadata without goal text or matched tokens."""
        result: dict[str, Any] = {
            "version": 1,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "score": self.score,
            "catalog_count": self.catalog_count,
            "eligible_count": self.eligible_count,
            "matched_count": self.matched_count,
        }
        if self.outcome == "selected":
            result.update({
                "skill_id": self.skill_id,
                "skill_version": self.version,
                "content_hash": self.content_hash,
            })
        return result


def _tokens(value: str) -> frozenset[str]:
    """Split on non-letter/digit Unicode characters (including Arabic text)."""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    tokens: set[str] = set()
    current: list[str] = []
    for char in normalized:
        category = unicodedata.category(char)
        if category[0] in {"L", "N"} or (category[0] == "M" and current):
            current.append(char)
        elif current:
            tokens.add("".join(current))
            current.clear()
    if current:
        tokens.add("".join(current))
    return frozenset(tokens)


def _string_set(values: Iterable[str], field: str) -> frozenset[str]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{field} must be an iterable of strings, not a string")
    try:
        iterator = iter(values)
        collected: list[str] = []
        for _ in range(_MAX_INPUT_ITEMS + 1):
            try:
                item = next(iterator)
            except StopIteration:
                break
            if len(collected) == _MAX_INPUT_ITEMS:
                raise ValueError(f"{field} exceeds the bounded item limit")
            if not isinstance(item, str) or not item.strip() or len(item) > _MAX_ITEM_CHARS:
                raise ValueError(f"{field} contains a malformed item")
            collected.append(item.strip())
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{field} must be a finite iterable of strings") from exc
    return frozenset(collected)


def _decision(
    outcome: str,
    reason_code: str,
    *,
    score: int = 0,
    catalog_count: int = 0,
    eligible_count: int = 0,
    matched_count: int = 0,
) -> SkillRoutingDecision:
    return SkillRoutingDecision(
        outcome=outcome,
        reason_code=reason_code,
        score=score,
        catalog_count=catalog_count,
        eligible_count=eligible_count,
        matched_count=matched_count,
    )


def route_skill(
    registry: Any,
    *,
    owner_identity_ref: str,
    objective: str,
    available_tools: Iterable[str],
    allowed_scope: Iterable[str],
    required_tools: Iterable[str] = (),
) -> SkillRoutingDecision:
    """Choose an eligible positive lexical match from one owner's active Skills.

    The registry's ``skill_heads`` table is queried rather than its revision
    history so old revisions cannot crowd current Skills out of the bounded
    catalog. All candidates are loaded again through ``get_active`` and checked
    against the registry's canonical tool specifications before scoring.
    """
    if not isinstance(owner_identity_ref, str) or not owner_identity_ref.strip() or len(owner_identity_ref) > _MAX_OWNER_CHARS:
        raise ValueError("owner_identity_ref must be a non-empty bounded string")
    if not isinstance(objective, str) or len(objective) > _MAX_OBJECTIVE_CHARS:
        raise ValueError("objective must be a string of at most 12000 characters")
    owner_ref = owner_identity_ref.strip()
    tools = _string_set(available_tools, "available_tools")
    scope = _string_set(allowed_scope, "allowed_scope")
    requested_tools = _string_set(required_tools, "required_tools")
    objective_tokens = _tokens(objective)
    if not objective_tokens:
        return _decision("no_match", "no_positive_match")

    # The registry currently has no public active-list operation. Read only the
    # bounded active-head index through its maintained connection context; use
    # get_active() for revision/status/expiry checks and never scan history.
    try:
        with registry._connect() as conn:
            rows = conn.execute(
                "SELECT skill_id FROM skill_heads "
                "WHERE owner_identity_ref=? AND active_version IS NOT NULL "
                "ORDER BY skill_id LIMIT ?",
                (owner_ref, _MAX_ACTIVE_SKILLS + 1),
            ).fetchall()
    except Exception:
        return _decision("unavailable", "registry_unavailable")
    if len(rows) > _MAX_ACTIVE_SKILLS:
        return _decision("unavailable", "catalog_limit_exceeded")

    revisions = []
    try:
        for row in rows:
            revision = registry.get_active(owner_ref, str(row[0]))
            if revision is None:
                continue
            if revision.owner_identity_ref != owner_ref or revision.status is not SkillStatus.APPROVED:
                continue
            validate_skill_definition(revision.definition, registry.tool_specs)
            revisions.append(revision)
    except Exception:
        # Corrupt/tampered active state fails closed; no unvalidated result is
        # allowed to compete with sound candidates.
        return _decision("unavailable", "invalid_active_skill", catalog_count=len(rows))

    scored: list[tuple[int, str, Any]] = []
    eligible_count = 0
    matched_count = 0
    for revision in revisions:
        definition = revision.definition
        name_tokens = _tokens(definition.name)
        capability_tokens: set[str] = set()
        for capability in definition.capabilities:
            capability_tokens.update(_tokens(capability))
        score = 3 * len(objective_tokens & name_tokens) + 2 * len(objective_tokens & capability_tokens)
        if score <= 0:
            continue
        matched_count += 1
        if (
            not set(definition.required_tools).issubset(tools)
            or not set(definition.allowed_scope).issubset(scope)
            or not requested_tools.issubset(definition.required_tools)
        ):
            continue
        eligible_count += 1
        scored.append((score, definition.skill_id, revision))

    if not scored:
        if matched_count:
            return _decision(
                "unavailable", "constraints_unsatisfied", catalog_count=len(revisions),
                eligible_count=0, matched_count=matched_count,
            )
        return _decision("no_match", "no_positive_match", catalog_count=len(revisions))

    highest = max(item[0] for item in scored)
    winners = sorted((item for item in scored if item[0] == highest), key=lambda item: item[1])
    if len(winners) != 1:
        return _decision(
            "ambiguous", "top_score_tie", score=highest, catalog_count=len(revisions),
            eligible_count=eligible_count, matched_count=matched_count,
        )
    revision = winners[0][2]
    definition = revision.definition
    return SkillRoutingDecision(
        outcome="selected",
        reason_code="eligible_positive_match",
        skill_id=definition.skill_id,
        version=definition.version,
        content_hash=definition.content_hash,
        score=highest,
        catalog_count=len(revisions),
        eligible_count=eligible_count,
        matched_count=matched_count,
    )
