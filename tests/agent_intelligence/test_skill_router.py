from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from agent.intelligence_layer.skill_router import route_skill
from agent.intelligence_layer.skills import (
    SkillApprovalGrant,
    SkillCandidateEvidence,
    SkillDefinition,
    SkillRevision,
    SkillStatus,
    SkillStep,
    SkillTestCase,
)
from tools.registry import REGISTRY

OWNER = "router-owner"
OTHER_OWNER = "other-owner"
SCOPE = ("host:example.test",)
TOOL = "search"


def owner_grant(action, owner_ref, skill_id, version):
    return SkillApprovalGrant(owner_ref, owner_ref, action, f"decision:{action}:{skill_id}:{version}")


def make_registry(tmp_path):
    from agent.intelligence_layer.skills import SkillRegistry

    return SkillRegistry(
        tmp_path / "router-skills.sqlite3",
        tool_specs={TOOL: REGISTRY[TOOL]},
        approval_authorizer=owner_grant,
    )


def make_definition(
    skill_id: str,
    *,
    name: str,
    capabilities: tuple[str, ...],
    allowed_scope: tuple[str, ...] = SCOPE,
    description: str = "A safe declarative search skill.",
    expires_at: str | None = None,
) -> SkillDefinition:
    return SkillDefinition(
        skill_id=skill_id,
        name=name,
        description=description,
        version=1,
        author_source="router-test",
        capabilities=capabilities,
        required_tools=(TOOL,),
        allowed_scope=allowed_scope,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 240}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"finding": {"type": "string", "maxLength": 500}},
            "required": ["finding"],
            "additionalProperties": False,
        },
        procedure=(SkillStep(
            step_id="search-step",
            tool_name=TOOL,
            action="search",
            argument_bindings={"query": "input.query"},
        ),),
        preconditions=("authorized scope is active",),
        postconditions=("finding is returned",),
        examples=({"query": "test query"},),
        tests=(SkillTestCase(
            test_id="basic",
            inputs={"query": "test query"},
            expected_tool_sequence=(TOOL,),
            fixture_outputs={"search-step": {"finding": "verified"}},
        ),),
        provenance="deterministic test fixture",
        confidence=0.75,
        output_bindings={"finding": "step.search-step.finding"},
        expires_at=expires_at,
    )


def register(registry, definition, owner_ref=OWNER, *, approve=True):
    registry.register_candidate(
        owner_ref,
        definition,
        SkillCandidateEvidence(
            owner_identity_ref=owner_ref,
            mission_id="test-mission",
            trajectory_sha256="a" * 64,
            critic_id="test-critic",
            validator_id="test-validator",
            verification_evidence_sha256="b" * 64,
            evidence_refs=("evidence:1",),
            candidate_sha256=definition.content_hash,
        ),
    )
    if approve:
        registry.approve(owner_ref, definition.skill_id, definition.version)
    return definition


def route(registry, objective, **overrides):
    arguments = {
        "owner_identity_ref": OWNER,
        "objective": objective,
        "available_tools": (TOOL,),
        "allowed_scope": SCOPE,
        "required_tools": (),
    }
    arguments.update(overrides)
    return route_skill(registry, **arguments)


def test_selects_active_approved_owner_skill_and_returns_bounded_metadata(tmp_path):
    registry = make_registry(tmp_path)
    definition = make_definition(
        "skill-01", name="Host research", capabilities=("web research",)
    )
    register(registry, definition)

    decision = route(registry, "Please perform host research for sensitive-customer-42")

    assert decision.outcome == "selected"
    assert decision.skill_id == "skill-01"
    assert decision.version == 1
    assert decision.content_hash == definition.content_hash
    metadata = decision.to_dict()
    assert metadata == {
        "version": 1,
        "outcome": "selected",
        "reason_code": "eligible_positive_match",
        "score": 8,
        "catalog_count": 1,
        "eligible_count": 1,
        "matched_count": 1,
        "skill_id": "skill-01",
        "skill_version": 1,
        "content_hash": definition.content_hash,
    }
    assert "sensitive-customer-42" not in json.dumps(metadata)
    assert "research" not in json.dumps(metadata)
    assert route(registry, "Please perform host research").to_dict() == metadata


def test_uses_unicode_whole_tokens_for_arabic_and_does_not_match_substrings(tmp_path):
    registry = make_registry(tmp_path)
    register(registry, make_definition(
        "arabic-analysis", name="تحليل الشبكة", capabilities=("استجابة للحوادث",)
    ))

    assert route(registry, "أحتاج تحليل الشبكة الآن").skill_id == "arabic-analysis"
    assert route(registry, "تحليلاتالشبكة").outcome == "no_match"


def test_descriptions_procedures_and_examples_do_not_influence_lexical_match(tmp_path):
    registry = make_registry(tmp_path)
    definition = make_definition(
        "web-research", name="Web research", capabilities=("threat intelligence",),
        description="filesystem delete shell command secret exfiltration",
    )
    definition = replace(
        definition,
        procedure=(replace(definition.procedure[0], action="filesystem delete"),),
        examples=({"query": "secret exfiltration shell command"},),
        content_hash="",
    )
    register(registry, definition)

    decision = route(registry, "filesystem delete shell command secret exfiltration")
    assert decision.outcome == "no_match"
    assert decision.reason_code == "no_positive_match"


def test_ambiguous_ties_abstain_without_binding_and_are_stable(tmp_path):
    registry = make_registry(tmp_path)
    register(registry, make_definition("alpha", name="Threat research", capabilities=("analysis",)))
    register(registry, make_definition("beta", name="Threat research", capabilities=("analysis",)))

    first = route(registry, "threat research")
    second = route(registry, "threat research")
    assert first.outcome == "ambiguous"
    assert first.skill_id is None
    assert first.to_dict() == second.to_dict()
    assert first.to_dict() == {
        "version": 1,
        "outcome": "ambiguous",
        "reason_code": "top_score_tie",
        "score": 6,
        "catalog_count": 2,
        "eligible_count": 2,
        "matched_count": 2,
    }
    assert "skill_id" not in first.to_dict()


def test_missing_strongest_candidate_falls_back_to_eligible_positive_match(tmp_path):
    registry = make_registry(tmp_path)
    register(registry, make_definition(
        "restricted-recon", name="Network reconnaissance",
        capabilities=("host intelligence",), allowed_scope=("host:secret.test",),
    ))
    register(registry, make_definition(
        "basic-network", name="Network", capabilities=("inventory",),
    ))

    decision = route(registry, "network reconnaissance")
    assert decision.outcome == "selected"
    assert decision.skill_id == "basic-network"
    assert decision.matched_count == 2
    assert decision.eligible_count == 1


def test_missing_tool_chooses_alternative_without_invoking_either_tool(tmp_path, monkeypatch):
    registry = make_registry(tmp_path)
    registry.tool_specs["status"] = REGISTRY["status"]
    register(registry, make_definition(
        "strong-search", name="Host research", capabilities=("investigation",),
    ))
    fallback = make_definition("status-fallback", name="Host", capabilities=("inventory",))
    fallback = replace(
        fallback,
        required_tools=("status",),
        procedure=(SkillStep("search-step", "status", "status", expects_evidence=False),),
        tests=(replace(fallback.tests[0], expected_tool_sequence=("status",)),),
        content_hash="",
    )
    register(registry, fallback)

    def forbidden(*args, **kwargs):
        pytest.fail("routing must not invoke registered tools")

    monkeypatch.setattr("tools.registry.execute", forbidden)
    decision = route(registry, "host research", available_tools=("status",))
    assert decision.skill_id == fallback.skill_id
    assert decision.eligible_count == 1
    assert decision.matched_count == 2


def test_unavailable_when_positive_matches_fail_tool_scope_or_requested_tool_constraints(tmp_path):
    registry = make_registry(tmp_path)
    register(registry, make_definition("scanner", name="Network scan", capabilities=("inventory",)))

    missing_tool = route(registry, "network scan", available_tools=())
    missing_scope = route(registry, "network scan", allowed_scope=())
    requested_tool_not_provided_by_skill = route(registry, "network scan", required_tools=("browser",))
    for decision in (missing_tool, missing_scope, requested_tool_not_provided_by_skill):
        assert decision.outcome == "unavailable"
        assert decision.reason_code == "constraints_unsatisfied"
        assert decision.skill_id is None
        assert decision.matched_count == 1


def test_unapproved_wrong_owner_revoked_and_expired_revisions_are_not_routable(tmp_path):
    registry = make_registry(tmp_path)
    candidate = make_definition("candidate", name="Host research", capabilities=("web research",))
    register(registry, candidate, approve=False)
    register(registry, make_definition("foreign", name="Host research", capabilities=("web research",)), OTHER_OWNER)
    revoked = register(registry, make_definition("revoked", name="Host research", capabilities=("web research",)))
    registry.revoke(OWNER, revoked.skill_id, 1)

    live_expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    expiring = register(registry, make_definition(
        "expired", name="Host research", capabilities=("web research",), expires_at=live_expiry,
    ))
    # Update the approved test record to a correctly re-hashed expired revision.
    expired_definition = replace(
        expiring,
        expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        content_hash="",
    )
    with registry._connect() as conn:
        conn.execute(
            "UPDATE skill_revisions SET content_hash=?, payload_json=? "
            "WHERE owner_identity_ref=? AND skill_id=? AND version=?",
            (expired_definition.content_hash, json.dumps(expired_definition.to_dict()), OWNER, expiring.skill_id, 1),
        )

    decision = route(registry, "host research")
    assert decision.outcome == "no_match"
    assert decision.catalog_count == 0


def test_empty_or_hostile_objective_never_executes_and_metadata_never_echoes_it(tmp_path):
    registry = make_registry(tmp_path)
    register(registry, make_definition("safe", name="Web research", capabilities=("threat analysis",)))
    hostile = "../../etc/passwd __import__('os').system('touch /tmp/router-pwned')"

    no_match = route(registry, hostile)
    assert no_match.outcome == "no_match"
    assert hostile not in json.dumps(no_match.to_dict())
    with pytest.raises(ValueError):
        route(registry, "x" * 12_001)
    with pytest.raises(ValueError):
        route(registry, "test", owner_identity_ref="  ")
    assert route(registry, "").outcome == "no_match"


def test_malformed_iterables_are_rejected_and_objective_limit_is_inclusive(tmp_path):
    registry = make_registry(tmp_path)
    with pytest.raises(ValueError):
        route(registry, "goal", available_tools="search")
    with pytest.raises(ValueError):
        route(registry, "goal", allowed_scope=("scope", 4))
    with pytest.raises(ValueError):
        route(registry, "goal", required_tools=None)
    with pytest.raises(ValueError):
        route(registry, None)
    assert route(registry, "x" * 12_000).outcome == "no_match"


def test_nested_mutation_detected_by_definition_validation_and_fails_closed(tmp_path, monkeypatch):
    registry = make_registry(tmp_path)
    definition = make_definition("mutable", name="Host research", capabilities=("web research",))
    register(registry, definition)
    original_get_active = registry.get_active

    def mutated_get_active(owner_ref, skill_id):
        revision = original_get_active(owner_ref, skill_id)
        if revision is not None:
            revision.definition.input_schema["properties"]["query"]["maxLength"] = 999
        return revision

    monkeypatch.setattr(registry, "get_active", mutated_get_active)
    decision = route(registry, "host research")
    assert decision.outcome == "unavailable"
    assert decision.reason_code == "invalid_active_skill"
    assert decision.skill_id is None


def test_catalog_bound_fails_closed_instead_of_truncating_active_heads(tmp_path):
    registry = make_registry(tmp_path)
    with registry._connect() as conn:
        conn.executemany(
            "INSERT INTO skill_heads(owner_identity_ref, skill_id, active_version, updated_at) VALUES(?,?,?,?)",
            [(OWNER, f"head-{index:04d}", 1, "2026-01-01T00:00:00+00:00") for index in range(501)],
        )
    decision = route(registry, "anything")
    assert decision.outcome == "unavailable"
    assert decision.reason_code == "catalog_limit_exceeded"
    assert decision.skill_id is None
