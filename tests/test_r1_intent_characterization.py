from __future__ import annotations

"""R1 INTENT CHARACTERIZATION TESTS (R1-C1 .. R1-C10).

These tests characterize the CURRENT behavior of the intent path and the
governed execution boundary on branch security/characterization-baseline.
They are security characterization / regression tests, NOT fixes.

Characterized paths:

- R1-C1  model output is parsed into a typed MissionIntent, with an
         explicit deterministic fallback when the model output is not JSON.
- R1-C2  the MissionIntent contract is frozen, complete, and carries a
         deterministic semantic fingerprint.
- R1-C3  HAZARD: there is no deterministic intent validator today. A model
         proposal can carry arbitrary authority-shaped fields
         (intent_type="GRANT_ALL", authorization_requirements including
         self-grants) straight into the typed MissionIntent.
- R1-C4  model output cannot mint authorization: AuthorizationDecision can
         only be issued from a typed AuthorizationContext, forged decision
         signatures fail validation, and dict evidence is rejected.
- R1-C5  an ExecutionAuthorizationProof bound to a mission plan is
         invalidated when the plan is mutated after derivation (TOCTOU).
- R1-C6  the prohibited path MODEL -> PLAN -> EXECUTE is blocked: the
         registry executes nothing without a signed proof of the exact
         execution class, and tampered proofs / mismatched decisions are
         rejected.
- R1-C7  the prohibited path MODEL -> PERMISSION is blocked at
         authorize_tool: untyped contexts cannot mint decisions.
         HAZARD PIN: non-owner-only sensitive tools still pass through the
         structural-only legacy adapter with no owner authentication.
- R1-C8  TOOL_RUNTIME authority minting is prohibited (R1-F1 closure):
         the registry no longer mints compatibility MissionAuthorization
         snapshots, run_project_tests without governed mission artifacts
         fails closed, and execution classes cannot be confused.
- R1-C9  API / intent fields cannot become authorization: intent dicts are
         rejected as owner evidence, and follow-up intents are recorded as
         proposals only (they do not touch the authorization snapshot or
         lifecycle status).
- R1-C10 HAZARD: AgentCore.run_owner_mission derives the ENTIRE authorized
         tool budget from the model-planned steps; there is no Owner Policy
         capability budget and no intersection. The fix must enforce
         MODEL_PLAN_TOOLS subset-of OWNER_AUTHORIZED_TOOL_BUDGET (effective
         budget = intersection, never union or derivation).

None of these tests modify production behavior. The R1 implementation
commits are expected to INVERT the hazard expectations (R1-C3, R1-C7
structural-only pin, R1-C10) while preserving every defensive pin.
"""

import dataclasses
import inspect
import json
from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot

import tools.registry as registry_module
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_intelligence.conversation import (
    MissionIntent,
    NaturalLanguageUnderstanding,
)
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext, AuthorizationDecision
from security.execution_proof import ExecutionAuthorizationProof
from security.mission_authorization import MissionAuthorizationSnapshot


class StubRouter:
    """Minimal model router stub: returns a fixed content string."""

    def __init__(self, content):
        self.content = content

    def generate(self, messages):
        return {"content": self.content}


def _owner_context(tmp_path, monkeypatch, request_id="req-r1"):
    import security.owner_policy as owner_policy

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _runtime(tmp_path, factory=make_test_snapshot):
    return MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda mission, step, action_id: {"success": True, "source": step.action},
        authorization_snapshot_factory=factory,
    )


def _plan(actions=("status",)):
    return Plan.initial("objective").replan(
        steps=tuple(PlanStep(f"s{i}", "objective", action=action) for i, action in enumerate(actions, start=1)),
        reason="characterization",
    )


def _owner_direct_proof(context, *, tool, argument=None, request_id=None):
    risk = {"status": "read", "search": "read", "run_project_tests": "bounded-exec"}.get(tool, "read")
    decision = AuthorizationDecision.issue(
        context, allowed=True, reason="authorized", tool=tool, risk_class=risk, argument=argument
    )
    proof = ExecutionAuthorizationProof.derive(
        mission_id="",
        request_id=request_id or context.request_id,
        tool=tool,
        argument=argument,
        decision=decision,
        execution_class="OWNER_DIRECT",
    )
    return decision, proof


# ---------------------------------------------------------------------------
# R1-C1: intent parsing (model proposal -> typed intent, fallback marked)
# ---------------------------------------------------------------------------


def test_r1c1_model_proposal_parses_into_typed_intent(tmp_path):
    """CURRENT BEHAVIOR: a router returning JSON yields a typed MissionIntent
    with source="model" and parsed fields.

    Invariant the R1 fix must preserve: MODEL_OUTPUT remains an untrusted
    proposal; the deterministic parser is the only path into the typed
    intent contract.
    """
    proposal = {
        "objective": "analyze the authorized workspace",
        "intent_type": "MISSION_REQUEST",
        "constraints": ["stay within scope"],
        "requested_artifacts": ["report"],
        "verification_criteria": ["tests pass"],
        "scope_references": ["workspace"],
        "authorization_requirements": [],
        "entities": ["workspace"],
        "ambiguities": [],
    }
    core = AgentCore(
        router=StubRouter(json.dumps(proposal)),
        store=MissionStore(Path(tmp_path) / "missions.sqlite3"),
    )
    intent = core.understand_mission_intent("analyze the authorized workspace")
    assert isinstance(intent, MissionIntent)
    assert intent.source == "model"
    assert intent.objective == "analyze the authorized workspace"
    assert intent.intent_type == "MISSION_REQUEST"
    assert intent.constraints == ("stay within scope",)
    assert intent.requested_artifacts == ("report",)
    assert intent.verification_criteria == ("tests pass",)
    assert intent.scope_references == ("workspace",)
    assert intent.authorization_requirements == ()
    assert intent.entities == ("workspace",)


def test_r1c1_invalid_model_output_falls_back_deterministically(tmp_path):
    """CURRENT BEHAVIOR: non-JSON model output falls back to the
    deterministic parser, explicitly marked source="deterministic_fallback"
    with the raw instruction preserved as the objective.

    Invariant the R1 fix must preserve: the fallback is deterministic and
    never elevates a failed model turn into trusted interpretation.
    """
    core = AgentCore(
        router=StubRouter("not json at all"),
        store=MissionStore(Path(tmp_path) / "missions.sqlite3"),
    )
    intent = core.understand_mission_intent("check system status")
    assert isinstance(intent, MissionIntent)
    assert intent.source == "deterministic_fallback"
    assert intent.objective == "check system status"
    assert "model unavailable; semantic interpretation requires owner review" in intent.ambiguities


# ---------------------------------------------------------------------------
# R1-C2: typed contract (frozen, complete, deterministic fingerprint)
# ---------------------------------------------------------------------------


def test_r1c2_mission_intent_contract_is_frozen_and_complete():
    """CURRENT BEHAVIOR: MissionIntent is a frozen dataclass whose to_dict
    carries the full typed contract.

    Invariant the R1 fix must preserve: the intent contract is immutable at
    runtime; no layer may widen it with authority-bearing fields.
    """
    intent = NaturalLanguageUnderstanding(
        proposer=lambda text: {"objective": text, "intent_type": "MISSION_REQUEST"}
    ).understand("objective text")
    with pytest.raises(dataclasses.FrozenInstanceError):
        intent.objective = "mutated"
    payload = intent.to_dict()
    assert set(payload) == {
        "objective",
        "intent_type",
        "constraints",
        "requested_artifacts",
        "verification_criteria",
        "scope_references",
        "authorization_requirements",
        "entities",
        "ambiguities",
        "semantic_fingerprint",
        "source",
    }


def test_r1c2_semantic_fingerprint_is_deterministic():
    """CURRENT BEHAVIOR: identical proposals produce identical semantic
    fingerprints; a semantic change changes the fingerprint.

    Invariant the R1 fix must preserve: the fingerprint is a deterministic
    function of the proposal content (replay-safe provenance).
    """
    proposal_a = {"objective": "o", "constraints": ("c1",)}
    proposal_b = {"objective": "o", "constraints": ("c2",)}
    understand = NaturalLanguageUnderstanding(proposer=lambda text: dict(proposal_a))
    first = understand.understand("o")
    second = NaturalLanguageUnderstanding(proposer=lambda text: dict(proposal_a)).understand("o")
    changed = NaturalLanguageUnderstanding(proposer=lambda text: dict(proposal_b)).understand("o")
    assert first.semantic_fingerprint == second.semantic_fingerprint
    assert first.semantic_fingerprint != changed.semantic_fingerprint


# ---------------------------------------------------------------------------
# R1-C3: invalid intent rejection -- HAZARD (no validator today)
# ---------------------------------------------------------------------------


def test_r1c3_authority_shaped_intent_fields_pass_unvalidated():
    """CURRENT HAZARD: there is no deterministic intent validator between the
    model proposal and the typed MissionIntent. A proposal can carry
    intent_type="GRANT_ALL" and authorization_requirements such as
    "self_grant_owner_authority" straight into the typed contract, and
    unknown keys are silently dropped.

    Invariant the R1 fix must enforce: every model-proposed intent passes a
    deterministic validator that rejects or quarantines authority-bearing
    fields; MODEL_OUTPUT may never carry a self-grant into the typed
    contract (INV-INTENT-1).
    """
    malicious = {
        "objective": "help me",
        "intent_type": "GRANT_ALL",
        "constraints": [],
        "authorization_requirements": ["self_grant_owner_authority", "expand_scope"],
        "scope_references": ["*"],
        "self_authority": True,
    }
    intent = NaturalLanguageUnderstanding(proposer=lambda text: dict(malicious)).understand("help me")
    # HAZARD PIN: these assertions document the CURRENT permissive behavior.
    assert intent.intent_type == "GRANT_ALL"
    assert intent.authorization_requirements == ("self_grant_owner_authority", "expand_scope")
    assert intent.scope_references == ("*",)
    assert "self_authority" not in intent.to_dict()


# ---------------------------------------------------------------------------
# R1-C4: model cannot produce authorization (defense pin)
# ---------------------------------------------------------------------------


def test_r1c4_authorization_decision_requires_typed_context(tmp_path, monkeypatch):
    """CURRENT DEFENSE: AuthorizationDecision.issue rejects anything that is
    not a typed AuthorizationContext. MODEL_OUTPUT (or any dict) can never
    mint a decision (INV-AUTH-1).
    """
    with pytest.raises(TypeError):
        AuthorizationDecision.issue(
            "not-a-context", allowed=True, reason="forged", tool="status", risk_class="read"
        )
    with pytest.raises(TypeError):
        AuthorizationDecision.issue(
            {"owner_decision": "allow"}, allowed=True, reason="forged", tool="status", risk_class="read"
        )


def test_r1c4_forged_decision_signature_fails_validation(tmp_path, monkeypatch):
    """CURRENT DEFENSE: a hand-constructed AuthorizationDecision with a
    forged signature fails is_valid_for; only HMAC-signed decisions from a
    typed context validate (INV-AUTH-1).
    """
    forged = AuthorizationDecision(
        allowed=True,
        reason="forged",
        request_id="req-r1",
        tool="status",
        risk_class="read",
        owner_evidence_fingerprint="f",
        policy_fingerprint="p",
        scope_fingerprint="s",
        decision_timestamp="2026-01-01T00:00:00+00:00",
        decision_source="model",
        decision_signature="deadbeef",
    )
    assert forged.is_valid_for("status", None, "req-r1") is False


def test_r1c4_dict_owner_evidence_rejected_in_context(tmp_path, monkeypatch):
    """CURRENT DEFENSE: AuthorizationContext requires typed
    OwnerAuthenticationEvidence and a typed OwnerPolicySnapshot; a model
    intent dict (or any dict payload) can never become owner evidence
    (INV-AUTH-1 / R1-C9 overlap).
    """
    intent = NaturalLanguageUnderstanding(proposer=lambda text: {"objective": text}).understand("o")
    context = _owner_context(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        AuthorizationContext(
            request_id="req-r1",
            owner_evidence=intent.to_dict(),
            policy_snapshot=context.policy_snapshot,
        )
    with pytest.raises(TypeError):
        AuthorizationContext(
            request_id="req-r1",
            owner_evidence=context.owner_evidence,
            policy_snapshot={"policy_version": "1"},
        )


def test_r1c4_typed_context_mints_valid_decision(tmp_path, monkeypatch):
    """CURRENT DEFENSE (positive): a typed owner-authenticated context does
    mint a decision that validates against exactly its tool/request binding.
    """
    context = _owner_context(tmp_path, monkeypatch)
    decision = AuthorizationDecision.issue(
        context, allowed=True, reason="authorized", tool="status", risk_class="read"
    )
    assert decision.is_valid_for("status", None, context.request_id) is True
    assert decision.is_valid_for("search", "q", context.request_id) is False
    assert decision.is_valid_for("status", None, "other-request") is False


# ---------------------------------------------------------------------------
# R1-C5: plan mutation after authorization is rejected (TOCTOU pin)
# ---------------------------------------------------------------------------


def test_r1c5_plan_mutation_invalidates_mission_bound_proof(tmp_path):
    """CURRENT DEFENSE: an ExecutionAuthorizationProof derived against the
    live mission (status, lifecycle revision, plan fingerprint, scope,
    snapshot hash) validates before execution and is invalidated by a plan
    mutation after derivation (INV-EXEC-2 / TOCTOU bound).

    Invariant the R1 fix must preserve: authorization artifacts are bound
    to the exact plan; replanning requires re-authorization.
    """
    runtime = _runtime(tmp_path)
    mission = runtime.create("request", "objective", _plan(("status",)), request_id="req-c5")
    assert mission.status is MissionStatus.READY
    snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
    proof = ExecutionAuthorizationProof.derive(
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool="status",
        argument=None,
        snapshot=snapshot,
        mission_status=mission.status.value,
        lifecycle_revision=len(mission.transitions),
        plan_hash=mission.plan.fingerprint,
        execution_class="MISSION_BOUND",
    )
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is True, (reason, code)
    mission.plan = mission.plan.replan(steps=(), reason="post-authorization mutation")
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False
    assert code == "PLAN_MISMATCH"


# ---------------------------------------------------------------------------
# R1-C6: MODEL -> PLAN -> EXECUTE prohibited path
# ---------------------------------------------------------------------------


def test_r1c6_execution_requires_proof(tmp_path):
    """CURRENT DEFENSE: the registry executes nothing without an
    ExecutionAuthorizationProof; a bare call (the historical
    MODEL -> PLAN -> EXECUTE shortcut) fails closed (INV-EXEC-1).
    """
    from tools.registry import execute

    with pytest.raises(PermissionError, match="PROOF_REQUIRED"):
        execute("status")


def test_r1c6_tampered_proof_signature_rejected(tmp_path, monkeypatch):
    """CURRENT DEFENSE: a proof with a corrupted signature fails PROOF_INVALID
    at the execution boundary; MODEL_OUTPUT cannot forge proof material
    (INV-PROOF-1).
    """
    from tools.registry import execute

    context = _owner_context(tmp_path, monkeypatch, request_id="req-c6")
    decision, proof = _owner_direct_proof(context, tool="status")
    object.__setattr__(proof, "proof_signature", "0" * 64)
    with pytest.raises(PermissionError, match="PROOF_INVALID"):
        execute(
            "status",
            authorization_decision=decision,
            request_id=context.request_id,
            execution_proof=proof,
        )


def test_r1c6_foreign_decision_rejected(tmp_path, monkeypatch):
    """CURRENT DEFENSE: an AuthorizationDecision minted for another request
    cannot authorize this execution; the proof must be bound to exactly
    the decision for this request (INV-PROOF-2).
    """
    from tools.registry import execute

    context = _owner_context(tmp_path, monkeypatch, request_id="req-c6-this")
    other = _owner_context(tmp_path, monkeypatch, request_id="req-c6-other")
    decision, proof = _owner_direct_proof(context, tool="status")
    foreign_decision, _ = _owner_direct_proof(other, tool="status")
    with pytest.raises(PermissionError, match="invalid or argument-mismatched AuthorizationDecision"):
        execute(
            "status",
            authorization_decision=foreign_decision,
            request_id=context.request_id,
            execution_proof=proof,
        )


# ---------------------------------------------------------------------------
# R1-C7: MODEL -> PERMISSION prohibited path
# ---------------------------------------------------------------------------


def test_r1c7_owner_only_tool_requires_typed_context():
    """CURRENT DEFENSE: owner-only tools fail closed without a typed
    AuthorizationContext (INV-AUTH-2).
    """
    result = authorize_tool("red_team_assess", context=None)
    assert result.allowed is False
    assert result.reason == "sensitive tool requires AuthorizationContext"


def test_r1c7_untyped_context_cannot_mint_decision():
    """CURRENT DEFENSE: a plain dict posing as a context makes
    authorize_tool raise before any decision can be minted; the model (or
    any caller) cannot smuggle "owner_decision": "allow" (INV-AUTH-1).
    """
    with pytest.raises(TypeError):
        authorize_tool("status", context={"owner_decision": "allow"})


def test_r1c7_unknown_tool_denied():
    """CURRENT DEFENSE: tools outside the registry are denied (INV-EXEC-3).
    """
    result = authorize_tool("grant_all_authority")
    assert result.allowed is False
    assert result.reason == "unknown tool"


def test_r1c7_structural_only_adapter_hazard_pin():
    """CURRENT HAZARD PIN: non-owner-only sensitive tools (requires_owner
    but not owner_only, e.g. "status") still pass the structural-only legacy
    adapter in authorize_tool with NO owner authentication.

    Invariant the R1 fix must enforce: no authorization path may succeed
    without typed owner authentication; the structural-only adapter must
    be removed or restricted to a non-authoritative classification
    (INV-AUTH-3).
    """
    result = authorize_tool("status", context=None)
    # HAZARD PIN: documents CURRENT permissive behavior.
    assert result.allowed is True
    assert result.reason == "authorized"
    assert result.decision is None


def test_r1c7_typed_context_authorizes_with_signed_decision(tmp_path, monkeypatch):
    """CURRENT DEFENSE (positive): a typed owner-authenticated context
    authorizes the tool and the decision is signed and request-bound.
    """
    context = _owner_context(tmp_path, monkeypatch, request_id="req-c7")
    result = authorize_tool("status", context=context)
    assert result.allowed is True
    assert result.decision is not None
    assert result.decision.is_valid_for("status", None, context.request_id) is True


# ---------------------------------------------------------------------------
# R1-C8: TOOL_RUNTIME authority minting prohibited (R1-F1 closure)
# ---------------------------------------------------------------------------


def test_r1c8_registry_never_mints_compatibility_snapshots():
    """CURRENT DEFENSE (R1-F1 closure regression): the registry source no
    longer contains the compatibility MissionAuthorizationSnapshot minting
    path; TOOL_RUNTIME consumes authorization, never creates it
    (INV-AUTH-2: NO AUTHORITY MINTING IN TOOL_RUNTIME).
    """
    source = inspect.getsource(registry_module)
    assert "compatibility_snapshot" not in source
    assert "MissionAuthorizationSnapshot.create" not in source


def test_r1c8_run_project_tests_fails_closed_without_governed_mission(tmp_path, monkeypatch):
    """CURRENT DEFENSE (R1-F1 closure): even a valid OWNER_DIRECT proof and
    decision cannot reach the run_project_tests handler without a governed
    workspace and a real mission authorization snapshot (fail closed).
    """
    from tools.registry import execute

    context = _owner_context(tmp_path, monkeypatch, request_id="req-c8")
    decision, proof = _owner_direct_proof(context, tool="run_project_tests", argument=".")
    with pytest.raises(PermissionError, match="requires a governed workspace and a mission authorization snapshot"):
        execute(
            "run_project_tests",
            ".",
            authorization_decision=decision,
            request_id=context.request_id,
            execution_proof=proof,
        )


def test_r1c8_execution_class_confusion_rejected(tmp_path, monkeypatch):
    """CURRENT DEFENSE: an OWNER_DIRECT proof cannot be replayed against a
    MISSION_BOUND execution (mission_id present); class confusion fails
    closed (INV-PROOF-3).
    """
    from tools.registry import execute

    context = _owner_context(tmp_path, monkeypatch, request_id="req-c8b")
    decision, proof = _owner_direct_proof(context, tool="status")
    with pytest.raises(PermissionError, match="EXECUTION_CLASS_MISMATCH"):
        execute(
            "status",
            authorization_decision=decision,
            request_id=context.request_id,
            execution_proof=proof,
            mission_id="mission-1",
        )


# ---------------------------------------------------------------------------
# R1-C9: API / intent fields cannot become authorization
# ---------------------------------------------------------------------------


def test_r1c9_intent_dict_is_not_owner_evidence(tmp_path, monkeypatch):
    """CURRENT DEFENSE: model intent payloads are structurally rejected as
    owner evidence (see also R1-C4). An API client cannot promote an intent
    into authorization material (INV-AUTH-4).
    """
    intent = NaturalLanguageUnderstanding(proposer=lambda text: {"objective": text}).understand("o")
    context = _owner_context(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        AuthorizationContext(
            request_id="req-c9",
            owner_evidence=intent.to_dict(),
            policy_snapshot=context.policy_snapshot,
        )


def test_r1c9_follow_up_intent_is_proposal_only(tmp_path):
    """CURRENT BEHAVIOR: continue_mission_instruction records the follow-up
    intent in mission.progress as an UNVALIDATED proposal; it does not touch
    the authorization snapshot, the plan, or the lifecycle status.

    HAZARD NOTE: today there is no deterministic intent validator on the
    follow-up path (same R1-C3 hazard); the fix must route follow-ups
    through the deterministic validator before they influence anything.
    """
    store = MissionStore(Path(tmp_path) / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda mission, step, action_id: {"success": True, "source": step.action}, authorization_snapshot_factory=make_test_snapshot)
    mission = runtime.create("request", "objective", _plan(), request_id="req-c9")
    snapshot_before = dict(mission.authorization_snapshot)
    status_before = mission.status

    core = AgentCore(
        router=StubRouter(json.dumps({"objective": "also check the accounts"})),
        store=store,
    )
    updated = core.continue_mission_instruction(mission.mission_id, "also check the accounts")

    intents = updated.progress.get("mission_intents", [])
    assert len(intents) == 1
    assert intents[0]["instruction"] == "also check the accounts"
    assert intents[0]["intent"]["source"] == "model"
    assert updated.authorization_snapshot == snapshot_before
    assert updated.status is status_before
    assert updated.status is MissionStatus.READY


# ---------------------------------------------------------------------------
# R1-C10: intent narrowing cannot expand the Owner budget -- HAZARD
# ---------------------------------------------------------------------------


def test_r1c10_model_plan_defines_entire_tool_budget_hazard(tmp_path, monkeypatch):
    """CURRENT HAZARD: AgentCore.run_owner_mission derives the mission
    authorization snapshot's allowed_tools / allowed_actions ENTIRELY from
    the model-planned steps. There is no Owner Policy capability budget and
    no intersection: whatever the model plans becomes the authorized budget.

    Invariant the R1 fix must enforce (INV-SCOPE-2 / Phase B):
    MODEL_PLAN_TOOLS subset-of OWNER_AUTHORIZED_TOOL_BUDGET, with
    effective_tools = owner_budget INTERSECTION model_requested_tools,
    never union and never derivation.
    """
    plan = _plan(("status", "search"))
    core = AgentCore(router=object(), store=MissionStore(Path(tmp_path) / "missions-core.sqlite3"))
    context = _owner_context(tmp_path, monkeypatch)
    core._auth = lambda instruction, owner_token, request_id, owner_session_id, owner_challenge: (context, "policy-context")
    core._plan = lambda objective, observation=None, **kwargs: plan

    mission = core.run_owner_mission(
        "check the workspace",
        owner_token="stubbed-auth",
        run=False,
    )
    snapshot = mission.authorization_snapshot
    # HAZARD PIN: the model-planned tools ARE the entire authorized budget.
    assert tuple(snapshot["allowed_tools"]) == ("status", "search")
    assert tuple(snapshot["allowed_actions"]) == ("status", "search")
