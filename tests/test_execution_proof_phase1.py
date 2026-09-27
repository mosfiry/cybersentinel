"""Phase One gate battery: security/execution_proof.py ported byte-exact from B3.

The unit (blob 98a4227c9a0227f2b034f0244f0fe4c802d24e41 on
security/b3-four-layer-intent) is DERIVED EVIDENCE, never a source of
authority. This battery proves the Phase One gate against the CANONICAL main
dependencies (X-E Owner username/password authentication ->
OwnerAuthenticationEvidence -> OwnerPolicySnapshot -> AuthorizationContext
-> AuthorizationDecision, plus MissionAuthorizationSnapshot):

- Architecture: the proof proves execution state/evidence only.
- Authentication: Owner identity comes only from the canonical X-E live path.
- Authorization: a proof never converts into an authorization grant.
- Owner policy: a proof cannot alter Owner Instruction or policy state.
- Evidence: evidence cannot mint a capability that does not exist.
- External data / model output: deterministic enforcement cannot be bypassed.

No real secrets, no network, no real external targets. The test password is
isolated to this file and is not the Owner password.
"""
from __future__ import annotations

import dataclasses
import inspect
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import core.db as core_db
import security.execution_proof as execution_proof_module
from security import owner_password as op
import security.owner_policy as owner_policy
from security.authorization_context import AuthorizationContext, AuthorizationDecision
from security.execution_proof import (
    ExecutionAuthorizationProof,
    ExecutionClass,
    ExecutionProofError,
    RejectionCode,
    canonical_execution_fingerprint,
    classify_snapshot_reason,
)
from security.mission_authorization import MissionAuthorizationSnapshot

TEST_PASSWORD = "phase-one-isolated-test-password-88"
TEST_TOOL = "local_system_info"
TEST_ARGUMENT = {"mode": "read"}


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "test-phase1-proof.db")
    yield tmp_path / "test-phase1-proof.db"


@pytest.fixture
def owner_context(tmp_db):
    """Canonical X-E chain: login -> authenticate_owner -> capture_policy_snapshot -> AuthorizationContext."""
    op.create_owner_account("mosfiry", TEST_PASSWORD)
    session = op.login("mosfiry", TEST_PASSWORD)
    request_id = "phase-one-request"
    evidence = owner_policy.authenticate_owner(session["session_id"], request_id)
    snapshot = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(
        request_id=request_id,
        owner_evidence=evidence,
        policy_snapshot=snapshot,
        session_id=session["session_id"],
    )


@pytest.fixture
def owner_decision(owner_context):
    return AuthorizationDecision.issue(
        owner_context,
        allowed=True,
        reason="owner-direct phase one test",
        tool=TEST_TOOL,
        risk_class="LOW",
        argument=TEST_ARGUMENT,
    )


def make_snapshot(*, mission_id: str = "mission-1", allowed_tools: tuple[str, ...] = (TEST_TOOL,), forbidden_actions: tuple[str, ...] = (), expires_in_seconds: int = 3600) -> MissionAuthorizationSnapshot:
    now = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="mosfiry",
        mission_id=mission_id,
        target_identity="mission-target",
        scope=("mission-target",),
        allowed_actions=allowed_tools,
        forbidden_actions=forbidden_actions,
        allowed_tools=allowed_tools,
        time_window={},
        max_duration=3600,
        rate_limits={},
        network_boundary={},
        data_boundary={},
        credential_boundary={},
        workspace_boundary={},
        policy_version="1",
        owner_approval="owner-approved-phase-one",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=expires_in_seconds)).isoformat(),
    )


# ---------------------------------------------------------------------------
# Gate: Architecture — the proof is derived evidence, never authority.
# ---------------------------------------------------------------------------

def test_mission_bound_proof_derive_and_verify_round_trip():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1",
        request_id="phase-one-request",
        tool=TEST_TOOL,
        argument=TEST_ARGUMENT,
        snapshot=snapshot,
        plan_hash="plan-fingerprint-1",
        mission_status="READY",
        lifecycle_revision=0,
        tool_call_id="tc-1",
        run_id="run-1",
    )
    assert proof.execution_class == ExecutionClass.MISSION_BOUND.value
    ok, reason, code = ExecutionAuthorizationProof.verify(
        proof, name=TEST_TOOL, argument=TEST_ARGUMENT, mission_id="mission-1",
        request_id="phase-one-request", tool_call_id="tc-1", run_id="run-1",
    )
    assert (ok, reason, code) == (True, "authorized", "")


def test_proof_is_frozen_immutable_evidence():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.tool = "some-other-tool"
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.execution_binding_hash = "0" * 64


def test_untyped_proof_object_rejected():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    for bogus in ({"proof": "attacker-crafted"}, None, "owner_authenticated=true", proof.to_dict()):
        ok, _, code = ExecutionAuthorizationProof.verify(bogus, name=TEST_TOOL, argument=TEST_ARGUMENT)
        assert ok is False
        assert code == RejectionCode.PROOF_INVALID.value


def test_serialization_round_trip_preserves_validity():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    restored = ExecutionAuthorizationProof.from_dict(proof.to_dict())
    ok, reason, code = ExecutionAuthorizationProof.verify(
        restored, name=TEST_TOOL, argument=TEST_ARGUMENT, mission_id="mission-1",
    )
    assert (ok, reason, code) == (True, "authorized", "")


def test_tampered_serialization_rejected():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    data = proof.to_dict()
    data["tool"] = "some-other-tool"
    forged = ExecutionAuthorizationProof.from_dict(data)
    ok, _, code = ExecutionAuthorizationProof.verify(forged, name="some-other-tool", argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.PROOF_INVALID.value


def test_forged_signature_rejected():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    object.__setattr__(proof, "proof_signature", "f" * 64)
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.PROOF_INVALID.value


def test_tampered_binding_hash_rejected():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    object.__setattr__(proof, "run_id", "another-run")
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.PROOF_INVALID.value


def test_proof_expires_deterministically():
    snapshot = make_snapshot()
    moment = datetime.now(timezone.utc)
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY", ttl_seconds=1, at=moment.isoformat(),
    )
    later = (moment + timedelta(seconds=10)).isoformat()
    assert proof.is_expired(at=later) is True
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, at=later)
    assert ok is False
    assert code == RejectionCode.PROOF_EXPIRED.value


# ---------------------------------------------------------------------------
# Gate: MISSION_BOUND binding completeness and snapshot enforcement.
# ---------------------------------------------------------------------------

def test_mission_bound_requires_typed_snapshot():
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, snapshot=None, plan_hash="plan-fingerprint-1",
            mission_status="READY",
        )
    assert err.value.code == RejectionCode.SNAPSHOT_INVALID.value


def test_mission_bound_requires_identity_plan_and_status():
    snapshot = make_snapshot()
    base = dict(request_id="phase-one-request", tool=TEST_TOOL, argument=TEST_ARGUMENT,
                snapshot=snapshot, mission_status="READY")
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(mission_id="", plan_hash="plan-fingerprint-1", **base)
    assert err.value.code == RejectionCode.PROOF_INCOMPLETE.value
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(mission_id="mission-1", plan_hash="", **base)
    assert err.value.code == RejectionCode.PROOF_INCOMPLETE.value
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(mission_id="mission-1", plan_hash="plan-fingerprint-1",
                                            mission_status="", **{k: v for k, v in base.items() if k != "mission_status"})
    assert err.value.code == RejectionCode.PROOF_INCOMPLETE.value


def test_snapshot_forbidden_tool_rejected_at_derivation():
    snapshot = make_snapshot(forbidden_actions=(TEST_TOOL,))
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
            mission_status="READY",
        )
    assert err.value.code == RejectionCode.FORBIDDEN_ACTION.value


def test_snapshot_tool_outside_allowlist_rejected_at_derivation():
    snapshot = make_snapshot(allowed_tools=("other_tool",))
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
            mission_status="READY",
        )
    assert err.value.code == RejectionCode.TOOL_NOT_ALLOWED.value


def test_expired_snapshot_rejected_at_derivation_and_verify():
    moment = datetime.now(timezone.utc)
    snapshot = make_snapshot(expires_in_seconds=1)
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY", at=moment.isoformat(),
    )
    later = (moment + timedelta(seconds=10)).isoformat()
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
            mission_status="READY", at=later,
        )
    assert err.value.code == RejectionCode.SNAPSHOT_EXPIRED.value
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, at=later)
    assert ok is False
    assert code == RejectionCode.SNAPSHOT_EXPIRED.value


def test_verify_rejects_wrong_tool_mission_request_and_run():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY", tool_call_id="tc-1", run_id="run-1",
    )
    assert ExecutionAuthorizationProof.verify(proof, name="other-tool", argument=TEST_ARGUMENT)[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, mission_id="mission-2")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, request_id="phase-one-other-request")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, tool_call_id="tc-2")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT, run_id="run-2")[2] == RejectionCode.RUN_MISMATCH.value


def test_verify_rejects_argument_mutation():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument={"mode": "write"})
    assert ok is False
    assert code == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_verify_rejects_tampered_embedded_snapshot():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY",
    )
    proof.snapshot["allowed_tools"] = ["some-other-tool", TEST_TOOL]
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.PROOF_INVALID.value


def test_disallowed_mission_status_rejected_at_verify():
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="COMPLETED",
    )
    ok, _, code = ExecutionAuthorizationProof.verify(proof, name=TEST_TOOL, argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.LIFECYCLE_MISMATCH.value


def test_unknown_execution_class_rejected():
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, execution_class="MODEL_CHOSEN",
        )
    assert err.value.code == RejectionCode.PROOF_INVALID.value


# ---------------------------------------------------------------------------
# Gate: Authentication + Authorization — OWNER_DIRECT over the canonical X-E path.
# ---------------------------------------------------------------------------

def test_owner_direct_proof_over_canonical_x_e_path(owner_decision):
    proof = ExecutionAuthorizationProof.derive(
        mission_id="ignored-for-owner-direct", request_id="phase-one-request",
        tool=TEST_TOOL, argument=TEST_ARGUMENT, decision=owner_decision,
        tool_call_id="tc-owner-1", execution_class=ExecutionClass.OWNER_DIRECT.value,
    )
    assert proof.execution_class == ExecutionClass.OWNER_DIRECT.value
    assert proof.mission_id == ""
    assert proof.decision_fingerprint == owner_decision.decision_signature
    assert proof.policy_fingerprint == owner_decision.policy_fingerprint
    assert proof.snapshot == {}
    ok, reason, code = ExecutionAuthorizationProof.verify(
        proof, name=TEST_TOOL, argument=TEST_ARGUMENT, request_id="phase-one-request",
        tool_call_id="tc-owner-1",
    )
    assert (ok, reason, code) == (True, "authorized", "")


def test_owner_direct_requires_typed_decision(owner_context):
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, decision={"allowed": True, "request_id": "phase-one-request"},
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_INVALID.value


def test_owner_direct_requires_decision_and_request(owner_context):
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, decision=None,
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_INCOMPLETE.value
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="", tool=TEST_TOOL, argument=TEST_ARGUMENT,
            decision=None, execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_INCOMPLETE.value


def test_owner_direct_rejects_snapshot_and_missing_decision(owner_decision):
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, decision=owner_decision, snapshot=make_snapshot(),
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_INVALID.value


def test_denied_decision_can_never_become_a_proof(owner_context):
    denied = AuthorizationDecision.issue(
        owner_context, allowed=False, reason="denied", tool=TEST_TOOL,
        risk_class="LOW", argument=TEST_ARGUMENT,
    )
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="phase-one-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, decision=denied,
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_decision_from_another_request_rejected(owner_decision):
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="some-other-request", tool=TEST_TOOL,
            argument=TEST_ARGUMENT, decision=owner_decision,
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_decision_for_another_tool_rejected(owner_decision):
    with pytest.raises(ExecutionProofError) as err:
        ExecutionAuthorizationProof.derive(
            mission_id="", request_id="phase-one-request", tool="some-other-tool",
            argument=TEST_ARGUMENT, decision=owner_decision,
            execution_class=ExecutionClass.OWNER_DIRECT.value,
        )
    assert err.value.code == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_owner_direct_missing_binding_rejected_at_verify(owner_decision):
    proof = ExecutionAuthorizationProof.derive(
        mission_id="", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, decision=owner_decision,
        execution_class=ExecutionClass.OWNER_DIRECT.value,
    )
    data = proof.to_dict()
    data["decision_fingerprint"] = ""
    stripped = ExecutionAuthorizationProof.from_dict(data)
    ok, _, code = ExecutionAuthorizationProof.verify(stripped, name=TEST_TOOL, argument=TEST_ARGUMENT)
    assert ok is False
    assert code == RejectionCode.PROOF_INVALID.value  # stripped binding invalidates the hash first


# ---------------------------------------------------------------------------
# Gate: live-mission re-validation (TOCTOU bound).
# ---------------------------------------------------------------------------

def make_mission(proof: ExecutionAuthorizationProof, snapshot: MissionAuthorizationSnapshot, *, plan_hash: str | None = None, run_id: str | None = None, scope: dict | None = None, status: str = "READY", transitions: int | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        mission_id=proof.mission_id,
        request_id=proof.request_id,
        plan=SimpleNamespace(fingerprint=plan_hash if plan_hash is not None else proof.plan_hash),
        progress={
            "execution_plan": {"plan_fingerprint": plan_hash if plan_hash is not None else proof.plan_hash},
            "model_run_id": run_id if run_id is not None else proof.run_id,
            "execution_run_id": run_id if run_id is not None else proof.run_id,
        },
        scope_snapshot=scope if scope is not None else {},
        status=SimpleNamespace(value=status),
        transitions=[0] * (transitions if transitions is not None else proof.lifecycle_revision),
        authorization_snapshot=snapshot.to_dict(),
    )


def _mission_bound_proof():
    snapshot = make_snapshot()
    return snapshot, ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY", lifecycle_revision=0, run_id="run-1",
    )


def test_validate_against_mission_success():
    snapshot, proof = _mission_bound_proof()
    mission = make_mission(proof, snapshot)
    assert ExecutionAuthorizationProof.validate_against_mission(proof, mission) == (True, "authorized", "")


def test_validate_against_mission_rejects_plan_scope_run_lifecycle_and_snapshot_changes():
    snapshot, proof = _mission_bound_proof()
    assert ExecutionAuthorizationProof.validate_against_mission(proof, make_mission(proof, snapshot, plan_hash="replanned-fingerprint"))[2] == RejectionCode.PLAN_MISMATCH.value
    assert ExecutionAuthorizationProof.validate_against_mission(proof, make_mission(proof, snapshot, run_id="run-2"))[2] == RejectionCode.RUN_MISMATCH.value
    assert ExecutionAuthorizationProof.validate_against_mission(proof, make_mission(proof, snapshot, scope={"changed": True}))[2] == RejectionCode.SCOPE_MISMATCH.value
    assert ExecutionAuthorizationProof.validate_against_mission(proof, make_mission(proof, snapshot, status="PAUSED"))[2] == RejectionCode.LIFECYCLE_MISMATCH.value
    amended = snapshot.amend(owner_approval="owner-approved-amendment", changes={"max_duration": 7200})
    assert ExecutionAuthorizationProof.validate_against_mission(proof, make_mission(proof, amended))[2] == RejectionCode.SNAPSHOT_MISMATCH.value


def test_validate_against_mission_rejects_cross_mission_and_owner_direct():
    snapshot, proof = _mission_bound_proof()
    other = make_mission(proof, snapshot)
    other.mission_id = "mission-2"
    assert ExecutionAuthorizationProof.validate_against_mission(proof, other)[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.validate_against_mission(proof, {"not": "a proof"})[2] == RejectionCode.PROOF_INVALID.value


def test_owner_direct_proof_cannot_execute_mission_bound(owner_decision):
    proof = ExecutionAuthorizationProof.derive(
        mission_id="", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, decision=owner_decision,
        execution_class=ExecutionClass.OWNER_DIRECT.value,
    )
    assert ExecutionAuthorizationProof.validate_against_mission(proof, object())[2] == RejectionCode.EXECUTION_CLASS_MISMATCH.value


# ---------------------------------------------------------------------------
# Gate: exported helpers + architecture scan (no legacy authority mechanisms).
# ---------------------------------------------------------------------------

def test_classify_snapshot_reason_is_deterministic():
    assert classify_snapshot_reason("authorization snapshot expired or not active") == RejectionCode.SNAPSHOT_EXPIRED
    assert classify_snapshot_reason("actions or tools outside snapshot") == RejectionCode.TOOL_NOT_ALLOWED
    assert classify_snapshot_reason("workspace boundary mismatch") == RejectionCode.WORKSPACE_BOUNDARY_MISMATCH
    assert classify_snapshot_reason("network boundary mismatch") == RejectionCode.NETWORK_BOUNDARY_MISMATCH
    assert classify_snapshot_reason("credential boundary mismatch") == RejectionCode.CREDENTIAL_BOUNDARY_MISMATCH
    assert classify_snapshot_reason("target mismatch") == RejectionCode.TARGET_MISMATCH
    assert classify_snapshot_reason("mission mismatch") == RejectionCode.SNAPSHOT_MISMATCH
    assert classify_snapshot_reason("something unexpected") == RejectionCode.SNAPSHOT_INVALID


def test_canonical_execution_fingerprint_is_order_insensitive():
    assert canonical_execution_fingerprint({"a": 1, "b": 2}) == canonical_execution_fingerprint({"b": 2, "a": 1})
    assert canonical_execution_fingerprint({"a": 1}) != canonical_execution_fingerprint({"a": 2})


def test_module_source_free_of_legacy_authority_mechanisms():
    """Phase One gate: the ported unit contains zero legacy-auth references."""
    source = inspect.getsource(execution_proof_module)
    for banned in (
        "OWNER_TOKEN",
        "owner_token",
        "owner_session",
        "verify_owner",
        "X-CyberSentinel-Owner-Token",
        "security.owner_password",
        "owner_session.py",
    ):
        assert banned not in source, f"legacy authority reference found in execution_proof: {banned}"
    # Authorization imports are exactly the canonical main modules.
    assert "from security.authorization_context import" in source
    assert "from security.mission_authorization import" in source


def test_proof_cannot_legislate_owner_policy(owner_decision):
    """Gate: a derived proof exposes no field capable of altering Owner Instruction/policy state."""
    snapshot = make_snapshot()
    proof = ExecutionAuthorizationProof.derive(
        mission_id="mission-1", request_id="phase-one-request", tool=TEST_TOOL,
        argument=TEST_ARGUMENT, snapshot=snapshot, plan_hash="plan-fingerprint-1",
        mission_status="READY", decision=owner_decision,
    )
    policy_fields = {name for name in ("owner_instruction", "policy_text", "policy_override", "authorize", "authority") if hasattr(proof, name)}
    assert policy_fields == set()
    assert proof.policy_fingerprint == owner_decision.policy_fingerprint
    # The proof's fingerprints are read-only bindings; the owner policy state is untouched.
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.policy_fingerprint = "attacker-fingerprint"
