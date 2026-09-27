"""B3-C5 second-pass attacker review battery (deep B3-scope security review).

Source of this battery: the post-completion second-pass attacker review of
the B3 four-layer intent + canonical execution boundary (execution paths,
registry boundary, authorization/proof, recovery, stale state).

REVIEW FINDING (fixed and proven here): the tool registry did not require
the typed AuthorizationDecision for OWNER_DIRECT-class executions. The
decision-binding checks in tools/registry.execute only ran when a decision
was supplied, and the decision was only mandatory for owner_only /
scope_required tools, so a captured owner-direct ExecutionAuthorizationProof
for a non-sensitive tool could be replayed at the registry boundary with NO
AuthorizationDecision at all. That contradicts the documented OWNER_DIRECT
contract ("the typed AuthorizationDecision that authorized the execution ...
are mandatory"). The registry now fails closed: an OWNER_DIRECT execution
without its typed decision is rejected with PROOF_INCOMPLETE before any
handler runs. This is pure tightening: no authority widening, and the
single-RUN (not single-USE) TTL replay semantics remain the documented
architecture decision (Case 15 in test_execution_proof_boundary.py).

Every rejection case asserts that NO TOOL HANDLER EXECUTED.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.execution_boundary import OwnerDirectBoundary
from security.execution_proof import (
    ExecutionAuthorizationProof,
    ExecutionClass,
    RejectionCode,
)
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import ToolSpec, execute as registry_execute


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="status"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _snapshot(mission):
    return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))


def _mission_proof(mission, *, run_id="run-1", tool="status", argument=None, **overrides):
    kwargs = dict(
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool=tool,
        argument=argument,
        snapshot=_snapshot(mission),
        tool_call_id="call_m1",
        run_id=run_id,
        plan_hash=mission.plan.fingerprint,
        scope=mission.scope_snapshot,
        mission_status=mission.status.value,
        lifecycle_revision=len(mission.transitions),
    )
    kwargs.update(overrides)
    return ExecutionAuthorizationProof.derive(**kwargs)


def _owner_decision(tmp_path, monkeypatch, *, tool="status", argument=None, request_id="req-owner"):
    import security.owner_policy as owner_policy

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    context = AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=owner_policy.capture_policy_snapshot(request_id, evidence))
    return authorize_tool([tool, argument], context=context)


class CountingStatus:
    def __init__(self):
        self.calls = 0

    def handler(self, argument=None, **kwargs):
        self.calls += 1
        return {"ok": True, "source": "status", "seen": argument}


@pytest.fixture
def counting_status(monkeypatch):
    counter = CountingStatus()
    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "counting status test tool", "read", False, None, counter.handler))
    return counter


# ---------------------------------------------------------------------------
# REVIEW FINDING: OWNER_DIRECT execution without its typed decision
# ---------------------------------------------------------------------------


def test_owner_direct_captured_proof_cannot_execute_without_decision(tmp_path, monkeypatch, counting_status):
    """A captured owner-direct proof replays with NO AuthorizationDecision.

    Before the review fix the registry accepted this call: the proof verified
    (it was derived from a real decision), the class matched, and the
    decision checks were skipped because no decision was supplied and the
    tool was not owner_only/scope_required. The registry must now fail
    closed with PROOF_INCOMPLETE and the handler must never run.
    """
    decision = _owner_decision(tmp_path, monkeypatch)
    assert decision.allowed and decision.decision is not None
    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od1")
    assert proof.execution_class == ExecutionClass.OWNER_DIRECT.value
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", None, request_id="req-owner", execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
    assert RejectionCode.PROOF_INCOMPLETE.value in str(excinfo.value)
    assert counting_status.calls == 0


def test_owner_direct_execution_with_typed_decision_still_executes(tmp_path, monkeypatch, counting_status):
    decision = _owner_decision(tmp_path, monkeypatch)
    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od2")
    result = registry_execute("status", None, authorization_decision=decision.decision, request_id="req-owner", execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
    assert result["ok"] is True
    assert counting_status.calls == 1


def test_owner_direct_decision_from_another_request_is_rejected(tmp_path, monkeypatch, counting_status):
    decision_a = _owner_decision(tmp_path, monkeypatch, request_id="req-a")
    decision_b = _owner_decision(tmp_path, monkeypatch, request_id="req-b")
    proof_a = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision_a.decision, request_id="req-a", tool_call_id="call_od3")
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", None, authorization_decision=decision_b.decision, request_id="req-b", execution_proof=proof_a, execution_class=ExecutionClass.OWNER_DIRECT.value)
    assert counting_status.calls == 0
    assert RejectionCode.PROOF_BINDING_MISMATCH.value in str(excinfo.value) or "AuthorizationDecision" in str(excinfo.value)


def test_owner_direct_replay_within_ttl_is_documented_single_run_semantics(tmp_path, monkeypatch, counting_status):
    """Characterization (NOT a defect claim): proofs are multi-use inside their TTL.

    This is the documented Case 15 architecture decision: replay resistance
    comes from exact tool/argument/mission/request/run binding, lifecycle
    revision pinning, snapshot rotation and registry re-verification. The
    review fix above closes the strictly worse variant of this window: a
    replay that carried NO decision at all. Replay WITH the same valid
    decision remains possible within the TTL and the 300s decision lifetime;
    a single-use ledger requires a durable nonce store (deferred to the
    Owner). This test pins the honest boundary so any accidental tightening
    or widening is noticed.
    """
    decision = _owner_decision(tmp_path, monkeypatch)
    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od4")
    for _ in range(2):
        result = registry_execute("status", None, authorization_decision=decision.decision, request_id="req-owner", execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
        assert result["ok"] is True
    assert counting_status.calls == 2


# ---------------------------------------------------------------------------
# Registry-boundary adversarial re-checks (deep review, B3 scope)
# ---------------------------------------------------------------------------


def test_expired_mission_proof_rejected_at_registry_without_handler(tmp_path, monkeypatch, counting_status):
    import security.execution_proof as proof_module

    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _mission_proof(mission, run_id="run-old")
    # Advance the deterministic clock past the 300s proof TTL (the snapshot
    # stays active for an hour, so the rejection is exactly PROOF_EXPIRED).
    later = datetime.now(timezone.utc) + timedelta(seconds=310)
    monkeypatch.setattr(proof_module, "_now", lambda: later.isoformat())
    with pytest.raises(PermissionError) as excinfo:
        registry_execute(
            "status",
            None,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=proof,
            execution_class=ExecutionClass.MISSION_BOUND.value,
            execution_run_id="run-old",
        )
    assert RejectionCode.PROOF_EXPIRED.value in str(excinfo.value)
    assert counting_status.calls == 0


def test_modified_argument_rejected_at_registry_without_handler(tmp_path, counting_status):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _mission_proof(mission, run_id="run-1")
    with pytest.raises(PermissionError) as excinfo:
        registry_execute(
            "status",
            "tampered-argument",
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=proof,
            execution_class=ExecutionClass.MISSION_BOUND.value,
            execution_run_id="run-1",
        )
    assert RejectionCode.PROOF_BINDING_MISMATCH.value in str(excinfo.value)
    assert counting_status.calls == 0


def test_tampered_serialized_proof_field_is_invalid(tmp_path, counting_status):
    """Serialization tamper: any post-derivation field change breaks the signed binding hash."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    data = _mission_proof(mission, run_id="run-1").to_dict()
    data["run_id"] = "run-forged"
    forged = ExecutionAuthorizationProof.from_dict(data)
    ok, _reason, code = ExecutionAuthorizationProof.verify(forged, name="status", argument=None, mission_id=mission.mission_id, request_id=mission.request_id, run_id="run-forged")
    assert ok is False and code == RejectionCode.PROOF_INVALID.value
    with pytest.raises(PermissionError):
        registry_execute(
            "status",
            None,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=forged,
            execution_class=ExecutionClass.MISSION_BOUND.value,
            execution_run_id="run-forged",
        )
    assert counting_status.calls == 0


def test_from_dict_unknown_field_is_rejected(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    data = _mission_proof(mission, run_id="run-1").to_dict()
    data["nonce"] = "attacker-minted-nonce"
    with pytest.raises(TypeError):
        ExecutionAuthorizationProof.from_dict(data)


def test_owner_direct_serialized_proof_rebinds_exactly(tmp_path, monkeypatch, counting_status):
    """A serialized owner-direct proof round-trips and still requires its decision."""
    decision = _owner_decision(tmp_path, monkeypatch)
    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od5")
    round_trip = ExecutionAuthorizationProof.from_dict(proof.to_dict())
    ok, _reason, _code = ExecutionAuthorizationProof.verify(round_trip, name="status", argument=None, request_id="req-owner")
    assert ok is True
    # but the round-tripped proof still cannot execute without the decision
    with pytest.raises(PermissionError, match=RejectionCode.PROOF_INCOMPLETE.value):
        registry_execute("status", None, request_id="req-owner", execution_proof=round_trip, execution_class=ExecutionClass.OWNER_DIRECT.value)
    assert counting_status.calls == 0


def test_mission_bound_path_unaffected_by_owner_direct_tightening(tmp_path, counting_status):
    """The tightening must not disturb the MISSION_BOUND class: same-run proof executes, rotated run fails closed."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _mission_proof(mission, run_id="run-live")
    result = registry_execute(
        "status",
        None,
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        mission_authorization=_snapshot(mission),
        execution_proof=proof,
        execution_class=ExecutionClass.MISSION_BOUND.value,
        execution_run_id="run-live",
    )
    assert result["ok"] is True
    assert counting_status.calls == 1
    with pytest.raises(PermissionError, match=RejectionCode.RUN_MISMATCH.value):
        registry_execute(
            "status",
            None,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=proof,
            execution_class=ExecutionClass.MISSION_BOUND.value,
            execution_run_id="run-rotated",
        )
    assert counting_status.calls == 1


def test_owner_direct_class_cannot_be_smuggled_via_explicit_class_kwarg(tmp_path, monkeypatch, counting_status):
    """An attacker marking a no-decision call explicitly OWNER_DIRECT still fails closed (class is not authority)."""
    decision = _owner_decision(tmp_path, monkeypatch)
    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="call_od6")
    with pytest.raises(PermissionError, match=RejectionCode.PROOF_INCOMPLETE.value):
        registry_execute("status", None, execution_proof=proof, execution_class=ExecutionClass.OWNER_DIRECT.value)
    assert counting_status.calls == 0
    # and an owner-direct proof stays unusable for mission-bound calls: the
    # registry rejects it at the earliest boundary (proof.verify raises
    # PROOF_BINDING_MISMATCH before the class comparison runs)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(PermissionError) as excinfo:
        registry_execute(
            "status",
            None,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            mission_authorization=_snapshot(mission),
            execution_proof=proof,
            execution_class=ExecutionClass.MISSION_BOUND.value,
            execution_run_id="run-x",
        )
    assert RejectionCode.PROOF_BINDING_MISMATCH.value in str(excinfo.value) or RejectionCode.EXECUTION_CLASS_MISMATCH.value in str(excinfo.value)
    assert counting_status.calls == 0


def test_authorization_context_fixture_rejects_untyped_sensitive_requests(tmp_path, monkeypatch):
    """INV-AUTH-3 regression within the review scope: a sensitive (owner-only) tool stays closed to untyped requests."""
    decision = _owner_decision(tmp_path, monkeypatch)
    assert decision.allowed and decision.decision is not None
    # No typed context and no typed evidence: structural-only is closed for
    # tools whose descriptor requires owner authorization.
    result = authorize_tool(["status", None])
    assert result.allowed is False
