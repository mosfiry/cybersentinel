from __future__ import annotations
"""Adversarial proof-carrying-execution boundary battery.

NOT EXECUTED in the authoring environment (no Python interpreter was
available there). Every case is written against the deterministic contracts
in security/execution_proof.py, tools/registry.py and
agent/mission_runtime.py at the tip of
feature/proof-carrying-execution-boundary.

Documented N/A cases (architecture, not silent omission):
- Case 15 (single-use proof ledger): proofs are multi-use by design inside
  their TTL; replay resistance comes from exact tool/argument/mission/request
  binding, lifecycle revision pinning, snapshot rotation and registry
  re-verification. A single-use ledger needs a durable nonce store that the
  current single-process MissionStore model does not provide.
- Cases 10/35/36 (evidence / worker capability authority): evidence records
  and worker capability metadata are not authority inputs anywhere in this
  codebase; nothing accepts them as proof material, so no flow exists to
  reject.
- Cases 12/37 (legacy chat execution path): chat-mode execution is not
  mission-bound and keeps its AuthorizationDecision HMAC boundary; the
  proof boundary applies to mission-bound registry calls only.
"""

from dataclasses import replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib

import pytest

from runtime_authorization import make_test_snapshot

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep
from security.execution_proof import (
    ExecutionAuthorizationProof,
    ExecutionProofError,
    RejectionCode,
    canonical_execution_fingerprint,
    classify_snapshot_reason,
)
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import ToolSpec, execute as registry_execute


def _runtime(tmp_path, factory=make_test_snapshot):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=factory)


def _mission(runtime, action="status"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _run_id(mission):
    return hashlib.sha256((mission.mission_id + mission.request_id).encode()).hexdigest()[:20]


def _proposal(mission, name="status", *, arguments=None, tool_call_id="call_001", n=1):
    return ToolCallProposal.create(name, arguments, mission_id=mission.mission_id, run_id=_run_id(mission), turn_id=_run_id(mission) + ":turn:1", action_id="a%d" % n, tool_call_id=tool_call_id)


class OneTurnModel:
    def __init__(self, proposals):
        self.proposals = tuple(proposals)
        self.done = False

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        if self.done:
            return ModelTurn(turn_id, content="done")
        self.done = True
        return ModelTurn(turn_id, tool_calls=self.proposals)


def _snapshot(mission):
    return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))


def _proof(mission, *, tool="status", argument=None, snapshot=None, **overrides):
    kwargs = dict(mission_id=mission.mission_id, request_id=mission.request_id, tool=tool, argument=argument, snapshot=snapshot or _snapshot(mission), tool_call_id="call_x", plan_hash=mission.plan.fingerprint, scope=mission.scope_snapshot, mission_status=mission.status.value, lifecycle_revision=len(mission.transitions))
    kwargs.update(overrides)
    return ExecutionAuthorizationProof.derive(**kwargs)


def test_valid_proof_execution_succeeds_and_is_audited(tmp_path, monkeypatch):
    import tools.registry

    calls = []

    def fake_execute(name, argument=None, **kwargs):
        calls.append((name, argument, kwargs))
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([_proposal(mission)]), tools=[], max_turns=2)
    assert [call[0] for call in calls] == ["status"]
    kwargs = calls[0][2]
    assert kwargs.get("mission_id") == mission.mission_id
    proof = kwargs.get("execution_proof")
    assert isinstance(proof, ExecutionAuthorizationProof)
    assert result.progress["model_loop"]["tool_results"][0]["ok"] is True
    events = [item.get("event") for item in result.trajectory]
    assert "ProofCreated" in events and "ProofVerified" in events


def test_tool_outside_owner_allowlist_is_rejected_before_execution(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: calls.append(a) or {"ok": True})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([_proposal(mission, "latest_intel")]), tools=[], max_turns=2)
    assert calls == []
    error = result.progress["model_loop"]["tool_results"][0]["error"]
    assert error.startswith("TOOL_NOT_ALLOWED:")
    assert any(item.get("event") == "ExecutionRejected" for item in result.trajectory)


def test_snapshot_gate_precedes_tool_resolution(tmp_path):
    # Security ordering: an unknown model-proposed tool is classified by the
    # Owner snapshot gate (TOOL_NOT_ALLOWED) before any tool resolution.
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    ok, code, reason = runtime._proposal_snapshot_gate(mission, "definitely_not_a_tool")
    assert ok is False and code == RejectionCode.TOOL_NOT_ALLOWED.value


def test_snapshot_gate_missing_snapshot_is_classified(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.authorization_snapshot = None
    ok, code, reason = runtime._proposal_snapshot_gate(mission, "status")
    assert ok is False and code == RejectionCode.SNAPSHOT_MISSING.value


def test_forbidden_tool_is_rejected_deterministically(tmp_path, monkeypatch):
    import tools.registry

    calls = []
    monkeypatch.setattr(tools.registry, "execute", lambda *a, **k: calls.append(a) or {"ok": True})

    def forbidden_factory(mission):
        base = make_test_snapshot(mission)
        return MissionAuthorizationSnapshot.create(
            owner_identity=base.owner_identity,
            mission_id=base.mission_id,
            target_identity=base.target_identity,
            scope=base.scope,
            allowed_actions=base.allowed_actions,
            forbidden_actions=("status",),
            allowed_tools=base.allowed_tools,
            time_window=base.time_window,
            max_duration=base.max_duration,
            rate_limits=base.rate_limits,
            network_boundary=base.network_boundary,
            data_boundary=base.data_boundary,
            credential_boundary=base.credential_boundary,
            workspace_boundary=base.workspace_boundary,
            policy_version=base.policy_version,
            owner_approval=base.owner_approval,
            created_at=base.created_at,
            expires_at=base.expires_at,
        )

    runtime = _runtime(tmp_path, forbidden_factory)
    mission = _mission(runtime, action="search")
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([_proposal(mission, "status")]), tools=[], max_turns=1)
    assert calls == []
    assert result.progress["model_loop"]["tool_results"][0]["error"].startswith("FORBIDDEN_ACTION:")


def test_entry_gate_blocks_expired_snapshot_with_structured_code(tmp_path):
    runtime = _runtime(tmp_path)
    now = datetime.now(timezone.utc)
    expired = MissionAuthorizationSnapshot.create(
        owner_identity="test-owner",
        mission_id="m-exp",
        target_identity="test-target",
        scope=("workspace",),
        allowed_actions=("status",),
        forbidden_actions=(),
        allowed_tools=("status",),
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={"status": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/workspace/test"},
        policy_version="test-policy-v1",
        owner_approval="test-owner-approval",
        created_at=(now - timedelta(hours=2)).isoformat(),
        expires_at=(now - timedelta(hours=1)).isoformat(),
    )
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="status"),), reason="test")
    mission = runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}], owner_identity_ref="test-owner", authorization_snapshot=expired.to_dict())
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([]), tools=[], max_turns=1)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert result.error.startswith("SNAPSHOT_EXPIRED:")
    assert any(item.get("event") == "ExecutionRejected" for item in result.trajectory)


def test_rejection_code_classification_is_deterministic():
    assert classify_snapshot_reason("authorization snapshot expired or not active") is RejectionCode.SNAPSHOT_EXPIRED
    assert classify_snapshot_reason("mission actions or tools outside authorization snapshot") is RejectionCode.TOOL_NOT_ALLOWED
    assert classify_snapshot_reason("workspace boundary mismatch") is RejectionCode.WORKSPACE_BOUNDARY_MISMATCH
    assert classify_snapshot_reason("authorization snapshot invalid: KeyError") is RejectionCode.SNAPSHOT_INVALID


def test_proof_bindings_reject_tool_argument_mission_and_request_substitution(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    ok, reason, code = ExecutionAuthorizationProof.verify(proof, name="status", argument=None, mission_id=mission.mission_id, request_id=mission.request_id, tool_call_id="call_x")
    assert ok is True and code == ""
    assert ExecutionAuthorizationProof.verify(proof, name="search", argument=None)[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name="status", argument="changed")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name="status", argument=None, mission_id="other")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name="status", argument=None, request_id="other")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert ExecutionAuthorizationProof.verify(proof, name="status", argument=None, tool_call_id="other")[2] == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_expired_proof_is_rejected(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, ttl_seconds=1)
    later = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    ok, reason, code = ExecutionAuthorizationProof.verify(proof, name="status", argument=None, at=later)
    assert ok is False and code == RejectionCode.PROOF_EXPIRED.value


def test_forged_and_tampered_proofs_are_rejected(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    forged = dataclass_replace(proof, tool="search")
    assert ExecutionAuthorizationProof.verify(forged, name="search", argument=None)[2] == RejectionCode.PROOF_INVALID.value
    tampered = dataclass_replace(proof, execution_binding_hash="f" * 64)
    assert ExecutionAuthorizationProof.verify(tampered, name="status", argument=None)[2] == RejectionCode.PROOF_INVALID.value
    as_dict = proof.to_dict()
    assert ExecutionAuthorizationProof.verify(as_dict, name="status", argument=None)[2] == RejectionCode.PROOF_INVALID.value
    unsigned = ExecutionAuthorizationProof.from_dict({**as_dict, "proof_signature": "0" * 64})
    assert ExecutionAuthorizationProof.verify(unsigned, name="status", argument=None)[2] == RejectionCode.PROOF_INVALID.value


def test_model_output_shapes_cannot_mint_proofs(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(ExecutionProofError) as excinfo:
        _proof(mission, decision=object())
    assert excinfo.value.code == RejectionCode.PROOF_INVALID.value
    with pytest.raises(ExecutionProofError) as excinfo2:
        _proof(mission, tool="definitely_not_a_tool")
    assert excinfo2.value.code == RejectionCode.TOOL_NOT_ALLOWED.value


def test_plan_mutation_invalidates_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    assert ExecutionAuthorizationProof.validate_against_mission(proof, mission)[0] is True
    mission.plan = mission.plan.replan(steps=(PlanStep("s2", "objective", action="status"),), reason="replan")
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False and code == RejectionCode.PLAN_MISMATCH.value


def test_scope_mutation_invalidates_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    mission.scope_snapshot = {"workspace_root": "/other"}
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False and code == RejectionCode.SCOPE_MISMATCH.value


def test_lifecycle_transition_invalidates_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    mission.transition(MissionStatus.RUNNING, "test")
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False and code == RejectionCode.LIFECYCLE_MISMATCH.value


def test_cancelled_and_recovery_missions_invalidate_normal_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    mission.transition(MissionStatus.CANCELLED, "test")
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False and code == RejectionCode.LIFECYCLE_MISMATCH.value

    runtime2 = _runtime(Path(str(tmp_path)) / "recovery")
    mission2 = _mission(runtime2)
    proof2 = _proof(mission2)
    mission2.transition(MissionStatus.RECOVERY_REQUIRED, "ambiguous outcome")
    ok2, _, code2 = ExecutionAuthorizationProof.validate_against_mission(proof2, mission2)
    assert ok2 is False and code2 == RejectionCode.LIFECYCLE_MISMATCH.value


def test_snapshot_rotation_invalidates_proof(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    renewed = _snapshot(mission).amend(owner_approval="re-approval", changes={}, expires_at=(datetime.now(timezone.utc) + timedelta(hours=2)).isoformat())
    mission.authorization_snapshot = renewed.to_dict()
    mission.provenance["authorization_snapshot_version"] = int(renewed.version)
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof, mission)
    assert ok is False and code == RejectionCode.SNAPSHOT_MISMATCH.value


def test_proof_from_another_mission_is_rejected_at_validation(tmp_path):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proof_a = _proof(mission_a)
    ok, reason, code = ExecutionAuthorizationProof.validate_against_mission(proof_a, mission_b)
    assert ok is False and code == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_canonical_fingerprint_is_order_insensitive_and_semantically_strict():
    assert canonical_execution_fingerprint({"b": 1, "a": {"y": 2, "x": 3}}) == canonical_execution_fingerprint({"a": {"x": 3, "y": 2}, "b": 1})
    assert canonical_execution_fingerprint({"a": 1}) != canonical_execution_fingerprint({"a": "1"})
    assert canonical_execution_fingerprint({"a": [1, 2]}) != canonical_execution_fingerprint({"a": [2, 1]})
    assert canonical_execution_fingerprint(None) != canonical_execution_fingerprint("")
    assert canonical_execution_fingerprint("caf\u00e9") != canonical_execution_fingerprint("cafe\u0301")


def test_unicode_argument_binding_round_trip(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="search")
    proof = _proof(mission, tool="search", argument="\u0627\u0633\u062a\u0639\u0645\u0627\u0644")
    ok, reason, code = ExecutionAuthorizationProof.verify(proof, name="search", argument="\u0627\u0633\u062a\u0639\u0645\u0627\u0644")
    assert ok is True and code == ""
    ok2, _, code2 = ExecutionAuthorizationProof.verify(proof, name="search", argument="\u0627\u0633\u062a\u0639\u0645\u0627\u0644 ")
    assert ok2 is False and code2 == RejectionCode.PROOF_BINDING_MISMATCH.value


def test_registry_requires_proof_for_mission_bound_execution(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", mission_id="m1")
    assert str(excinfo.value).startswith("PROOF_REQUIRED:")


def test_registry_boundary_rejects_foreign_and_forged_proofs(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime, action="search")
    proof_a = _proof(mission_a)
    assert registry_execute("status", mission_id=mission_a.mission_id, request_id=mission_a.request_id, execution_proof=proof_a) == {"ok": True}
    with pytest.raises(PermissionError) as e_foreign:
        registry_execute("status", mission_id=mission_b.mission_id, request_id=mission_b.request_id, execution_proof=proof_a)
    assert str(e_foreign.value).startswith("PROOF_BINDING_MISMATCH:")
    with pytest.raises(PermissionError) as e_forged:
        registry_execute("status", mission_id=mission_a.mission_id, execution_proof=proof_a.to_dict())
    assert str(e_forged.value).startswith("PROOF_INVALID:")
    with pytest.raises(PermissionError) as e_cross_tool:
        registry_execute("search", "query", mission_id=mission_a.mission_id, execution_proof=proof_a)
    assert str(e_cross_tool.value).startswith("PROOF_BINDING_MISMATCH:")


def test_parallel_proposals_each_carry_their_own_proof(tmp_path, monkeypatch):
    import tools.registry

    calls = []

    def fake_execute(name, argument=None, **kwargs):
        calls.append((name, argument, kwargs))
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposals = [
        _proposal(mission, "status", tool_call_id="call_a", n=1),
        _proposal(mission, "search", {"query": "q"}, tool_call_id="call_b", n=2),
    ]
    runtime.run_model_loop(mission.mission_id, OneTurnModel(proposals), tools=[], max_turns=2)
    assert [call[0] for call in calls] == ["status", "search"]
    proofs = [call[2].get("execution_proof") for call in calls]
    assert all(isinstance(proof, ExecutionAuthorizationProof) for proof in proofs)
    assert proofs[0].tool_call_id != proofs[1].tool_call_id
    # A proof derived for one parallel proposal cannot serve another.
    ok, reason, code = ExecutionAuthorizationProof.verify(proofs[0], name="search", argument="q")
    assert ok is False and code == RejectionCode.PROOF_BINDING_MISMATCH.value


# ---------------------------------------------------------------------------
# Owner-direct execution class (chat / task paths)
# ---------------------------------------------------------------------------

def _owner_decision(tmp_path, monkeypatch, *, tool="status", argument=None, request_id="req-owner"):
    import security.owner_policy as owner_policy
    from security.authorization import authorize_tool
    from security.authorization_context import AuthorizationContext

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    context = AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=owner_policy.capture_policy_snapshot(request_id, evidence))
    return authorize_tool([tool, argument] if argument is not None else [tool], context=context)


def test_owner_direct_proof_requires_typed_decision_and_request_identity(tmp_path, monkeypatch):
    from security.execution_boundary import OwnerDirectBoundary

    decision = _owner_decision(tmp_path, monkeypatch)
    assert decision.allowed and decision.decision is not None
    # No typed AuthorizationDecision -> there is no authorization to derive
    # evidence from.
    with pytest.raises(ExecutionProofError) as e_decision:
        OwnerDirectBoundary.derive(tool="status", argument=None, decision=None, request_id="req-owner")
    assert e_decision.value.code == RejectionCode.PROOF_INCOMPLETE.value
    # Missing request identity -> the proof cannot be bound to a request (or
    # the decision itself refuses the mismatched request identity).
    with pytest.raises(ExecutionProofError) as e_request:
        OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="")
    assert e_request.value.code in {RejectionCode.PROOF_INCOMPLETE.value, RejectionCode.PROOF_BINDING_MISMATCH.value}
    # A mission authorization snapshot can never be smuggled into an
    # owner-direct proof: the class forbids carrying mission authority.
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(ExecutionProofError) as e_snapshot:
        ExecutionAuthorizationProof.derive(execution_class="OWNER_DIRECT", mission_id="", request_id="req-owner", tool="status", argument=None, snapshot=_snapshot(mission), decision=decision.decision, tool_call_id="x")
    assert e_snapshot.value.code == RejectionCode.PROOF_INVALID.value


def test_owner_direct_execution_through_registry_boundary(tmp_path, monkeypatch):
    import tools.registry
    from security.execution_boundary import OwnerDirectBoundary

    calls = []

    def fake_handler(argument):
        calls.append(argument)
        return {"ok": True, "seen": argument}

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, fake_handler))
    decision = _owner_decision(tmp_path, monkeypatch)
    result = OwnerDirectBoundary.execute(tool="status", argument=None, decision=decision.decision, request_id="req-owner", tool_call_id="req-owner:status")
    assert result == {"ok": True, "seen": None}
    assert calls == [None]


def test_owner_direct_registry_call_without_proof_is_rejected(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    decision = _owner_decision(tmp_path, monkeypatch)
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", authorization_decision=decision.decision, request_id="req-owner")
    assert str(excinfo.value).startswith("PROOF_REQUIRED:")
    assert "OWNER_DIRECT" in str(excinfo.value)


def test_execution_class_mismatch_owner_direct_proof_in_mission_bound_call(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    decision = _owner_decision(tmp_path, monkeypatch)
    from security.execution_boundary import OwnerDirectBoundary

    owner_proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision.decision, request_id="req-owner")
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    # Presenting mission governance kwargs re-classifies the call as
    # MISSION_BOUND; an owner-direct proof can never satisfy that class.
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", mission_authorization=_snapshot(mission), execution_proof=owner_proof)
    assert str(excinfo.value).startswith("EXECUTION_CLASS_MISMATCH:")


def test_execution_class_mismatch_mission_proof_in_owner_direct_call(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission_proof = _proof(mission)
    # A mission-bound proof presented to an owner-direct (non-mission) call is
    # rejected before any handler runs.
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", execution_proof=mission_proof, execution_class="OWNER_DIRECT")
    assert str(excinfo.value).startswith(("EXECUTION_CLASS_MISMATCH:", "PROOF_BINDING_MISMATCH:"))


def test_registry_binds_proof_to_the_supplied_authorization_decision(tmp_path, monkeypatch):
    import tools.registry

    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "test probe", "read", True, None, lambda _a: {"ok": True}))
    decision_a = _owner_decision(tmp_path, monkeypatch, request_id="req-a")
    decision_b = _owner_decision(tmp_path, monkeypatch, request_id="req-b")
    from security.execution_boundary import OwnerDirectBoundary

    proof_a = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision_a.decision, request_id="req-a")
    # Substituting decision B for a proof derived from decision A must be
    # rejected: the proof is bound to exactly one canonical decision.
    with pytest.raises(PermissionError) as excinfo:
        registry_execute("status", authorization_decision=decision_b.decision, request_id="req-b", execution_proof=proof_a, execution_class="OWNER_DIRECT")
    assert "PROOF_BINDING_MISMATCH" in str(excinfo.value) or "AuthorizationDecision" in str(excinfo.value)


def test_mission_bound_proof_completeness_is_enforced(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    # plan_hash is a required MISSION_BOUND binding: an empty plan fingerprint
    # means the proof is not bound to the mission plan.
    with pytest.raises(ExecutionProofError) as excinfo:
        _proof(mission, plan_hash="")
    assert excinfo.value.code == RejectionCode.PROOF_INCOMPLETE.value
    with pytest.raises(ExecutionProofError) as excinfo_status:
        _proof(mission, mission_status="")
    assert excinfo_status.value.code == RejectionCode.PROOF_INCOMPLETE.value
    with pytest.raises(ExecutionProofError) as excinfo_snapshot:
        _proof(mission, snapshot=None)
    assert excinfo_snapshot.value.code == RejectionCode.SNAPSHOT_INVALID.value


def test_embedded_snapshot_identity_tamper_is_rejected(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    tampered = dict(proof.to_dict())
    tampered["snapshot"] = {**(tampered.get("snapshot") or {}), "mission_id": "other-mission"}
    rebuilt = ExecutionAuthorizationProof.from_dict(tampered)
    ok, reason, code = ExecutionAuthorizationProof.verify(rebuilt, name="status", argument=None, mission_id=mission.mission_id, request_id=mission.request_id)
    assert ok is False and code == RejectionCode.SNAPSHOT_MISMATCH.value


def test_cancelled_and_terminal_status_proofs_cannot_execute(tmp_path):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    for terminal in ("CANCELLED", "GOAL_COMPLETED", "RECOVERY_REQUIRED", "FAILED_RETRY_EXHAUSTED"):
        proof = _proof(mission, mission_status=terminal)
        ok, reason, code = ExecutionAuthorizationProof.verify(proof, name="status", argument=None, mission_id=mission.mission_id, request_id=mission.request_id)
        assert ok is False and code == RejectionCode.LIFECYCLE_MISMATCH.value, terminal
