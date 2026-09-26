"""Stage B (Security Tooling Expansion): Tool Adapter adversarial battery.

Proves the adapter contract over the FIRST concrete adapter
(LocalSystemInfoAdapter -> registered local_system_info tool) and the generic
ToolAdapter framework:

- every authorization / plan / proof / availability rejection happens BEFORE
  tools.registry.execute, therefore before any handler (asserted with a
  handler spy AND a registry-execute spy: counts must stay 0);
- dry_run never reaches the registry, a handler, or a subprocess;
- missing binary / unknown tool fail closed with no fallback execution;
- wrong mission / request / tool / argument bindings, forged proofs, expired
  proofs, replayed proofs after run rotation, plan mismatch, class confusion
  are all rejected deterministically with classified codes;
- execution failure, timeout, normalization failure, evidence failure, and
  cleanup failure are classified and can never surface as success;
- cleanup runs exactly once on every path and is inert;
- raw output, normalized output, evidence, metadata, and error state stay
  separated; tool output can never forge envelope metadata or authority;
- the adapter module never derives proofs, never calls handlers directly,
  never mutates the registry, and imports no forbidden layer (AST).

Stage A cross-layer proof: a tool that exists in the Layer 1 catalog (nmap)
but is NOT registered at runtime fails closed at the adapter boundary —
definition is not registration, and catalog membership is not authorization.
"""

from __future__ import annotations

import ast
from dataclasses import replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
from typing import Any

import pytest

import tools.registry
from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.execution_proof import ExecutionAuthorizationProof, ExecutionProofError, RejectionCode
from security.mission_authorization import MissionAuthorizationSnapshot
from security.tool_adapter import (
    AdapterErrorCode,
    LOCAL_SYSTEM_INFO_ADAPTER,
    LocalSystemInfoAdapter,
    ToolAdapter,
    ToolAdapterRequest,
)
from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY


MODULE_PATH = Path(__file__).resolve().parents[1] / "security" / "tool_adapter.py"


# ---------------------------------------------------------------------------
# Fixtures and helpers (patterns copied from tests/test_b3_c5_run_binding.py)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="local_system_info"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _proof(mission, *, run_id="", tool="local_system_info", argument=None, **overrides):
    kwargs = dict(
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool=tool,
        argument=argument,
        snapshot=MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {})),
        tool_call_id="call_x",
        run_id=run_id,
        plan_hash=mission.plan.fingerprint,
        scope=mission.scope_snapshot,
        mission_status=mission.status.value,
        lifecycle_revision=len(mission.transitions),
    )
    kwargs.update(overrides)
    return ExecutionAuthorizationProof.derive(**kwargs)


def _request(mission, proof, **overrides):
    values: dict[str, Any] = dict(
        tool="local_system_info",
        argument=None,
        execution_class="MISSION_BOUND",
        execution_proof=proof,
        mission=mission,
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        run_id="",
    )
    values.update(overrides)
    return ToolAdapterRequest(**values)


class CountingHandler:
    def __init__(self, result=None, exc=None, delay=0.0):
        self.calls = 0
        self.result = {"ok": True, "source": "local_system_info"} if result is None else result
        self.exc = exc
        self.delay = delay

    def __call__(self, argument=None, **kwargs):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.exc is not None:
            raise self.exc
        return dict(self.result)


def _patch_handler(monkeypatch, **handler_kwargs):
    counter = CountingHandler(**handler_kwargs)
    spec = tools.registry.get_tool("local_system_info")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "local_system_info", dataclass_replace(spec, handler=counter))
    return counter


@pytest.fixture
def counting_handler(monkeypatch):
    return _patch_handler(monkeypatch)


@pytest.fixture
def execute_spy(monkeypatch):
    real_execute = tools.registry.execute
    calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    return calls


# Test-local adapters exercising framework paths.


class UnregisteredToolAdapter(ToolAdapter):
    """nmap exists in the Stage A catalog but is NOT a registered runtime tool."""

    tool_name = "nmap"


class MissingBinaryAdapter(LocalSystemInfoAdapter):
    required_binary = "cybersentinel-no-such-binary-xyz"


class SlowToolAdapter(LocalSystemInfoAdapter):
    timeout_seconds = 1


class RecordingCleanupAdapter(LocalSystemInfoAdapter):
    def __init__(self):
        self.cleanup_calls = 0

    def cleanup(self, request):
        self.cleanup_calls += 1


class FailingCleanupAdapter(LocalSystemInfoAdapter):
    def __init__(self):
        self.cleanup_calls = 0

    def cleanup(self, request):
        self.cleanup_calls += 1
        raise RuntimeError("cleanup exploded")


class FailingEvidenceAdapter(LocalSystemInfoAdapter):
    def collect_evidence(self, *args, **kwargs):
        raise RuntimeError("evidence store exploded")


# ---------------------------------------------------------------------------
# 1. Valid execution (mission-bound)
# ---------------------------------------------------------------------------


def test_stage_b_valid_mission_bound_execution_allowed(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proof = _proof(mission, run_id="run-1")
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert result.status == "SUCCESS"
    assert result.ok is True
    assert result.executed is True
    assert result.dry_run is False
    assert counting_handler.calls == 1
    assert execute_spy == ["local_system_info"]
    assert result.normalized_output == {"ok": True, "source": "local_system_info"}
    assert result.error_state == {}
    assert result.cleanup_ran is True
    assert result.cleanup_error == ""


def test_stage_b_real_handler_integration(tmp_path, execute_spy):
    """The REAL registered handler (no monkeypatch): local, read-only info."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "SUCCESS"
    assert isinstance(result.raw_output, dict)
    assert "platform" in result.normalized_output
    assert execute_spy == ["local_system_info"]


def test_stage_b_evidence_record_is_structured_and_bound(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof))
    evidence = result.evidence
    assert evidence["record_type"] == "TOOL_ADAPTER_EVIDENCE"
    assert evidence["provenance"] == "TOOL_ADAPTER"
    assert evidence["classification"] == "UNTRUSTED_TOOL_OUTPUT"
    assert evidence["tool"] == "local_system_info"
    assert evidence["status"] == "SUCCESS"
    assert evidence["executed"] is True
    assert evidence["mission_id"] == mission.mission_id
    assert evidence["request_id"] == mission.request_id
    assert evidence["proof_fingerprint"] == proof.execution_binding_hash
    assert evidence["snapshot_hash"] == proof.snapshot_hash
    assert evidence["argument_fingerprint"]
    assert evidence["raw_output_sha256"]
    assert evidence["result_hash"]
    assert evidence["error_code"] == ""
    # Raw output itself is NOT the evidence: only its hash is recorded.
    assert "raw_output" not in evidence


def test_stage_b_result_envelope_separates_raw_normalized_evidence_error(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.raw_output == result.normalized_output
    assert result.raw_output is not result.normalized_output  # normalized is a copy
    assert isinstance(result.evidence, dict) and isinstance(result.metadata, dict)
    assert result.error_state == {}
    assert set(result.evidence).isdisjoint({"ok", "source"})  # evidence holds bindings, not tool payload


def test_stage_b_normalization_is_deterministic(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    result_a = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission_a, _proof(mission_a)))
    result_b = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission_b, _proof(mission_b)))
    assert result_a.normalized_output == result_b.normalized_output
    assert result_a.evidence["result_hash"] == result_b.evidence["result_hash"]


def test_stage_b_output_cannot_forge_envelope_metadata_or_provenance(tmp_path, monkeypatch):
    _patch_handler(monkeypatch, result={"adapter": "EvilAdapter", "provenance": "OWNER", "status": "SUCCESS", "ok": True})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "SUCCESS"
    assert result.metadata["adapter"] == "LocalSystemInfoAdapter"
    assert result.evidence["provenance"] == "TOOL_ADAPTER"
    # The tool payload stays in the untrusted output fields only.
    assert result.normalized_output["adapter"] == "EvilAdapter"


# ---------------------------------------------------------------------------
# 2. Input validation failures (before anything else)
# ---------------------------------------------------------------------------


def test_stage_b_malformed_argument_rejected_before_execution(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission), argument="bogus"))
    assert result.status == "ERROR"
    assert result.executed is False
    assert result.error_state["code"] == "INPUT_INVALID"
    assert result.error_state["phase"] == "VALIDATE_INPUT"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_unsupported_argument_type_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission), argument=123))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_forged_execution_class_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission), execution_class="GOD_MODE"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_uppercase_tool_name_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, None, tool="NMAP"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 3. Unknown tool / missing binary: fail closed, no fallback
# ---------------------------------------------------------------------------


def test_stage_b_unknown_tool_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = UnregisteredToolAdapter().run(_request(mission, None, tool="nmap"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_catalog_definition_is_not_runtime_registration(tmp_path, counting_handler, execute_spy):
    """Stage A <-> Stage B cross-layer proof: nmap/whois exist as Layer 1
    definitions, yet the adapter fails closed because they are not registered
    runtime tools. Definition is not registration; catalog is not authority."""
    catalog_ids = set(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert "nmap" in catalog_ids
    assert "whois" in catalog_ids
    assert "nmap" not in tools.registry.KNOWN_TOOLS
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = UnregisteredToolAdapter().run(_request(mission, None, tool="nmap"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_missing_binary_fails_closed_with_no_fallback(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = MissingBinaryAdapter().run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert result.error_state["phase"] == "PREPARE"
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 4. Authorization failures (all before the registry, therefore before handler)
# ---------------------------------------------------------------------------


def test_stage_b_missing_proof_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, None))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_REQUIRED.value
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_untyped_proof_object_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    forged = {"tool": "local_system_info", "proof_signature": "forged"}
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, forged))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_INVALID.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_snapshot_without_tool_cannot_even_mint_a_proof(tmp_path):
    """The EXISTING chain refuses to derive authority for a tool outside the
    owner snapshot allowlist — the adapter never gets the chance to run it."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="status")  # snapshot allows status/search only
    with pytest.raises(ExecutionProofError) as excinfo:
        _proof(mission, tool="local_system_info")
    assert excinfo.value.code == RejectionCode.TOOL_NOT_ALLOWED.value


def test_stage_b_wrong_tool_binding_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof_for_search = _proof(mission, tool="search", argument="q")
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof_for_search))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_argument_mismatch_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, argument="tampered-argument")
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof, argument=None))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_wrong_mission_binding_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proof_a = _proof(mission_a)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission_b, proof_a))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_wrong_request_binding_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof, request_id="req-other"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 5. Plan binding failures
# ---------------------------------------------------------------------------


def test_stage_b_invalid_plan_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, plan_hash="forged-plan-fingerprint")
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PLAN_MISMATCH"
    assert result.error_state["rejection_code"] == RejectionCode.PLAN_MISMATCH.value
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_stale_plan_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)  # bound to the plan fingerprint at derivation time
    mission.progress["execution_plan"] = {"plan_fingerprint": "rotated-plan-fingerprint"}
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PLAN_MISMATCH"
    assert result.error_state["rejection_code"] == RejectionCode.PLAN_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 6. Proof integrity failures
# ---------------------------------------------------------------------------


def test_stage_b_forged_proof_signature_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    tampered = _proof(mission).to_dict()
    tampered["proof_signature"] = "f" * 64
    forged = ExecutionAuthorizationProof.from_dict(tampered)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, forged))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_INVALID.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_stale_expired_proof_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, ttl_seconds=1)
    time.sleep(1.2)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_EXPIRED.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_replayed_proof_after_run_rotation_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proof = _proof(mission, run_id="run-1")
    first = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert first.status == "SUCCESS"
    assert counting_handler.calls == 1
    # The run rotates; the same proof must never execute again.
    mission.progress["model_run_id"] = "run-2"
    replay = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert replay.status == "ERROR"
    assert replay.error_state["rejection_code"] == RejectionCode.RUN_MISMATCH.value
    assert counting_handler.calls == 1
    assert execute_spy == ["local_system_info"]


# ---------------------------------------------------------------------------
# 7. Execution-class confusion
# ---------------------------------------------------------------------------


def _owner_direct_proof_and_decision(tmp_path, request_id="req-od"):
    context = make_test_authorization_context(request_id, tmp_path)
    decision = authorize_tool("local_system_info", context=context).decision
    assert decision is not None
    proof = ExecutionAuthorizationProof.derive(
        mission_id="",
        request_id=request_id,
        tool="local_system_info",
        argument=None,
        decision=decision,
        execution_class="OWNER_DIRECT",
    )
    return proof, decision


def test_stage_b_owner_direct_execution_allowed(tmp_path, counting_handler, execute_spy):
    proof, decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_system_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        authorization_decision=decision,
    )
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(request)
    assert result.status == "SUCCESS"
    assert result.executed is True
    assert counting_handler.calls == 1
    assert execute_spy == ["local_system_info"]
    assert result.evidence["execution_class"] == "OWNER_DIRECT"


def test_stage_b_owner_direct_without_decision_rejected(tmp_path, counting_handler, execute_spy):
    proof, _decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_system_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        authorization_decision=None,
    )
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_owner_direct_with_mission_binding_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof, _decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_system_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        mission=mission,  # class confusion: owner-direct run carrying mission bindings
    )
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_owner_direct_with_unbound_decision_rejected(tmp_path, counting_handler, execute_spy):
    proof_a, _decision_a = _owner_direct_proof_and_decision(tmp_path, request_id="req-a")
    _proof_b, decision_b = _owner_direct_proof_and_decision(tmp_path, request_id="req-b")
    request = ToolAdapterRequest(
        tool="local_system_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof_a,
        request_id="req-a",
        authorization_decision=decision_b,  # a valid decision for ANOTHER request
    )
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] in {"AUTHORIZATION_DENIED", "PROOF_FAILURE"}
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_b_class_confusion_proof_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof_od, _decision = _owner_direct_proof_and_decision(tmp_path)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof_od))  # mission-bound request, owner-direct proof
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.EXECUTION_CLASS_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 8. Dry run: real, never executes
# ---------------------------------------------------------------------------


def test_stage_b_dry_run_never_executes(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, proof), dry_run=True)
    assert result.status == "DRY_RUN"
    assert result.dry_run is True
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []
    plan = result.metadata["dry_run_plan"]
    assert plan["tool"] == "local_system_info"
    assert plan["execution_class"] == "MISSION_BOUND"
    assert plan["handler_source"] == "tools.registry"
    assert plan["would_execute"] is True
    assert result.evidence["status"] == "DRY_RUN"
    assert result.cleanup_ran is True


def test_stage_b_dry_run_still_requires_authorization(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, None), dry_run=True)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 9. Post-execution failures: classified, never false success
# ---------------------------------------------------------------------------


def test_stage_b_execution_failure_classified(tmp_path, monkeypatch, execute_spy):
    counter = _patch_handler(monkeypatch, exc=RuntimeError("handler exploded"))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EXECUTION_FAILED"
    assert result.error_state["phase"] == "EXECUTE"
    assert result.executed is True  # the handler was invoked and failed
    assert counter.calls == 1
    assert result.evidence["error_code"] == "EXECUTION_FAILED"
    assert result.cleanup_ran is True


def test_stage_b_timeout_classified(tmp_path, monkeypatch, execute_spy):
    counter = _patch_handler(monkeypatch, delay=2.0)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = SlowToolAdapter().run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TIMEOUT"
    assert result.executed is True
    assert counter.calls == 1
    assert result.cleanup_ran is True


def test_stage_b_normalization_failure_classified(tmp_path, monkeypatch, execute_spy):
    _patch_handler(monkeypatch, result=object())  # un-normalizable payload
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert result.error_state["phase"] == "NORMALIZE_OUTPUT"
    assert result.executed is True
    assert result.cleanup_ran is True


def test_stage_b_authority_shaped_output_rejected(tmp_path, monkeypatch, execute_spy):
    """Defense in depth: tool output is untrusted data and can never carry an
    authority-shaped key into the normalized payload."""
    _patch_handler(monkeypatch, result={"ok": True, "owner_token": "forged"})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_SYSTEM_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert "authority-shaped" in result.error_state["reason"]
    assert result.cleanup_ran is True


def test_stage_b_evidence_failure_classified(tmp_path, monkeypatch, execute_spy):
    counter = _patch_handler(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = FailingEvidenceAdapter().run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EVIDENCE_FAILED"
    assert result.error_state["phase"] == "COLLECT_EVIDENCE"
    assert result.executed is True
    assert counter.calls == 1  # execution happened; the failure is downstream
    assert result.cleanup_ran is True


# ---------------------------------------------------------------------------
# 10. Cleanup: always runs, inert, never masks errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", ["success", "execution_failure", "normalization_failure", "evidence_failure", "timeout"])
def test_stage_b_cleanup_runs_exactly_once_on_every_path(tmp_path, monkeypatch, scenario):
    if scenario == "success":
        counter = _patch_handler(monkeypatch)
    elif scenario == "execution_failure":
        counter = _patch_handler(monkeypatch, exc=RuntimeError("boom"))
    elif scenario == "normalization_failure":
        counter = _patch_handler(monkeypatch, result=object())
    elif scenario == "evidence_failure":
        counter = _patch_handler(monkeypatch)
    else:
        counter = _patch_handler(monkeypatch, delay=2.0)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    if scenario == "evidence_failure":
        adapter = FailingEvidenceAdapter()
    elif scenario == "timeout":
        adapter = SlowToolAdapter()
    else:
        adapter = RecordingCleanupAdapter()
    result = adapter.run(_request(mission, _proof(mission)))
    assert result.status in {"SUCCESS", "ERROR"}
    # Cleanup always ran exactly once and was inert: the handler was invoked
    # exactly once (by execute, never by cleanup) in every scenario.
    assert counter.calls == 1
    assert result.cleanup_ran is True
    if isinstance(adapter, RecordingCleanupAdapter):
        assert adapter.cleanup_calls == 1


def test_stage_b_cleanup_failure_on_success_is_not_silent(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    adapter = FailingCleanupAdapter()
    result = adapter.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "CLEANUP_FAILED"
    assert result.error_state["phase"] == "CLEANUP"
    assert counter.calls == 1
    assert adapter.cleanup_calls == 1
    assert result.cleanup_ran is False
    assert result.cleanup_error


def test_stage_b_cleanup_failure_does_not_mask_primary_error(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch, exc=RuntimeError("primary failure"))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    adapter = FailingCleanupAdapter()
    result = adapter.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EXECUTION_FAILED"  # primary preserved
    assert result.cleanup_error  # cleanup failure recorded separately
    assert counter.calls == 1


# ---------------------------------------------------------------------------
# 11. Consolidated rejection battery: handler and registry never invoked
# ---------------------------------------------------------------------------


def _rejection_scenarios(tmp_path):
    """Every pre-execution rejection in one list; the consolidated test proves
    none of them ever reaches tools.registry.execute or the handler."""
    runtime = _runtime(tmp_path)
    scenarios = []

    mission = _mission(runtime)
    scenarios.append(("malformed-argument", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission), argument="bogus")))

    mission = _mission(runtime)
    scenarios.append(("unsupported-argument-type", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission), argument=123)))

    mission = _mission(runtime)
    scenarios.append(("unknown-tool", UnregisteredToolAdapter(), _request(mission, None, tool="nmap")))

    mission = _mission(runtime)
    scenarios.append(("missing-binary", MissingBinaryAdapter(), _request(mission, _proof(mission))))

    mission = _mission(runtime)
    scenarios.append(("missing-proof", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, None)))

    mission = _mission(runtime)
    scenarios.append(("wrong-tool-binding", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission, tool="search", argument="q"))))

    mission = _mission(runtime)
    scenarios.append(("argument-mismatch", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission, argument="tampered"))))

    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    scenarios.append(("wrong-mission-binding", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission_b, _proof(mission_a))))

    mission = _mission(runtime)
    scenarios.append(("wrong-request-binding", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission), request_id="req-other")))

    mission = _mission(runtime)
    scenarios.append(("invalid-plan", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission, plan_hash="forged-plan"))))

    mission = _mission(runtime)
    proof = _proof(mission)
    mission.progress["execution_plan"] = {"plan_fingerprint": "rotated"}
    scenarios.append(("stale-plan", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, proof)))

    mission = _mission(runtime)
    tampered = _proof(mission).to_dict()
    tampered["proof_signature"] = "f" * 64
    scenarios.append(("forged-proof-signature", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, ExecutionAuthorizationProof.from_dict(tampered))))

    mission = _mission(runtime)
    scenarios.append(("forged-execution-class", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission), execution_class="GOD_MODE")))

    mission = _mission(runtime)
    proof_od, _decision = _owner_direct_proof_and_decision(tmp_path)
    scenarios.append(("class-confusion", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, proof_od)))

    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-9"
    scenarios.append(("run-mismatch", LOCAL_SYSTEM_INFO_ADAPTER, _request(mission, _proof(mission, run_id="run-1"), run_id="run-1")))

    return scenarios


def test_stage_b_every_rejected_request_never_invokes_handler_nor_registry(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)
    real_execute = tools.registry.execute
    execute_calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        execute_calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    for label, adapter, request in _rejection_scenarios(tmp_path):
        result = adapter.run(request)
        assert result.status == "ERROR", label
        assert result.executed is False, label
        assert result.error_state, label
        assert result.ok is False, label
    assert counter.calls == 0
    assert execute_calls == []


# ---------------------------------------------------------------------------
# 12. Module-level invariants (AST): no minting, no direct handlers, no
#     registry mutation, no forbidden imports
# ---------------------------------------------------------------------------

ALLOWED_TOP_MODULES = {"__future__", "dataclasses", "enum", "hashlib", "json", "re", "shutil", "typing"}
ALLOWED_MODULES = {"tools.registry", "security.authorization_context", "security.execution_proof", "security.mission_authorization"}


def _adapter_ast():
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def test_stage_b_adapter_import_allowlist():
    for node in ast.walk(_adapter_ast()):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in ALLOWED_TOP_MODULES, f"forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert module.split(".")[0] in ALLOWED_TOP_MODULES or module in ALLOWED_MODULES, f"forbidden import: {module}"


def test_stage_b_adapter_never_derives_proofs():
    """INV-ADP-1: the adapter layer can never mint an ExecutionAuthorizationProof."""
    for node in ast.walk(_adapter_ast()):
        assert not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "derive"), (
            "the adapter module must never call any .derive() (proof minting stays in the authorization layers)"
        )


def test_stage_b_adapter_never_calls_handlers_directly():
    """INV-ADP-2: no direct handler invocation; only tools.registry.execute."""
    for node in ast.walk(_adapter_ast()):
        assert not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "handler"), (
            "the adapter module must never call a tool handler directly"
        )


def test_stage_b_adapter_never_mutates_the_registry():
    tree = _adapter_ast()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and target.value.attr == "REGISTRY":
                    raise AssertionError("the adapter module must never write to tools.registry.REGISTRY")
                if isinstance(target, ast.Attribute) and target.attr == "REGISTRY":
                    raise AssertionError("the adapter module must never rebind the registry")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr":
            raise AssertionError("the adapter module must never use setattr")


def test_stage_b_adapter_defines_no_subprocess_or_process_surface():
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in ("subprocess", "os.system", "popen", "eval(", "exec("):
        assert forbidden not in source, f"adapter module must not contain process surface: {forbidden}"

