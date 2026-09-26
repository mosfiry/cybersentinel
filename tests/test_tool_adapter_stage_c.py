"""Stage C (Security Tooling Expansion): second-adapter adversarial battery.

Proves the Stage B adapter contract over the SECOND concrete adapter
(LocalProcessInfoAdapter -> registered local_process_info tool) and the
architectural decision that registration is a separate, explicit act from
catalog definition (catalog_ids INTERSECT KNOWN_TOOLS stays empty):

- the adapter is an orchestration layer, NOT an authorization layer:
  every authority-shaped rejection happens BEFORE tools.registry.execute,
  therefore before any handler (asserted with a handler spy AND a
  registry-execute spy: both must stay untouched);
- the tool is local, informational, read-only, non-destructive and
  strictly argument-free: ANY argument is a widening attempt and fails
  closed at input validation, before authorization, before the handler;
- the required external binary (ps) is checked in PREPARE: when the
  binary is unavailable the adapter fails CLOSED with no fallback;
- dry-run never reaches the registry, a handler, or a subprocess;
- forged / expired / cross-mission / cross-run / stale-plan /
  stale-snapshot / stale-lifecycle proofs are rejected deterministically;
- execution failure, timeout, normalization failure, evidence failure and
  cleanup failure are classified and can never surface as success;
- cleanup runs exactly once on every path, is inert, and never masks the
  primary error;
- tool output is untrusted data: authority-shaped output keys are rejected
  at normalization and can never become envelope metadata or authority;
- the adapter has NO execution path outside tools.registry.execute;
- the five authority boundaries are proven explicitly:
  adapter exists != tool authorized; ToolSpec exists != registered;
  registered != authorized for this mission; authorized != proof valid;
  proof valid != execution allowed after plan/snapshot/run changes.
"""

from __future__ import annotations

import time
from dataclasses import replace as dataclass_replace
from pathlib import Path
from typing import Any

import pytest

import tools.registry
from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.execution_proof import ExecutionAuthorizationProof, ExecutionProofError, RejectionCode
from security.tool_adapter import (
    AUTHORITY_OUTPUT_TOKENS,
    LOCAL_PROCESS_INFO_ADAPTER,
    LocalProcessInfoAdapter,
    ToolAdapter,
    ToolAdapterRequest,
)
from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY


VALID_PROCESS_PAYLOAD = {
    "processes": [
        {"pid": 1, "ppid": 0, "user": "root", "command": "init"},
        {"pid": 42, "ppid": 1, "user": "daemon", "command": "cybersentinel-sentinel"},
    ],
    "count": 2,
}


# ---------------------------------------------------------------------------
# Fixtures and helpers (patterns proven by the Stage B battery)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="local_process_info"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _proof(mission, *, run_id="", tool="local_process_info", argument=None, **overrides):
    from security.mission_authorization import MissionAuthorizationSnapshot

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
        tool="local_process_info",
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
        self.result = dict(VALID_PROCESS_PAYLOAD) if result is None else result
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
    spec = tools.registry.get_tool("local_process_info")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "local_process_info", dataclass_replace(spec, handler=counter))
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


class MissingPsBinaryAdapter(LocalProcessInfoAdapter):
    required_binary = "cybersentinel-no-such-binary-xyz"


class SlowProcessAdapter(LocalProcessInfoAdapter):
    timeout_seconds = 1


class RecordingCleanupAdapter(LocalProcessInfoAdapter):
    def __init__(self):
        self.cleanup_calls = 0

    def cleanup(self, request):
        self.cleanup_calls += 1


class FailingCleanupAdapter(LocalProcessInfoAdapter):
    def __init__(self):
        self.cleanup_calls = 0

    def cleanup(self, request):
        self.cleanup_calls += 1
        raise RuntimeError("cleanup exploded")


class FailingEvidenceAdapter(LocalProcessInfoAdapter):
    def collect_evidence(self, *args, **kwargs):
        raise RuntimeError("evidence store exploded")


class CatalogOnlyToolAdapter(ToolAdapter):
    """nmap exists in the Layer 1 catalog but is NOT a registered runtime tool."""

    tool_name = "nmap"


def _set_mission_snapshot(mission, snapshot):
    try:
        mission.authorization_snapshot = snapshot
    except Exception:
        object.__setattr__(mission, "authorization_snapshot", snapshot)


# ---------------------------------------------------------------------------
# 1. Valid execution and envelope separation
# ---------------------------------------------------------------------------


def test_stage_c_valid_mission_bound_execution_allowed(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proof = _proof(mission, run_id="run-1")
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert result.status == "SUCCESS"
    assert result.ok is True
    assert result.executed is True
    assert result.dry_run is False
    assert counting_handler.calls == 1
    assert execute_spy == ["local_process_info"]
    assert result.normalized_output == VALID_PROCESS_PAYLOAD
    assert result.error_state == {}
    assert result.cleanup_ran is True
    assert result.cleanup_error == ""


def test_stage_c_real_handler_integration(tmp_path, execute_spy):
    """The REAL registered handler (no monkeypatch): local read-only ps listing."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "SUCCESS"
    assert result.executed is True
    assert execute_spy == ["local_process_info"]
    normalized = result.normalized_output
    assert isinstance(normalized["processes"], list) and normalized["processes"]
    assert normalized["count"] == len(normalized["processes"])
    for record in normalized["processes"]:
        assert isinstance(record["pid"], int)
        assert isinstance(record["ppid"], int)
        assert isinstance(record["user"], str)
        assert isinstance(record["command"], str)


def test_stage_c_evidence_record_is_structured_and_bound(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    evidence = result.evidence
    assert evidence["record_type"] == "TOOL_ADAPTER_EVIDENCE"
    assert evidence["provenance"] == "TOOL_ADAPTER"
    assert evidence["classification"] == "UNTRUSTED_TOOL_OUTPUT"
    assert evidence["tool"] == "local_process_info"
    assert evidence["status"] == "SUCCESS"
    assert evidence["executed"] is True
    assert evidence["mission_id"] == mission.mission_id
    assert evidence["request_id"] == mission.request_id
    assert evidence["proof_fingerprint"] == proof.execution_binding_hash
    assert evidence["raw_output_sha256"]
    assert evidence["result_hash"]
    # Raw output itself is NOT the evidence: only its hash is recorded.
    assert "processes" not in evidence
    assert "raw_output" not in evidence


def test_stage_c_result_envelope_separates_raw_normalized_evidence_error(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.raw_output == result.normalized_output
    assert result.raw_output is not result.normalized_output  # normalized is a copy
    assert isinstance(result.evidence, dict) and isinstance(result.metadata, dict)
    assert result.error_state == {}
    assert set(result.evidence).isdisjoint({"processes", "count"})


def test_stage_c_normalization_is_deterministic(tmp_path, counting_handler):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    result_a = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_a, _proof(mission_a)))
    result_b = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_b, _proof(mission_b)))
    assert result_a.normalized_output == result_b.normalized_output
    assert result_a.evidence["result_hash"] == result_b.evidence["result_hash"]


def test_stage_c_output_cannot_forge_envelope_metadata_or_provenance(tmp_path, monkeypatch):
    _patch_handler(monkeypatch, result=dict(VALID_PROCESS_PAYLOAD, adapter="EvilAdapter", provenance="OWNER", status="SUCCESS"))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "SUCCESS"
    assert result.metadata["adapter"] == "LocalProcessInfoAdapter"
    assert result.evidence["provenance"] == "TOOL_ADAPTER"
    # The tool payload stays in the untrusted output fields only.
    assert result.normalized_output["adapter"] == "EvilAdapter"


def test_stage_c_deterministic_shape_is_enforced(tmp_path, monkeypatch, execute_spy):
    """Deterministic normalize: the process listing shape is validated, not trusted."""
    _patch_handler(monkeypatch, result=dict(VALID_PROCESS_PAYLOAD))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "SUCCESS"
    assert result.normalized_output["count"] == 2


# ---------------------------------------------------------------------------
# 2. Input: the informational tool accepts NO argument (widening fails closed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("argument", ["ps aux", "--no-headers", "1", {"pid": 1}, 123, True])
def test_stage_c_any_argument_is_widening_and_rejected(tmp_path, counting_handler, execute_spy, argument):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission), argument=argument))
    assert result.status == "ERROR"
    assert result.executed is False
    assert result.error_state["code"] == "INPUT_INVALID"
    assert result.error_state["phase"] == "VALIDATE_INPUT"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_uppercase_tool_name_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, None, tool="LOCAL_PROCESS_INFO"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_forged_execution_class_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission), execution_class="GOD_MODE"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_missing_mission_object_rejected_for_mission_bound(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    request = ToolAdapterRequest(
        tool="local_process_info",
        argument=None,
        execution_class="MISSION_BOUND",
        execution_proof=proof,
        mission=None,  # the live mission is mandatory for mission-bound execution
        mission_id=mission.mission_id,
        request_id=mission.request_id,
    )
    result = LOCAL_PROCESS_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 3. Tool identity: registration, snapshot membership, identity binding
# ---------------------------------------------------------------------------


def test_stage_c_catalog_definition_is_not_runtime_registration(tmp_path, counting_handler, execute_spy):
    """Path A invariant: the catalog defines, the registry registers. nmap is a
    Layer 1 definition only; the adapter fails closed because it is not a
    registered runtime tool."""
    catalog_ids = set(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert "nmap" in catalog_ids
    assert "nmap" not in tools.registry.KNOWN_TOOLS
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = CatalogOnlyToolAdapter().run(_request(mission, None, tool="nmap"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_registered_tool_catalog_disjointness_invariant_holds(tmp_path):
    """The architectural decision of Stage C: registering local_process_info
    did NOT weaken the Stage A invariant — catalog definition and runtime
    registration stay fully disjoint (Path A)."""
    catalog_ids = set(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert "local_process_info" in tools.registry.KNOWN_TOOLS
    assert "local_process_info" not in catalog_ids
    assert catalog_ids.isdisjoint(tools.registry.KNOWN_TOOLS)


def test_stage_c_registered_tool_spec_shape_is_defensive():
    spec = tools.registry.get_tool("local_process_info")
    assert spec is not None
    assert spec.risk_class == "read"
    assert spec.argument_type is None  # strictly informational, argument-free
    assert spec.owner_only is False
    assert spec.scope_required is False
    assert spec.network_access == "none"
    assert spec.filesystem_access == "none"


def test_stage_c_tool_not_in_snapshot_cannot_even_mint_a_proof(tmp_path):
    """The EXISTING chain refuses to derive authority for a tool outside the
    owner snapshot allowlist/budget — the adapter never gets the chance."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="status")  # snapshot allows status/search only
    with pytest.raises(ExecutionProofError) as excinfo:
        _proof(mission, tool="local_process_info")
    assert excinfo.value.code == RejectionCode.TOOL_NOT_ALLOWED.value


def test_stage_c_proof_for_other_tool_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof_for_search = _proof(mission, tool="search", argument="q")
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof_for_search))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_proof_for_system_info_rejected_by_process_adapter(tmp_path, counting_handler, execute_spy):
    """Identity confusion between the two registered adapters is impossible:
    a local_system_info proof never authorizes a local_process_info run."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof_system = _proof(mission, tool="local_system_info")
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof_system))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_class_confusion_owner_direct_proof_on_mission_bound_request(tmp_path, counting_handler, execute_spy):
    context = make_test_authorization_context("req-od", tmp_path)
    decision = authorize_tool("local_process_info", context=context).decision
    assert decision is not None
    proof_od = ExecutionAuthorizationProof.derive(
        mission_id="",
        request_id="req-od",
        tool="local_process_info",
        argument=None,
        decision=decision,
        execution_class="OWNER_DIRECT",
    )
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof_od))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.EXECUTION_CLASS_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 4. Authority battery: every rejection happens BEFORE the registry
# ---------------------------------------------------------------------------


def test_stage_c_missing_proof_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, None))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_REQUIRED.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_untyped_proof_object_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    forged = {"tool": "local_process_info", "proof_signature": "forged"}
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, forged))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_INVALID.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_forged_proof_signature_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    tampered = _proof(mission).to_dict()
    tampered["proof_signature"] = "f" * 64
    forged = ExecutionAuthorizationProof.from_dict(tampered)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, forged))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_INVALID.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_expired_proof_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, ttl_seconds=1)
    time.sleep(1.2)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_EXPIRED.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_proof_from_another_mission_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proof_a = _proof(mission_a)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_b, proof_a))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_proof_from_another_request_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, request_id="req-other"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_stale_plan_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)  # bound to the plan fingerprint at derivation time
    mission.progress["execution_plan"] = {"plan_fingerprint": "rotated-plan-fingerprint"}
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PLAN_MISMATCH"
    assert result.error_state["rejection_code"] == RejectionCode.PLAN_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_forged_plan_hash_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, plan_hash="forged-plan-fingerprint")
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PLAN_MISMATCH"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_stale_snapshot_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    # The owner authorization snapshot rotates after the proof was derived.
    tampered = dict(mission.authorization_snapshot or {})
    tampered["version"] = int(tampered.get("version", 1)) + 1
    _set_mission_snapshot(mission, tampered)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "AUTHORIZATION_DENIED"
    assert result.error_state["rejection_code"] == RejectionCode.SNAPSHOT_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_stale_lifecycle_revision_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission, lifecycle_revision=len(mission.transitions) + 1)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "AUTHORIZATION_DENIED"
    assert result.error_state["rejection_code"] == RejectionCode.LIFECYCLE_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_run_mismatch_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-9"
    proof = _proof(mission, run_id="run-1")
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.RUN_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 5. Replay semantics
# ---------------------------------------------------------------------------


def test_stage_c_replay_after_run_rotation_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proof = _proof(mission, run_id="run-1")
    first = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert first.status == "SUCCESS"
    assert counting_handler.calls == 1
    # The run rotates; the same proof must never execute again.
    mission.progress["model_run_id"] = "run-2"
    replay = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert replay.status == "ERROR"
    assert replay.error_state["rejection_code"] == RejectionCode.RUN_MISMATCH.value
    assert counting_handler.calls == 1
    assert execute_spy == ["local_process_info"]


def test_stage_c_proof_reuse_semantics_within_same_run(tmp_path, counting_handler, execute_spy):
    """Current chain semantics, documented: a proof is single-RUN bound but
    not single-USE (no consumption nonce exists in the authorization layers).
    Reuse inside the SAME run still passes every binding check; any rotation
    of plan, snapshot, or run invalidates it (proven above and below). This
    boundary is recorded for the Owner: single-use proof consumption is a
    deliberate future decision, not an adapter-layer invention."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proof = _proof(mission, run_id="run-1")
    first = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    second = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert first.status == "SUCCESS"
    assert second.status == "SUCCESS"
    assert counting_handler.calls == 2
    assert execute_spy == ["local_process_info", "local_process_info"]
    # But a rotated plan with the SAME proof is rejected on the next reuse.
    mission.progress["execution_plan"] = {"plan_fingerprint": "rotated"}
    third = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof, run_id="run-1"))
    assert third.status == "ERROR"
    assert third.error_state["rejection_code"] == RejectionCode.PLAN_MISMATCH.value


# ---------------------------------------------------------------------------
# 6. Dry run: real authorization, zero execution
# ---------------------------------------------------------------------------


def test_stage_c_dry_run_never_executes(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, proof), dry_run=True)
    assert result.status == "DRY_RUN"
    assert result.dry_run is True
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []
    plan = result.metadata["dry_run_plan"]
    assert plan["tool"] == "local_process_info"
    assert plan["execution_class"] == "MISSION_BOUND"
    assert plan["handler_source"] == "tools.registry"
    assert plan["required_binary"] == "ps"
    assert plan["would_execute"] is True
    assert result.evidence["status"] == "DRY_RUN"
    assert result.cleanup_ran is True


def test_stage_c_dry_run_still_requires_authorization(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, None), dry_run=True)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_dry_run_fails_closed_when_binary_missing(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = MissingPsBinaryAdapter().run(_request(mission, proof), dry_run=True)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert result.error_state["phase"] == "PREPARE"
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 7. Missing binary: fail closed, no fallback
# ---------------------------------------------------------------------------


def test_stage_c_missing_ps_binary_fails_closed_with_no_fallback(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof = _proof(mission)
    result = MissingPsBinaryAdapter().run(_request(mission, proof))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert result.error_state["phase"] == "PREPARE"
    assert result.executed is False
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 8. Owner-direct execution class
# ---------------------------------------------------------------------------


def _owner_direct_proof_and_decision(tmp_path, request_id="req-od"):
    context = make_test_authorization_context(request_id, tmp_path)
    decision = authorize_tool("local_process_info", context=context).decision
    assert decision is not None
    proof = ExecutionAuthorizationProof.derive(
        mission_id="",
        request_id=request_id,
        tool="local_process_info",
        argument=None,
        decision=decision,
        execution_class="OWNER_DIRECT",
    )
    return proof, decision


def test_stage_c_owner_direct_execution_allowed(tmp_path, counting_handler, execute_spy):
    proof, decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_process_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        authorization_decision=decision,
    )
    result = LOCAL_PROCESS_INFO_ADAPTER.run(request)
    assert result.status == "SUCCESS"
    assert result.executed is True
    assert counting_handler.calls == 1
    assert execute_spy == ["local_process_info"]
    assert result.evidence["execution_class"] == "OWNER_DIRECT"


def test_stage_c_owner_direct_without_decision_rejected(tmp_path, counting_handler, execute_spy):
    proof, _decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_process_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        authorization_decision=None,
    )
    result = LOCAL_PROCESS_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_owner_direct_with_mission_binding_rejected(tmp_path, counting_handler, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proof, _decision = _owner_direct_proof_and_decision(tmp_path)
    request = ToolAdapterRequest(
        tool="local_process_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof,
        request_id="req-od",
        mission=mission,  # class confusion: owner-direct run carrying mission bindings
    )
    result = LOCAL_PROCESS_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] == "INPUT_INVALID"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_owner_direct_with_unbound_decision_rejected(tmp_path, counting_handler, execute_spy):
    proof_a, _decision_a = _owner_direct_proof_and_decision(tmp_path, request_id="req-a")
    _proof_b, decision_b = _owner_direct_proof_and_decision(tmp_path, request_id="req-b")
    request = ToolAdapterRequest(
        tool="local_process_info",
        argument=None,
        execution_class="OWNER_DIRECT",
        execution_proof=proof_a,
        request_id="req-a",
        authorization_decision=decision_b,  # a valid decision for ANOTHER request
    )
    result = LOCAL_PROCESS_INFO_ADAPTER.run(request)
    assert result.status == "ERROR"
    assert result.error_state["code"] in {"AUTHORIZATION_DENIED", "PROOF_FAILURE"}
    assert counting_handler.calls == 0
    assert execute_spy == []


# ---------------------------------------------------------------------------
# 9. Post-execution failures: classified, never false success
# ---------------------------------------------------------------------------


def test_stage_c_execution_failure_classified(tmp_path, monkeypatch, execute_spy):
    counter = _patch_handler(monkeypatch, exc=RuntimeError("handler exploded"))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EXECUTION_FAILED"
    assert result.error_state["phase"] == "EXECUTE"
    assert result.executed is True  # the handler was invoked and failed
    assert counter.calls == 1
    assert result.evidence["error_code"] == "EXECUTION_FAILED"
    assert result.cleanup_ran is True


def test_stage_c_timeout_classified(tmp_path, monkeypatch, execute_spy):
    counter = _patch_handler(monkeypatch, delay=2.0)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = SlowProcessAdapter().run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TIMEOUT"
    assert result.executed is True
    assert counter.calls == 1
    assert result.cleanup_ran is True


def test_stage_c_normalization_failure_on_bad_shape_classified(tmp_path, monkeypatch, execute_spy):
    _patch_handler(monkeypatch, result={"processes": [{"pid": "one", "ppid": 0, "user": "root", "command": "init"}], "count": 1})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert result.error_state["phase"] == "NORMALIZE_OUTPUT"
    assert result.executed is True
    assert result.cleanup_ran is True


def test_stage_c_normalization_failure_on_count_mismatch_classified(tmp_path, monkeypatch, execute_spy):
    _patch_handler(monkeypatch, result={"processes": VALID_PROCESS_PAYLOAD["processes"], "count": 5})
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert result.cleanup_ran is True


def test_stage_c_normalization_failure_on_non_dict_classified(tmp_path, monkeypatch, execute_spy):
    _patch_handler(monkeypatch, result=["pid", "ppid"])  # un-normalizable payload
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert result.cleanup_ran is True


def test_stage_c_evidence_failure_classified(tmp_path, monkeypatch, execute_spy):
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
def test_stage_c_cleanup_runs_exactly_once_on_every_path(tmp_path, monkeypatch, scenario):
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
        adapter = SlowProcessAdapter()
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


def test_stage_c_cleanup_failure_on_success_is_not_silent(tmp_path, monkeypatch):
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


def test_stage_c_cleanup_failure_does_not_mask_primary_error(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch, exc=RuntimeError("primary failure"))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    adapter = FailingCleanupAdapter()
    result = adapter.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EXECUTION_FAILED"  # primary preserved
    assert result.cleanup_error  # cleanup failure recorded separately
    assert counter.calls == 1


def test_stage_c_cleanup_runs_on_dry_run_and_rejections(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    adapter = RecordingCleanupAdapter()
    dry = adapter.run(_request(mission, _proof(mission)), dry_run=True)
    assert dry.status == "DRY_RUN"
    assert dry.cleanup_ran is True
    rejected = adapter.run(_request(mission, None))
    assert rejected.status == "ERROR"
    assert rejected.cleanup_ran is True
    assert adapter.cleanup_calls == 2
    assert counter.calls == 0  # cleanup is inert: never touches the handler


# ---------------------------------------------------------------------------
# 11. Output poisoning: untrusted tool output can never become authority
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "poison_key",
    [
        "owner",
        "owner_token",
        "authorization",
        "permission",
        "scope",
        "policy",
        "proof",
        "proof_signature",
        "plan_hash",
        "plan_fingerprint",
        "execution_plan",
        "execution_class",
        "budget",
        "credential",
        "token",
    ],
)
def test_stage_c_authority_shaped_output_rejected(tmp_path, monkeypatch, execute_spy, poison_key):
    """Defense in depth: tool output is untrusted data and can never carry an
    authority-shaped key into the normalized payload."""
    _patch_handler(monkeypatch, result=dict(VALID_PROCESS_PAYLOAD, **{poison_key: "forged"}))
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "NORMALIZATION_FAILED"
    assert "authority-shaped" in result.error_state["reason"]
    assert result.cleanup_ran is True


def test_stage_c_widened_authority_blocklist_is_in_place():
    """Regression guard for the Stage C widening of the authority-shaped
    output blocklist (defense in depth against output poisoning)."""
    tokens = set(AUTHORITY_OUTPUT_TOKENS)
    for required in (
        "owner", "proof", "policy", "scope", "budget",
        "plan_hash", "plan_fingerprint", "execution_plan", "execution_class",
        "authorization", "permission", "credential", "token",
    ):
        assert required in tokens, f"authority-shaped token missing from blocklist: {required}"


# ---------------------------------------------------------------------------
# 12. Integration: the adapter has NO execution path outside the chain
# ---------------------------------------------------------------------------


def test_stage_c_adapter_cannot_reach_the_handler_without_the_registry(tmp_path, monkeypatch):
    """If tools.registry.execute does not invoke the handler, the adapter
    cannot either: the handler spy stays at zero while the (stubbed) registry
    boundary is the ONLY call path. This proves the adapter holds no direct
    handler path of its own."""
    counter = _patch_handler(monkeypatch)
    seen: list[dict] = []

    def stub_execute(name, argument=None, **kwargs):
        seen.append({"name": name, "kwargs": set(kwargs)})
        return dict(VALID_PROCESS_PAYLOAD)  # never touches the real handler

    monkeypatch.setattr(tools.registry, "execute", stub_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "SUCCESS"
    assert counter.calls == 0  # the adapter itself never invoked the handler
    assert len(seen) == 1
    assert seen[0]["name"] == "local_process_info"
    # The registry boundary receives the FULL chain state, not a bare call.
    assert {"mission_id", "request_id", "mission_authorization", "execution_proof", "execution_class", "execution_run_id"} <= seen[0]["kwargs"]


def test_stage_c_registry_failure_surfaces_as_classified_execution_failure(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)

    def exploding_execute(name, argument=None, **kwargs):
        raise RuntimeError("registry boundary exploded")

    monkeypatch.setattr(tools.registry, "execute", exploding_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "EXECUTION_FAILED"
    assert counter.calls == 0
    assert result.cleanup_ran is True


def test_stage_c_registry_permission_error_surfaces_as_authorization_rejection(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)

    def denying_execute(name, argument=None, **kwargs):
        raise PermissionError("PROOF_EXPIRED: registry re-check refused the proof")

    monkeypatch.setattr(tools.registry, "execute", denying_execute)
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, _proof(mission)))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_EXPIRED.value
    assert counter.calls == 0


# ---------------------------------------------------------------------------
# 13. THE decisive test set: the Tool Adapter is NOT an Authorization Layer
# ---------------------------------------------------------------------------


def test_stage_c_boundary_1_adapter_existing_is_not_tool_authorization(tmp_path, counting_handler, execute_spy):
    """Boundary 1: adapter exists != tool authorized. The adapter is present
    and the tool is registered, yet with no proof there is no execution."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    assert tools.registry.get_tool("local_process_info") is not None
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, None))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_boundary_2_toolspec_existing_is_not_registration(tmp_path, counting_handler, execute_spy):
    """Boundary 2: ToolSpec existing != registered. nmap has a typed catalog
    ToolSpec yet is not a runtime-registered tool: fail closed."""
    catalog_ids = set(DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids())
    assert "nmap" in catalog_ids
    assert "nmap" not in tools.registry.KNOWN_TOOLS
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    result = CatalogOnlyToolAdapter().run(_request(mission, None, tool="nmap"))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "TOOL_UNAVAILABLE"
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_boundary_3_registered_is_not_authorized_for_this_mission(tmp_path, counting_handler, execute_spy):
    """Boundary 3: registered != authorized for this mission. The tool is in
    the registry, but the mission owner snapshot does not include it: the
    chain refuses to mint a proof, and a foreign-mission proof is rejected."""
    runtime = _runtime(tmp_path)
    other = _mission(runtime, action="status")  # snapshot without local_process_info
    with pytest.raises(ExecutionProofError) as excinfo:
        _proof(other, tool="local_process_info")
    assert excinfo.value.code == RejectionCode.TOOL_NOT_ALLOWED.value
    # And a proof minted for a mission that DID authorize it cannot be used here.
    authorized_mission = _mission(runtime)
    foreign_proof = _proof(authorized_mission)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(other, foreign_proof))
    assert result.status == "ERROR"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_BINDING_MISMATCH.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_boundary_4_authorized_is_not_proof_valid(tmp_path, counting_handler, execute_spy):
    """Boundary 4: authorized != proof valid. A real authorization decision
    exists for the request, yet a forged proof still fails closed."""
    context = make_test_authorization_context("req-od", tmp_path)
    decision = authorize_tool("local_process_info", context=context).decision
    assert decision is not None  # the tool IS authorized for this request
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    tampered = _proof(mission).to_dict()
    tampered["proof_signature"] = "f" * 64
    forged = ExecutionAuthorizationProof.from_dict(tampered)
    result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission, forged))
    assert result.status == "ERROR"
    assert result.error_state["code"] == "PROOF_FAILURE"
    assert result.error_state["rejection_code"] == RejectionCode.PROOF_INVALID.value
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_stage_c_boundary_5_valid_proof_is_not_execution_after_changes(tmp_path, counting_handler, execute_spy):
    """Boundary 5: proof valid != execution allowed. A fully valid proof is
    rejected the moment plan, snapshot, or run state changes underneath it."""
    runtime = _runtime(tmp_path)
    mission_plan = _mission(runtime)
    proof_plan = _proof(mission_plan)
    mission_plan.progress["execution_plan"] = {"plan_fingerprint": "rotated"}
    plan_result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_plan, proof_plan))
    assert plan_result.status == "ERROR"
    assert plan_result.error_state["rejection_code"] == RejectionCode.PLAN_MISMATCH.value

    mission_snapshot = _mission(runtime)
    proof_snapshot = _proof(mission_snapshot)
    tampered = dict(mission_snapshot.authorization_snapshot or {})
    tampered["version"] = int(tampered.get("version", 1)) + 1
    _set_mission_snapshot(mission_snapshot, tampered)
    snapshot_result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_snapshot, proof_snapshot))
    assert snapshot_result.status == "ERROR"
    assert snapshot_result.error_state["rejection_code"] == RejectionCode.SNAPSHOT_MISMATCH.value

    mission_run = _mission(runtime)
    mission_run.progress["model_run_id"] = "run-1"
    proof_run = _proof(mission_run, run_id="run-1")
    first = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_run, proof_run, run_id="run-1"))
    assert first.status == "SUCCESS"
    mission_run.progress["model_run_id"] = "run-2"
    run_result = LOCAL_PROCESS_INFO_ADAPTER.run(_request(mission_run, proof_run, run_id="run-1"))
    assert run_result.status == "ERROR"
    assert run_result.error_state["rejection_code"] == RejectionCode.RUN_MISMATCH.value

    assert counting_handler.calls == 1  # only the single legitimate execution
    assert execute_spy == ["local_process_info"]


# ---------------------------------------------------------------------------
# 14. Consolidated rejection battery: handler and registry never invoked
# ---------------------------------------------------------------------------


def _rejection_scenarios(tmp_path):
    """Every pre-execution rejection in one list; the consolidated test proves
    none of them ever reaches tools.registry.execute or the handler."""
    runtime = _runtime(tmp_path)
    scenarios = []

    mission = _mission(runtime)
    scenarios.append(("widening-argument", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission), argument="ps aux")))

    mission = _mission(runtime)
    scenarios.append(("uppercase-tool", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, None, tool="LOCAL_PROCESS_INFO")))

    mission = _mission(runtime)
    scenarios.append(("forged-execution-class", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission), execution_class="GOD_MODE")))

    mission = _mission(runtime)
    scenarios.append(("catalog-only-tool", CatalogOnlyToolAdapter(), _request(mission, None, tool="nmap")))

    mission = _mission(runtime)
    scenarios.append(("missing-binary", MissingPsBinaryAdapter(), _request(mission, _proof(mission))))

    mission = _mission(runtime)
    scenarios.append(("missing-proof", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, None)))

    mission = _mission(runtime)
    scenarios.append(("untyped-proof", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, {"tool": "local_process_info"})))

    mission = _mission(runtime)
    tampered = _proof(mission).to_dict()
    tampered["proof_signature"] = "f" * 64
    scenarios.append(("forged-proof-signature", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, ExecutionAuthorizationProof.from_dict(tampered))))

    mission = _mission(runtime)
    scenarios.append(("proof-for-other-tool", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission, tool="search", argument="q"))))

    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    scenarios.append(("proof-from-other-mission", LOCAL_PROCESS_INFO_ADAPTER, _request(mission_b, _proof(mission_a))))

    mission = _mission(runtime)
    scenarios.append(("proof-from-other-request", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission), request_id="req-other")))

    mission = _mission(runtime)
    scenarios.append(("forged-plan-hash", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission, plan_hash="forged-plan"))))

    mission = _mission(runtime)
    proof = _proof(mission)
    mission.progress["execution_plan"] = {"plan_fingerprint": "rotated"}
    scenarios.append(("stale-plan", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, proof)))

    mission = _mission(runtime)
    proof = _proof(mission)
    tampered = dict(mission.authorization_snapshot or {})
    tampered["version"] = int(tampered.get("version", 1)) + 1
    _set_mission_snapshot(mission, tampered)
    scenarios.append(("stale-snapshot", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, proof)))

    mission = _mission(runtime)
    scenarios.append(("stale-lifecycle-revision", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission, lifecycle_revision=len(mission.transitions) + 1))))

    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-9"
    scenarios.append(("run-mismatch", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, _proof(mission, run_id="run-1"), run_id="run-1")))

    mission = _mission(runtime)
    proof_od, _decision = _owner_direct_proof_and_decision(tmp_path)
    scenarios.append(("class-confusion", LOCAL_PROCESS_INFO_ADAPTER, _request(mission, proof_od)))

    return scenarios


def test_stage_c_every_rejected_request_never_invokes_handler_nor_registry(tmp_path, monkeypatch):
    counter = _patch_handler(monkeypatch)
    real_execute = tools.registry.execute
    execute_calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        execute_calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    scenarios = _rejection_scenarios(tmp_path)
    assert len(scenarios) >= 16  # the adversarial battery stays comprehensive
    for label, adapter, request in scenarios:
        result = adapter.run(request)
        assert result.status == "ERROR", label
        assert result.executed is False, label
        assert result.error_state, label
        assert result.ok is False, label
        assert result.cleanup_ran is True, label
    assert counter.calls == 0
    assert execute_calls == []
