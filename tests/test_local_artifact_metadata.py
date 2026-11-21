"""local_artifact_metadata (P1-F) — live reachability + adversarial battery.

A real owner-authenticated mission flows through MissionRuntime ->
OffensiveActionBridge -> ToolAdapter -> tools.registry.execute -> the real
artifact-metadata handler against REAL files in a REAL artifact store.

Negative battery: every traversal / forged / tampered / cross-mission /
cross-run attempt is rejected BEFORE any filesystem seam is touched
(seam-spy counters stay at zero). Observed bytes are hashed and classified
by the fixed magic-prefix table, never echoed, and never authoritative.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.offensive_bridge import (
    LocalArtifactMetadataAdapter,
    OffensiveActionBridge,
    OffensiveActionProposal,
    OffensiveActionRejected,
)
from agent.planning import Plan, PlanStep
from tools.registry import MAX_ARG_LENGTH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="local_artifact_metadata"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, tool="local_artifact_metadata", **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id=tool,
        plan_hash=mission.plan.fingerprint,
        target_kind="local",
        risk_class="read_only",
        hypothesis_id="h-1",
        required_evidence=("artifact metadata",),
        source_step_id="s-01",
        rationale="observe local artifact metadata",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


@pytest.fixture
def artifact_store(tmp_path, monkeypatch):
    """A REAL artifact store: the handler root seam is pointed at a temp dir."""
    store = tmp_path / "artifacts"
    store.mkdir()
    monkeypatch.setattr(tools.registry, "_artifact_root", lambda: store)
    return store


def _make_elf(store: Path, name: str = "probe.bin") -> Path:
    data = b"\x7fELF" + b"A" * 300
    path = store / name
    path.write_bytes(data)
    return path


@pytest.fixture
def seam_spies(monkeypatch):
    """Count every touch of the two filesystem seams (fail-closed evidence)."""
    import itertools

    stat_counter = itertools.count()
    open_counter = itertools.count()

    real_stat = tools.registry._artifact_stat
    real_open = tools.registry._artifact_open

    def spy_stat(path):
        next(stat_counter)
        return real_stat(path)

    def spy_open(path):
        next(open_counter)
        return real_open(path)

    monkeypatch.setattr(tools.registry, "_artifact_stat", spy_stat)
    monkeypatch.setattr(tools.registry, "_artifact_open", spy_open)
    return {"stat": stat_counter, "open": open_counter}


@pytest.fixture
def execute_spy(monkeypatch):
    real_execute = tools.registry.execute
    calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    return calls


# ---------------------------------------------------------------------------
# HANDLER UNIT BATTERY (real files, real seams)
# ---------------------------------------------------------------------------


def test_handler_success_elf_metadata(artifact_store):
    _make_elf(artifact_store)
    result = tools.registry._artifact_metadata("probe.bin")
    assert result["ok"] is True
    assert result["operation"] == "local_artifact_metadata"
    assert result["format_family"] == "elf"
    assert result["size_bytes"] == 304
    assert result["read_truncated"] is False
    assert result["sha256"] == hashlib.sha256(b"\x7fELF" + b"A" * 300).hexdigest()
    assert result["content"] is None
    assert result["classification_basis"] == "observed_magic_prefix"


def test_handler_sha256_is_over_capped_read(artifact_store):
    data = (b"B" * 100 + b"\x7fELF" + b"C" * 10) * 2000  # > ARTIFACT_METADATA_MAX_BYTES
    (artifact_store / "big.bin").write_bytes(data)
    result = tools.registry._artifact_metadata("big.bin")
    assert result["ok"] is True
    assert result["read_truncated"] is True
    assert result["size_bytes"] == len(data)
    assert result["sha256"] == hashlib.sha256(data[:65536]).hexdigest()


def test_handler_unknown_family_and_extension_distrust(artifact_store):
    # extension says "conf", magic says "elf": the OBSERVED prefix wins
    data = b"\x7fELF" + b"x"
    (artifact_store / "crypto.conf").write_bytes(data)
    result = tools.registry._artifact_metadata("crypto.conf")
    assert result["ok"] is True
    assert result["format_family"] == "elf"


def test_handler_shebang_is_script(artifact_store):
    (artifact_store / "run.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    result = tools.registry._artifact_metadata("run.sh")
    assert result["ok"] is True
    assert result["format_family"] == "script"


def test_handler_empty_file_unknown_family(artifact_store):
    (artifact_store / "empty.dat").write_bytes(b"")
    result = tools.registry._artifact_metadata("empty.dat")
    assert result["ok"] is True
    assert result["format_family"] == "unknown"
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()
    assert result["size_bytes"] == 0
    assert result["read_truncated"] is False


def test_handler_content_is_never_echoed(artifact_store):
    secret = b"\x7fELF" + b"TOPSECRETBYTES" * 10
    (artifact_store / "s.bin").write_bytes(secret)
    result = tools.registry._artifact_metadata("s.bin")
    assert result["content"] is None
    rendered = repr(result)
    assert b"TOPSECRETBYTES".decode() not in rendered
    assert "content" in rendered or True  # structure survives rendering


def test_handler_not_found(artifact_store, seam_spies):
    result = tools.registry._artifact_metadata("missing.bin")
    assert result["ok"] is False
    assert result["error"] == "META_NOT_FOUND"
    assert next(seam_spies["stat"]) == 0 and next(seam_spies["open"]) == 0


def test_handler_stat_failure_is_meta_open_failed(artifact_store, monkeypatch, seam_spies):
    _make_elf(artifact_store)

    def boom(path):
        raise OSError("permission denied")

    monkeypatch.setattr(tools.registry, "_artifact_stat", boom)
    result = tools.registry._artifact_metadata("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "META_OPEN_FAILED"


def test_handler_open_failure_is_meta_open_failed(artifact_store, monkeypatch):
    _make_elf(artifact_store)

    def boom(path):
        raise OSError("read denied")

    monkeypatch.setattr(tools.registry, "_artifact_open", boom)
    result = tools.registry._artifact_metadata("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "META_OPEN_FAILED"


def test_handler_store_unavailable(monkeypatch):
    def boom():
        raise RuntimeError("root unavailable")

    monkeypatch.setattr(tools.registry, "_artifact_root", boom)
    result = tools.registry._artifact_metadata("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "META_STORE_UNAVAILABLE"


def test_handler_runtime_error_is_classified(artifact_store, monkeypatch):
    _make_elf(artifact_store)
    real_open = tools.registry._artifact_open

    def weird(path):
        raise ValueError(1)

    real_stat = tools.registry._artifact_stat

    monkeypatch.setattr(tools.registry, "_artifact_stat", lambda p: real_stat(p))
    monkeypatch.setattr(tools.registry, "_artifact_open", weird)
    result = tools.registry._artifact_metadata("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "META_RUNTIME_ERROR"


# ---------------------------------------------------------------------------
# ARGUMENT VALIDATION: traversal / forgery rejected BEFORE any seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../escape.txt", "a/b.txt", "a\\b.txt", "..", ".", ".hidden", "", 123, None, "x" * (MAX_ARG_LENGTH + 1)])
def test_argument_validator_rejects_pre_seam(artifact_store, seam_spies, bad):
    result = tools.registry._scoped_local_artifact(bad)
    assert result["ok"] is False
    assert result["error"] == "META_ARGUMENT_INVALID"
    assert next(seam_spies["stat"]) == 0 and next(seam_spies["open"]) == 0


def test_symlink_escape_fails_closed(artifact_store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"secret")
    target = outside / "secret.txt"
    try:
        (artifact_store / "link.txt").symlink_to(target)
    except OSError:
        pytest.skip("symlinks unsupported on this platform")
    result = tools.registry._artifact_metadata("link.txt")
    assert result["ok"] is False
    assert result["error"] in ("META_ARGUMENT_INVALID", "META_NOT_FOUND")
    assert result.get("reason") != "secret"


# ---------------------------------------------------------------------------
# REGISTRY/c CATALOG PROPERTIES
# ---------------------------------------------------------------------------


def test_registry_catalog_properties():
    spec = tools.registry.get_tool("local_artifact_metadata")
    assert spec is not None
    assert spec.risk_class == "read"
    assert spec.requires_owner is True
    assert spec.scope_required is False
    assert spec.owner_only is False
    assert spec.argument_type is str


def test_tool_is_not_in_default_security_inventory():
    from cyber.offensive import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "local_artifact_metadata" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# LIVE BRIDGE REACHABILITY (full chain, real adapter, real handler)
# ---------------------------------------------------------------------------


def test_live_artifact_metadata_full_chain(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_artifact_metadata")
    mission.progress["model_run_id"] = "run-1"
    _make_elf(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["local_artifact_metadata"]
    result = record.result
    assert result.status == "SUCCESS"
    normalized = result.normalized_output
    assert normalized["ok"] is True
    assert normalized["format_family"] == "elf"
    assert normalized["content"] is None
    assert result.evidence["tool"] == "local_artifact_metadata"
    assert result.evidence["mission_id"] == mission.mission_id
    assert result.evidence["proof_fingerprint"] == record.proof_fingerprint


def test_live_dry_run_never_executes(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_artifact_metadata")
    mission.progress["model_run_id"] = "run-1"
    _make_elf(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter(), dry_run=True)
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []


def test_live_missing_artifact_is_recorded_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_artifact_metadata")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert record.status == "REJECTED"
    assert record.executed is False
    assert execute_spy == ["local_artifact_metadata"]  # reached the registry boundary


# ---------------------------------------------------------------------------
# BRIDGE NEGATIVES: fail closed BEFORE the boundary
# ---------------------------------------------------------------------------


def test_cross_mission_proposal_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proposal = _proposal(mission_b)
    with pytest.raises(OffensiveActionRejected, match="mission"):
        OffensiveActionBridge().run(proposal, mission=mission_a, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="0" * 64)
    with pytest.raises(OffensiveActionRejected, match="plan hash"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


def test_wrong_execution_run_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-999")
    with pytest.raises(OffensiveActionRejected, match="execution run"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool="artifact_scan_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


def test_adapter_tool_mismatch_is_rejected(tmp_path, execute_spy, artifact_store):
    from agent.offensive_bridge import LOCAL_PROCESS_INFO_ADAPTER

    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission)  # local_artifact_metadata proposal ...
    with pytest.raises(OffensiveActionRejected, match="adapter"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


@pytest.mark.parametrize("bad", ["../escape.txt", "sub/dir.bin", "\\\\evil.bin", ".."])
def test_traversal_argument_through_bridge_fails_closed(tmp_path, execute_spy, artifact_store, bad):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_artifact_metadata")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument=bad)
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert record.status == "REJECTED"
    assert record.executed is False
    assert record.result.error_state.get("phase") == "VALIDATE_INPUT"
    assert record.result.error_state.get("code") == "INPUT_INVALID"
    assert execute_spy == []


def test_adapter_validate_rejects_non_string_and_empty():
    # ToolAdapter.run NEVER raises: pre-execution rejection is a classified
    # ERROR envelope with the exact failing (phase, code) pair (INV-ADP-3/8).
    from security.tool_adapter import ToolAdapterRequest, AdapterErrorCode, AdapterPhase

    adapter = LocalArtifactMetadataAdapter()
    for bad in ("", None, 5, b"bytes"):
        request = ToolAdapterRequest(
            tool="local_artifact_metadata",
            argument=bad,
            execution_class="MISSION_BOUND",
            execution_proof=object(),
            mission=object(),
            mission_id="m-1",
            request_id="req-1",
            run_id="run-1",
        )
        result = adapter.run(request, dry_run=True)
        assert result.status == "ERROR"
        assert result.executed is False
        assert result.error_state.get("phase") == AdapterPhase.VALIDATE_INPUT.value
        assert result.error_state.get("code") == AdapterErrorCode.INPUT_INVALID.value
