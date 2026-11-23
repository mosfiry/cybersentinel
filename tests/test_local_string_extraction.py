"""local_string_extraction (P1-H) — live reachability + adversarial battery.

A real owner-authenticated mission flows through MissionRuntime ->
OffensiveActionBridge -> ToolAdapter -> tools.registry.execute -> the real
bounded printable-string extraction handler against REAL files in a REAL
artifact store.

The analyzed file is NEVER executed: ONE stat + ONE capped read through the
single filesystem seams, then ONE deterministic linear scan over the capped
prefix. Negative battery: every traversal / forged / tampered / cross-mission
/ cross-run attempt is rejected BEFORE any filesystem seam is touched
(seam-spy counters stay at zero). Extracted runs and classifications are
OBSERVED data with zero authority (INV-OFF-1/2); secret-like values are
fingerprint-redacted by the fixed code-defined table, never echoed.
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
    LocalStringExtractionAdapter,
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


def _mission(runtime, action="local_string_extraction"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, tool="local_string_extraction", **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id=tool,
        plan_hash=mission.plan.fingerprint,
        target_kind="local",
        risk_class="read_only",
        argument="strings.bin",
        hypothesis_id="h-1",
        required_evidence=("static string analysis",),
        source_step_id="s-01",
        rationale="statically extract printable strings from a captured artifact",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


@pytest.fixture
def artifact_store(tmp_path, monkeypatch):
    store = tmp_path / "artifacts"
    store.mkdir()
    monkeypatch.setattr(tools.registry, "_artifact_root", lambda: store)
    return store


def _make_strings_blob(store: Path, name: str = "strings.bin", *, runs=None) -> Path:
    if runs is None:
        runs = ["/bin/sh", "http://10.0.0.1/beacon", "password=NOT-A-REAL-VALUE-1234"]
    parts = bytearray()
    for text in runs:
        parts += b"\x00\x01\x02"
        parts += text.encode("ascii")
        parts += b"\x00"
    path = store / name
    path.write_bytes(bytes(parts))
    return path


@pytest.fixture
def seam_spies(monkeypatch):
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
def list_seam_spies(monkeypatch):
    stat_calls: list = []
    open_calls: list = []
    real_stat = tools.registry._artifact_stat
    real_open = tools.registry._artifact_open

    def spy_stat(path):
        stat_calls.append(str(path))
        return real_stat(path)

    def spy_open(path):
        open_calls.append(str(path))
        return real_open(path)

    monkeypatch.setattr(tools.registry, "_artifact_stat", spy_stat)
    monkeypatch.setattr(tools.registry, "_artifact_open", spy_open)
    return {"stat": stat_calls, "open": open_calls}


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
# HANDLER UNIT BATTERY (real files, real seams, static extraction only)
# ---------------------------------------------------------------------------


def test_handler_success_runs_offsets_order(artifact_store):
    _make_strings_blob(artifact_store)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is True
    assert result["operation"] == "local_string_extraction"
    values = [record["value"] for record in result["strings"]]
    assert values[0] == "/bin/sh"
    assert values[1] == "http://10.0.0.1/beacon"
    assert results_prefix_match(values[2], "password=")
    offsets = [record["offset"] for record in result["strings"]]
    assert offsets == sorted(offsets)
    assert result["analysis_kind"] == "static_string_read"
    assert result["content"] is None
    assert result["read_truncated"] is False


def results_prefix_match(value, prefix):
    return value.startswith(prefix)


def test_handler_secret_value_is_fingerprint_redacted_never_echoed(artifact_store):
    _make_strings_blob(artifact_store)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is True
    assert "NOT-A-REAL-VALUE-1234" not in repr(result)
    record = next(record for record in result["strings"] if record["value"].startswith("password="))
    expected = "password=REDACTED:" + hashlib.sha256(b"NOT-A-REAL-VALUE-1234").hexdigest()[:12]
    assert record["value"] == expected
    assert record["value_redacted"] is True
    assert record["value_sha256"] == hashlib.sha256(b"password=NOT-A-REAL-VALUE-1234").hexdigest()
    assert result["redacted_values"] == 1
    assert result["redaction_basis"] == "code_defined_secret_value_table"


def test_handler_non_secret_string_is_not_redacted(artifact_store):
    _make_strings_blob(artifact_store, runs=["just-a-normal-string"])
    result = tools.registry._printable_string_analysis("strings.bin")
    record = result["strings"][0]
    assert record["value"] == "just-a-normal-string"
    assert record["value_redacted"] is False


def test_handler_min_run_length_filters_short_runs(artifact_store):
    _make_strings_blob(artifact_store, runs=["abc", "abcdef"])
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is True
    assert result["total_printable_runs"] == 2
    assert result["qualifying_printable_runs"] == 1
    assert result["strings_returned"] == 1
    assert result["strings"][0]["value"] == "abcdef"


def test_handler_sha256_is_over_capped_read(artifact_store):
    data = (b"\x00" + b"aBcD" + b"\x00") * 16000  # > STRING_EXTRACTION_MAX_BYTES
    (artifact_store / "big.bin").write_bytes(data)
    result = tools.registry._printable_string_analysis("big.bin")
    assert result["ok"] is True
    assert result["read_truncated"] is True
    assert result["size_bytes"] == len(data)
    assert result["sha256"] == hashlib.sha256(data[:65536]).hexdigest()


def test_handler_value_truncation_flag(artifact_store):
    _make_strings_blob(artifact_store, runs=["A" * 300])
    result = tools.registry._printable_string_analysis("strings.bin")
    record = result["strings"][0]
    assert record["length"] == 300
    assert len(record["value"]) == 256
    assert record["value_truncated"] is True


def test_handler_hard_run_cap_is_deterministic(artifact_store):
    runs = ["run%02d-xxxx" % index for index in range(70)]
    _make_strings_blob(artifact_store, runs=runs)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is True
    assert result["qualifying_printable_runs"] == 70
    assert result["strings_returned"] == 64
    assert result["strings_truncated"] is True
    assert [record["value"] for record in result["strings"]] == runs[:64]


def test_handler_empty_or_nonprintable_file_is_data_not_failure(artifact_store):
    (artifact_store / "empty.bin").write_bytes(b"")
    result = tools.registry._printable_string_analysis("empty.bin")
    assert result["ok"] is True
    assert result["strings"] == []
    assert result["strings_truncated"] is False


def test_handler_extension_is_never_trusted(artifact_store):
    _make_strings_blob(artifact_store, "photo.jpg")
    result = tools.registry._printable_string_analysis("photo.jpg")
    assert result["ok"] is True
    assert result["format_family"] == "unknown"


def test_handler_not_found(artifact_store):
    result = tools.registry._printable_string_analysis("missing.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_NOT_FOUND"


def test_handler_stat_failure_is_str_open_failed(artifact_store, monkeypatch):
    _make_strings_blob(artifact_store)

    def boom(path):
        raise OSError("permission denied")

    monkeypatch.setattr(tools.registry, "_artifact_stat", boom)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_OPEN_FAILED"


def test_handler_open_failure_is_str_open_failed(artifact_store, monkeypatch):
    _make_strings_blob(artifact_store)

    def boom(path):
        raise OSError("read denied")

    monkeypatch.setattr(tools.registry, "_artifact_open", boom)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_OPEN_FAILED"


def test_handler_store_unavailable(monkeypatch):
    def boom():
        raise RuntimeError("root unavailable")

    monkeypatch.setattr(tools.registry, "_artifact_root", boom)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_STORE_UNAVAILABLE"


def test_handler_runtime_error_is_classified(artifact_store, monkeypatch):
    _make_strings_blob(artifact_store)

    def weird(path):
        raise ValueError(1)

    monkeypatch.setattr(tools.registry, "_artifact_open", weird)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_RUNTIME_ERROR"


def test_handler_scan_failure_is_classified(artifact_store, monkeypatch):
    _make_strings_blob(artifact_store)

    def boom(value):
        raise ValueError("redaction exploded")

    monkeypatch.setattr(tools.registry, "_redact_secret_value", boom)
    result = tools.registry._printable_string_analysis("strings.bin")
    assert result["ok"] is False
    assert result["error"] == "STR_RUNTIME_ERROR"


def test_handler_no_authority_keys(artifact_store):
    _make_strings_blob(artifact_store)
    result = tools.registry._printable_string_analysis("strings.bin")
    for key in result:
        assert not any(token in key for token in ("token", "password", "secret", "authorization", "policy", "proof", "scope"))


# ---------------------------------------------------------------------------
# ARGUMENT VALIDATION: traversal / forgery rejected BEFORE any seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../escape.txt", "a/b.txt", "a\\b.txt", "..", ".", ".hidden", "", 123, None, "x" * (MAX_ARG_LENGTH + 1)])
def test_argument_validator_rejects_pre_seam(artifact_store, seam_spies, bad):
    result = tools.registry._scoped_string_extraction(bad)
    assert result["ok"] is False
    assert result["error"] == "STR_ARGUMENT_INVALID"
    assert next(seam_spies["stat"]) == 0 and next(seam_spies["open"]) == 0


def test_symlink_escape_fails_closed(artifact_store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "outside.bin"
    target.write_bytes(b"data")
    try:
        (artifact_store / "link.bin").symlink_to(target)
    except OSError:
        pytest.skip("symlinks unsupported on this platform")
    result = tools.registry._printable_string_analysis("link.bin")
    assert result["ok"] is False
    assert result["error"] in ("STR_ARGUMENT_INVALID", "STR_NOT_FOUND")


# ---------------------------------------------------------------------------
# REGISTRY CATALOG PROPERTIES + REGISTERED GATED WRAPPER
# ---------------------------------------------------------------------------


def test_registry_catalog_properties():
    spec = tools.registry.get_tool("local_string_extraction")
    assert spec is not None
    assert spec.risk_class == "analysis"
    assert spec.requires_owner is True
    assert spec.scope_required is False
    assert spec.owner_only is False
    assert spec.argument_type is str


def test_tool_is_not_in_default_security_inventory():
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "local_string_extraction" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


def test_registered_handler_is_the_gated_wrapper():
    spec = tools.registry.get_tool("local_string_extraction")
    assert spec is not None
    assert spec.handler.__name__ == "_scoped_string_extraction"


@pytest.mark.parametrize("bad", ["sub/strings.bin", "../strings.bin", "a\\b.bin", "..", ".", ".hidden", ""])
def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, list_seam_spies, bad):
    _make_strings_blob(artifact_store)
    result = tools.registry.get_tool("local_string_extraction").handler(bad)
    assert result["ok"] is False
    assert result["error"] == "STR_ARGUMENT_INVALID"
    assert result["operation"] == "local_string_extraction"
    # rejected BEFORE any filesystem seam is touched
    assert list_seam_spies["stat"] == []
    assert list_seam_spies["open"] == []


def test_registry_gate_then_valid_name_executes_bounded(artifact_store, list_seam_spies):
    _make_strings_blob(artifact_store)
    spec = tools.registry.get_tool("local_string_extraction")
    ok = spec.handler("strings.bin")
    assert ok["ok"] is True
    assert ok["strings_returned"] >= 1
    # exactly ONE stat + ONE capped read
    assert len(list_seam_spies["stat"]) == 1
    assert len(list_seam_spies["open"]) == 1


# ---------------------------------------------------------------------------
# LIVE BRIDGE REACHABILITY (full chain, real adapter, real handler)
# ---------------------------------------------------------------------------


def test_live_string_extraction_full_chain(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_string_extraction")
    mission.progress["model_run_id"] = "run-1"
    _make_strings_blob(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["local_string_extraction"]
    result = record.result
    assert result.status == "SUCCESS"
    normalized = result.normalized_output
    assert normalized["ok"] is True
    assert normalized["strings_returned"] == len(normalized["strings"])
    assert "NOT-A-REAL-VALUE-1234" not in repr(normalized["strings"])
    assert normalized["content"] is None
    assert result.evidence["tool"] == "local_string_extraction"
    assert result.evidence["mission_id"] == mission.mission_id
    assert result.evidence["proof_fingerprint"] == record.proof_fingerprint


def test_live_dry_run_never_executes(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_string_extraction")
    mission.progress["model_run_id"] = "run-1"
    _make_strings_blob(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter(), dry_run=True)
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []


def test_live_missing_artifact_is_classified_observation(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_string_extraction")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument="missing.bin")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert execute_spy == ["local_string_extraction"]
    assert record.result.normalized_output["ok"] is False
    assert record.result.normalized_output["error"] == "STR_NOT_FOUND"
    assert record.result.normalized_output.get("content") is None


# ---------------------------------------------------------------------------
# BRIDGE NEGATIVES: fail closed BEFORE the boundary
# ---------------------------------------------------------------------------


def test_cross_mission_proposal_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proposal = _proposal(mission_b)
    with pytest.raises(OffensiveActionRejected, match="mission"):
        OffensiveActionBridge().run(proposal, mission=mission_a, adapter=LocalStringExtractionAdapter())
    assert execute_spy == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="0" * 64)
    with pytest.raises(OffensiveActionRejected, match="plan hash"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert execute_spy == []


def test_wrong_execution_run_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-999")
    with pytest.raises(OffensiveActionRejected, match="execution run"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert execute_spy == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool="string_dumper_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert execute_spy == []


def test_adapter_tool_mismatch_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission)  # local_string_extraction proposal ...
    with pytest.raises(OffensiveActionRejected, match="adapter"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


@pytest.mark.parametrize("bad", ["../escape.txt", "sub/dir.bin", "a\\b.bin", "..", ""])
def test_traversal_argument_through_bridge_fails_closed(tmp_path, execute_spy, artifact_store, bad):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_string_extraction")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument=bad)
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalStringExtractionAdapter())
    assert record.status == "REJECTED"
    assert record.executed is False
    assert record.result.error_state.get("phase") == "VALIDATE_INPUT"
    assert record.result.error_state.get("code") == "INPUT_INVALID"
    assert execute_spy == []


def test_adapter_validate_rejects_non_string_and_empty():
    from security.tool_adapter import ToolAdapterRequest, AdapterErrorCode, AdapterPhase

    adapter = LocalStringExtractionAdapter()
    for bad in ("", None, 5, b"bytes"):
        request = ToolAdapterRequest(
            tool="local_string_extraction",
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
