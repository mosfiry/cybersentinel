"""local_binary_analysis (P1-G) — live reachability + adversarial battery.

A real owner-authenticated mission flows through MissionRuntime ->
OffensiveActionBridge -> ToolAdapter -> tools.registry.execute -> the real
static header analysis handler against REAL files in a REAL artifact store.

The analyzed file is NEVER executed: ONE stat + ONE capped read through the
single filesystem seams, then deterministic fixed-offset byte arithmetic.
Negative battery: every traversal / forged / tampered / cross-mission /
cross-run attempt is rejected BEFORE any filesystem seam is touched
(seam-spy counters stay at zero). Header fields and classifications are
OBSERVED data with zero authority (INV-OFF-1/2).
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
    LocalBinaryAnalysisAdapter,
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


def _mission(runtime, action="local_binary_analysis"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, tool="local_binary_analysis", **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id=tool,
        plan_hash=mission.plan.fingerprint,
        target_kind="local",
        risk_class="read_only",
        argument="probe.bin",
        hypothesis_id="h-1",
        required_evidence=("static binary analysis",),
        source_step_id="s-01",
        rationale="statically analyze a captured artifact header",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


@pytest.fixture
def artifact_store(tmp_path, monkeypatch):
    store = tmp_path / "artifacts"
    store.mkdir()
    monkeypatch.setattr(tools.registry, "_artifact_root", lambda: store)
    return store


def _make_elf64(store: Path, name: str = "probe.bin") -> Path:
    h = bytearray(b"\x7fELF" + bytes([2, 1, 1]) + bytes(9))
    h += (2).to_bytes(2, "little")           # ET_EXEC
    h += (62).to_bytes(2, "little")          # EM_X86_64
    h += (1).to_bytes(4, "little")           # version
    h += (0x401000).to_bytes(8, "little")    # e_entry
    h += bytes(120)
    path = store / name
    path.write_bytes(bytes(h) + b"PADDING")
    return path


def _make_elf32(store: Path, name: str = "probe32.bin") -> Path:
    h = bytearray(b"\x7fELF" + bytes([1, 1, 1]) + bytes(9))
    h += (3).to_bytes(2, "little")           # ET_DYN
    h += (40).to_bytes(2, "little")          # EM_ARM
    h += (1).to_bytes(4, "little")
    h += (0x8000).to_bytes(4, "little")      # e_entry (32-bit)
    h += bytes(120)
    path = store / name
    path.write_bytes(bytes(h))
    return path


def _make_macho64(store: Path, name: str = "probe.macho") -> Path:
    data = bytes([0xCF, 0xFA, 0xED, 0xFE])          # MH_MAGIC_64
    data += (0x01000007).to_bytes(4, "little")       # CPU_TYPE_X86_64
    data += (2).to_bytes(4, "little")                # MH_EXECUTE
    data += bytes(4)                                  # reserved
    data += (5).to_bytes(4, "little")                # ncmds
    path = store / name
    path.write_bytes(data + b"LOAD" * 3)
    return path


def _make_universal(store: Path, name: str = "probe.universal") -> Path:
    data = bytes([0xCA, 0xFE, 0xBA, 0xBE]) + (2).to_bytes(4, "big")
    path = store / name
    path.write_bytes(data + bytes(32))
    return path


def _make_pe(store: Path, name: str = "probe.exe", *, lfanew=0x40) -> Path:
    dos = bytearray(b"MZ" + bytes(0x3A))
    dos += lfanew.to_bytes(4, "little") if lfanew + 4 <= 0x40 or True else (0).to_bytes(4, "little")
    path = store / name
    pe = bytearray(b"PE\x00\x00")
    pe += (0x8664).to_bytes(2, "little")       # IMAGE_FILE_MACHINE_AMD64
    pe += (3).to_bytes(2, "little")            # number of sections
    pe += bytes(12)
    pe += (0xF0).to_bytes(2, "little")         # size of optional header
    far = lfanew if lfanew < 0x10 else 0x3C
    if far + 4 <= 0x40:
        body = bytes(lfanew + 4)
    else:
        body = bytes(0x3C - 2 + 4) if False else bytes(0)
    payload = bytes(dos[:0x40]) if lfanew >= 0x40 else bytes(dos[: lfanew])
    if lfanew >= 0x40:
        path.write_bytes(payload + bytes(pe))
    else:
        combined = bytearray(bytes(dos[: lfanew]) + bytes(pe))
        combined[0x3C:0x40] = lfanew.to_bytes(4, "little")
        path.write_bytes(bytes(combined) + bytes(8))
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
def execute_spy(monkeypatch):
    real_execute = tools.registry.execute
    calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    return calls


# ---------------------------------------------------------------------------
# HANDLER UNIT BATTERY (real files, real seams, static parsing only)
# ---------------------------------------------------------------------------


def test_handler_success_elf64(artifact_store):
    _make_elf64(artifact_store)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is True
    assert result["operation"] == "local_binary_analysis"
    assert result["format_family"] == "elf"
    fields = result["header_fields"]
    assert fields["elf_class"] == "64-bit"
    assert fields["elf_data"] == "little_endian"
    assert fields["elf_type"] == 2
    assert fields["elf_machine"] == 62
    assert fields["elf_entry_point"] == 0x401000
    assert fields["elf_program_header_count"] == 0
    assert fields["elf_section_header_count"] == 0
    assert result["analysis_kind"] == "static_header_read"
    assert result["content"] is None
    assert result["read_truncated"] is False


def test_handler_success_elf32(artifact_store):
    _make_elf32(artifact_store)
    result = tools.registry._binary_header_analysis("probe32.bin")
    assert result["ok"] is True
    assert result["format_family"] == "elf"
    fields = result["header_fields"]
    assert fields["elf_class"] == "32-bit"
    assert fields["elf_type"] == 3
    assert fields["elf_machine"] == 40
    assert fields["elf_entry_point"] == 0x8000


def test_handler_success_macho64(artifact_store):
    _make_macho64(artifact_store)
    result = tools.registry._binary_header_analysis("probe.macho")
    assert result["ok"] is True
    assert result["format_family"] == "mach_o_64"
    fields = result["header_fields"]
    assert fields["macho_cputype"] == 0x01000007
    assert fields["macho_filetype"] == 2
    assert fields["macho_load_command_count"] == 5


def test_handler_success_universal(artifact_store):
    _make_universal(artifact_store)
    result = tools.registry._binary_header_analysis("probe.universal")
    assert result["ok"] is True
    assert result["format_family"] == "mach_o_universal"
    assert result["header_fields"]["universal_fat_arch_count"] == 2


def test_handler_success_pe(artifact_store):
    _make_pe(artifact_store)
    result = tools.registry._binary_header_analysis("probe.exe")
    assert result["ok"] is True
    assert result["format_family"] == "pe"
    fields = result["header_fields"]
    assert fields["pe_signature"] == "present"
    assert fields["pe_machine"] == 0x8664
    assert fields["pe_number_of_sections"] == 3
    assert fields["pe_size_of_optional_header"] == 0xF0


def test_handler_pe_signature_outside_capped_prefix(artifact_store):
    _make_pe(artifact_store, lfanew=0x2000)  # beyond the 4096-byte cap
    result = tools.registry._binary_header_analysis("probe.exe")
    assert result["ok"] is True
    assert result["header_fields"]["pe_signature"] == "outside_capped_prefix"


def test_handler_unknown_family_has_empty_fields(artifact_store):
    (artifact_store / "blob.dat").write_bytes(b"\x00\x01\x02\x03")
    result = tools.registry._binary_header_analysis("blob.dat")
    assert result["ok"] is True
    assert result["format_family"] == "unknown"
    assert result["header_fields"] == {}


def test_handler_extension_is_never_trusted(artifact_store):
    _make_elf64(artifact_store, "photo.jpg")
    result = tools.registry._binary_header_analysis("photo.jpg")
    assert result["ok"] is True
    assert result["format_family"] == "elf"


def test_handler_sha256_is_over_capped_read(artifact_store):
    data = (b"\x7fELF" + b"Z" * 9) * 600  # > BINARY_ANALYSIS_MAX_BYTES
    (artifact_store / "big.bin").write_bytes(data)
    result = tools.registry._binary_header_analysis("big.bin")
    assert result["ok"] is True
    assert result["read_truncated"] is True
    assert result["size_bytes"] == len(data)
    assert result["sha256"] == hashlib.sha256(data[:4096]).hexdigest()


def test_handler_content_is_never_echoed(artifact_store):
    secret = b"\x7fELF" + b"TOPSECRETBYTES" * 10
    (artifact_store / "s.bin").write_bytes(secret)
    result = tools.registry._binary_header_analysis("s.bin")
    assert result["content"] is None
    assert "TOPSECRETBYTES" not in repr(result)


def test_handler_not_found(artifact_store, seam_spies):
    result = tools.registry._binary_header_analysis("missing.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_NOT_FOUND"
    assert next(seam_spies["stat"]) == 0 and next(seam_spies["open"]) == 0


def test_handler_stat_failure_is_bin_open_failed(artifact_store, monkeypatch):
    _make_elf64(artifact_store)

    def boom(path):
        raise OSError("permission denied")

    monkeypatch.setattr(tools.registry, "_artifact_stat", boom)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_OPEN_FAILED"


def test_handler_open_failure_is_bin_open_failed(artifact_store, monkeypatch):
    _make_elf64(artifact_store)

    def boom(path):
        raise OSError("read denied")

    monkeypatch.setattr(tools.registry, "_artifact_open", boom)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_OPEN_FAILED"


def test_handler_store_unavailable(monkeypatch):
    def boom():
        raise RuntimeError("root unavailable")

    monkeypatch.setattr(tools.registry, "_artifact_root", boom)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_STORE_UNAVAILABLE"


def test_handler_runtime_error_is_classified(artifact_store, monkeypatch):
    _make_elf64(artifact_store)

    def weird(path):
        raise ValueError(1)

    monkeypatch.setattr(tools.registry, "_artifact_open", weird)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_RUNTIME_ERROR"


def test_handler_parser_failure_is_classified(artifact_store, monkeypatch):
    _make_elf64(artifact_store)
    def boom(prefix):
        raise ValueError("parser exploded")

    monkeypatch.setitem(tools.registry._BINARY_HEADER_PARSERS, "elf", boom)
    result = tools.registry._binary_header_analysis("probe.bin")
    assert result["ok"] is False
    assert result["error"] == "BIN_RUNTIME_ERROR"


# ---------------------------------------------------------------------------
# ARGUMENT VALIDATION: traversal / forgery rejected BEFORE any seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../escape.txt", "a/b.txt", "a\\b.txt", "..", ".", ".hidden", "", 123, None, "x" * (MAX_ARG_LENGTH + 1)])
def test_argument_validator_rejects_pre_seam(artifact_store, seam_spies, bad):
    result = tools.registry._scoped_binary_analysis(bad)
    assert result["ok"] is False
    assert result["error"] == "BIN_ARGUMENT_INVALID"
    assert next(seam_spies["stat"]) == 0 and next(seam_spies["open"]) == 0


def test_symlink_escape_fails_closed(artifact_store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"secret")
    target = outside / "secret.exe"
    try:
        target.write_bytes(b"secret")
        (artifact_store / "link.bin").symlink_to(target)
    except OSError:
        pytest.skip("symlinks unsupported on this platform")
    result = tools.registry._binary_header_analysis("link.bin")
    assert result["ok"] is False
    assert result["error"] in ("BIN_ARGUMENT_INVALID", "BIN_NOT_FOUND")
    assert "secret" not in repr(result)


# ---------------------------------------------------------------------------
# REGISTRY CATALOG PROPERTIES
# ---------------------------------------------------------------------------


def test_registry_catalog_properties():
    spec = tools.registry.get_tool("local_binary_analysis")
    assert spec is not None
    assert spec.risk_class == "analysis"
    assert spec.requires_owner is True
    assert spec.scope_required is False
    assert spec.owner_only is False
    assert spec.argument_type is str


def test_tool_is_not_in_default_security_inventory():
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "local_binary_analysis" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# LIVE BRIDGE REACHABILITY (full chain, real adapter, real handler)
# ---------------------------------------------------------------------------


def test_live_binary_analysis_full_chain(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_binary_analysis")
    mission.progress["model_run_id"] = "run-1"
    _make_elf64(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["local_binary_analysis"]
    result = record.result
    assert result.status == "SUCCESS"
    normalized = result.normalized_output
    assert normalized["ok"] is True
    assert normalized["format_family"] == "elf"
    assert normalized["header_fields"]["elf_machine"] == 62
    assert normalized["content"] is None
    assert result.evidence["tool"] == "local_binary_analysis"
    assert result.evidence["mission_id"] == mission.mission_id
    assert result.evidence["proof_fingerprint"] == record.proof_fingerprint


def test_live_dry_run_never_executes(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_binary_analysis")
    mission.progress["model_run_id"] = "run-1"
    _make_elf64(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter(), dry_run=True)
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []


def test_live_missing_artifact_is_classified_observation(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_binary_analysis")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument="missing.bin")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert execute_spy == ["local_binary_analysis"]
    assert record.result.normalized_output["ok"] is False
    assert record.result.normalized_output["error"] == "BIN_NOT_FOUND"
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
        OffensiveActionBridge().run(proposal, mission=mission_a, adapter=LocalBinaryAnalysisAdapter())
    assert execute_spy == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="0" * 64)
    with pytest.raises(OffensiveActionRejected, match="plan hash"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert execute_spy == []


def test_wrong_execution_run_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-999")
    with pytest.raises(OffensiveActionRejected, match="execution run"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert execute_spy == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool="binary_disassembler_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert execute_spy == []


def test_adapter_tool_mismatch_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission)  # local_binary_analysis proposal ...
    with pytest.raises(OffensiveActionRejected, match="adapter"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


@pytest.mark.parametrize("bad", ["../escape.txt", "sub/dir.bin", "a\\b.bin", "..", ""])
def test_traversal_argument_through_bridge_fails_closed(tmp_path, execute_spy, artifact_store, bad):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_binary_analysis")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument=bad)
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalBinaryAnalysisAdapter())
    assert record.status == "REJECTED"
    assert record.executed is False
    assert record.result.error_state.get("phase") == "VALIDATE_INPUT"
    assert record.result.error_state.get("code") == "INPUT_INVALID"
    assert execute_spy == []


def test_adapter_validate_rejects_non_string_and_empty():
    from security.tool_adapter import ToolAdapterRequest, AdapterErrorCode, AdapterPhase

    adapter = LocalBinaryAnalysisAdapter()
    for bad in ("", None, 5, b"bytes"):
        request = ToolAdapterRequest(
            tool="local_binary_analysis",
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
