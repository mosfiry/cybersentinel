"""local_import_analysis (P1-I) — live reachability + adversarial battery.

A real owner-authenticated mission flows through MissionRuntime ->
OffensiveActionBridge -> ToolAdapter -> tools.registry.execute -> the real
bounded static import-table + entropy handler against REAL files in a REAL
artifact store.

The analyzed file is NEVER executed: ONE stat + ONE capped read through the
single filesystem seams, then deterministic fixed-offset arithmetic over the
capped prefix. Negative battery: every traversal / forged / tampered /
cross-mission / cross-run attempt is rejected BEFORE any filesystem seam is
touched (seam-spy counters stay at zero). Parsed libraries, imported names,
and the entropy statistic are OBSERVED data with zero authority
(INV-OFF-1/2); anything outside the capped prefix is an observable None,
never invented.
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
    LocalImportAnalysisAdapter,
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


def _mission(runtime, action="local_import_analysis"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, tool="local_import_analysis", **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id=tool,
        plan_hash=mission.plan.fingerprint,
        target_kind="local",
        risk_class="read_only",
        argument="imports.bin",
        hypothesis_id="h-1",
        required_evidence=("static import analysis",),
        source_step_id="s-01",
        rationale="statically extract the import table from a captured artifact",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


@pytest.fixture
def artifact_store(tmp_path, monkeypatch):
    store = tmp_path / "artifacts"
    store.mkdir()
    monkeypatch.setattr(tools.registry, "_artifact_root", lambda: store)
    return store


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
# Synthetic artifact builders (real files, minimal but well-formed headers)
# ---------------------------------------------------------------------------


def _u32(value, little=True):
    return int(value).to_bytes(4, "little" if little else "big")


def _u64(value, little=True):
    return int(value).to_bytes(8, "little" if little else "big")


def _make_pe_blob(store: Path, name: str = "imports.bin") -> Path:
    lfanew = 0x40
    optional_header = lfanew + 24  # 0x58
    data_dir_base = optional_header + 96  # 0xB8
    section_dir = optional_header + 0xE0  # 0x138
    body = 0x1000  # RVA == file offset for simplicity
    desc = body  # import descriptors
    dll_name_rva = body + 0x30
    thunk_rva = body + 0x50
    hint_rva = body + 0x60
    blob = bytearray(0x1400)
    blob[0:2] = b"MZ"
    blob[0x3C:0x40] = _u32(lfanew)
    blob[lfanew:lfanew + 4] = b"PE\x00\x00"
    blob[lfanew + 4:lfanew + 6] = _u32(0x14C)[:2]          # machine i386
    blob[lfanew + 6:lfanew + 8] = _u32(1)[:2]              # one section
    blob[lfanew + 20:lfanew + 22] = _u32(0xE0)[:2]         # size of optional header
    blob[optional_header:optional_header + 2] = _u32(0x10B)[:2]  # PE32
    blob[optional_header + 92:optional_header + 96] = _u32(2)  # NumberOfRvaAndSizes
    blob[data_dir_base + 8:data_dir_base + 12] = _u32(desc)    # import directory RVA
    blob[data_dir_base + 12:data_dir_base + 16] = _u32(0x40)   # import directory size
    section = bytearray(40)
    section[8:12] = _u32(0x100)        # VirtualSize
    section[12:16] = _u32(body)        # VirtualAddress
    section[16:20] = _u32(0x180)       # SizeOfRawData
    section[20:24] = _u32(body)        # PointerToRawData
    blob[section_dir:section_dir + 40] = section
    # import descriptors: one real entry + the zero terminator
    blob[desc:desc + 4] = _u32(thunk_rva)          # OriginalFirstThunk
    blob[desc + 4:desc + 8] = _u32(0)              # TimeDateStamp
    blob[desc + 8:desc + 12] = _u32(0)             # ForwarderChain
    blob[desc + 12:desc + 16] = _u32(dll_name_rva) # Name RVA
    blob[desc + 16:desc + 20] = _u32(thunk_rva + 8)  # FirstThunk
    blob[body + 0x50:body + 0x54] = _u32(hint_rva)   # name thunk
    blob[body + 0x54:body + 0x58] = _u32(0x80000004)  # ordinal thunk
    blob[body + 0x58:body + 0x5C] = _u32(0)          # terminator
    blob[dll_name_rva:dll_name_rva + 9] = b"evil.dll\x00"
    blob[hint_rva:hint_rva + 2] = _u32(0)[:2]        # hint
    blob[hint_rva + 2:hint_rva + 17] = b"CreateProcessA\x00"
    path = store / name
    path.write_bytes(bytes(blob))
    return path


def _make_elf32_blob(store: Path, name: str = "imports.bin") -> Path:
    phoff = 0x34
    phentsize = 32
    dyn_body = 0x74   # dynamic-table entries (AFTER both program headers)
    strtab_vaddr = 0x8C
    blob = bytearray(0xC0)
    blob[0:4] = b"\x7fELF"
    blob[4:7] = bytes([1, 1, 1])  # 32-bit, little endian, v1
    blob[28:32] = _u32(phoff)
    blob[42:44] = _u32(phentsize)[:2]
    blob[44:46] = _u32(2)[:2]  # two program headers (PT_LOAD + PT_DYNAMIC)
    # program header 0 at 0x34: PT_LOAD covering the dynamic + string bodies
    seg0 = 0x34
    blob[seg0:seg0 + 4] = _u32(1)
    blob[seg0 + 4:seg0 + 8] = _u32(0x54)    # p_offset
    blob[seg0 + 8:seg0 + 12] = _u32(0x54)   # p_vaddr
    blob[seg0 + 16:seg0 + 20] = _u32(0x60)  # p_filesz -> covers 0x54..0xB4
    # program header 1 at 0x54: PT_DYNAMIC pointing at the entries
    seg1 = 0x54
    blob[seg1:seg1 + 4] = _u32(2)
    blob[seg1 + 4:seg1 + 8] = _u32(dyn_body)
    blob[seg1 + 8:seg1 + 12] = _u32(dyn_body)
    blob[seg1 + 16:seg1 + 20] = _u32(0x18)  # p_filesz: three 8-byte entries
    # dynamic entries at dyn_body: DT_NEEDED(1) -> strtab offset 1; DT_STRTAB(5); DT_NULL(0)
    blob[dyn_body:dyn_body + 4] = _u32(1)
    blob[dyn_body + 4:dyn_body + 8] = _u32(1)
    blob[dyn_body + 8:dyn_body + 12] = (5).to_bytes(4, "little")
    blob[dyn_body + 12:dyn_body + 16] = _u32(strtab_vaddr)
    blob[dyn_body + 16:dyn_body + 24] = b"\x00" * 8  # DT_NULL
    # string table at 0x8C: NUL + "libpthread.so"
    blob[strtab_vaddr:strtab_vaddr + 14] = b"\x00libpthread.so\x00"
    path = store / name
    path.write_bytes(bytes(blob))
    return path


def _make_macho64_blob(store: Path, name: str = "imports.bin") -> Path:
    blob = bytearray(0x80)
    blob[0:4] = bytes([0xCF, 0xFA, 0xED, 0xFE])  # 64-bit little-endian Mach-O magic
    blob[16:20] = _u32(1)                        # one load command
    blob[20:24] = _u32(0x28)                     # sizeofcmds (40 bytes)
    # load command at 32: LC_LOAD_DYLIB, cmdsize 24, name at offset 24 within the command
    blob[32:36] = _u32(0x0C)
    blob[36:40] = _u32(0x18)
    blob[40:44] = _u32(0x18)  # name offset inside the command -> command end (0x38)
    blob[0x38:0x38 + 15] = b"libSystem.dylib\x00"
    path = store / name
    path.write_bytes(bytes(blob))
    return path


def _make_universal_blob(store: Path, name: str = "imports.bin") -> Path:
    blob = bytearray(0x20)
    blob[0:4] = b"\xca\xfe\xba\xbe"
    blob[4:8] = _u32(2, little=False)  # two embedded architectures
    path = store / name
    path.write_bytes(bytes(blob))
    return path


# ---------------------------------------------------------------------------
# HANDLER UNIT BATTERY (real files, real seams, static analysis only)
# ---------------------------------------------------------------------------


def test_handler_pe_imports_success(artifact_store):
    blob_path = _make_pe_blob(artifact_store)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is True, result
    assert result["operation"] == "local_import_analysis"
    assert result["format_family"] == "pe"
    assert result["parse_status"] == "ok"
    assert result["imports_returned"] == 1
    record = result["imports"][0]
    assert record["library"] == "evil.dll"
    assert record["functions"] == [
        {"import_type": "name", "name": "CreateProcessA"},
        {"import_type": "ordinal", "ordinal": 4},
    ]
    assert record["functions_truncated"] is False
    assert result["analysis_kind"] == "static_import_read"
    assert result["content"] is None
    assert result["read_truncated"] is False
    assert result["sha256"] == hashlib.sha256(blob_path.read_bytes()).hexdigest()


def test_handler_pe_extension_is_never_trusted(artifact_store):
    _make_pe_blob(artifact_store, "photo.jpg")
    result = tools.registry._import_analysis("photo.jpg")
    assert result["ok"] is True
    assert result["format_family"] == "pe"
    assert result["imports_returned"] == 1


def test_handler_elf_dt_needed_success(artifact_store):
    _make_elf32_blob(artifact_store)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is True, result
    assert result["format_family"] == "elf"
    assert result["parse_status"] == "ok"
    assert [record["library"] for record in result["imports"]] == ["libpthread.so"]
    assert result["imports_truncated"] is False


def test_handler_macho_dylib_success(artifact_store):
    _make_macho64_blob(artifact_store)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is True, result
    assert result["format_family"] == "mach_o_64"
    assert result["parse_status"] == "ok"
    assert result["imports"] == [
        {"command": "LC_LOAD_DYLIB", "library": "libSystem.dylib", "functions": [], "functions_truncated": False}
    ]


def test_handler_universal_fat_binary_is_observed_never_guessed(artifact_store):
    _make_universal_blob(artifact_store)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is True
    assert result["format_family"] == "mach_o_universal"
    assert result["imports"] == []
    assert result["imports_truncated"] is False
    assert result["parse_status"] == "ok"


def test_handler_unknown_family_is_data_not_failure(artifact_store):
    (artifact_store / "text.bin").write_bytes(b"plain text, no imports here")
    result = tools.registry._import_analysis("text.bin")
    assert result["ok"] is True
    assert result["format_family"] == "unknown"
    assert result["parse_status"] == "unsupported_format_for_imports"
    assert result["imports"] == []


def test_handler_entropy_statistic_is_deterministic(artifact_store):
    (artifact_store / "uniform.bin").write_bytes(b"\x00" * 4096)
    result = tools.registry._import_analysis("uniform.bin")
    assert result["entropy_bits_per_byte"] == 0.0
    (artifact_store / "half.bin").write_bytes(bytes(1 if index % 2 == 0 else 0 for index in range(4096)))
    result = tools.registry._import_analysis("half.bin")
    assert result["entropy_bits_per_byte"] == 1.0


def test_handler_entropy_over_capped_read(artifact_store):
    data = (b"\x00" * 100 + b"\x01") * 4000  # > IMPORT_ANALYSIS_MAX_BYTES
    (artifact_store / "big.bin").write_bytes(data)
    result = tools.registry._import_analysis("big.bin")
    assert result["ok"] is True
    assert result["read_truncated"] is True
    assert result["size_bytes"] == len(data)
    assert result["read_cap_bytes"] == 262144
    assert result["sha256"] == hashlib.sha256(data[:262144]).hexdigest()
    assert 0.0 < result["entropy_bits_per_byte"] < 0.1


def test_handler_not_found(artifact_store):
    result = tools.registry._import_analysis("missing.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_NOT_FOUND"


def test_handler_stat_failure_is_imp_open_failed(artifact_store, monkeypatch):
    _make_pe_blob(artifact_store)

    def boom(path):
        raise OSError("permission denied")

    monkeypatch.setattr(tools.registry, "_artifact_stat", boom)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_OPEN_FAILED"


def test_handler_open_failure_is_imp_open_failed(artifact_store, monkeypatch):
    _make_pe_blob(artifact_store)

    def boom(path):
        raise OSError("read denied")

    monkeypatch.setattr(tools.registry, "_artifact_open", boom)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_OPEN_FAILED"


def test_handler_store_unavailable(monkeypatch):
    def boom():
        raise RuntimeError("root unavailable")

    monkeypatch.setattr(tools.registry, "_artifact_root", boom)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_STORE_UNAVAILABLE"


def test_handler_runtime_error_is_classified(artifact_store, monkeypatch):
    _make_pe_blob(artifact_store)

    def weird(path):
        raise ValueError(1)

    monkeypatch.setattr(tools.registry, "_artifact_open", weird)
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_RUNTIME_ERROR"


def test_handler_parse_failure_is_imp_runtime_error(artifact_store, monkeypatch):
    _make_pe_blob(artifact_store)

    def boom(prefix, field_max):
        raise ValueError("parser exploded")

    monkeypatch.setattr(tools.registry, "_IMPORT_HEADER_PARSERS", {"pe": boom})
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is False
    assert result["error"] == "IMP_RUNTIME_ERROR"


def test_handler_pe_signature_outside_prefix_is_data(artifact_store):
    blob = bytearray(_make_pe_blob(artifact_store).read_bytes())
    blob[0x3C:0x40] = _u32(0x100000)  # e_lfanew beyond every capped prefix
    (artifact_store / "imports.bin").write_bytes(bytes(blob))
    result = tools.registry._import_analysis("imports.bin")
    assert result["ok"] is True
    assert result["format_family"] == "pe"  # the MZ prefix is still observed
    assert result["parse_status"] == "pe_signature_outside_capped_prefix"
    assert result["imports"] == []
    assert result["sha256"] == hashlib.sha256(bytes(blob[:262144])).hexdigest()


def test_handler_no_authority_keys(artifact_store):
    _make_pe_blob(artifact_store)
    result = tools.registry._import_analysis("imports.bin")
    for key in result:
        assert not any(token in key for token in ("token", "password", "secret", "authorization", "policy", "proof", "scope"))


# ---------------------------------------------------------------------------
# ARGUMENT VALIDATION: traversal / forgery rejected BEFORE any seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["../escape.txt", "a/b.txt", "a\\b.txt", "..", ".", ".hidden", "", 123, None, "x" * (MAX_ARG_LENGTH + 1)])
def test_argument_validator_rejects_pre_seam(artifact_store, seam_spies, bad):
    result = tools.registry._scoped_import_analysis(bad)
    assert result["ok"] is False
    assert result["error"] == "IMP_ARGUMENT_INVALID"
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
    result = tools.registry._import_analysis("link.bin")
    assert result["ok"] is False
    assert result["error"] in ("IMP_ARGUMENT_INVALID", "IMP_NOT_FOUND")


# ---------------------------------------------------------------------------
# REGISTRY CATALOG PROPERTIES + REGISTERED GATED WRAPPER
# ---------------------------------------------------------------------------


def test_registry_catalog_properties():
    spec = tools.registry.get_tool("local_import_analysis")
    assert spec is not None
    assert spec.risk_class == "analysis"
    assert spec.requires_owner is True
    assert spec.scope_required is False
    assert spec.owner_only is False
    assert spec.argument_type is str


def test_tool_is_not_in_default_security_inventory():
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "local_import_analysis" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


def test_registered_handler_is_the_gated_wrapper():
    spec = tools.registry.get_tool("local_import_analysis")
    assert spec is not None
    assert spec.handler.__name__ == "_scoped_import_analysis"


@pytest.mark.parametrize("bad", ["sub/imports.bin", "../imports.bin", "a\\b.bin", "..", ".", ".hidden", ""])
def test_registry_gate_rejects_non_bare_names_pre_seam(artifact_store, list_seam_spies, bad):
    _make_pe_blob(artifact_store)
    result = tools.registry.get_tool("local_import_analysis").handler(bad)
    assert result["ok"] is False
    assert result["error"] == "IMP_ARGUMENT_INVALID"
    assert result["operation"] == "local_import_analysis"
    # rejected BEFORE any filesystem seam is touched
    assert list_seam_spies["stat"] == []
    assert list_seam_spies["open"] == []


def test_registry_gate_then_valid_name_executes_bounded(artifact_store, list_seam_spies):
    _make_pe_blob(artifact_store)
    spec = tools.registry.get_tool("local_import_analysis")
    ok = spec.handler("imports.bin")
    assert ok["ok"] is True
    assert ok["imports_returned"] >= 1
    # exactly ONE stat + ONE capped read
    assert len(list_seam_spies["stat"]) == 1
    assert len(list_seam_spies["open"]) == 1


# ---------------------------------------------------------------------------
# LIVE BRIDGE REACHABILITY (full chain, real adapter, real handler)
# ---------------------------------------------------------------------------


def test_live_import_analysis_full_chain(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_import_analysis")
    mission.progress["model_run_id"] = "run-1"
    _make_pe_blob(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter())
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["local_import_analysis"]
    result = record.result
    assert result.status == "SUCCESS"
    normalized = result.normalized_output
    assert normalized["ok"] is True
    assert normalized["imports_returned"] == len(normalized["imports"])
    assert normalized["imports"][0]["library"] == "evil.dll"


def test_live_import_analysis_dry_run(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_import_analysis")
    mission.progress["model_run_id"] = "run-1"
    _make_pe_blob(artifact_store)
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter(), dry_run=True)
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []


def test_forged_plan_hash_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", plan_hash="0" * 64)
    with pytest.raises(OffensiveActionRejected, match="plan"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter())
    assert execute_spy == []


def test_mission_mismatch_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime, action="local_import_analysis")
    mission_b = _mission(runtime, action="local_import_analysis")
    mission_a.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission_a, execution_run_id="run-1", mission_id=mission_b.mission_id)
    with pytest.raises(OffensiveActionRejected, match="mission"):
        OffensiveActionBridge().run(proposal, mission=mission_a, adapter=LocalImportAnalysisAdapter())
    assert execute_spy == []


def test_wrong_execution_run_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-999")
    with pytest.raises(OffensiveActionRejected, match="execution run"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter())
    assert execute_spy == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool="import_dumper_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter())
    assert execute_spy == []


def test_adapter_tool_mismatch_is_rejected(tmp_path, execute_spy, artifact_store):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)  # local_import_analysis proposal ...
    with pytest.raises(OffensiveActionRejected, match="adapter"):
        OffensiveActionBridge().run(proposal=_proposal(mission), mission=mission, adapter=LocalArtifactMetadataAdapter())
    assert execute_spy == []


@pytest.mark.parametrize("bad", ["../escape.txt", "sub/dir.bin", "a\\b.bin", "..", ".", ""])
def test_traversal_argument_through_bridge_fails_closed(tmp_path, execute_spy, artifact_store, bad):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_import_analysis")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1", argument=bad)
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LocalImportAnalysisAdapter())
    assert record.status == "REJECTED"
    assert record.executed is False
    assert record.result.error_state.get("phase") == "VALIDATE_INPUT"
    assert record.result.error_state.get("code") == "INPUT_INVALID"
    assert execute_spy == []


def test_adapter_rejects_non_string_and_empty():
    from security.tool_adapter import ToolAdapterRequest, AdapterErrorCode, AdapterPhase

    adapter = LocalImportAnalysisAdapter()
    for bad in ("", None, 5, b"bytes"):
        request = ToolAdapterRequest(
            tool="local_import_analysis",
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
