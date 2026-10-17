"""Diagnostic only: a passing test may record a blocked profile-free launch."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _native_helpers():
    spec = importlib.util.spec_from_file_location(
        "lowbox_test_helpers", ROOT / "tests/test_windows_appcontainer_workspace_native.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOKEN_CLASSES = {
    "TokenType": 8, "TokenImpersonationLevel": 9, "TokenPrivileges": 3,
    "TokenIntegrityLevel": 25, "TokenIsAppContainer": 29,
    "TokenCapabilities": 30, "TokenAppContainerSid": 31,
    "TokenIsLessPrivilegedAppContainer": 46,
}


def _uint(value):
    assert type(value) is int and 0 <= value <= 0xFFFFFFFF


def _validate_query(query):
    assert query["name"] in TOKEN_CLASSES
    assert query["class"] == TOKEN_CLASSES[query["name"]]
    for key in ("buffer_size", "returned_length"):
        _uint(query[key])
    assert type(query["success"]) is bool
    assert query["ntstatus"] is None  # GetTokenInformation exposes Win32, not NTSTATUS.
    assert query["validation"] in {None, "valid", "invalid", "not_applicable"}
    if query["success"]:
        assert query["win32_error"] is None
    else:
        _uint(query["win32_error"])
        assert query["win32_error"] != 0
    if not query["success"] or query["validation"] != "valid":
        assert query["value"] is None
    else:
        assert query["value"] is not None
        value = query["value"]
        assert query["returned_length"] <= query["buffer_size"]
        name = query["name"]
        if name in {"TokenIsAppContainer", "TokenIsLessPrivilegedAppContainer"}:
            assert type(value) is bool
        elif name == "TokenType":
            assert type(value) is int and value in {1, 2}
        elif name == "TokenImpersonationLevel":
            assert type(value) is int and 0 <= value <= 3
        elif name == "TokenIntegrityLevel":
            _uint(value)
        elif name == "TokenAppContainerSid":
            assert isinstance(value, str) and re.fullmatch(r"S-1-[0-9-]+", value)
        elif name == "TokenPrivileges":
            assert isinstance(value, list)
            for privilege in value:
                _uint(privilege["luid_low"])
                _uint(privilege["attributes"])
                assert type(privilege["luid_high"]) is int
                assert -(1 << 31) <= privilege["luid_high"] < (1 << 31)
        elif name == "TokenCapabilities":
            assert isinstance(value, list)
            for capability in value:
                assert isinstance(capability["sid"], str)
                _uint(capability["attributes"])


def _query_value(observation, name):
    values = [query["value"] for query in observation["queries"]
              if query["name"] == name and query["success"]
              and query["validation"] == "valid" and query["value"] is not None]
    assert len(values) <= 1
    return values[0] if values else None


def _validate_observations(report):
    observations = report["observations"]
    for key in ("pretoken", "lowbox", "child", "thread_token"):
        observation = observations[key]
        assert isinstance(observation["queries"], list) and len(observation["queries"]) <= 16
        for query in observation["queries"]:
            _validate_query(query)
    pretoken = observations["pretoken"]
    for key, name in (("token_type", "TokenType"), ("integrity_rid", "TokenIntegrityLevel"),
                      ("privileges", "TokenPrivileges")):
        assert pretoken[key] == _query_value(pretoken, name)
    thread = observations["thread_token"]
    assert thread["state"] in {"not_checked", "present", "absent", "query_error"}
    if thread["state"] in {"not_checked", "present"}:
        assert thread["win32_error"] is None
    else:
        _uint(thread["win32_error"])
        assert thread["win32_error"] != 0
        assert (thread["win32_error"] == 1008) == (thread["state"] == "absent")
    if thread["state"] != "present":
        assert thread["queries"] == []
    handle = observations["input_handle"]
    assert handle["class"] == "ObjectBasicInformation" and handle["info_class"] == 0
    assert handle["win32_error"] is None  # Native query does not expose Win32 error.
    for key in ("buffer_size", "returned_length"):
        _uint(handle[key])
    assert type(handle["success"]) is bool
    assert handle["validation"] in {None, "valid", "invalid", "not_applicable"}
    assert handle["ntstatus"] is None or re.fullmatch(r"0x[0-9A-F]{8}", handle["ntstatus"])
    if handle["success"]:
        assert handle["ntstatus"] is not None and int(handle["ntstatus"], 16) < 0x80000000
    if handle["success"] and handle["validation"] == "valid":
        _uint(handle["value"])
        assert 56 <= handle["returned_length"] <= handle["buffer_size"]
    else:
        assert handle["value"] is None
    if report["child_token_verified"]:
        child = observations["child"]
        for query in child["queries"]:
            assert query["validation"] != "invalid"
            assert query["success"] or (query["buffer_size"] == 0 and query["win32_error"] == 122)
        assert _query_value(child, "TokenIsAppContainer") is True
        assert _query_value(child, "TokenIsLessPrivilegedAppContainer") is True
        assert _query_value(child, "TokenIntegrityLevel") == 4096
        assert _query_value(child, "TokenCapabilities") == []
        assert _query_value(child, "TokenAppContainerSid") is not None


def _validate_report(report):
    assert report["classification"] in {"supported", "blocked", "inconclusive"}
    assert isinstance(report["stage"], str) and report["stage"]
    assert report["ntstatus"] is None or re.fullmatch(r"0x[0-9A-Fa-f]{8}", report["ntstatus"])
    for key in ("win32_error", "cleanup_error"):
        assert type(report[key]) is int and 0 <= report[key] <= 0xFFFFFFFF
    for key in ("child_token_verified", "resumed"):
        assert type(report[key]) is bool
    assert not report["resumed"] or report["child_token_verified"]
    if report["classification"] == "supported":
        assert report["child_token_verified"] and report["resumed"]
        assert report["ntstatus"] == "0x00000000"
        assert report["child_exit_code"] == 0
        assert report["win32_error"] == report["cleanup_error"] == 0
    if not report["child_token_verified"]:
        assert not report["resumed"]
    _validate_observations(report)


def _profile_snapshot(helpers, identity):
    # Existing reader checks exact SID mapping/storage, known package directories,
    # and GetAppContainerFolderPath. Never serialize paths, account names or SIDs.
    raw = helpers._profile_artifacts(identity)
    folder = raw["folder_api"]
    return {
        "mapping_exists": raw["mapping_exists"],
        "storage_exists": raw["storage_exists"],
        "existing_candidate_count": len(raw["existing_candidate_paths"]),
        "folder_hresult": (folder["lookup_hresult"] & 0xFFFFFFFF)
        if folder["lookup_hresult"] is not None else None,
        "folder_lookup_succeeded": folder["lookup_succeeded"],
        "folder_exists": folder["folder_exists"],
    }


def _has_profile(snapshot):
    return (snapshot["mapping_exists"] or snapshot["storage_exists"]
            or snapshot["existing_candidate_count"] != 0
            or snapshot["folder_lookup_succeeded"] or snapshot["folder_exists"] is True)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows lowbox APIs")
def test_native_profile_free_lowbox_launch(tmp_path, record_property):
    from workspace.windows_appcontainer_workspace import _WindowsNative

    helpers = _native_helpers()
    source = ROOT / "tests/native/lowbox_launch_probe.c"
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    located = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=True,
    )
    assert located.stdout.strip(), "VS C++ compiler unavailable"
    devcmd = Path(located.stdout.strip().splitlines()[-1]) / "Common7/Tools/VsDevCmd.bat"
    assert devcmd.is_file()
    exe = tmp_path / "lowbox_launch_probe.exe"
    command = (f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && '
               f'cl /nologo /W4 /WX /MT /DUNICODE /D_UNICODE /TC "{source}" '
               f'/Fo:"{tmp_path / "probe.obj"}" /Fe:"{exe}" /link advapi32.lib')
    compiled = helpers._run_compile_command(command, tmp_path)
    assert compiled.returncode == 0 and exe.is_file(), compiled.stdout[-6000:]
    serialization = subprocess.run(
        [str(exe), "--serialization-self-test"], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=10, check=True, close_fds=True,
    )
    synthetic_report = json.loads(serialization.stdout)
    _validate_report(synthetic_report)
    assert synthetic_report["stage"] == "serialization_self_test"
    assert synthetic_report["child_token_verified"] is False
    assert synthetic_report["resumed"] is False
    assert synthetic_report["pretoken_win32"] == 87
    assert synthetic_report["pretoken_appcontainer"] == 0
    assert synthetic_report["pretoken_lpac"] == -1
    assert synthetic_report["observations"]["pretoken"]["token_type"] == 1
    assert synthetic_report["observations"]["pretoken"]["integrity_rid"] is None
    assert synthetic_report["observations"]["pretoken"]["privileges"] == []
    assert synthetic_report["observations"]["input_handle"]["value"] is None
    assert synthetic_report["observations"]["child"]["queries"][1]["validation"] == "invalid"
    assert synthetic_report["observations"]["child"]["queries"][1]["value"] is None
    native = _WindowsNative()
    identity_name = "cs-lowbox-experiment-" + uuid.uuid4().hex
    sid, sid_string = native.derive_sid(identity_name)
    identity = SimpleNamespace(identity_name=identity_name, sid_string=sid_string)
    evidence = {
        "schema": "windows-lowbox-launch-experiment-v2",
        "source_commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "windows_version": list(sys.getwindowsversion()[:3]),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "mission_acceptance": "BLOCKED",
        "backend_enabled_by_slice": False,
        "artifact_inspection_scope": "exact SID registry mapping/storage and known package paths only; not machine-wide auditing",
        "acl_changes": False,
        "serialization_self_test": synthetic_report,
    }
    try:
        # No ACL edits, no inherited handles, no profile creation. Existing private
        # build-directory traversal may itself block the documented launch route.
        try:
            evidence["profile_before"] = _profile_snapshot(helpers, identity)
            assert not _has_profile(evidence["profile_before"]), "unexpected preexisting profile"
            result = subprocess.run(
                [str(exe), sid_string, str(tmp_path)], stdin=subprocess.DEVNULL,
                capture_output=True, text=True, encoding="utf-8", errors="strict",
                timeout=20, shell=False, check=False, close_fds=True,
            )
            assert result.returncode == 0, "native diagnostic harness failed"
            report = json.loads(result.stdout)
            _validate_report(report)
            evidence["native"] = report
        finally:
            evidence["profile_after"] = _profile_snapshot(helpers, identity)
            evidence["unexpected_profile_artifacts"] = _has_profile(evidence["profile_after"])
            evidence["classification"] = (evidence["native"]["classification"]
                if "native" in evidence and not evidence["unexpected_profile_artifacts"] else "inconclusive")
        assert not evidence["unexpected_profile_artifacts"], "unexpected profile/storage artifacts; preserved, never deleted"
    finally:
        native.free_sid(sid)
        record_property("lowbox_experiment", json.dumps(evidence, sort_keys=True))
        if os.environ.get("GITHUB_ACTIONS") == "true":
            (ROOT / "native-lowbox-launch.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def _sample_query(name, value=None, *, error=None, buffer_size=4, returned_length=4):
    return dict(name=name, **{"class": TOKEN_CLASSES[name]}, buffer_size=buffer_size,
                returned_length=returned_length, win32_error=error, ntstatus=None,
                success=error is None, validation="valid" if error is None else None,
                value=value if error is None else None)


def _sample_report(**changes):
    report = dict(classification="blocked", stage="child-token", ntstatus="0x00000000",
                  win32_error=1349, cleanup_error=0, child_token_verified=False,
                  resumed=False, child_exit_code=None,
                  observations={
                      "pretoken": dict(token_type=1, integrity_rid=8192, privileges=[], queries=[
                          _sample_query("TokenIsAppContainer", False),
                          _sample_query("TokenIsLessPrivilegedAppContainer", error=87),
                          _sample_query("TokenType", 1),
                          _sample_query("TokenIntegrityLevel", 8192, buffer_size=32, returned_length=32),
                          _sample_query("TokenPrivileges", []),
                      ]),
                      "lowbox": {"queries": []}, "child": {"queries": []},
                      "thread_token": dict(state="absent", win32_error=1008, queries=[]),
                      "input_handle": dict(**{"class": "ObjectBasicInformation"}, info_class=0,
                          buffer_size=56, returned_length=56, win32_error=None,
                          ntstatus="0x00000000", success=True, validation="valid", value=8),
                  })
    report.update(changes)
    if report["child_token_verified"]:
        report["observations"]["child"]["queries"] = [
            _sample_query("TokenIsAppContainer", True),
            _sample_query("TokenIsLessPrivilegedAppContainer", True),
            _sample_query("TokenIntegrityLevel", 4096, buffer_size=32, returned_length=32),
            _sample_query("TokenCapabilities", []),
            _sample_query("TokenAppContainerSid", "S-1-15-2-1234", buffer_size=32, returned_length=32),
        ]
    return report


def test_lowbox_evidence_accepts_blocked_without_claiming_launch():
    _validate_report(_sample_report())


@pytest.mark.parametrize("changes", [
    {"resumed": True}, {"classification": "supported"},
    {"ntstatus": "success"}, {"win32_error": -1}, {"cleanup_error": True},
    {"classification": "accepted"},
    {"classification": "supported", "child_token_verified": True, "resumed": True,
     "win32_error": 0, "child_exit_code": 0, "ntstatus": "0xC0000022"},
    {"classification": "supported", "child_token_verified": True, "resumed": True,
     "win32_error": 0, "child_exit_code": 0, "cleanup_error": 5},
])
def test_lowbox_evidence_rejects_unsafe_or_ambiguous_success(changes):
    with pytest.raises(AssertionError):
        _validate_report(_sample_report(**changes))


def test_lowbox_supported_requires_verified_child_and_clean_exit():
    _validate_report(_sample_report(classification="supported", child_token_verified=True,
                                   resumed=True, win32_error=0, child_exit_code=0))


def test_lowbox_mixed_query_evidence_round_trips_without_masking_success():
    report = json.loads(json.dumps(_sample_report()))
    _validate_report(report)
    pretoken = report["observations"]["pretoken"]
    assert _query_value(pretoken, "TokenIsAppContainer") is False
    assert _query_value(pretoken, "TokenIsLessPrivilegedAppContainer") is None
    assert pretoken["integrity_rid"] == 8192 and pretoken["token_type"] == 1
    assert pretoken["privileges"] == []
    assert report["observations"]["input_handle"]["value"] == 8
    assert not report["child_token_verified"] and not report["resumed"]


@pytest.mark.parametrize("field,value", [
    ("value", True), ("win32_error", None), ("ntstatus", "0xC0000022"),
    ("class", 8), ("buffer_size", -1), ("returned_length", True),
])
def test_lowbox_rejects_malformed_failed_query_evidence(field, value):
    report = _sample_report()
    report["observations"]["pretoken"]["queries"][1][field] = value
    with pytest.raises(AssertionError):
        _validate_report(report)


@pytest.mark.parametrize("index", range(5))
def test_lowbox_rejects_verified_child_with_missing_required_observation(index):
    report = _sample_report(child_token_verified=True)
    report["observations"]["child"]["queries"].pop(index)
    with pytest.raises(AssertionError):
        _validate_report(report)


def test_lowbox_invalid_success_cannot_supply_caller_fact():
    report = _sample_report()
    report["observations"]["pretoken"]["queries"][3]["validation"] = "invalid"
    with pytest.raises(AssertionError):
        _validate_report(report)
    report["observations"]["pretoken"]["queries"][3]["value"] = None
    report["observations"]["pretoken"]["integrity_rid"] = None
    _validate_report(report)


def test_lowbox_failed_native_handle_query_never_claims_granted_access():
    report = _sample_report()
    handle = report["observations"]["input_handle"]
    handle.update(success=False, ntstatus="0xC0000022", validation="not_applicable")
    with pytest.raises(AssertionError):
        _validate_report(report)
    handle["value"] = None
    _validate_report(report)


def test_lowbox_successful_valid_query_requires_value():
    report = _sample_report()
    report["observations"]["pretoken"]["queries"][0]["value"] = None
    with pytest.raises(AssertionError):
        _validate_report(report)


def test_lowbox_native_object_length_overreport_is_rejected():
    report = _sample_report()
    report["observations"]["input_handle"]["returned_length"] = 57
    with pytest.raises(AssertionError):
        _validate_report(report)


def test_lowbox_workflow_is_diagnostic_and_never_soft_fails():
    source = (ROOT / ".github/workflows/windows-lowbox-experiment.yml").read_text()
    assert "continue-on-error" not in source
    assert "ref: ${{ github.sha }}" in source
    assert "test_native_profile_free_lowbox_launch" in source
    assert "if-no-files-found: error" in source
    assert 'report["source_commit"] == os.environ["GITHUB_SHA"]' in source
    assert 'report["mission_acceptance"] == "BLOCKED"' in source
    assert '"skipped"' in source


def test_lowbox_observation_does_not_expand_input_authority():
    source = (ROOT / "tests/native/lowbox_launch_probe.c").read_text()
    assert source.count("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &base_token)") == 1
    assert source.count("nt_create_lowbox(&lowbox_token,") == 1
    for forbidden in (
        "AdjustTokenPrivileges(", "AdjustTokenGroups(", "SetTokenInformation(",
        "CreateAppContainerProfile(", "DeleteAppContainerProfile(",
        "SetNamedSecurityInfo", "SetSecurityInfo(", "SetThreadToken(",
    ):
        assert forbidden not in source
    assert "NtQueryObject" in source
    assert "GrantedAccess" in source
    assert "OpenThreadToken(GetCurrentThread(), TOKEN_QUERY," in source
