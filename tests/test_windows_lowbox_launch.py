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
    native = _WindowsNative()
    identity_name = "cs-lowbox-experiment-" + uuid.uuid4().hex
    sid, sid_string = native.derive_sid(identity_name)
    identity = SimpleNamespace(identity_name=identity_name, sid_string=sid_string)
    evidence = {
        "schema": "windows-lowbox-launch-experiment-v1",
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


def _sample_report(**changes):
    report = dict(classification="blocked", stage="child-token", ntstatus="0x00000000",
                  win32_error=1349, cleanup_error=0, child_token_verified=False,
                  resumed=False, child_exit_code=None)
    report.update(changes)
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


def test_lowbox_workflow_is_diagnostic_and_never_soft_fails():
    source = (ROOT / ".github/workflows/windows-lowbox-experiment.yml").read_text()
    assert "continue-on-error" not in source
    assert "ref: ${{ github.sha }}" in source
    assert "test_native_profile_free_lowbox_launch" in source
    assert "if-no-files-found: error" in source
    assert 'report["source_commit"] == os.environ["GITHUB_SHA"]' in source
    assert 'report["mission_acceptance"] == "BLOCKED"' in source
    assert '"skipped"' in source
