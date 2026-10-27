from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/windows-registered-lpac-storage.yml"


def test_registered_profile_gate_is_exact_branch_native_and_no_soft_failures():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "branches: [experiment/d2-registered-lpac-proof-20261027]" in source
    assert "github.repository == 'mosfiry/cybersentinel'" in source
    assert "github.ref == 'refs/heads/experiment/d2-registered-lpac-proof-20261027'" in source
    assert "runs-on: windows-latest" in source
    assert "timeout-minutes: 30" in source
    assert "ref: ${{ github.sha }}" in source
    assert "persist-credentials: false" in source
    assert "permissions:\n  contents: read" in source
    assert "continue-on-error" not in source
    assert "Run registered-LPAC storage boundary gate" in source
    assert "scripts/run_windows_registered_lpac_gate.py" in source
    assert "tests/test_windows_appcontainer_workspace_native.py" in source
    assert "workspace/windows_appcontainer_workspace.py" in source
    assert "workspace/windows_vhd_workspace.py" in source
    assert "if: always()" in source
    assert "if-no-files-found: error" in source
    assert "${{ runner.temp }}/registered-lpac-storage-gate.json" in source
    assert "${{ runner.temp }}/registered-lpac-validation.json" in source
    assert ".xml" not in source and ".log" not in source and ".pml" not in source


def test_exact_native_case_cannot_be_skipped_and_mission_stays_blocked():
    test_source = (ROOT / "tests/test_windows_registered_lpac_prototype.py").read_text(encoding="utf-8")
    assert "test_native_lpac_registered_profile_storage_boundary" in test_source
    assert "_WINDOWS_NATIVE = pytest.mark.skipif" in test_source
    runner = (ROOT / "scripts/run_windows_registered_lpac_gate.py").read_text(encoding="utf-8")
    assert 'NATIVE_CASE = "test_native_lpac_registered_profile_storage_boundary"' in runner
    assert "EXPECTED_NATIVE_CASES = [*LEGACY_NATIVE_CASES, NATIVE_CASE]" in runner
    assert '"tests/test_windows_appcontainer_workspace_native.py"' in runner
    for name in (
        "test_native_lpac_identity_and_workspace_read_write",
        "test_native_lpac_denies_outside_write_and_create",
        "test_native_lpac_denies_other_run_workspace",
        "test_native_lpac_exit_cleanup_revokes_workspace",
    ):
        assert f'"{name}"' in runner
    assert 'native_names == expected_native' in runner
    assert 'counts["skipped_count"] == 0' in runner
    assert 'legacy_parent_attestation_coverage' in runner
    assert 'parent_launch_failure_diagnostic' in runner
    assert 'parent_launch_return_code' in runner
    assert '"mission_acceptance": "BLOCKED"' in runner
    assert '"backend_enabled_by_slice": False' in runner
    assert '"network_denial"' in runner
    assert '"crash_and_host_reboot_recovery"' in runner
    assert "cleanup_proven" in runner
    assert 'evidence.get("profile_cleanup_confirmed_count") == len(profile_ids)' in runner
    assert '"registered_registry_write_verified"' in test_source
    assert '"registered_registry_value_absent_before"' in test_source
    assert '"registered_registry_value_set"' in test_source
    assert '"temp_api_points_to_workspace"' in test_source
    assert '"post_exit_job_attestation"' in test_source
    assert '"launcher_failure_diagnostic"' in test_source
    legacy_source = (ROOT / "tests/test_windows_appcontainer_workspace_native.py").read_text(encoding="utf-8")
    assert "_launch_failure_diagnostic(stderr)" in legacy_source
    assert 'record_property("parent_launch_failure_diagnostic"' in legacy_source
    assert "GetFinalPathNameByHandleW" in test_source
    native_probe = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    assert "existing_file ? OPEN_EXISTING : CREATE_NEW" in native_probe
    assert native_probe.index("if (!temp_path_check.ok)") < native_probe.index("temp_write = attempt_write(")


def test_junit_sanitizer_keeps_only_case_results_and_allowlisted_attestations(tmp_path: Path):
    spec = importlib.util.spec_from_file_location(
        "registered_lpac_gate_runner", ROOT / "scripts/run_windows_registered_lpac_gate.py"
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    root = ET.Element("testsuite")
    pre = {
        "version": 1, "token_verified": True, "is_appcontainer": True, "is_lpac": True,
        "low_integrity": True, "expected_sid_match": True, "zero_capabilities": True,
        "job_membership_verified": True, "raw_windows_path": "C:\\sensitive\\private",
    }
    post = {
        "version": 1, "active_processes": 0, "total_processes": 1,
        "raw_windows_path": "C:\\sensitive\\private",
    }
    launcher_failure = {
        "failure_step": "CreateProcessW LPAC", "failure_win32_error": 17,
        "create_process": {
            "version": 2, "scope": "broker_only", "win32_error": 17,
            "image_is_file": True, "broker_pid": 1234,
            "raw_windows_path": "C:\\sensitive\\private",
        },
    }
    for name in runner.LEGACY_NATIVE_CASES:
        case = ET.SubElement(root, "testcase", name=name)
        properties = ET.SubElement(case, "properties")
        ET.SubElement(properties, "property", name="parent_pre_resume_attestation", value=json.dumps(pre))
        ET.SubElement(properties, "property", name="parent_post_exit_job_attestation", value=json.dumps(post))
        ET.SubElement(properties, "property", name="parent_launch_return_code", value="20")
        ET.SubElement(properties, "property", name="parent_launch_failure_diagnostic", value=json.dumps(launcher_failure))
    ET.SubElement(root, "testcase", name=runner.NATIVE_CASE)
    junit = tmp_path / "private-junit.xml"
    ET.ElementTree(root).write(junit, encoding="utf-8", xml_declaration=True)

    counts = runner._junit_counts(junit)
    assert counts["native_case_names"] == runner.EXPECTED_NATIVE_CASES
    assert counts["native_nonpassing_count"] == 0
    attestations = counts["legacy_parent_attestations"]
    assert len(attestations) == 4
    assert all(item["pre_resume"] and item["post_exit_job"] for item in attestations)
    assert all(item["launcher_return_codes"] == [20] for item in attestations)
    assert all(item["launcher_failures"][0]["failure_win32_error"] == 17 for item in attestations)
    assert all(item["launcher_failures"][0]["create_process"]["image_is_file"] is True for item in attestations)
    serialized = json.dumps(counts)
    assert "raw_windows_path" not in serialized
    assert "broker_pid" not in serialized
    assert "sensitive" not in serialized
    assert "C:\\\\sensitive" not in serialized
