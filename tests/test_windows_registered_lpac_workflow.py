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
    assert 'env=_safe_test_environment(dict(os.environ))' in runner
    assert '_sanitize_environment_control' in runner
    assert 'parent_environment_control' in runner
    assert '"diagnostic_environment_control_required_for_storage_acceptance": False' in runner
    assert 'validation["diagnostic_environment_control_status"]' in runner
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
    assert 'summary["environment_control"]' in test_source
    legacy_source = (ROOT / "tests/test_windows_appcontainer_workspace_native.py").read_text(encoding="utf-8")
    assert "_launch_failure_diagnostic(stderr)" in legacy_source
    assert 'record_property("parent_launch_failure_diagnostic"' in legacy_source
    assert 'record_property("parent_environment_control"' in legacy_source
    assert "env=_safe_native_environment(dict(os.environ))" in legacy_source
    assert "_safe_native_environment(dict(os.environ))" in test_source
    assert "GetFinalPathNameByHandleW" in test_source
    native_probe = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    assert "existing_file ? OPEN_EXISTING : CREATE_NEW" in native_probe
    assert native_probe.index("if (!temp_path_check.ok)") < native_probe.index("temp_write = attempt_write(")
    control_start = native_probe.index("static BOOL run_lp_environment_null_control")
    control_end = native_probe.index("static void report_environment_control", control_start)
    control_source = native_probe[control_start:control_end]
    assert "CreateProcessW(image, control_command" in control_source
    assert "UpdateProcThreadAttribute" in control_source and "PROC_THREAD_ATTRIBUTE_JOB_LIST" in control_source
    assert "AssignProcessToJobObject" not in control_source and "IsProcessInJob" in control_source
    assert "verify_token" in control_source and "TerminateProcess" in control_source
    assert "TerminateJobObject" in control_source
    assert "cleanup_confirmed" in control_source
    assert "ResumeThread" not in control_source
    assert 'L"lpac_environment_control:' in native_probe
    assert "diagnostic_only" in native_probe and "comparison_complete" in native_probe
    assert 'L"CYBERSENTINEL_TEST_ENV_SANITIZED"' in control_source
    assert "parent_environment_filtered" in native_probe


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
            "drive_current_directory_env_present": True,
            "image_is_file": True, "broker_pid": 1234,
            "raw_windows_path": "C:\\sensitive\\private",
        },
        "environment_control": {
            "version": 1, "scope": "broker_only", "diagnostic_only": True, "comparison_complete": True,
            "lp_environment_null": True,
            "parent_environment_filtered": True, "attempted": True, "setup_error": 0, "create_succeeded": True,
            "create_win32_error": 0, "create_ntstatus_available": False,
            "create_ntstatus_advisory": "0x00000000", "job_attribute_error": 0,
            "job_membership_verified": True, "job_membership_error": 0,
            "token_verified": True, "token_verification_error": 0,
            "terminated": True, "job_active_processes": 0, "job_total_processes": 1,
            "job_empty": True, "cleanup_confirmed": True, "cleanup_error": 0,
            "raw_windows_path": "C:\\sensitive\\private",
            "raw_environment": "ACTIONS_RUNTIME_TOKEN=sentinel-secret",
        },
    }
    for name in runner.LEGACY_NATIVE_CASES:
        case = ET.SubElement(root, "testcase", name=name)
        properties = ET.SubElement(case, "properties")
        ET.SubElement(properties, "property", name="parent_pre_resume_attestation", value=json.dumps(pre))
        ET.SubElement(properties, "property", name="parent_post_exit_job_attestation", value=json.dumps(post))
        ET.SubElement(properties, "property", name="parent_launch_return_code", value="20")
        ET.SubElement(properties, "property", name="parent_launch_failure_diagnostic", value=json.dumps(launcher_failure))
        ET.SubElement(properties, "property", name="parent_environment_control", value=json.dumps(launcher_failure["environment_control"]))
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
    assert all(item["launcher_failures"][0]["create_process"]["drive_current_directory_env_present"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["environment_control"]["create_succeeded"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["environment_control"]["cleanup_confirmed"] is True for item in attestations)
    assert all(item["environment_controls"][0]["comparison_complete"] is True for item in attestations)
    incomplete = dict(launcher_failure["environment_control"], token_verified=False, comparison_complete=True)
    safe_incomplete = runner._sanitize_environment_control(incomplete)
    assert safe_incomplete is not None and safe_incomplete["comparison_complete"] is False
    serialized = json.dumps(counts)
    assert "raw_windows_path" not in serialized
    assert "broker_pid" not in serialized
    assert "sensitive" not in serialized
    assert "C:\\\\sensitive" not in serialized
    assert "raw_environment" not in serialized and "sentinel-secret" not in serialized


def test_pytest_child_environment_uses_explicit_allowlist():
    spec = importlib.util.spec_from_file_location(
        "registered_lpac_gate_environment", ROOT / "scripts/run_windows_registered_lpac_gate.py"
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    safe = runner._safe_test_environment({
        "PATH": r"C:\\Windows\\System32", "TEMP": r"C:\\Temp",
        "COMSPEC": r"C:\\Windows\\System32\\cmd.exe", "SystemRoot": r"C:\\Windows",
        "ProgramFiles(x86)": r"C:\\Program Files (x86)",
        "GITHUB_SHA": "exact-sha", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
        "RUNNER_TEMP": r"C:\\runner-temp", "ImageOS": "windows-2025", "ImageVersion": "20261001.1",
        "ACTIONS_RUNTIME_TOKEN": "runtime-secret", "GITHUB_TOKEN": "github-secret",
        "GITHUB_REPOSITORY": "owner/repo", "DEPLOY_PASSWORD": "password-secret",
        "SENTRY_DSN": "https://sentinel.invalid/secret", "DATABASE_URL": "postgres://secret@db.invalid/x",
        "DOCKER_CONFIG": r"C:\\Users\\runner\\.docker", "PIP_INDEX_URL": "https://user:secret@pypi.invalid/simple",
    })
    assert safe["PATH"] == r"C:\\Windows\\System32"
    assert safe["TEMP"] == r"C:\\Temp"
    assert safe["SystemRoot"] == r"C:\\Windows"
    assert safe["ProgramFiles(x86)"] == r"C:\\Program Files (x86)"
    assert safe["GITHUB_SHA"] == "exact-sha" and safe["GITHUB_RUN_ID"] == "123"
    assert safe["GITHUB_RUN_ATTEMPT"] == "2" and safe["RUNNER_TEMP"] == r"C:\\runner-temp"
    assert safe["ImageOS"] == "windows-2025" and safe["ImageVersion"] == "20261001.1"
    assert "ACTIONS_RUNTIME_TOKEN" not in safe and "GITHUB_TOKEN" not in safe
    assert "GITHUB_REPOSITORY" not in safe and "DEPLOY_PASSWORD" not in safe
    assert "SENTRY_DSN" not in safe and "DATABASE_URL" not in safe
    assert "DOCKER_CONFIG" not in safe and "PIP_INDEX_URL" not in safe
    assert set(safe) == {
        "PATH", "TEMP", "COMSPEC", "SystemRoot", "ProgramFiles(x86)",
        "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_TEMP", "ImageOS", "ImageVersion",
    }


def test_native_environment_block_uses_sorted_case_insensitive_order():
    native_probe = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    start = native_probe.index("#define APPEND_ENV")
    end = native_probe.index("#undef APPEND_ENV", start)
    block = native_probe[start:end]
    ordered_entries = [
        "APPEND_ENV(drive_env);",
        "APPEND_ENV(path_env);",
        "APPEND_ENV(system_root_env);",
        "APPEND_ENV(temp_env);",
        "APPEND_ENV(tmp_env);",
        "APPEND_ENV(windir_env);",
    ]
    positions = [block.index(entry) for entry in ordered_entries]
    assert positions == sorted(positions)
    assert "CREATE_UNICODE_ENVIRONMENT" in native_probe
    assert 'L"=%c:=%ls"' in block
    assert "drive_current_directory_env_present" in native_probe
