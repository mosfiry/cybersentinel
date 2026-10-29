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
    control_start = native_probe.index("static BOOL run_lp_environment_control")
    control_end = native_probe.index("static void report_environment_control", control_start)
    control_source = native_probe[control_start:control_end]
    assert "CreateProcessW(image, control_command" in control_source
    assert "GetEnvironmentStringsW" in control_source and "FreeEnvironmentStringsW" in control_source
    assert "environment_to_use" in control_source
    assert "if (main_environment_block)" in control_source
    assert "control_environment_block_is_filtered" in control_source
    assert "UpdateProcThreadAttribute" in control_source and "PROC_THREAD_ATTRIBUTE_JOB_LIST" in control_source
    assert "AssignProcessToJobObject" not in control_source and "IsProcessInJob" in control_source
    assert "verify_token" in control_source and "TerminateProcess" in control_source
    assert "TerminateJobObject" in control_source
    assert "cleanup_confirmed" in control_source
    assert "return result->cleanup_confirmed;" in control_source
    assert "if (!result->cleanup_confirmed)" in control_source
    assert "report_control_cleanup_diagnostic(result)" in control_source
    create_failure_source = control_source[
        control_source.index("if (!create_succeeded)"):control_source.index("result->create_succeeded = TRUE")
    ]
    assert "result->job_handle_closed = close_control_job_handle" in create_failure_source
    assert "return result->cleanup_confirmed;" in create_failure_source
    assert "*job_out = *job;" in native_probe
    assert 'L"TokenIsLessPrivilegedAppContainer_query"' in native_probe
    assert "token_details.api_error" in control_source
    assert "ERROR_INVALID_TOKEN" not in native_probe
    assert "GetSidIdentifierAuthority" in native_probe
    assert "SECURITY_MANDATORY_LABEL_AUTHORITY" in native_probe
    assert "*subauthority_count != 1" in native_probe
    assert "ResumeThread" not in control_source
    assert 'L"lpac_environment_control"' in native_probe
    assert 'L"lpac_environment_snapshot_control"' in native_probe
    assert 'L"lpac_main_environment_block_control"' in native_probe
    assert 'L"lpac_main_environment_variant_control"' in native_probe
    assert 'L"lpac_merged_environment_control"' in native_probe
    assert "build_merged_environment_block(" in native_probe
    assert "CompareStringOrdinal(" in native_probe
    assert "merged_environment_builder_self_test(" in native_probe
    assert "environment_block_preserves_custom_entries(" in native_probe
    assert "merged_environment_block" in runner
    assert "build_environment_block_omitting_entry" in native_probe
    assert "_sanitize_environment_variant_controls" in runner
    variant_start = native_probe.index('if (wcscmp(argv[3], L"registered-storage") == 0')
    variant_end = native_probe.index("ZeroMemory(&job_limits", variant_start)
    variant_source = native_probe[variant_start:variant_end]
    assert 'wcscmp(argv[3], L"registered-storage") == 0' in variant_source
    assert "build_environment_block_omitting_entry(" in variant_source
    assert "variant_index + 1" in variant_source
    assert "run_lp_environment_control(" in variant_source
    assert "CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW" in variant_source
    assert "ResumeThread" not in variant_source
    assert "diagnostic_only" in native_probe and "comparison_complete" in native_probe
    assert 'L"CYBERSENTINEL_TEST_ENV_SANITIZED"' in control_source
    assert "parent_environment_filtered" in native_probe
    assert "explicit environment control cleanup unconfirmed" in native_probe
    assert "Keep process and Job handles for the caller's final retry." in native_probe
    assert "if (control_process_terminated && control_job_empty)" in native_probe
    assert 'L"diagnostic cleanup unconfirmed"' in native_probe
    assert 'L"lpac_cleanup_diagnostic:' in native_probe
    verify_start = native_probe.index("static BOOL verify_token(")
    verify_end = native_probe.index("\nstatic BOOL", verify_start + len("static BOOL verify_token("))
    verify_source = native_probe[verify_start:verify_end]
    assert "TOKEN_VERIFY_RECORD_FAIL(L\"TokenIsLessPrivilegedAppContainer_query\"" in verify_source
    assert verify_source.index("TokenIsLessPrivilegedAppContainer_query") < verify_source.index("TokenAppContainerSid")
    assert "all_checks_passed" in verify_source and "return all_checks_passed;" in verify_source
    assert "goto done" not in verify_source
    launch_start = native_probe.index("static int launch_child(")
    launch_end = native_probe.index("int wmain(", launch_start)
    launch_source = native_probe[launch_start:launch_end]
    create_pos = launch_source.index("CreateProcessW(argv[0], command")
    membership_pos = launch_source.index("IsProcessInJob(process.hProcess")
    token_pos = launch_source.index("parent_token_verified = verify_token(")
    resume_pos = launch_source.index("ResumeThread(process.hThread)")
    assert create_pos < membership_pos < token_pos < resume_pos
    assert "main_environment_to_use, argv[4]" in launch_source
    assert "main_environment_to_use = merged_env_block;" in launch_source
    assert "merged_environment_selected_for_main = TRUE;" in launch_source
    assert "report_cleanup_diagnostic(&main_cleanup)" in launch_source


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
            "is_appcontainer": True, "is_lpac": True, "low_integrity": True,
            "expected_sid_match": True, "zero_capabilities": True,
            "token_is_appcontainer_query_succeeded": True, "token_is_appcontainer_return_length": 4,
            "token_is_appcontainer_api_error": 0, "token_is_lpac_query_succeeded": True,
            "token_is_lpac_return_length": 4, "token_is_lpac_api_error": 0,
            "token_failure_stage": "complete", "token_api_error": 0, "token_return_length": 4,
            "terminated": True, "job_query_succeeded": True, "job_active_processes": 0,
            "job_total_processes": 1, "job_empty": True,
            "process_handle_closed": True, "thread_handle_closed": True, "job_handle_closed": True,
            "cleanup_confirmed": True, "cleanup_error": 0,
            "raw_windows_path": "C:\\sensitive\\private",
            "raw_environment": "ACTIONS_RUNTIME_TOKEN=sentinel-secret",
            "token_raw": "sensitive-token-data",
        },
        "explicit_environment_control": {
            "version": 1, "scope": "broker_only", "diagnostic_only": True,
            "comparison_complete": True, "lp_environment_null": False,
            "parent_environment_filtered": True, "parent_environment_entry_count": 23,
            "explicit_environment_snapshot_safe": True, "explicit_environment_entry_count": 23,
            "attempted": True, "setup_error": 0, "create_succeeded": True,
            "create_win32_error": 0, "create_ntstatus_available": False,
            "create_ntstatus_advisory": "0x00000000", "job_attribute_error": 0,
            "job_membership_verified": True, "job_membership_error": 0,
            "token_verified": False, "token_verification_error": 87,
            "is_appcontainer": True, "is_lpac": False, "low_integrity": False,
            "expected_sid_match": False, "zero_capabilities": False,
            "token_is_appcontainer_query_succeeded": True, "token_is_appcontainer_return_length": 4,
            "token_is_appcontainer_api_error": 0, "token_is_lpac_query_succeeded": False,
            "token_is_lpac_return_length": 0, "token_is_lpac_api_error": 87,
            "token_failure_stage": "TokenIsLessPrivilegedAppContainer_query",
            "token_api_error": 87, "token_return_length": 0,
            "terminated": True, "job_active_processes": 0, "job_total_processes": 1,
            "job_empty": True, "cleanup_confirmed": True, "cleanup_error": 0,
            "raw_environment": "ACTION_TOKEN=sentinel-secret", "raw_variable_names": ["SECRET_KEY"],
        },
        "main_environment_block_control": {
            "version": 1, "scope": "broker_only", "diagnostic_only": True,
            "comparison_complete": True, "lp_environment_null": True,
            "parent_environment_filtered": True, "parent_environment_entry_count": 29,
            "main_environment_block": True, "main_environment_block_safe": True,
            "main_environment_entry_count": 6, "attempted": True, "setup_error": 0,
            "create_succeeded": False, "create_win32_error": 203,
            "job_membership_verified": False, "terminated": False, "job_empty": False,
            "cleanup_confirmed": True, "private_value": "must be dropped",
            "raw_environment": "private-value", "raw_variable_names": ["PRIVATE_NAME"],
        },
        "merged_environment_control": {
            "version": 1, "scope": "broker_only", "diagnostic_only": True,
            "comparison_complete": True, "lp_environment_null": False,
            "parent_environment_filtered": True, "main_environment_block": True,
            "main_environment_block_safe": True, "merged_environment_block": True,
            "merged_environment_builder_selftest_passed": True,
            "merged_custom_entries_verified": True, "merged_environment_selected_for_main": True,
            "merged_environment_entry_count": 29, "main_environment_entry_count": 29,
            "attempted": True, "setup_error": 0, "create_succeeded": True,
            "create_win32_error": 0, "terminated": True, "job_empty": True,
            "cleanup_confirmed": True, "cleanup_error": 0,
            "raw_environment": "private-value", "raw_variable_names": ["PRIVATE_NAME"],
        },
        "main_environment_variant_controls": [
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "comparison_complete": True, "lp_environment_null": False,
                "main_environment_block": True, "main_environment_block_safe": True,
                "main_environment_variant": True, "main_environment_variant_id": 1,
                "main_environment_entry_count": 5, "attempted": True, "setup_error": 0,
                "create_succeeded": False, "create_win32_error": 203,
                "cleanup_confirmed": True, "cleanup_error": 0,
                "raw_environment": "private-value", "raw_variable_names": ["SECRET_KEY"],
            },
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "comparison_complete": True, "lp_environment_null": False,
                "main_environment_block": True, "main_environment_block_safe": True,
                "main_environment_variant": True, "main_environment_variant_id": 2,
                "main_environment_entry_count": 5, "attempted": True, "setup_error": 0,
                "create_succeeded": True, "create_win32_error": 0,
                "terminated": True, "job_empty": True, "cleanup_confirmed": True,
                "cleanup_error": 0, "private_field": "must be dropped",
            },
        ],
        "token_diagnostic": {
            "version": 1, "scope": "broker_only", "token_verified": False,
            "is_appcontainer": True, "is_lpac": False, "low_integrity": False,
            "expected_sid_match": False, "zero_capabilities": False,
            "token_is_appcontainer_query_succeeded": True, "token_is_appcontainer_return_length": 4,
            "token_is_appcontainer_api_error": 0, "token_is_lpac_query_succeeded": False,
            "token_is_lpac_return_length": 0, "token_is_lpac_api_error": 87,
            "token_failure_stage": "TokenIsLessPrivilegedAppContainer_query",
            "token_api_error": 87, "token_return_length": 0, "raw_sid": "private-sid",
        },
        "cleanup_diagnostics": [
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "attempted": True, "process_created": True, "resume_attempted": False,
                "resume_succeeded": False, "termination_requested": True,
                "process_signaled": True, "job_membership_verified": True,
                "job_query_succeeded": True, "job_active_processes": 0, "job_total_processes": 1,
                "job_empty": True, "process_handle_closed": True, "thread_handle_closed": True,
                "job_handle_closed": True, "cleanup_error": 0, "cleanup_confirmed": True,
                "raw_path": "C:\\sensitive\\private", "raw_sid": "private-sid",
            },
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "attempted": True, "process_created": True, "resume_attempted": False,
                "resume_succeeded": False, "termination_requested": True,
                "process_signaled": True, "job_membership_verified": True,
                "job_query_succeeded": True, "job_active_processes": 1, "job_total_processes": 1,
                "job_empty": False, "process_handle_closed": True, "thread_handle_closed": True,
                "job_handle_closed": True, "cleanup_error": 0, "cleanup_confirmed": True,
            },
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "attempted": True, "process_created": False, "resume_attempted": False,
                "resume_succeeded": False, "termination_requested": False,
                "process_signaled": False, "job_membership_verified": False,
                "job_query_succeeded": False, "job_active_processes": 0, "job_total_processes": 0,
                "job_empty": True, "process_handle_closed": True, "thread_handle_closed": True,
                "job_handle_closed": True, "cleanup_error": 0, "cleanup_confirmed": True,
            },
            {
                "version": 1, "scope": "broker_only", "diagnostic_only": True,
                "attempted": True, "process_created": True, "resume_attempted": True,
                "resume_succeeded": True, "termination_requested": True,
                "process_signaled": True, "job_membership_verified": True,
                "job_query_succeeded": True, "job_active_processes": 0, "job_total_processes": 1,
                "job_empty": True, "process_handle_closed": True, "thread_handle_closed": True,
                "job_handle_closed": True, "cleanup_error": 0, "cleanup_confirmed": True,
            },
        ],
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
    assert all(item["launcher_failures"][0]["explicit_environment_control"]["lp_environment_null"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["explicit_environment_control"]["comparison_complete"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["explicit_environment_control"]["explicit_environment_entry_count"] == 23 for item in attestations)
    assert all(item["launcher_failures"][0]["main_environment_block_control"]["main_environment_block"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["main_environment_block_control"]["main_environment_block_safe"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["main_environment_block_control"]["main_environment_entry_count"] == 6 for item in attestations)
    assert all(item["launcher_failures"][0]["main_environment_block_control"]["create_win32_error"] == 203 for item in attestations)
    assert all(item["launcher_failures"][0]["main_environment_block_control"]["comparison_complete"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["merged_environment_block"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["merged_environment_builder_selftest_passed"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["merged_environment_entry_count"] == 29 for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["merged_custom_entries_verified"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["merged_environment_selected_for_main"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["merged_environment_control"]["comparison_complete"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["cleanup_diagnostics"][0]["cleanup_confirmed"] is True for item in attestations)
    assert all(item["launcher_failures"][0]["cleanup_diagnostics"][1]["cleanup_confirmed"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["cleanup_diagnostics"][2]["cleanup_confirmed"] is False for item in attestations)
    assert all(item["launcher_failures"][0]["cleanup_diagnostics"][3]["cleanup_confirmed"] is False for item in attestations)
    assert all("raw_path" not in json.dumps(item["launcher_failures"][0]["cleanup_diagnostics"]) for item in attestations)
    assert all([v["main_environment_variant_id"] for v in item["launcher_failures"][0]["main_environment_variant_controls"]] == [1, 2] for item in attestations)
    assert all(all(v["comparison_complete"] is False for v in item["launcher_failures"][0]["main_environment_variant_controls"]) for item in attestations)
    assert all(item["launcher_failures"][0]["token_diagnostic"]["token_failure_stage"] == "TokenIsLessPrivilegedAppContainer_query" for item in attestations)
    assert all(item["launcher_failures"][0]["token_diagnostic"]["token_api_error"] == 87 for item in attestations)
    assert all(item["environment_controls"][0]["comparison_complete"] is True for item in attestations)
    assert all(item["environment_controls"][0]["token_failure_stage"] == "complete" for item in attestations)
    incomplete = dict(launcher_failure["environment_control"], token_verified=False, comparison_complete=True)
    safe_incomplete = runner._sanitize_environment_control(incomplete)
    assert safe_incomplete is not None and safe_incomplete["comparison_complete"] is False
    forged_explicit = dict(launcher_failure["environment_control"], lp_environment_null=True)
    safe_explicit = runner._sanitize_environment_control(
        forged_explicit, allow_comparison_complete=False
    )
    assert safe_explicit is not None and safe_explicit["comparison_complete"] is False
    forged_failure = dict(launcher_failure, explicit_environment_control=forged_explicit)
    safe_failure = runner._sanitize_parent_launch_failure(forged_failure)
    assert safe_failure is not None
    assert safe_failure["explicit_environment_control"]["lp_environment_null"] is True
    assert safe_failure["explicit_environment_control"]["comparison_complete"] is False
    forged_snapshot_control = dict(
        launcher_failure["explicit_environment_control"], lp_environment_null=True, comparison_complete=True
    )
    safe_snapshot_control = runner._sanitize_environment_control(forged_snapshot_control)
    assert safe_snapshot_control is not None and safe_snapshot_control["comparison_complete"] is False
    forged_main_block = dict(launcher_failure["main_environment_block_control"], lp_environment_null=True, comparison_complete=True)
    safe_main_block = runner._sanitize_environment_control(forged_main_block)
    assert safe_main_block is not None and safe_main_block["comparison_complete"] is False
    forged_merged = dict(
        launcher_failure["merged_environment_control"], lp_environment_null=True,
        main_environment_block=False, comparison_complete=True,
    )
    safe_merged = runner._sanitize_environment_control(forged_merged)
    assert safe_merged is not None and safe_merged["comparison_complete"] is False
    lpac_query_failed = dict(
        launcher_failure["environment_control"],
        token_is_lpac_query_succeeded=False,
        token_is_lpac_return_length=0,
        token_is_lpac_api_error=87,
        token_failure_stage="TokenIsLessPrivilegedAppContainer_query",
        token_api_error=87,
        token_verification_error=87,
        comparison_complete=True,
    )
    safe_lpac_failure = runner._sanitize_environment_control(lpac_query_failed)
    assert safe_lpac_failure is not None
    assert safe_lpac_failure["comparison_complete"] is False
    assert safe_lpac_failure["token_failure_stage"] == "TokenIsLessPrivilegedAppContainer_query"
    assert safe_lpac_failure["token_api_error"] == 87
    assert safe_lpac_failure["token_is_lpac_return_length"] == 0
    unknown_stage = dict(launcher_failure["environment_control"], token_failure_stage="C:\\private\\token")
    safe_unknown_stage = runner._sanitize_environment_control(unknown_stage)
    assert safe_unknown_stage is not None and "token_failure_stage" not in safe_unknown_stage
    assert safe_unknown_stage["comparison_complete"] is False
    duplicate_variants = dict(
        launcher_failure,
        main_environment_variant_controls=[
            dict(launcher_failure["main_environment_variant_controls"][0]),
            dict(launcher_failure["main_environment_variant_controls"][0]),
            dict(launcher_failure["main_environment_variant_controls"][0], main_environment_variant_id=99),
        ],
    )
    safe_duplicate_variants = runner._sanitize_parent_launch_failure(duplicate_variants)
    assert safe_duplicate_variants is not None
    assert [v["main_environment_variant_id"] for v in safe_duplicate_variants["main_environment_variant_controls"]] == [1]
    serialized = json.dumps(counts)
    assert "raw_windows_path" not in serialized
    assert "broker_pid" not in serialized
    assert "sensitive" not in serialized
    assert "C:\\\\sensitive" not in serialized
    assert "raw_environment" not in serialized and "sentinel-secret" not in serialized
    assert "private-value" not in serialized and "PRIVATE_NAME" not in serialized
    assert "merged_environment_control" in serialized
    assert "must be dropped" not in serialized
    assert "SECRET_KEY" not in serialized
    assert "token_raw" not in serialized and "sensitive-token-data" not in serialized
    assert "raw_sid" not in serialized and "private-sid" not in serialized


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
