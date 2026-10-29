"""Run the experimental registered-LPAC storage gate without publishing raw logs."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFE_TEST_ENV_KEYS = frozenset({
    "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE",
    "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "ALLUSERSPROFILE", "PUBLIC",
    "OS", "USERNAME", "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
    "NUMBER_OF_PROCESSORS", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
    "RUNNER_TEMP", "IMAGEOS", "IMAGEVERSION",
})
SENSITIVE_ENV_MARKERS = (
    "TOKEN", "SECRET", "PASS", "CREDENTIAL", "KEY", "AUTH", "COOKIE", "CERT",
)
NATIVE_CASE = "test_native_lpac_registered_profile_storage_boundary"
LEGACY_NATIVE_CASES = [
    "test_native_lpac_identity_and_workspace_read_write",
    "test_native_lpac_denies_outside_write_and_create",
    "test_native_lpac_denies_other_run_workspace",
    "test_native_lpac_exit_cleanup_revokes_workspace",
]
EXPECTED_NATIVE_CASES = [*LEGACY_NATIVE_CASES, NATIVE_CASE]
TOKEN_FAILURE_STAGES = frozenset({
    "not_run", "invalid_token_or_expected_sid", "OpenProcessToken",
    "close suspended LPAC token handle",
    "TokenIsAppContainer_query", "TokenIsAppContainer_return_length", "TokenIsAppContainer_false",
    "TokenIsLessPrivilegedAppContainer_query", "TokenIsLessPrivilegedAppContainer_return_length",
    "TokenIsLessPrivilegedAppContainer_false", "TokenAppContainerSid_size_query", "TokenAppContainerSid_size",
    "TokenAppContainerSid_allocate", "TokenAppContainerSid_query", "TokenAppContainerSid_return_length",
    "expected_sid_mismatch", "TokenIntegrityLevel_size_query", "TokenIntegrityLevel_size",
    "TokenIntegrityLevel_allocate", "TokenIntegrityLevel_query", "TokenIntegrityLevel_return_length",
    "TokenIntegrityLevel_sid_invalid", "TokenIntegrityLevel_authority_invalid", "integrity_not_low",
    "TokenCapabilities_size_query",
    "TokenCapabilities_size", "TokenCapabilities_allocate", "TokenCapabilities_query",
    "TokenCapabilities_return_length", "capabilities_nonzero", "complete",
})
LEGACY_LAUNCH_FAILURE_STEPS = {
    "parse child SID", "open child token", "child LPAC token verification", "write bounded evidence report",
    "parse launcher SID", "allocate process attribute list", "set LPAC process attributes",
    "build child command line", "build restricted child environment", "child environment too large",
    "create bounded child job", "set LPAC child job attribute", "CreateProcessW LPAC",
    "environment control cleanup unconfirmed", "explicit environment control cleanup unconfirmed",
    "main environment block control cleanup unconfirmed", "build main environment variant",
    "main environment variant control cleanup unconfirmed", "merged environment control cleanup unconfirmed",
    "validate merged environment block",
    "verify suspended LPAC child job membership", "suspended LPAC child token verification",
    "main LPAC process cleanup unconfirmed",
    "resume LPAC child", "bounded LPAC child wait", "read child exit code",
    "query completed LPAC job accounting", "LPAC job did not become empty",
}
LAUNCH_DIAGNOSTIC_BOOL_FIELDS = (
    "image_is_absolute", "image_is_file", "parent_can_read_image", "image_size_available",
    "cwd_is_absolute", "cwd_is_directory", "module_matches_image", "ntstatus_available",
    "drive_current_directory_env_present",
)
LAUNCH_DIAGNOSTIC_INT_FIELDS = (
    "win32_error", "image_attributes_error", "image_open_error", "image_size_bytes",
    "image_size_error", "cwd_attributes_error", "known_dependency_mask",
    "known_dependency_expected_mask", "system_directory_error", "broker_bitness", "launch_flags",
)
ENVIRONMENT_CONTROL_BOOL_FIELDS = (
    "diagnostic_only", "comparison_complete", "lp_environment_null", "parent_environment_filtered",
    "explicit_environment_snapshot_safe", "main_environment_block", "main_environment_block_safe",
    "main_environment_variant", "merged_environment_block",
    "merged_environment_builder_selftest_passed", "merged_custom_entries_verified",
    "merged_environment_selected_for_main", "process_handle_closed", "thread_handle_closed",
    "job_handle_closed", "job_query_succeeded", "attempted", "create_succeeded", "create_ntstatus_available",
    "job_membership_verified", "token_verified", "is_appcontainer", "is_lpac", "low_integrity",
    "expected_sid_match", "zero_capabilities", "token_is_appcontainer_query_succeeded",
    "token_is_lpac_query_succeeded", "terminated", "job_empty", "cleanup_confirmed",
)
ENVIRONMENT_CONTROL_INT_FIELDS = (
    "parent_environment_entry_count", "explicit_environment_entry_count", "main_environment_entry_count",
    "main_environment_variant_id", "merged_environment_entry_count",
    "setup_error", "create_win32_error", "job_attribute_error", "job_membership_error",
    "token_verification_error", "token_is_appcontainer_return_length", "token_is_appcontainer_api_error",
    "token_is_lpac_return_length", "token_is_lpac_api_error", "token_api_error", "token_return_length",
    "job_active_processes", "job_total_processes", "cleanup_error",
)
TOKEN_DIAGNOSTIC_BOOL_FIELDS = (
    "token_verified", "is_appcontainer", "is_lpac", "low_integrity", "expected_sid_match",
    "zero_capabilities", "token_is_appcontainer_query_succeeded", "token_is_lpac_query_succeeded",
)
TOKEN_DIAGNOSTIC_INT_FIELDS = (
    "token_is_appcontainer_return_length", "token_is_appcontainer_api_error",
    "token_is_lpac_return_length", "token_is_lpac_api_error", "token_api_error", "token_return_length",
)
CLEANUP_DIAGNOSTIC_BOOL_FIELDS = (
    "diagnostic_only", "attempted", "process_created", "resume_attempted",
    "resume_succeeded", "termination_requested", "process_signaled",
    "job_membership_verified", "job_query_succeeded", "job_empty",
    "process_handle_closed", "thread_handle_closed", "job_handle_closed",
)
CLEANUP_DIAGNOSTIC_INT_FIELDS = (
    "job_active_processes", "job_total_processes", "cleanup_error",
)


def _safe_test_environment(source: dict[str, str]) -> dict[str, str]:
    """Pass only required Windows OS and run metadata into the pytest subprocess."""
    safe: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if upper not in SAFE_TEST_ENV_KEYS:
            continue
        if any(marker in upper for marker in SENSITIVE_ENV_MARKERS):
            continue
        safe[key] = value
    return safe


def _sanitize_environment_control(
    value: object, *, allow_comparison_complete: bool = True
) -> dict[str, object] | None:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("scope") != "broker_only":
        return None
    control: dict[str, object] = {"version": 1, "scope": "broker_only"}
    for field in ENVIRONMENT_CONTROL_BOOL_FIELDS:
        if field == "comparison_complete":
            continue
        if type(value.get(field)) is bool:
            control[field] = value[field]
    for field in ENVIRONMENT_CONTROL_INT_FIELDS:
        if type(value.get(field)) is int:
            control[field] = value[field]
    token_failure_stage = value.get("token_failure_stage")
    if isinstance(token_failure_stage, str) and token_failure_stage in TOKEN_FAILURE_STAGES:
        control["token_failure_stage"] = token_failure_stage
    ntstatus = value.get("create_ntstatus_advisory")
    if isinstance(ntstatus, str) and len(ntstatus) == 10 and ntstatus.startswith("0x") and all(char in "0123456789abcdefABCDEF" for char in ntstatus[2:]):
        control["create_ntstatus_advisory"] = ntstatus
    required_true = (
        "diagnostic_only", "lp_environment_null", "parent_environment_filtered", "attempted",
        "create_succeeded", "job_membership_verified", "token_verified", "is_appcontainer", "is_lpac",
        "low_integrity", "expected_sid_match", "zero_capabilities",
        "token_is_appcontainer_query_succeeded", "token_is_lpac_query_succeeded",
        "terminated", "job_query_succeeded", "job_empty", "process_handle_closed",
        "thread_handle_closed", "job_handle_closed", "cleanup_confirmed",
    )
    required_zero = (
        "setup_error", "create_win32_error", "job_attribute_error", "job_membership_error",
        "token_verification_error", "token_is_appcontainer_api_error", "token_is_lpac_api_error",
        "token_api_error", "cleanup_error", "job_active_processes",
    )
    explicit_block_mode = (
        value.get("explicit_environment_snapshot_safe") is True
        or value.get("main_environment_block") is True
        or value.get("merged_environment_block") is True
    )
    control["comparison_complete"] = allow_comparison_complete and not explicit_block_mode and (
        all(control.get(field) is True for field in required_true)
        and all(control.get(field) == 0 for field in required_zero)
        and control.get("token_failure_stage") == "complete"
        and control.get("token_is_appcontainer_return_length") == 4
        and control.get("token_is_lpac_return_length") == 4
        and control.get("job_total_processes") == 1
    )
    return control


def _sanitize_token_diagnostic(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("scope") != "broker_only":
        return None
    diagnostic: dict[str, object] = {"version": 1, "scope": "broker_only"}
    for field in TOKEN_DIAGNOSTIC_BOOL_FIELDS:
        if type(value.get(field)) is bool:
            diagnostic[field] = value[field]
    for field in TOKEN_DIAGNOSTIC_INT_FIELDS:
        if type(value.get(field)) is int:
            diagnostic[field] = value[field]
    token_failure_stage = value.get("token_failure_stage")
    if isinstance(token_failure_stage, str) and token_failure_stage in TOKEN_FAILURE_STAGES:
        diagnostic["token_failure_stage"] = token_failure_stage
    return diagnostic if len(diagnostic) > 2 else None


def _sanitize_cleanup_diagnostic(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("scope") != "broker_only":
        return None
    cleanup: dict[str, object] = {"version": 1, "scope": "broker_only"}
    for field in CLEANUP_DIAGNOSTIC_BOOL_FIELDS:
        if type(value.get(field)) is bool:
            cleanup[field] = value[field]
    for field in CLEANUP_DIAGNOSTIC_INT_FIELDS:
        number = value.get(field)
        if type(number) is int and 0 <= number <= 0xFFFFFFFF:
            cleanup[field] = number
    handles_closed = all(cleanup.get(field) is True for field in (
        "process_handle_closed", "thread_handle_closed", "job_handle_closed",
    ))
    if cleanup.get("process_created") is True:
        resume_safe = (
            cleanup.get("diagnostic_only") is True
            and cleanup.get("resume_attempted") is False
            and cleanup.get("resume_succeeded") is False
        ) or (
            cleanup.get("diagnostic_only") is False
            and (cleanup.get("resume_attempted") is False or (
                cleanup.get("resume_attempted") is True
                and cleanup.get("resume_succeeded") is True
                and cleanup.get("job_membership_verified") is True
            ))
        )
        cleanup["cleanup_confirmed"] = (
            cleanup.get("attempted") is True
            and cleanup.get("diagnostic_only") in (True, False)
            and cleanup.get("process_signaled") is True
            and cleanup.get("job_query_succeeded") is True
            and cleanup.get("job_empty") is True
            and cleanup.get("job_active_processes") == 0
            and cleanup.get("cleanup_error") == 0
            and handles_closed and resume_safe
        )
    else:
        cleanup["cleanup_confirmed"] = (
            cleanup.get("process_created") is False and handles_closed
            and cleanup.get("cleanup_error") == 0
            and (cleanup.get("attempted") is False or (
                cleanup.get("job_query_succeeded") is True
                and cleanup.get("job_empty") is True
                and cleanup.get("job_active_processes") == 0
            ))
        )
    return cleanup


def _sanitize_environment_variant_controls(value: object) -> list[dict[str, object]] | None:
    if not isinstance(value, list):
        return None
    safe: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw in value[:6]:
        control = _sanitize_environment_control(raw, allow_comparison_complete=False)
        if control is None:
            continue
        variant_id = control.get("main_environment_variant_id")
        entry_count = control.get("main_environment_entry_count")
        if (type(variant_id) is not int or not 1 <= variant_id <= 6 or variant_id in seen
                or control.get("diagnostic_only") is not True
                or control.get("lp_environment_null") is not False
                or control.get("main_environment_block") is not True
                or control.get("main_environment_block_safe") is not True
                or control.get("main_environment_variant") is not True
                or type(entry_count) is not int or not 0 <= entry_count <= 6):
            continue
        control["comparison_complete"] = False
        seen.add(variant_id)
        safe.append(control)
    safe.sort(key=lambda item: int(item["main_environment_variant_id"]))
    return safe or None


def _sanitize_parent_launch_failure(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    safe: dict[str, object] = {}
    step = value.get("failure_step")
    if isinstance(step, str) and step in LEGACY_LAUNCH_FAILURE_STEPS:
        safe["failure_step"] = step
    code = value.get("failure_win32_error")
    if type(code) is int and 0 <= code <= 0xFFFFFFFF:
        safe["failure_win32_error"] = code
    raw_diagnostic = value.get("create_process")
    if isinstance(raw_diagnostic, dict) and type(raw_diagnostic.get("version")) is int and raw_diagnostic.get("version") == 2 and raw_diagnostic.get("scope") == "broker_only":
        diagnostic: dict[str, object] = {"version": 2, "scope": "broker_only"}
        for field in LAUNCH_DIAGNOSTIC_BOOL_FIELDS:
            if type(raw_diagnostic.get(field)) is bool:
                diagnostic[field] = raw_diagnostic[field]
        for field in LAUNCH_DIAGNOSTIC_INT_FIELDS:
            if type(raw_diagnostic.get(field)) is int:
                diagnostic[field] = raw_diagnostic[field]
        ntstatus = raw_diagnostic.get("ntstatus_advisory")
        if isinstance(ntstatus, str) and len(ntstatus) == 10 and ntstatus.startswith("0x") and all(char in "0123456789abcdefABCDEF" for char in ntstatus[2:]):
            diagnostic["ntstatus_advisory"] = ntstatus
        safe["create_process"] = diagnostic
    control = _sanitize_environment_control(value.get("environment_control"))
    if control is not None:
        safe["environment_control"] = control
    explicit_environment_control = _sanitize_environment_control(
        value.get("explicit_environment_control"), allow_comparison_complete=False
    )
    if explicit_environment_control is not None:
        safe["explicit_environment_control"] = explicit_environment_control
    main_environment_block_control = _sanitize_environment_control(
        value.get("main_environment_block_control"), allow_comparison_complete=False
    )
    if main_environment_block_control is not None:
        safe["main_environment_block_control"] = main_environment_block_control
    merged_environment_control = _sanitize_environment_control(
        value.get("merged_environment_control"), allow_comparison_complete=False
    )
    if (merged_environment_control is not None
            and merged_environment_control.get("diagnostic_only") is True
            and merged_environment_control.get("lp_environment_null") is False
            and merged_environment_control.get("main_environment_block") is True
            and merged_environment_control.get("merged_environment_block") is True
            and type(merged_environment_control.get("merged_environment_builder_selftest_passed")) is bool
            and type(merged_environment_control.get("merged_environment_entry_count")) is int
            and 0 <= int(merged_environment_control["merged_environment_entry_count"]) <= 128
            and merged_environment_control.get("comparison_complete") is False):
        safe["merged_environment_control"] = merged_environment_control
    main_environment_variant_controls = _sanitize_environment_variant_controls(
        value.get("main_environment_variant_controls")
    )
    if main_environment_variant_controls is not None:
        safe["main_environment_variant_controls"] = main_environment_variant_controls
    token_diagnostic = _sanitize_token_diagnostic(value.get("token_diagnostic"))
    if token_diagnostic is not None:
        safe["token_diagnostic"] = token_diagnostic
    raw_cleanup_diagnostics = value.get("cleanup_diagnostics")
    if isinstance(raw_cleanup_diagnostics, list):
        cleanup_diagnostics = []
        for item in raw_cleanup_diagnostics[:16]:
            cleanup = _sanitize_cleanup_diagnostic(item)
            if cleanup is not None:
                cleanup_diagnostics.append(cleanup)
        if cleanup_diagnostics:
            safe["cleanup_diagnostics"] = cleanup_diagnostics
    return safe or None


def _junit_counts(path: Path) -> dict[str, object]:
    try:
        cases = list(ET.parse(path).iter("testcase"))
    except (OSError, ET.ParseError):
        return {"test_count": 0, "failed_count": 0, "error_count": 0, "skipped_count": 0,
                "native_case_names": [], "native_nonpassing_count": 0,
                "native_case_results": [], "legacy_parent_attestations": []}
    native = [case for case in cases if (case.get("name") or "").split("[", 1)[0] in EXPECTED_NATIVE_CASES]
    failed = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    native_nonpassing = sum(any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in native)
    case_results = []
    legacy_attestations = []
    for case in native:
        name = (case.get("name") or "").split("[", 1)[0]
        if case.find("failure") is not None:
            outcome = "FAIL"
        elif case.find("error") is not None:
            outcome = "ERROR"
        elif case.find("skipped") is not None:
            outcome = "SKIP"
        else:
            outcome = "PASS"
        case_results.append({"name": name, "outcome": outcome})
        if name not in LEGACY_NATIVE_CASES:
            continue
        attestation_sets = {
            "pre_resume": [], "post_exit_job": [],
            "launcher_return_codes": [], "launcher_failures": [], "environment_controls": [],
        }
        properties = case.find("properties")
        if properties is not None:
            for prop in properties.findall("property"):
                property_name = prop.get("name")
                if property_name == "parent_launch_return_code":
                    raw_code = prop.get("value", "")
                    try:
                        code = int(raw_code)
                    except ValueError:
                        continue
                    if str(code) == raw_code and -0x80000000 <= code <= 0xFFFFFFFF:
                        attestation_sets["launcher_return_codes"].append(code)
                    continue
                if property_name == "parent_launch_failure_diagnostic":
                    try:
                        raw_failure = json.loads(prop.get("value", ""))
                    except json.JSONDecodeError:
                        continue
                    safe_failure = _sanitize_parent_launch_failure(raw_failure)
                    if safe_failure is not None:
                        attestation_sets["launcher_failures"].append(safe_failure)
                    continue
                if property_name == "parent_environment_control":
                    try:
                        raw_control = json.loads(prop.get("value", ""))
                    except json.JSONDecodeError:
                        continue
                    safe_control = _sanitize_environment_control(raw_control)
                    if safe_control is not None:
                        attestation_sets["environment_controls"].append(safe_control)
                    continue
                if property_name not in {"parent_pre_resume_attestation", "parent_post_exit_job_attestation"}:
                    continue
                try:
                    value = json.loads(prop.get("value", ""))
                except json.JSONDecodeError:
                    continue
                if not isinstance(value, dict):
                    continue
                if property_name == "parent_pre_resume_attestation":
                    required = ("token_verified", "is_appcontainer", "is_lpac", "low_integrity",
                                "expected_sid_match", "zero_capabilities", "job_membership_verified")
                    if type(value.get("version")) is int and value.get("version") == 1 and all(value.get(field) is True for field in required):
                        attestation_sets["pre_resume"].append({"version": 1, **{field: True for field in required}})
                elif (type(value.get("version")) is int and value.get("version") == 1
                      and type(value.get("active_processes")) is int and value.get("active_processes") == 0
                      and type(value.get("total_processes")) is int and value.get("total_processes") == 1):
                    attestation_sets["post_exit_job"].append({
                        "version": 1, "active_processes": 0, "total_processes": 1,
                    })
        legacy_attestations.append({"name": name, **attestation_sets})
    return {
        "test_count": len(cases),
        "failed_count": failed,
        "error_count": errors,
        "skipped_count": skipped,
        "native_case_names": [(case.get("name") or "").split("[", 1)[0] for case in native],
        "native_nonpassing_count": native_nonpassing,
        "native_case_results": case_results,
        "legacy_parent_attestations": legacy_attestations,
    }


def main() -> int:
    output_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "registered-lpac-storage-gate.json"
    validation_path = output_dir / "registered-lpac-validation.json"
    junit_path = output_dir / "registered-lpac-private-junit.xml"
    for path in (evidence_path, validation_path, junit_path):
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    source_commit = os.environ.get("GITHUB_SHA", "local-unpinned")
    evidence_path.write_text(json.dumps({
        "schema": "registered-lpac-storage-gate-v1",
        "source_commit": source_commit,
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "gate_status": "INCONCLUSIVE",
        "result_code": "native_gate_did_not_write_evidence",
        "mission_started": False,
        "network_gate": "NOT_RUN",
        "profile_ids": [],
        "profile_cleanup_confirmed_count": 0,
        "profile_quarantined_count": 0,
        "vhd_cleanup_confirmed": False,
        "process_tree_state": "no_child_resumed",
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    command = [
        sys.executable, "-m", "pytest", "-q",
        "tests/test_windows_appcontainer_workspace_native.py",
        "tests/test_registered_lpac_prototype.py",
        "tests/test_windows_registered_lpac_prototype.py",
        f"--junitxml={junit_path}", "-o", "junit_family=xunit1",
    ]
    runner_exception = None
    try:
        result = subprocess.run(
            command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
            shell=False, timeout=900, check=False, env=_safe_test_environment(dict(os.environ)),
        )
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124
        runner_exception = "pytest_timeout"
    except OSError as exc:
        exit_code = 125
        runner_exception = type(exc).__name__

    counts = _junit_counts(junit_path)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            evidence = None
    except (OSError, json.JSONDecodeError):
        evidence = None
    native_names = counts["native_case_names"]
    expected_native = EXPECTED_NATIVE_CASES
    exact_coverage = native_names == expected_native and counts["native_nonpassing_count"] == 0
    no_test_failures = counts["failed_count"] == 0 and counts["error_count"] == 0 and counts["skipped_count"] == 0
    legacy_attestations = counts["legacy_parent_attestations"]
    legacy_attestation_coverage = (
        [item["name"] for item in legacy_attestations] == LEGACY_NATIVE_CASES
        and all(item["pre_resume"] and item["post_exit_job"] for item in legacy_attestations)
    )
    profile_ids = evidence.get("profile_ids") if isinstance(evidence, dict) else None
    cleanup_proven = (
        isinstance(evidence, dict)
        and isinstance(profile_ids, list)
        and len(profile_ids) == 3
        and evidence.get("profile_cleanup_confirmed_count") == len(profile_ids)
        and evidence.get("profile_quarantined_count") == 0
        and evidence.get("vhd_cleanup_confirmed") is True
        and evidence.get("process_tree_state") == "job_active_processes_zero_child_exit_observed"
        and evidence.get("child_exit_code") == 0
        and evidence.get("mission_started") is False
        and evidence.get("profile_folder_outside_vhd") is True
        and evidence.get("get_temp_path_points_to_workspace") is True
        and evidence.get("simultaneous_profiles_had_distinct_sids") is True
        and evidence.get("retired_sid_not_reused") is True
    )
    evidence_pass = isinstance(evidence, dict) and evidence.get("gate_status") == "PASS" and cleanup_proven
    exact_sha = isinstance(evidence, dict) and evidence.get("source_commit") == source_commit
    valid = (exit_code == 0 and exact_coverage and no_test_failures and legacy_attestation_coverage
             and evidence_pass and exact_sha)
    evidence_gate_status = evidence.get("gate_status") if isinstance(evidence, dict) else None
    final_gate_status = "PASS" if valid else ("FAIL" if evidence_gate_status == "FAIL" else "INCONCLUSIVE")
    validation = {
        "schema": "registered-lpac-validation-v1",
        "source_commit": source_commit,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "pytest_exit_code": exit_code,
        "runner_exception": runner_exception,
        "gate_status": final_gate_status,
        "validation_status": "PASS" if valid else ("FAIL" if final_gate_status == "FAIL" else "INCONCLUSIVE"),
        "native_case_count": len(native_names),
        "native_case_names": native_names,
        "native_nonpassing_count": counts["native_nonpassing_count"],
        "native_case_results": counts["native_case_results"],
        "legacy_parent_attestations": legacy_attestations,
        "legacy_parent_attestation_coverage": legacy_attestation_coverage,
        "total_test_count": counts["test_count"],
        "failed_count": counts["failed_count"],
        "error_count": counts["error_count"],
        "skipped_count": counts["skipped_count"],
        "exact_sha_evidence": exact_sha,
        "cleanup_and_process_evidence_proven": cleanup_proven,
        "diagnostic_environment_control_required_for_storage_acceptance": False,
        "diagnostic_environment_control_status": "NOT_RECORDED",
        "mission_acceptance": "BLOCKED",
        "backend_enabled_by_slice": False,
        "not_validated": [
            "network_denial", "host_file_and_registry_confinement_beyond_profile_store",
            "combined_vhd_job_lpac_mission", "aggregate_resource_bounds",
            "crash_and_host_reboot_recovery", "production_broker",
        ],
    }
    if isinstance(evidence, dict):
        validation["result_code"] = evidence.get("result_code")
        registered_control = _sanitize_environment_control(evidence.get("environment_control"))
        if registered_control is not None:
            validation["registered_environment_control"] = registered_control
            validation["diagnostic_environment_control_status"] = (
                "COMPLETED" if registered_control["comparison_complete"] else "INCOMPLETE"
            )
        if not cleanup_proven and evidence.get("gate_status") == "PASS":
            validation["result_code"] = "cleanup_or_process_attestation_unconfirmed"
        validation["windows_version"] = evidence.get("windows_version")
        validation["windows_build"] = evidence.get("windows_build")
        validation["profile_cleanup_confirmed_count"] = evidence.get("profile_cleanup_confirmed_count")
        validation["profile_quarantined_count"] = evidence.get("profile_quarantined_count")
        validation["vhd_cleanup_confirmed"] = evidence.get("vhd_cleanup_confirmed")
        validation["process_tree_state"] = evidence.get("process_tree_state")
    validation_path.write_text(json.dumps(validation, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    try:
        junit_path.unlink()
    except FileNotFoundError:
        pass
    print(json.dumps({
        "schema": validation["schema"],
        "validation_status": validation["validation_status"],
        "gate_status": validation["gate_status"],
        "result_code": validation.get("result_code"),
        "native_case_count": validation["native_case_count"],
        "skipped_count": validation["skipped_count"],
        "mission_acceptance": validation["mission_acceptance"],
    }, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
