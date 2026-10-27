"""Portable source guards only; these do not prove native LPAC isolation."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_lpac_launch_failure_captures_error_before_diagnostics_and_stays_failed():
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    binding = source.split("job_list[0] = job;", 1)[1].split("if (!CreateProcessW(argv[0]", 1)[0]
    launch = source.split("if (!CreateProcessW(argv[0]", 1)[1].split("job_query_ok = IsProcessInJob", 1)[0]
    assert "UpdateProcThreadAttribute" in binding and "PROC_THREAD_ATTRIBUTE_JOB_LIST" in binding
    assert "DWORD launch_error = GetLastError();" in launch
    assert launch.index("DWORD launch_error = GetLastError();") < launch.index("report_launch_failure(")
    assert 'status = fail(L"CreateProcessW LPAC", launch_error); goto done;' in launch
    assert "CREATE_SUSPENDED" in launch and "CREATE_NO_WINDOW" in launch


def test_failure_diagnostics_are_bounded_redacted_and_do_not_claim_child_identity():
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    diagnostic = source.split("static void report_launch_failure(", 1)[1].split("static int launch_child(", 1)[0]
    for field in (
        "scope\\\":\\\"broker_only", "image_is_absolute", "image_attributes_error",
        "parent_can_read_image", "image_open_error", "image_size_bytes",
        "cwd_is_absolute", "cwd_attributes_error", "module_matches_image",
        "known_dependency_mask", "known_dependency_expected_mask",
        "broker_pid", "broker_bitness", "launch_flags", "win32_error",
        "ntstatus_available", "ntstatus_advisory",
    ):
        assert field in diagnostic
    assert "FormatMessageW(" in diagnostic
    assert "FORMAT_MESSAGE_IGNORE_INSERTS" in diagnostic
    assert "GetFileAttributesW(image)" in diagnostic
    assert "GetFileAttributesW(cwd)" in diagnostic
    assert "is_absolute_windows_path(image)" in diagnostic
    assert "is_absolute_windows_path(cwd)" in diagnostic
    assert "CreateFileW(image, GENERIC_READ" in diagnostic
    assert "GetSystemDirectoryW(" in source
    assert "GetModuleFileNameW(" in diagnostic
    assert 'L"%ls' not in diagnostic  # Never format image/cwd/SID/argv or environment values.
    for forbidden in ("CreateProcessW(", "ResumeThread(", "CreateAppContainerProfile(", "SetNamedSecurityInfo", "SetFileSecurity", "token_verified\\\":true"):
        assert forbidden not in diagnostic


def test_broker_open_is_explicitly_not_evidence_of_lpac_image_access():
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    diagnostic = source.split("static void report_launch_failure(", 1)[1].split("static int launch_child(", 1)[0]
    assert "Parent readability is not LPAC access" in source
    assert "parent_can_read_image" in diagnostic
    assert "known_system_dependency_mask" in source


def test_d2_branch_uses_the_existing_strict_windows_gate():
    source = (ROOT / ".github/workflows/windows-sandbox-contract.yml").read_text(encoding="utf-8")
    assert "branches: [fix/blocker-d-review-20261010, fix/blocker-d2-lpac-20261021]" in source
    assert source.count("github.ref == 'refs/heads/fix/blocker-d2-lpac-20261021'") == 2
    assert "continue-on-error" not in source
    assert '"mission_acceptance": "BLOCKED"' in source
    assert '"backend_enabled_by_slice": False' in source
