"""Portable source guards only; these do not prove native LPAC isolation."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_lpac_launch_failure_captures_error_before_diagnostics_and_stays_failed():
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    launch = source.split("if (!CreateProcessW(argv[0]", 1)[1].split("if (!AssignProcessToJobObject", 1)[0]
    assert "DWORD launch_error = GetLastError();" in launch
    assert launch.index("DWORD launch_error = GetLastError();") < launch.index("report_launch_failure(")
    assert 'status = fail(L"CreateProcessW LPAC", launch_error); goto done;' in launch
    assert "CREATE_SUSPENDED" in launch and "CREATE_NO_WINDOW" in launch


def test_failure_diagnostics_are_bounded_redacted_and_do_not_claim_child_identity():
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    diagnostic = source.split("static void report_launch_failure(", 1)[1].split("static int launch_child(", 1)[0]
    for field in ("image_attributes_error", "cwd_attributes_error", "module_matches_image", "win32_error", "ntstatus_available", "ntstatus_advisory"):
        assert field in diagnostic
    assert "FormatMessageW(" in diagnostic
    assert "FORMAT_MESSAGE_IGNORE_INSERTS" in diagnostic
    assert "GetFileAttributesW(image)" in diagnostic
    assert "GetFileAttributesW(cwd)" in diagnostic
    assert "GetModuleFileNameW(" in diagnostic
    assert 'L"%ls' not in diagnostic  # Never format image/cwd/SID/argv or environment values.
    for forbidden in ("CreateProcessW(", "ResumeThread(", "CreateAppContainerProfile(", "SetNamedSecurityInfo", "SetFileSecurity", "token_verified\\\":true"):
        assert forbidden not in diagnostic


def test_d2_branch_uses_the_existing_strict_windows_gate():
    source = (ROOT / ".github/workflows/windows-sandbox-contract.yml").read_text(encoding="utf-8")
    assert "branches: [fix/blocker-d-review-20261010, fix/blocker-d2-lpac-20261021]" in source
    assert source.count("github.ref == 'refs/heads/fix/blocker-d2-lpac-20261021'") == 2
    assert "continue-on-error" not in source
    assert '"mission_acceptance": "BLOCKED"' in source
    assert '"backend_enabled_by_slice": False' in source
