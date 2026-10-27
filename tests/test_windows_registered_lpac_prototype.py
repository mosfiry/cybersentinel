from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import ntpath
import json
import os
import platform
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.registered_lpac_prototype import (
    OwnershipJournal,
    PrototypeError,
    RegisteredProfile,
    WindowsProfileApi,
    new_run_id,
    profile_name_for_run,
    sha256_text,
)

ROOT = Path(__file__).resolve().parents[1]
_WINDOWS_NATIVE = pytest.mark.skipif(
    sys.platform != "win32" or os.name != "nt",
    reason="requires native Windows profile, VHD, token, and Job APIs",
)
_ERROR_ACCESS_DENIED = 5


@dataclass
class _OwnedProfile:
    profile: RegisteredProfile
    journal: OwnershipJournal
    job_is_empty: bool = True
    handles_closed: bool = True


def _native_helpers():
    spec = importlib.util.spec_from_file_location(
        "registered_lpac_native_helpers",
        ROOT / "tests" / "test_windows_appcontainer_workspace_native.py",
    )
    if spec is None or spec.loader is None:
        raise PrototypeError("native_test_helpers_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compile_probe(build_dir: Path, helpers) -> Path:
    source = ROOT / "tests" / "native" / "appcontainer_acl_probe.c"
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not source.is_file() or not vswhere.is_file():
        raise PrototypeError("native_compiler_unavailable")
    located = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", shell=False, timeout=30, check=False,
    )
    if located.returncode != 0 or not located.stdout.strip():
        raise PrototypeError("native_compiler_unavailable")
    devcmd = Path(located.stdout.strip().splitlines()[-1]) / "Common7" / "Tools" / "VsDevCmd.bat"
    exe = build_dir / "appcontainer_acl_probe.exe"
    obj = build_dir / "appcontainer_acl_probe.obj"
    command = (
        f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && '
        f'cl /nologo /W4 /WX /MT /DUNICODE /D_UNICODE /TC '
        f'"{source}" /Fo:"{obj}" /Fe:"{exe}" /link advapi32.lib userenv.lib'
    )
    result = helpers._run_compile_command(command, build_dir)
    if result.returncode != 0 or not exe.is_file():
        raise PrototypeError("native_probe_compile_failed")
    return exe


def _create_owned_profile(api: WindowsProfileApi, journal_root: Path, owner_sid: str,
                          journal_history: list[OwnershipJournal]) -> _OwnedProfile:
    run_id = new_run_id()
    name = profile_name_for_run(run_id)
    journal = OwnershipJournal.create(journal_root / f"{run_id}.jsonl", run_id, owner_sid)
    journal_history.append(journal)
    try:
        sid = api.create(name)
        derived = api.derive_sid(name)
        if sid != derived:
            journal.transition("QUARANTINED")
            raise PrototypeError("created_profile_sid_mismatch")
        journal.transition("PROFILE_CREATED", package_sid_sha256=sha256_text(sid))
        folder = api.folder_path(sid)
        journal.transition("PROFILE_PATH_RESOLVED", profile_folder_sha256=sha256_text(str(folder)))
        return _OwnedProfile(RegisteredProfile(name=name, sid=sid, folder_path=folder), journal)
    except BaseException:
        if journal.state not in {"QUARANTINED", "DELETED"}:
            try:
                journal.transition("QUARANTINED")
            except PrototypeError:
                pass
        raise


def _delete_owned_profile(owned: _OwnedProfile, api: WindowsProfileApi, current_owner_sid: str) -> bool:
    sid_hash = sha256_text(owned.profile.sid)
    observed_folder = api.folder_path(owned.profile.sid)
    decision = owned.journal.recovery_decision(
        observed_sid_sha256=sid_hash,
        derived_sid_sha256=sha256_text(api.derive_sid(owned.profile.name)),
        owner_sid_sha256=sha256_text(current_owner_sid),
        observed_profile_folder_sha256=sha256_text(str(observed_folder)),
        job_is_empty=owned.job_is_empty,
        handles_closed=owned.handles_closed,
    )
    if decision != "DELETE_OWNED_PROFILE":
        if owned.journal.state not in {"QUARANTINED", "DELETED"}:
            owned.journal.transition("QUARANTINED")
        return False
    if owned.journal.state != "CLEANUP_PENDING":
        owned.journal.transition("CLEANUP_PENDING")
    api.delete(owned.profile.name)
    if owned.profile.folder_path.exists():
        owned.journal.transition("QUARANTINED")
        return False
    owned.journal.transition("DELETED")
    return True


def _folder_snapshot(path: Path) -> dict[str, int | bool]:
    if not path.is_dir():
        return {"exists": False, "files": 0, "directories": 0, "top_level_file_bytes": 0}
    files = directories = total = 0
    for child in path.iterdir():
        if child.is_symlink():
            continue
        if child.is_file():
            files += 1
            try:
                total += child.stat().st_size
            except OSError:
                pass
        elif child.is_dir():
            directories += 1
    return {"exists": True, "files": files, "directories": directories, "top_level_file_bytes": total}


def _final_path_by_handle(path: Path) -> str:
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    get_final_path = kernel.GetFinalPathNameByHandleW
    get_final_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    get_final_path.restype = ctypes.c_uint32
    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_file(str(path), 0x80, 0x1 | 0x2 | 0x4, None, 3, 0x02000000, None)
    if handle == invalid_handle:
        raise PrototypeError("final_path_open_failed", system_error=ctypes.get_last_error())
    try:
        required = get_final_path(handle, None, 0, 1)  # VOLUME_NAME_GUID, normalized path.
        if not required or required > 32768:
            raise PrototypeError("final_path_query_failed", system_error=ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = get_final_path(handle, buffer, len(buffer), 1)
        if not written or written >= len(buffer):
            raise PrototypeError("final_path_query_failed", system_error=ctypes.get_last_error())
        return buffer.value
    finally:
        close_handle(handle)


def _final_path_is_under(target: str, root: str) -> bool:
    try:
        target_text = ntpath.normcase(ntpath.normpath(target))
        root_text = ntpath.normcase(ntpath.normpath(root))
        return ntpath.commonpath([target_text, root_text]) == root_text
    except (OSError, ValueError):
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _check_map(evidence: dict) -> dict[str, dict[str, int | bool]]:
    checks = evidence.get("checks")
    if not isinstance(checks, list):
        return {}
    return {str(item.get("name")): {"ok": bool(item.get("ok")), "error": int(item.get("error", -1))}
            for item in checks if isinstance(item, dict)}


def _pre_resume_attestation(stderr: str) -> dict | None:
    prefix = "pre_resume_attestation: "
    for line in stderr.splitlines():
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix):])
            except (TypeError, ValueError):
                return None
            return value if isinstance(value, dict) else None
    return None


def _post_exit_attestation(stderr: str) -> dict | None:
    prefix = "post_exit_job_attestation: "
    for line in stderr.splitlines():
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix):])
            except (TypeError, ValueError):
                return None
            return value if isinstance(value, dict) else None
    return None


def _classify_storage(checks: dict[str, dict[str, int | bool]]) -> tuple[str, str]:
    filesystem_names = (
        "outside_existing_file_write",
        "outside_new_file_create",
        "outside_directory_create",
    )
    filesystem = [checks.get(name) for name in filesystem_names]
    if any(item is None for item in filesystem):
        return "INCONCLUSIVE", "filesystem_evidence_missing"
    if any(item["ok"] is False and item["error"] == 0 for item in filesystem):
        return "FAIL", "REGISTERED_LPAC_STORAGE_BOUNDARY_FAIL"
    if not all(item["ok"] is True and item["error"] == _ERROR_ACCESS_DENIED for item in filesystem):
        return "INCONCLUSIVE", "filesystem_denial_not_proven"

    if checks.get("registered_registry_api_available", {}).get("ok") is not True:
        return "INCONCLUSIVE", "documented_registry_api_unavailable"
    if checks.get("registered_registry_value_absent_before", {}).get("ok") is not True:
        return "INCONCLUSIVE", "registry_fixture_not_fresh"
    registry_set = checks.get("registered_registry_value_set")
    registry_verified = checks.get("registered_registry_write_verified")
    if registry_set is None or registry_verified is None:
        return "INCONCLUSIVE", "registry_write_evidence_missing"
    if registry_set["ok"] is True or registry_verified["ok"] is True:
        return "FAIL", "REGISTERED_LPAC_STORAGE_BOUNDARY_FAIL"
    if registry_set["error"] == _ERROR_ACCESS_DENIED and registry_verified["error"] == _ERROR_ACCESS_DENIED:
        return "PASS", "registered_profile_storage_denied_for_file_and_registry_fixtures"
    return "INCONCLUSIVE", "registry_write_denial_not_proven"


def _denied_storage_checks() -> dict[str, dict[str, int | bool]]:
    checks = {
        name: {"ok": True, "error": _ERROR_ACCESS_DENIED}
        for name in ("outside_existing_file_write", "outside_new_file_create", "outside_directory_create")
    }
    checks.update({
        "registered_registry_api_available": {"ok": True, "error": 0},
        "registered_registry_value_absent_before": {"ok": True, "error": 0},
        "registered_registry_value_set": {"ok": False, "error": _ERROR_ACCESS_DENIED},
        "registered_registry_write_verified": {"ok": False, "error": _ERROR_ACCESS_DENIED},
    })
    return checks


def test_storage_classifier_only_passes_proven_denials_and_rejects_side_effects() -> None:
    checks = _denied_storage_checks()
    assert _classify_storage(checks)[0] == "PASS"

    file_write_succeeded = dict(checks)
    file_write_succeeded["outside_existing_file_write"] = {"ok": False, "error": 0}
    assert _classify_storage(file_write_succeeded)[0] == "FAIL"

    registry_value_was_set = dict(checks)
    registry_value_was_set["registered_registry_value_set"] = {"ok": True, "error": 0}
    assert _classify_storage(registry_value_was_set)[0] == "FAIL"

    registry_write_verified = dict(checks)
    registry_write_verified["registered_registry_write_verified"] = {"ok": True, "error": 0}
    assert _classify_storage(registry_write_verified)[0] == "FAIL"

    missing_registry_proof = dict(checks)
    del missing_registry_proof["registered_registry_value_set"]
    assert _classify_storage(missing_registry_proof)[0] == "INCONCLUSIVE"


@pytest.fixture(scope="session")
def registered_native_probe(tmp_path_factory):
    if sys.platform != "win32" or os.name != "nt":
        pytest.fail("registered native probe fixture was requested off Windows")
    helpers = _native_helpers()
    build_dir = tmp_path_factory.mktemp("registered-lpac-native-probe")
    return _compile_probe(build_dir, helpers)


@_WINDOWS_NATIVE
def test_native_lpac_registered_profile_storage_boundary(tmp_path: Path, registered_native_probe: Path) -> None:
    """Test one bounded native profile-storage gate; never starts a Mission."""
    helpers = _native_helpers()
    api = WindowsProfileApi()
    evidence_root = Path(os.environ.get("RUNNER_TEMP", str(tmp_path)))
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_root / "registered-lpac-storage-gate.json"
    private_root = tmp_path / "private-profile-ownership"
    private_root.mkdir()
    helpers._create_protected_test_root(private_root)
    owner_sid = helpers._broker_sid()
    owned_profiles: list[_OwnedProfile] = []
    journal_history: list[OwnershipJournal] = []
    vhd_workspace = None
    probe_report: dict | None = None
    process_result: subprocess.CompletedProcess[str] | None = None
    probe_timed_out = False
    summary: dict = {
        "schema": "registered-lpac-storage-gate-v1",
        "source_commit": os.environ.get("GITHUB_SHA", "local-unpinned"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "windows_version": list(sys.getwindowsversion()[:3]),
        "windows_build": platform.version(),
        "native_probe_source_sha256": hashlib.sha256((ROOT / "tests/native/appcontainer_acl_probe.c").read_bytes()).hexdigest(),
        "gate_status": "INCONCLUSIVE",
        "result_code": "native_gate_not_completed",
        "mission_started": False,
        "network_gate": "NOT_RUN",
        "registry_fixture": "documented_GetAppContainerRegistryLocation",
        "vhd_capacity_bytes": 64 * 1024 * 1024,
        "profile_ids": [],
        "profile_cleanup_confirmed_count": 0,
        "profile_quarantined_count": 0,
        "vhd_cleanup_confirmed": False,
        "profile_storage_folder_c_outside_vhd": None,
    }
    failure_message = "registered LPAC storage gate did not complete"
    try:
        profile_a = _create_owned_profile(api, private_root, owner_sid, journal_history)
        owned_profiles.append(profile_a)
        profile_b = _create_owned_profile(api, private_root, owner_sid, journal_history)
        owned_profiles.append(profile_b)
        if profile_a.profile.sid == profile_b.profile.sid or profile_a.profile.folder_path == profile_b.profile.folder_path:
            raise PrototypeError("concurrent_profile_identity_collision")
        summary["simultaneous_profiles_had_distinct_sids"] = True
        summary["simultaneous_profiles_had_distinct_storage_paths"] = True
        summary["profile_ids"].extend([
            {"run_id_sha256": sha256_text(profile_a.journal.document["run_id"]),
             "profile_name_sha256": sha256_text(profile_a.profile.name),
             "package_sid_sha256": sha256_text(profile_a.profile.sid)},
            {"run_id_sha256": sha256_text(profile_b.journal.document["run_id"]),
             "profile_name_sha256": sha256_text(profile_b.profile.name),
             "package_sid_sha256": sha256_text(profile_b.profile.sid)},
        ])

        if not _delete_owned_profile(profile_a, api, helpers._broker_sid()):
            raise PrototypeError("retired_profile_cleanup_unconfirmed")
        owned_profiles.remove(profile_a)
        summary["retired_profile_deleted_before_new_identity"] = True
        profile_c = _create_owned_profile(api, private_root, owner_sid, journal_history)
        owned_profiles.append(profile_c)
        if profile_c.profile.sid in {profile_a.profile.sid, profile_b.profile.sid}:
            raise PrototypeError("retired_or_concurrent_sid_reused")
        if profile_c.profile.folder_path in {profile_a.profile.folder_path, profile_b.profile.folder_path}:
            raise PrototypeError("retired_or_concurrent_storage_reused")
        summary["retired_sid_not_reused"] = True
        summary["profile_ids"].append({
            "run_id_sha256": sha256_text(profile_c.journal.document["run_id"]),
            "profile_name_sha256": sha256_text(profile_c.profile.name),
            "package_sid_sha256": sha256_text(profile_c.profile.sid),
        })

        for owned in (profile_b, profile_c):
            if not owned.profile.folder_path.is_dir():
                raise PrototypeError("registered_profile_folder_missing")
        from workspace import windows_vhd_workspace as vhd
        host_root = tmp_path / "vhd-host-root"
        host_root.mkdir()
        helpers._create_protected_test_root(host_root)
        vhd_workspace = vhd.WindowsVhdWorkspace.create(host_root, vhd.MIN_CAPACITY_BYTES)

        probe = helpers._prepare_root_and_probe(
            vhd_workspace.mount_path,
            SimpleNamespace(sid_string=profile_c.profile.sid, identity_name=profile_c.profile.name),
            registered_native_probe,
        )
        workspace_path = vhd_workspace.mount_path / "registered-workspace"
        from workspace.windows_appcontainer_workspace import _WindowsNative
        workspace_native = _WindowsNative()
        workspace_native.create_directory(workspace_path, profile_c.profile.sid)
        report_path = workspace_path / "registered-lpac-evidence.json"

        entries, workspace_owner, labels, workspace_dacl_protected = helpers._get_security(workspace_path, include_label=True)
        workspace_aces = [entry for entry in entries if entry["sid"] == profile_c.profile.sid and entry["type"] == 0]
        if workspace_owner != owner_sid or not workspace_dacl_protected or not workspace_aces:
            raise PrototypeError("workspace_acl_precondition_failed")
        if any(entry["mask"] & 0x000C0000 for entry in workspace_aces):
            raise PrototypeError("workspace_acl_has_security_write")
        summary["workspace_acl"] = {
            "protected": bool(workspace_dacl_protected),
            "owner_is_broker": workspace_owner == owner_sid,
            "package_allow_masks": [hex(entry["mask"]) for entry in workspace_aces],
            "package_has_write_dac_or_owner": any(entry["mask"] & 0x000C0000 for entry in workspace_aces),
            "low_integrity_label_present": any(item[0] == "S-1-16-4096" for item in labels),
            "acl_sha256": sha256_text(json.dumps({"entries": entries, "labels": labels, "protected": workspace_dacl_protected}, sort_keys=True)),
        }
        profile_entries, profile_owner, profile_labels, profile_protected = helpers._get_security(
            profile_c.profile.folder_path, include_label=True
        )
        summary["registered_profile_storage_acl"] = {
            "protected": bool(profile_protected),
            "owner_is_package_sid": profile_owner == profile_c.profile.sid,
            "package_allow_ace_present": any(entry["sid"] == profile_c.profile.sid and entry["type"] == 0 for entry in profile_entries),
            "acl_sha256": sha256_text(json.dumps({"entries": profile_entries, "labels": profile_labels, "protected": profile_protected}, sort_keys=True)),
        }

        profile_final_path = _final_path_by_handle(profile_c.profile.folder_path)
        vhd_final_path = _final_path_by_handle(vhd_workspace.mount_path)
        summary["profile_storage_resolved_path_sha256"] = sha256_text(profile_final_path)
        summary["vhd_mount_resolved_path_sha256"] = sha256_text(vhd_final_path)
        summary["profile_folder_outside_vhd"] = not _final_path_is_under(profile_final_path, vhd_final_path)
        summary["profile_storage_folder_c_outside_vhd"] = summary["profile_folder_outside_vhd"]
        if not summary["profile_folder_outside_vhd"]:
            raise PrototypeError("profile_storage_path_not_outside_vhd")

        vhd_size_before = vhd_workspace.image_path.stat().st_size
        vhd_hash_before = _sha256_file(vhd_workspace.image_path)
        profile_before = _folder_snapshot(profile_c.profile.folder_path)
        sentinel = profile_c.profile.folder_path / "broker-sentinel.bin"
        sentinel.write_bytes(b"small registered profile boundary sentinel")
        sentinel_size_before = sentinel.stat().st_size
        profile_before_child = _folder_snapshot(profile_c.profile.folder_path)
        if profile_c.journal.state == "PROFILE_PATH_RESOLVED":
            profile_c.journal.transition("PROBE_RUNNING")
            profile_c.job_is_empty = False
            profile_c.handles_closed = False

        command = [
            str(probe), "--launch", profile_c.profile.sid, "registered-storage",
            str(workspace_path), str(sentinel), str(profile_c.profile.folder_path), str(report_path),
        ]
        try:
            process_result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", shell=False, timeout=45, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                env=helpers._safe_native_environment(dict(os.environ)),
            )
        except subprocess.TimeoutExpired:
            probe_timed_out = True
            raise PrototypeError("registered_storage_probe_timeout") from None
        summary["launcher_exit_code"] = int(process_result.returncode)
        attestation = _pre_resume_attestation(process_result.stderr)
        required_parent_fields = (
            "token_verified", "is_appcontainer", "is_lpac", "low_integrity",
            "expected_sid_match", "zero_capabilities", "job_membership_verified",
        )
        pre_resume_valid = isinstance(attestation, dict) and type(attestation.get("version")) is int and attestation.get("version") == 1 and all(
            attestation.get(field) is True for field in required_parent_fields
        )
        summary["pre_resume_attestation_present"] = isinstance(attestation, dict)
        if isinstance(attestation, dict):
            summary["pre_resume_attestation"] = {
                "version": 1 if type(attestation.get("version")) is int and attestation.get("version") == 1 else None,
                **{field: attestation.get(field) is True for field in required_parent_fields},
            }
        launch_diagnostic = helpers._launch_failure_diagnostic(process_result.stderr)
        if launch_diagnostic is not None:
            environment_control = launch_diagnostic.get("environment_control")
            if isinstance(environment_control, dict):
                summary["environment_control"] = environment_control
            if process_result.returncode != 0:
                summary["launcher_failure_diagnostic"] = launch_diagnostic
        post_exit = _post_exit_attestation(process_result.stderr)
        post_exit_valid = (
            isinstance(post_exit, dict)
            and type(post_exit.get("version")) is int and post_exit.get("version") == 1
            and type(post_exit.get("active_processes")) is int and post_exit.get("active_processes") == 0
            and type(post_exit.get("total_processes")) is int and post_exit.get("total_processes") == 1
        )
        summary["post_exit_job_attestation_present"] = isinstance(post_exit, dict)
        if isinstance(post_exit, dict):
            summary["post_exit_job_attestation"] = {
                "version": post_exit.get("version") if type(post_exit.get("version")) is int else None,
                "active_processes": post_exit.get("active_processes") if type(post_exit.get("active_processes")) is int else None,
                "total_processes": post_exit.get("total_processes") if type(post_exit.get("total_processes")) is int else None,
            }
        if post_exit_valid:
            profile_c.job_is_empty = True
            profile_c.handles_closed = True
        if process_result.returncode != 0:
            if launch_diagnostic is not None or not pre_resume_valid:
                raise PrototypeError("registered_profile_launcher_failed")
            if post_exit_valid:
                raise PrototypeError("registered_profile_child_failed")
        if not post_exit_valid:
            raise PrototypeError("post_exit_job_empty_attestation_missing")
        if process_result.returncode != 0:
            raise PrototypeError("registered_profile_child_failed")
        if not report_path.is_file():
            raise PrototypeError("registered_storage_evidence_missing")
        probe_report = json.loads(report_path.read_text(encoding="utf-8"))
        if profile_c.journal.state == "PROBE_RUNNING":
            profile_c.journal.transition("PROBE_COMPLETE")

        checks = _check_map(probe_report)
        required_token_fields = (
            "token_verified", "is_appcontainer", "is_lpac", "low_integrity",
            "expected_sid_match", "zero_capabilities",
        )
        if probe_report.get("version") != 2 or any(probe_report.get(field) is not True for field in required_token_fields):
            raise PrototypeError("registered_child_token_not_verified")
        if not isinstance(attestation, dict) or any(attestation.get(field) is not True for field in (
            "token_verified", "is_appcontainer", "is_lpac", "low_integrity",
            "expected_sid_match", "zero_capabilities", "job_membership_verified",
        )):
            raise PrototypeError("pre_resume_token_or_job_attestation_missing")
        if checks.get("environment_minimal", {}).get("ok") is not True or checks.get("temp_api_points_to_workspace", {}).get("ok") is not True:
            raise PrototypeError("temp_environment_not_bound_to_vhd_workspace")
        if checks.get("temp_api_write_inside_workspace", {}).get("ok") is not True or checks.get("temp_api_read_inside_workspace", {}).get("ok") is not True:
            raise PrototypeError("temp_api_workspace_write_not_verified")
        summary["pre_resume_attestation"] = attestation
        summary["post_exit_job_attestation"] = post_exit
        summary["native_checks"] = checks
        summary["child_exit_code"] = process_result.returncode
        summary["vhd_image_bytes_before"] = vhd_size_before
        summary["vhd_image_bytes_after"] = vhd_workspace.image_path.stat().st_size
        summary["vhd_image_sha256_before"] = vhd_hash_before
        summary["vhd_image_sha256_after"] = _sha256_file(vhd_workspace.image_path)
        profile_after_child = _folder_snapshot(profile_c.profile.folder_path)
        summary["profile_inventory"] = {
            "before_marker": profile_before,
            "before_child": profile_before_child,
            "after_child": profile_after_child,
            "broker_sentinel_size_before": sentinel_size_before,
            "broker_sentinel_size_after": sentinel.stat().st_size if sentinel.exists() else None,
            "new_file_created": (profile_c.profile.folder_path / "new.bin").exists(),
            "new_directory_created": (profile_c.profile.folder_path / "newdir").is_dir(),
        }
        summary["temp_tmp_point_to_workspace"] = checks.get("environment_minimal", {}).get("ok") is True
        summary["get_temp_path_points_to_workspace"] = checks.get("temp_api_points_to_workspace", {}).get("ok") is True

        if not summary["profile_folder_outside_vhd"]:
            raise PrototypeError("profile_storage_path_not_outside_vhd")
        status, result_code = _classify_storage(checks)
        summary["gate_status"] = status
        summary["result_code"] = result_code
        summary["mission_started"] = False
        summary["network_gate"] = "NOT_RUN"
        if status == "FAIL":
            failure_message = "REGISTERED_LPAC_STORAGE_BOUNDARY_FAIL"
        elif status == "INCONCLUSIVE":
            failure_message = f"registered LPAC storage gate inconclusive ({result_code})"
        else:
            failure_message = ""
    except BaseException as exc:
        summary["gate_status"] = "INCONCLUSIVE"
        summary["result_code"] = exc.code if isinstance(exc, PrototypeError) else type(exc).__name__
        summary["failure_type"] = type(exc).__name__
        if isinstance(exc, PrototypeError) and exc.system_error is not None:
            summary["system_error"] = exc.system_error
        if isinstance(exc, AssertionError):
            summary["failure_type"] = "assertion_failed"
        failure_message = f"registered LPAC storage gate inconclusive ({summary['result_code']})"
    finally:
        if vhd_workspace is not None:
            try:
                image_path = vhd_workspace.image_path
                mount_path = vhd_workspace.mount_path
                vhd_workspace.close()
                summary["vhd_cleanup_confirmed"] = not image_path.exists() and not mount_path.exists()
            except BaseException:
                summary["vhd_cleanup_confirmed"] = False
                summary["vhd_cleanup_required"] = True
        for owned in reversed(owned_profiles):
            try:
                if _delete_owned_profile(owned, api, helpers._broker_sid()):
                    pass
            except BaseException:
                try:
                    if owned.journal.state not in {"QUARANTINED", "DELETED"}:
                        owned.journal.transition("QUARANTINED")
                except BaseException:
                    pass
        summary["profile_cleanup_confirmed_count"] = sum(journal.state == "DELETED" for journal in journal_history)
        summary["profile_quarantined_count"] = sum(journal.state != "DELETED" for journal in journal_history)
        if ((vhd_workspace is not None and not summary["vhd_cleanup_confirmed"]) or
                summary["profile_quarantined_count"] > 0):
            if summary["gate_status"] == "PASS":
                summary["gate_status"] = "INCONCLUSIVE"
                summary["result_code"] = "cleanup_unconfirmed"
        if probe_timed_out:
            summary["process_tree_state"] = "QUARANTINE_AND_REFUSE"
        elif process_result is not None and summary.get("post_exit_job_attestation", {}).get("active_processes") == 0:
            summary["process_tree_state"] = "job_active_processes_zero_child_exit_observed"
        elif process_result is not None:
            summary["process_tree_state"] = "launcher_exited_job_empty_unproven"
        else:
            summary["process_tree_state"] = "no_child_resumed"
        try:
            evidence_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        except OSError:
            failure_message = "registered LPAC storage evidence could not be preserved"

    if not summary["vhd_cleanup_confirmed"] and vhd_workspace is not None:
        pytest.fail("registered LPAC VHD cleanup unconfirmed; quarantine required")
    if summary["profile_quarantined_count"]:
        pytest.fail("registered LPAC profile cleanup unconfirmed; quarantine required")
    if failure_message:
        pytest.fail(failure_message)
    assert summary["gate_status"] == "PASS"
    assert summary["result_code"] == "registered_profile_storage_denied_for_file_and_registry_fixtures"
