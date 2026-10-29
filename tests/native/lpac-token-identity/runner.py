from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any


class DiagnosticFailure(RuntimeError):
    def __init__(self, stage: str, code: int | None = None):
        super().__init__(stage)
        self.stage = stage
        self.code = code


def _win_api() -> tuple[Any, Any, Any]:
    if sys.platform != "win32":
        raise DiagnosticFailure("windows_only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32, advapi32, userenv


def _sid_to_string(advapi32: Any, kernel32: Any, sid: ctypes.c_void_p) -> str:
    convert = advapi32.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    convert.restype = wintypes.BOOL
    text = ctypes.c_wchar_p()
    if not convert(sid, ctypes.byref(text)):
        raise DiagnosticFailure("convert_sid_to_text", ctypes.get_last_error())
    try:
        return text.value or ""
    finally:
        kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _derive_unregistered_appcontainer_sid() -> str:
    kernel32, advapi32, userenv = _win_api()
    derive = userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    derive.restype = ctypes.c_long
    sid = ctypes.c_void_p()
    name = f"Cue.CyberSentinel.LpacTokenIdentity.{uuid.uuid4().hex}"
    result = int(derive(name, ctypes.byref(sid)))
    if result != 0 or not sid.value:
        raise DiagnosticFailure("derive_unregistered_appcontainer_sid", result & 0xFFFFFFFF)
    try:
        return _sid_to_string(advapi32, kernel32, sid)
    finally:
        kernel32.LocalFree(sid)


def _current_user_sid() -> str:
    kernel32, advapi32, _ = _win_api()
    token = ctypes.c_void_p()
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    open_token.restype = wintypes.BOOL
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.restype = ctypes.c_void_p
    if not open_token(get_current_process(), 0x0008, ctypes.byref(token)):
        raise DiagnosticFailure("open_current_process_token", ctypes.get_last_error())
    try:
        needed = wintypes.DWORD(0)
        get_info = advapi32.GetTokenInformation
        get_info.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        get_info.restype = wintypes.BOOL
        get_info(token, 1, None, 0, ctypes.byref(needed))  # TokenUser size query.
        if ctypes.get_last_error() != 122 or not needed.value or needed.value > 65536:
            raise DiagnosticFailure("query_current_user_sid_size", ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_info(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise DiagnosticFailure("query_current_user_sid", ctypes.get_last_error())
        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]
        class TokenUser(ctypes.Structure):
            _fields_ = [("User", SidAndAttributes)]
        user = ctypes.cast(buffer, ctypes.POINTER(TokenUser)).contents
        if not user.User.Sid:
            raise DiagnosticFailure("current_user_sid_missing")
        return _sid_to_string(advapi32, kernel32, ctypes.c_void_p(user.User.Sid))
    finally:
        kernel32.CloseHandle(token)


def _set_protected_dacl(path: Path, sddl: str) -> None:
    kernel32, advapi32, _ = _win_api()
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, wintypes.DWORD,
                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD(0)
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)):
        raise DiagnosticFailure("convert_sddl", ctypes.get_last_error())
    try:
        present = wintypes.BOOL(False)
        defaulted = wintypes.BOOL(False)
        dacl = ctypes.c_void_p()
        get_dacl = advapi32.GetSecurityDescriptorDacl
        get_dacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        get_dacl.restype = wintypes.BOOL
        if not get_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                        ctypes.byref(defaulted)) or not present.value or not dacl.value:
            raise DiagnosticFailure("read_sddl_dacl", ctypes.get_last_error())
        set_named = advapi32.SetNamedSecurityInfoW
        set_named.argtypes = [ctypes.c_wchar_p, ctypes.c_int, wintypes.DWORD,
                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_void_p]
        set_named.restype = wintypes.DWORD
        # SE_FILE_OBJECT=1; DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        result = int(set_named(str(path), 1, 0x00000004 | 0x80000000,
                               None, None, dacl, None))
        if result:
            raise DiagnosticFailure("set_protected_dacl", result)
    finally:
        kernel32.LocalFree(descriptor)


def _compile_probe(build_dir: Path) -> tuple[Path, str, str]:
    program_files = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        raise DiagnosticFailure("vswhere_unavailable")
    located = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", shell=False, timeout=30, check=False,
    )
    if located.returncode != 0 or not located.stdout.strip():
        raise DiagnosticFailure("visual_studio_not_found", located.returncode)
    installation = Path(located.stdout.strip().splitlines()[-1])
    devcmd = installation / "Common7" / "Tools" / "VsDevCmd.bat"
    if not devcmd.is_file():
        raise DiagnosticFailure("vs_developer_command_unavailable")

    source = Path(__file__).resolve().with_name("probe.c")
    executable = build_dir / "lpac_token_identity_probe.exe"
    object_file = build_dir / "lpac_token_identity_probe.obj"
    command = (
        f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && '
        'echo WINDOWS_SDK_VERSION=%WindowsSDKVersion% && '
        f'cl /nologo /W4 /WX /MT /DUNICODE /D_UNICODE /TC "{source}" '
        f'/Fo:"{object_file}" /Fe:"{executable}" /link advapi32.lib userenv.lib'
    )
    compiled = subprocess.run(
        ["cmd.exe", "/d", "/c", command], cwd=str(build_dir),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", shell=False,
        timeout=120, check=False,
    )
    output = compiled.stdout
    if compiled.returncode != 0 or not executable.is_file():
        raise DiagnosticFailure("native_probe_compile_failed", compiled.returncode)
    sdk_match = re.search(r"WINDOWS_SDK_VERSION=([^\s]+)", output, flags=re.IGNORECASE)
    compiler_match = re.search(r"Microsoft.*?Version\s+([^\s]+)", output, flags=re.IGNORECASE)
    sdk_version = sdk_match.group(1) if sdk_match else "not_reported"
    compiler_version = compiler_match.group(1) if compiler_match else "not_reported"
    return executable, sdk_version, compiler_version


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8")


def _control_passes(control: Any, expected_lpac: bool) -> bool:
    expected_access = 2 if expected_lpac else 3
    if not isinstance(control, dict) or control.get("requested_lpac") is not expected_lpac:
        return False
    appcontainer = control.get("appcontainer_query", {})
    sid = control.get("appcontainer_sid", {})
    integrity = control.get("integrity", {})
    capabilities = control.get("capabilities", {})
    access = control.get("access_check", {})
    cleanup = control.get("cleanup", {})
    queries = control.get("class46_queries", [])
    return bool(
        control.get("process_created") is True
        and control.get("job_membership_verified") is True
        and control.get("job_active_before") == 1
        and control.get("job_total_before") == 1
        and control.get("token_opened") is True
        and appcontainer.get("class") == 29
        and appcontainer.get("buffer_size") == 4
        and appcontainer.get("return_length") == 4
        and appcontainer.get("success") is True
        and appcontainer.get("value") == 1
        and sid.get("success") is True
        and sid.get("expected_sid_match") is True
        and integrity.get("success") is True
        and integrity.get("rid") == 4096
        and capabilities.get("success") is True
        and capabilities.get("count") == 0
        and access.get("success") is True
        and access.get("access_granted") is True
        and access.get("granted_access") == expected_access
        and access.get("expected_access") == expected_access
        and len(queries) == 3
        and [q.get("buffer_size") for q in queries] == [0, 4, 8]
        and all("return_length" in q and "win32_error" in q for q in queries)
        and cleanup.get("process_signaled") is True
        and cleanup.get("job_query_succeeded") is True
        and cleanup.get("job_active_processes") == 0
        and cleanup.get("job_total_processes") == 1
        and cleanup.get("job_empty") is True
        and cleanup.get("process_handle_closed") is True
        and cleanup.get("thread_handle_closed") is True
        and cleanup.get("job_handle_closed") is True
        and cleanup.get("attributes_deleted") is True
        and control.get("passed") is True
    )


def main() -> int:
    output_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    evidence_path = output_dir / "lpac-token-identity-diagnostic.json"
    evidence: dict[str, Any] = {
        "schema": "lpac-token-identity-runner-v1",
        "source_commit": os.environ.get("GITHUB_SHA", "local"),
        "runner_image": os.environ.get("ImageOS"),
        "runner_image_version": os.environ.get("ImageVersion"),
        "windows_version": platform.version() if sys.platform == "win32" else None,
        "windows_build": (sys.getwindowsversion().build if sys.platform == "win32" else None),
        "windows_sdk_version": None,
        "compiler_version": None,
        "mission_started": False,
        "network_tests_run": False,
        "storage_tests_run": False,
        "profile_registration_attempted": False,
        "native_probe": None,
        "probe_return_code": None,
        "scratch_cleanup_succeeded": False,
        "status": "INCONCLUSIVE",
    }
    scratch_root: Path | None = None
    success = False

    try:
        if sys.platform != "win32":
            raise DiagnosticFailure("windows_only")
        with tempfile.TemporaryDirectory(prefix="lpac-token-id-build-") as build_name:
            executable, sdk_version, compiler_version = _compile_probe(Path(build_name))
            evidence["windows_sdk_version"] = sdk_version
            evidence["compiler_version"] = compiler_version

            sid = _derive_unregistered_appcontainer_sid()
            user_sid = _current_user_sid()
            system_drive = os.environ.get("SystemDrive") or Path(os.environ["SystemRoot"]).drive
            system_drive_root = Path(system_drive + "\\")
            scratch_root = system_drive_root / f"cs-lpac-token-identity-{uuid.uuid4().hex}"
            scratch_root.mkdir()
            _set_protected_dacl(
                scratch_root,
                f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})(A;OICI;0x00100020;;;{sid})",
            )
            control_dir = scratch_root / "control"
            control_dir.mkdir()
            _set_protected_dacl(
                control_dir,
                f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})(A;OICI;0x001200A9;;;{sid})",
            )
            probe_path = control_dir / executable.name
            shutil.copy2(executable, probe_path)
            minimal_env = {
                "SystemRoot": os.environ["SystemRoot"],
                "PATH": str(Path(os.environ["SystemRoot"]) / "System32"),
            }
            process = subprocess.run(
                [str(probe_path), "--diagnostic", sid], cwd=str(control_dir),
                env=minimal_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                shell=False, timeout=60, check=False,
            )
            evidence["probe_return_code"] = process.returncode
            evidence["probe_stderr_nonempty"] = bool(process.stderr.strip())
            try:
                evidence["native_probe"] = json.loads(process.stdout.strip().splitlines()[-1])
            except (IndexError, json.JSONDecodeError):
                evidence["native_probe"] = {"json_report_received": False}
            probe_report = evidence["native_probe"]
            success = bool(
                process.returncode == 0
                and isinstance(probe_report, dict)
                and probe_report.get("schema") == "lpac-token-identity-diagnostic-v1"
                and probe_report.get("token_information_class") == 46
                and probe_report.get("resume_attempted") is False
                and probe_report.get("mission_started") is False
                and probe_report.get("network_tests_run") is False
                and probe_report.get("storage_tests_run") is False
                and probe_report.get("profile_registration_attempted") is False
                and _control_passes(probe_report.get("ordinary_appcontainer"), False)
                and _control_passes(probe_report.get("lpac_candidate"), True)
                and probe_report.get("passed") is True
            )
    except DiagnosticFailure as exc:
        evidence["setup_failure_stage"] = exc.stage
        evidence["setup_failure_code"] = exc.code
    except subprocess.TimeoutExpired:
        evidence["setup_failure_stage"] = "native_probe_timeout"
    except Exception as exc:  # Keep artifacts bounded and avoid copying paths or raw output.
        evidence["setup_failure_stage"] = f"unexpected_{type(exc).__name__}"
    finally:
        if scratch_root is not None:
            try:
                shutil.rmtree(scratch_root)
                evidence["scratch_cleanup_succeeded"] = not scratch_root.exists()
            except OSError:
                evidence["scratch_cleanup_succeeded"] = False
        if not evidence["scratch_cleanup_succeeded"]:
            success = False
        evidence["status"] = "PASS" if success else "INCONCLUSIVE"
        _write_evidence(evidence_path, evidence)
        print(f"Sanitized token-identity evidence written; status={evidence['status']}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
