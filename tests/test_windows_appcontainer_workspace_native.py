from __future__ import annotations

import ctypes
from contextlib import contextmanager
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest


_WINDOWS_NATIVE = pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows AppContainer and LPAC support")
_ERROR_ACCESS_DENIED = 5
_FILE_READ_EXECUTE = 0x001200A9
_FILE_REPORT = 0x001301BF
_FILE_TRAVERSE = 0x00100020
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_LABEL_SECURITY_INFORMATION = 0x00000010
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_FILE_OBJECT = 1


def _run_compile_command(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run only the test's fixed VS developer setup and cl compile command."""
    # cmd.exe does not parse Python list2cmdline's backslash-escaped embedded
    # quotes. Keep the trusted fixed command in a batch file and pass only its
    # path through argv, preserving spaces in the Visual Studio installation.
    script = cwd / "compile-native-probe.cmd"
    # The ASCII prefix changes cmd's active code page before it reads the next
    # UTF-8 command line, including non-ASCII account/temp/repository paths.
    prefix = "@echo off\r\nchcp 65001 >nul\r\nif errorlevel 1 exit /b %errorlevel%\r\n"
    script.write_bytes((prefix + command + "\r\nexit /b %errorlevel%\r\n").encode("utf-8"))
    return subprocess.run(
        ["cmd.exe", "/d", "/c", str(script)],
        cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
        shell=False, timeout=120, check=False,
    )


@pytest.fixture(scope="session")
def native_probe_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the trusted probe once with the static CRT; unavailable VS is a failure."""
    if sys.platform != "win32":
        pytest.fail("native probe compilation fixture was requested off Windows")
    repo = Path(__file__).resolve().parents[1]
    source = repo / "tests" / "native" / "appcontainer_acl_probe.c"
    assert source.is_file(), f"trusted C source is missing: {source}"
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        pytest.fail(f"Visual Studio locator unavailable: {vswhere}")
    located = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", shell=False, timeout=30, check=False,
    )
    if located.returncode != 0 or not located.stdout.strip():
        pytest.fail(f"Visual Studio C++ toolchain is unavailable: {located.stderr[-1000:]}")
    installation = Path(located.stdout.strip().splitlines()[-1])
    devcmd = installation / "Common7" / "Tools" / "VsDevCmd.bat"
    if not devcmd.is_file():
        pytest.fail(f"VS developer command is unavailable: {devcmd}")
    build_dir = tmp_path_factory.mktemp("native-appcontainer-probe-build")
    exe = build_dir / "appcontainer_acl_probe.exe"
    obj_dir = build_dir / "obj"
    obj_dir.mkdir()
    obj_file = obj_dir / "appcontainer_acl_probe.obj"
    command = (
        f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && '
        f'cl /nologo /W4 /WX /MT /DUNICODE /D_UNICODE /TC '
        f'"{source}" /Fo:"{obj_file}" /Fe:"{exe}" /link advapi32.lib userenv.lib'
    )
    compiled = _run_compile_command(command, build_dir)
    if compiled.returncode != 0 or not exe.is_file():
        pytest.fail(f"native LPAC probe compilation failed ({compiled.returncode}):\n{compiled.stdout[-6000:]}")
    return exe


@pytest.fixture
def native_acl_root(record_property):
    """Do not require traversal of the broker's private user-profile path."""
    if sys.platform != "win32":
        pytest.fail("native root fixture was requested off Windows")
    system_root = Path(os.environ["SystemRoot"])
    assert system_root.is_absolute() and not system_root.drive.startswith("\\\\"), "Windows system root must be local and absolute"
    parent = Path(system_root.anchor)
    assert parent.is_dir(), "Windows system volume root is unavailable"
    root = parent / f"cs-native-lpac-{uuid.uuid4().hex}"
    root.mkdir()  # Atomic collision rejection; never adopt a preexisting path.
    try:
        _create_protected_test_root(root)
        record_property("native_control_root", str(root))
        yield root
    finally:
        shutil.rmtree(root)


def _win_dll(name: str):
    dll = ctypes.WinDLL(name, use_last_error=True)
    handle = ctypes.c_void_p
    dword = ctypes.c_ulong
    if name.lower() == "kernel32.dll":
        dll.GetCurrentProcess.argtypes = []
        dll.GetCurrentProcess.restype = handle
        dll.CloseHandle.argtypes = [handle]
        dll.CloseHandle.restype = ctypes.c_int
        dll.LocalFree.argtypes = [handle]
        dll.LocalFree.restype = handle
    elif name.lower() == "advapi32.dll":
        dll.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
        dll.OpenProcessToken.restype = ctypes.c_int
        dll.GetTokenInformation.argtypes = [handle, ctypes.c_int, handle, dword, ctypes.POINTER(dword)]
        dll.GetTokenInformation.restype = ctypes.c_int
        dll.ConvertSidToStringSidW.argtypes = [handle, ctypes.POINTER(ctypes.c_wchar_p)]
        dll.ConvertSidToStringSidW.restype = ctypes.c_int
        dll.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, handle]
        dll.LookupPrivilegeValueW.restype = ctypes.c_int
        dll.AdjustTokenPrivileges.argtypes = [handle, ctypes.c_int, handle, dword, handle, ctypes.POINTER(dword)]
        dll.AdjustTokenPrivileges.restype = ctypes.c_int
        dll.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [ctypes.c_wchar_p, dword, ctypes.POINTER(handle), ctypes.POINTER(dword)]
        dll.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
        for function in (dll.GetSecurityDescriptorDacl, dll.GetSecurityDescriptorSacl):
            function.argtypes = [handle, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(handle), ctypes.POINTER(ctypes.c_int)]
            function.restype = ctypes.c_int
        dll.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, dword, handle, handle, handle, handle]
        dll.SetNamedSecurityInfoW.restype = dword
        dll.GetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, dword, ctypes.POINTER(handle), ctypes.POINTER(handle), ctypes.POINTER(handle), ctypes.POINTER(handle), ctypes.POINTER(handle)]
        dll.GetNamedSecurityInfoW.restype = dword
        dll.GetSecurityDescriptorControl.argtypes = [handle, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(dword)]
        dll.GetSecurityDescriptorControl.restype = ctypes.c_int
        dll.GetAce.argtypes = [handle, dword, ctypes.POINTER(handle)]
        dll.GetAce.restype = ctypes.c_int
    elif name.lower() == "ole32.dll":
        dll.CoTaskMemFree.argtypes = [handle]
        dll.CoTaskMemFree.restype = None
    return dll


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    advapi, kernel = _win_dll("advapi32.dll"), _win_dll("kernel32.dll")
    text = ctypes.c_wchar_p()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _broker_sid() -> str:
    advapi, kernel = _win_dll("advapi32.dll"), _win_dll("kernel32.dll")
    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = ctypes.c_ulong()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value < ctypes.sizeof(ctypes.c_void_p):
            raise AssertionError("GetTokenInformation(TokenUser) returned an invalid size")
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buf, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        return _sid_to_string(sid)
    finally:
        kernel.CloseHandle(token)


@contextmanager
def _security_privilege(name: str):
    """Enable one security privilege for this process and restore its prior state."""
    advapi, kernel = _win_dll("advapi32.dll"), _win_dll("kernel32.dll")

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_ulong)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    previous = TOKEN_PRIVILEGES()
    previous_size = ctypes.c_ulong()
    try:
        luid = LUID()
        if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        requested = TOKEN_PRIVILEGES()
        requested.PrivilegeCount = 1
        requested.Privileges[0].Luid = luid
        requested.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not advapi.AdjustTokenPrivileges(token, False, ctypes.byref(requested), ctypes.sizeof(previous),
                                            ctypes.byref(previous), ctypes.byref(previous_size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED
            raise PermissionError("test broker lacks SeSecurityPrivilege required for mandatory-label evidence")
        try:
            yield
        finally:
            if previous_size.value and not advapi.AdjustTokenPrivileges(token, False, ctypes.byref(previous), 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)


def _apply_sddl(path: Path, sddl: str) -> None:
    """Apply test-only exact-SID ACLs without adding a production ACL API."""
    advapi, kernel = _win_dll("advapi32.dll"), _win_dll("kernel32.dll")
    descriptor, size = ctypes.c_void_p(), ctypes.c_ulong()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    if not convert(sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        dacl, dacl_present, dacl_defaulted = ctypes.c_void_p(), ctypes.c_int(), ctypes.c_int()
        if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(dacl_present), ctypes.byref(dacl), ctypes.byref(dacl_defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        info = _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION
        sacl = ctypes.c_void_p()
        if "S:" in sddl:
            present, defaulted = ctypes.c_int(), ctypes.c_int()
            if not advapi.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
                raise ctypes.WinError(ctypes.get_last_error())
            if present.value:
                info |= _LABEL_SECURITY_INFORMATION
        fn = advapi.SetNamedSecurityInfoW
        if info & _LABEL_SECURITY_INFORMATION:
            with _security_privilege("SeSecurityPrivilege"):
                status = fn(str(path), _SE_FILE_OBJECT, info, None, None, dacl if dacl_present.value else None, sacl)
        else:
            status = fn(str(path), _SE_FILE_OBJECT, info, None, None, dacl if dacl_present.value else None, sacl)
        if status:
            raise OSError(status, f"SetNamedSecurityInfoW failed for {path}")
    finally:
        kernel.LocalFree(descriptor)


def _get_security(path: Path, include_label: bool = False) -> tuple[list[dict[str, Any]], str | None, list[tuple[str, int]], bool]:
    """Return ACE metadata, owner SID and mandatory-label ACEs for assertions."""
    advapi, kernel = _win_dll("advapi32.dll"), _win_dll("kernel32.dll")
    dacl, owner, sacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    info = _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION | (_LABEL_SECURITY_INFORMATION if include_label else 0)
    fn = advapi.GetNamedSecurityInfoW
    if include_label:
        with _security_privilege("SeSecurityPrivilege"):
            status = fn(str(path), _SE_FILE_OBJECT, info, ctypes.byref(owner), None, ctypes.byref(dacl), ctypes.byref(sacl), ctypes.byref(descriptor))
    else:
        status = fn(str(path), _SE_FILE_OBJECT, info, ctypes.byref(owner), None, ctypes.byref(dacl), ctypes.byref(sacl), ctypes.byref(descriptor))
    if status:
        raise OSError(status, f"GetNamedSecurityInfoW failed for {path}")
    entries: list[dict[str, Any]] = []
    labels: list[tuple[str, int]] = []
    dacl_protected = False
    try:
        if owner.value:
            owner_text = _sid_to_string(owner)
        else:
            owner_text = None
        control, revision = ctypes.c_ushort(), ctypes.c_ulong()
        get_control = advapi.GetSecurityDescriptorControl
        if descriptor.value and get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            dacl_protected = bool(control.value & 0x1000)  # SE_DACL_PROTECTED
        class ACL_HEADER(ctypes.Structure):
            _fields_ = [("revision", ctypes.c_ubyte), ("sbz1", ctypes.c_ubyte), ("size", ctypes.c_ushort), ("count", ctypes.c_ushort), ("sbz2", ctypes.c_ushort)]
        if dacl.value:
            acl = ctypes.cast(dacl, ctypes.POINTER(ACL_HEADER)).contents
            get_ace = advapi.GetAce
            get_ace.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
            get_ace.restype = ctypes.c_int
            for index in range(acl.count):
                ace = ctypes.c_void_p()
                if not get_ace(dacl, index, ctypes.byref(ace)):
                    raise ctypes.WinError(ctypes.get_last_error())
                head = ctypes.string_at(ace, 8)
                ace_type, flags = head[0], head[1]
                if ace_type in (0, 1, 2, 3):
                    mask = int.from_bytes(head[4:8], "little")
                    sid = _sid_to_string(ctypes.c_void_p(ace.value + 8))
                    entries.append({"type": ace_type, "flags": flags, "mask": mask, "sid": sid})
                else:
                    # Refuse to silently bless object/callback/unknown ACE layouts.
                    entries.append({"type": ace_type, "flags": flags, "mask": int.from_bytes(head[4:8], "little"), "sid": None})
        if include_label and sacl.value:
            acl = ctypes.cast(sacl, ctypes.POINTER(ACL_HEADER)).contents
            get_ace = advapi.GetAce
            for index in range(acl.count):
                ace = ctypes.c_void_p()
                if not get_ace(sacl, index, ctypes.byref(ace)):
                    raise ctypes.WinError(ctypes.get_last_error())
                head = ctypes.string_at(ace, 8)
                if head[0] == 17:  # SYSTEM_MANDATORY_LABEL_ACE_TYPE
                    labels.append((_sid_to_string(ctypes.c_void_p(ace.value + 8)), int.from_bytes(head[4:8], "little")))
        return entries, owner_text, labels, dacl_protected
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def _prepare_root_and_probe(root: Path, workspace: Any, template: Path, extra_sids: tuple[str, ...] = ()) -> Path:
    broker = _broker_sid()
    all_sids = tuple(dict.fromkeys((workspace.sid_string, *extra_sids)))
    root.mkdir(parents=True, exist_ok=True)
    traverse = "".join(f"(A;;0x{_FILE_TRAVERSE:08X};;;{sid})" for sid in all_sids)
    _apply_sddl(root, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker}){traverse}")
    control = root / "native-control"
    control.mkdir()
    rx = "".join(f"(A;OICI;0x{_FILE_READ_EXECUTE:08X};;;{sid})" for sid in all_sids)
    _apply_sddl(control, f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{broker}){rx}")
    executable = control / "appcontainer_acl_probe.exe"
    shutil.copy2(template, executable)
    # The protected control directory grants only per-run SID READ+EXECUTE; the
    # configured root grants only SID-specific traversal, never broad access.
    return executable


def _create_protected_test_root(root: Path) -> None:
    """Create a broker/SYSTEM-only protected root before production setup runs."""
    broker = _broker_sid()
    root.mkdir(parents=True, exist_ok=True)
    _apply_sddl(root, f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{broker})")


def _make_directory(path: Path, sddl: str) -> None:
    path.mkdir()
    _apply_sddl(path, sddl)


def _make_file(path: Path, data: bytes, sddl: str) -> None:
    path.write_bytes(data)
    _apply_sddl(path, sddl)


def _profile_artifacts(workspace: Any) -> dict[str, Any]:
    """Check known profile paths, exact per-SID mapping key, and the OS folder API."""
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    candidates = [local / "Packages" / workspace.identity_name, local / "Packages" / workspace.sid_string]
    registry_prefix = "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer"
    import winreg
    registry_keys = {
        "mapping_exists": registry_prefix + "\\Mappings\\" + workspace.sid_string,
        "storage_exists": registry_prefix + "\\Storage\\" + workspace.sid_string,
    }
    registry_state: dict[str, bool] = {}
    for key, registry_path in registry_keys.items():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_READ):
                registry_state[key] = True
        except FileNotFoundError:
            registry_state[key] = False
        except OSError as exc:
            raise AssertionError(f"could not check exact AppContainer registry key {key}: {exc}") from exc

    folder_result: dict[str, Any] = {"lookup_hresult": None, "lookup_succeeded": False, "folder_exists": None}
    userenv = _win_dll("userenv.dll")
    get_folder = getattr(userenv, "GetAppContainerFolderPath", None)
    if get_folder is not None:
        get_folder.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_wchar_p)]
        get_folder.restype = ctypes.c_long
        path_ptr = ctypes.c_wchar_p()
        try:
            hr = int(get_folder(workspace.sid_string, ctypes.byref(path_ptr)))
            folder_result["lookup_hresult"] = hr
            folder_result["lookup_succeeded"] = hr == 0
            if hr == 0 and path_ptr.value:
                folder = Path(path_ptr.value)
                folder_result.update({"folder": str(folder), "folder_exists": folder.exists()})
                candidates.append(folder)
        finally:
            if path_ptr.value:
                # The API's allocated path is freed with CoTaskMemFree.
                _win_dll("ole32.dll").CoTaskMemFree(ctypes.cast(path_ptr, ctypes.c_void_p))
    return {
        **registry_state,
        "candidate_paths": [str(p) for p in candidates],
        "existing_candidate_paths": [str(p) for p in candidates if p.exists()],
        "folder_api": folder_result,
    }


def _assert_profileless(workspace: Any, phase: str, record_property) -> None:
    artifacts = _profile_artifacts(workspace)
    record_property(f"profile_storage_{phase}", json.dumps(artifacts, sort_keys=True))
    assert not artifacts["mapping_exists"] and not artifacts["storage_exists"], f"unexpected AppContainer profile/storage registry key during {phase}: {artifacts}"
    assert not artifacts["existing_candidate_paths"], f"unexpected AppContainer profile directory during {phase}: {artifacts}"
    folder_api = artifacts["folder_api"]
    assert not (folder_api["lookup_succeeded"] and folder_api["folder_exists"]), f"GetAppContainerFolderPath exists during {phase}: {artifacts}"


def _launch(probe: Path, workspace: Any, mode: str, arg1: Path, arg2: Path, report: Path, record_property) -> dict[str, Any]:
    argv = [str(probe), "--launch", workspace.sid_string, mode, str(workspace.workspace_path), str(arg1), str(arg2), str(report)]
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        stdout, stderr = process.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        raise AssertionError("native LPAC launcher exceeded its bounded 40-second deadline")
    if process.returncode != 0:
        record_property("parent_launch_return_code", str(process.returncode))
        diagnostic = _launch_failure_diagnostic(stderr)
        if diagnostic is not None:
            record_property("parent_launch_failure_diagnostic", json.dumps(diagnostic, sort_keys=True))
    assert process.returncode == 0, f"LPAC launcher/child failed ({process.returncode}); stdout={stdout[-1000:]}; stderr={stderr[-2000:]}"
    assert report.is_file(), f"LPAC child produced no bounded JSON evidence at {report}"
    evidence = json.loads(report.read_text(encoding="utf-8"))
    assert evidence["version"] == 2 and evidence["token_verified"] is True
    pre_prefix = "pre_resume_attestation: "
    post_prefix = "post_exit_job_attestation: "
    pre = next((json.loads(line[len(pre_prefix):]) for line in stderr.splitlines() if line.startswith(pre_prefix)), None)
    post = next((json.loads(line[len(post_prefix):]) for line in stderr.splitlines() if line.startswith(post_prefix)), None)
    assert isinstance(pre, dict) and all(pre.get(field) is True for field in (
        "token_verified", "is_appcontainer", "is_lpac", "low_integrity",
        "expected_sid_match", "zero_capabilities", "job_membership_verified",
    )), "pre-resume token/Job attestation missing or invalid"
    assert isinstance(post, dict) and post.get("active_processes") == 0 and post.get("total_processes") == 1, \
        "post-exit Job-empty attestation missing or invalid"
    record_property("parent_pre_resume_attestation", json.dumps(pre, sort_keys=True))
    record_property("parent_post_exit_job_attestation", json.dumps(post, sort_keys=True))
    return evidence


_LAUNCH_FAILURE_STEPS = frozenset({
    "parse child SID", "open child token", "child LPAC token verification", "write bounded evidence report",
    "parse launcher SID", "allocate process attribute list", "set LPAC process attributes",
    "build child command line", "build restricted child environment", "child environment too large",
    "create bounded child job", "CreateProcessW LPAC", "assign LPAC child to kill-on-close job",
    "verify suspended LPAC child job membership", "suspended LPAC child token verification",
    "resume LPAC child", "bounded LPAC child wait", "read child exit code",
    "query completed LPAC job accounting", "LPAC job did not become empty",
})
_LAUNCH_DIAGNOSTIC_BOOL_FIELDS = (
    "image_is_absolute", "image_is_file", "parent_can_read_image", "image_size_available",
    "cwd_is_absolute", "cwd_is_directory", "module_matches_image", "ntstatus_available",
)
_LAUNCH_DIAGNOSTIC_INT_FIELDS = (
    "win32_error", "image_attributes_error", "image_open_error", "image_size_bytes",
    "image_size_error", "cwd_attributes_error", "known_dependency_mask",
    "known_dependency_expected_mask", "system_directory_error", "broker_bitness", "launch_flags",
)


def _launch_failure_diagnostic(stderr: str) -> dict[str, Any] | None:
    """Extract only fixed failure labels and broker-only scalar diagnostics."""
    result: dict[str, Any] = {}
    prefix = "lpac_launch_diagnostic: "
    for line in stderr.splitlines():
        match = re.fullmatch(r"probe failure: ([A-Za-z0-9 _-]+) \(([0-9]{1,10})\)", line.strip())
        if match and match.group(1) in _LAUNCH_FAILURE_STEPS:
            result["failure_step"] = match.group(1)
            result["failure_win32_error"] = int(match.group(2))
        if not line.startswith(prefix):
            continue
        try:
            value = json.loads(line[len(prefix):])
        except (TypeError, ValueError):
            continue
        if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 2 or value.get("scope") != "broker_only":
            continue
        diagnostic: dict[str, Any] = {"version": 2, "scope": "broker_only"}
        for field in _LAUNCH_DIAGNOSTIC_BOOL_FIELDS:
            if type(value.get(field)) is bool:
                diagnostic[field] = value[field]
        for field in _LAUNCH_DIAGNOSTIC_INT_FIELDS:
            if type(value.get(field)) is int:
                diagnostic[field] = value[field]
        ntstatus = value.get("ntstatus_advisory")
        if isinstance(ntstatus, str) and re.fullmatch(r"0x[0-9A-Fa-f]{8}", ntstatus):
            diagnostic["ntstatus_advisory"] = ntstatus
        result["create_process"] = diagnostic
    return result or None


def test_launch_failure_diagnostic_is_allowlisted() -> None:
    diagnostic = {
        "version": 2, "scope": "broker_only", "win32_error": 17,
        "image_is_absolute": True, "image_is_file": True, "parent_can_read_image": True,
        "image_size_available": True, "image_size_bytes": 4096, "cwd_is_absolute": True,
        "cwd_is_directory": True, "module_matches_image": True, "known_dependency_mask": 15,
        "known_dependency_expected_mask": 15, "broker_bitness": 64, "launch_flags": 0x8000,
        "ntstatus_available": True, "ntstatus_advisory": "0xC0000005",
        "broker_pid": 1234, "raw_windows_path": r"C:\private\sensitive",
    }
    parsed = _launch_failure_diagnostic(
        "probe failure: CreateProcessW LPAC (17)\n"
        "lpac_launch_diagnostic: " + json.dumps(diagnostic)
    )
    assert parsed is not None
    assert parsed["failure_step"] == "CreateProcessW LPAC"
    assert parsed["failure_win32_error"] == 17
    assert parsed["create_process"]["win32_error"] == 17
    assert "broker_pid" not in json.dumps(parsed) and "raw_windows_path" not in json.dumps(parsed)
    assert "sensitive" not in json.dumps(parsed)


def _assert_check(evidence: dict[str, Any], name: str, ok: bool = True, error: int = 0) -> None:
    matches = [item for item in evidence["checks"] if item["name"] == name]
    assert len(matches) == 1, f"evidence did not contain exactly one {name}: {evidence}"
    assert matches[0]["ok"] is ok and matches[0]["error"] == error, f"unexpected native result for {name}: {matches[0]}"


@_WINDOWS_NATIVE
def test_native_lpac_identity_and_workspace_read_write(native_acl_root: Path, native_probe_template: Path, record_property) -> None:
    from workspace.windows_appcontainer_workspace import WindowsAppContainerWorkspace, AppContainerWorkspaceError

    root = native_acl_root
    _create_protected_test_root(root)
    workspace = WindowsAppContainerWorkspace.create(root)
    try:
        assert len(workspace.run_id) == 32 and uuid.UUID(hex=workspace.run_id).hex == workspace.run_id
        assert workspace.identity_name == f"cs.{workspace.run_id}"
        assert workspace.sid_string.startswith("S-1-15-2-")
        record_property("run_id", workspace.run_id)
        record_property("identity_name", workspace.identity_name)
        record_property("sid", workspace.sid_string)
        record_property("workspace_path", str(workspace.workspace_path))
        _assert_profileless(workspace, "before_launch", record_property)

        probe = _prepare_root_and_probe(root, workspace, native_probe_template)
        entries, owner, _, protected = _get_security(workspace.workspace_path)
        assert owner == _broker_sid(), f"workspace owner is not the broker SID: {owner}"
        assert owner != workspace.sid_string, "AppContainer unexpectedly owns the sandbox directory"
        assert protected, "workspace DACL is not protected from inherited ACL entries"
        assert all(not (entry["flags"] & 0x10) for entry in entries), f"workspace DACL contains inherited ACEs: {entries}"
        broad_sids = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-15-2-1", "S-1-15-2-2"}
        assert not any(entry["sid"] in broad_sids and entry["type"] == 0 for entry in entries), f"workspace has a broad allow grant (including ALL APPLICATION PACKAGES): {entries}"
        assert all(entry["sid"] is not None for entry in entries), f"unparsed or object-specific DACL ACE could hide a grant: {entries}"
        app_aces = [entry for entry in entries if entry["sid"] == workspace.sid_string and entry["type"] == 0]
        assert app_aces, f"no exact AppContainer allow ACE in workspace DACL: {entries}"
        assert all((entry["mask"] & 0x000C0000) == 0 for entry in app_aces), f"sandbox SID has WRITE_DAC/WRITE_OWNER: {app_aces}"
        record_property("workspace_acl_appcontainer_masks", ",".join(hex(e["mask"]) for e in app_aces))

        report = workspace.workspace_path / "native-evidence.json"
        evidence = _launch(probe, workspace, "rw", Path("ignored-file"), Path("ignored-dir"), report, record_property)
        _assert_check(evidence, "environment_minimal")
        for check in ("workspace_write", "workspace_read", "nested_directory_create", "nested_file_write"):
            _assert_check(evidence, check)
        _assert_check(evidence, "workspace_file_dacl_tamper_denied", error=_ERROR_ACCESS_DENIED)
        _assert_check(evidence, "workspace_file_owner_change_denied", error=_ERROR_ACCESS_DENIED)
        record_property("native_identity_evidence", json.dumps(evidence, sort_keys=True))
        _assert_profileless(workspace, "after_launch", record_property)

        # A directory junction must be rejected if this Windows runner permits
        # creating one; this is a probe, not a skip of any required native test.
        junction = root / "root-reparse-probe"
        linked = False
        try:
            os.symlink(str(workspace.workspace_path), junction, target_is_directory=True)
            linked = True
        except OSError as exc:
            record_property("reparse_probe", f"not_available_winerror_{getattr(exc, 'winerror', None)}")
        if linked:
            with pytest.raises(AppContainerWorkspaceError) as caught:
                WindowsAppContainerWorkspace.create(junction)
            assert caught.value.code == "reparse_root"
            record_property("reparse_probe", "junction_rejected")
            junction.rmdir()
    finally:
        workspace.close()
        assert not workspace.cleanup_required


@_WINDOWS_NATIVE
def test_native_lpac_denies_outside_write_and_create(native_acl_root: Path, native_probe_template: Path, record_property) -> None:
    from workspace.windows_appcontainer_workspace import WindowsAppContainerWorkspace

    root = native_acl_root
    _create_protected_test_root(root)
    workspace = WindowsAppContainerWorkspace.create(root)
    try:
        probe = _prepare_root_and_probe(root, workspace, native_probe_template)
        broker = _broker_sid()
        outside = root / "broker-writable-low"
        _make_directory(outside, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})S:(ML;OICI;NW;;;LW)")
        victim = outside / "existing.bin"
        payload = b"broker-owned low mandatory label sentinel"
        _make_file(victim, payload, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})S:(ML;;NW;;;LW)")
        _make_file(outside / "write-check.bin", b"DACL not MIC sentinel", f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})S:(ML;;NW;;;LW)")
        dir_entries, _, dir_labels, _ = _get_security(outside, include_label=True)
        file_entries, _, file_labels, _ = _get_security(victim, include_label=True)
        assert dir_labels == [("S-1-16-4096", 1)], f"outside directory is not low-labeled: {dir_labels}"
        assert file_labels == [("S-1-16-4096", 1)], f"outside file is not low-labeled: {file_labels}"
        assert not any(e["sid"] == "S-1-15-2-1" for e in (*dir_entries, *file_entries))
        report = workspace.workspace_path / "outside-evidence.json"
        evidence = _launch(probe, workspace, "outside", victim, outside, report, record_property)
        _assert_check(evidence, "environment_minimal")
        for check in ("outside_existing_file_write", "outside_new_file_create", "outside_directory_create"):
            _assert_check(evidence, check, error=_ERROR_ACCESS_DENIED)
        assert victim.read_bytes() == payload, "LPAC changed the broker's low-label sentinel"
        assert not (outside / "new.bin").exists() and not (outside / "newdir").exists()
        record_property("outside_denial_evidence", json.dumps(evidence, sort_keys=True))
        _assert_profileless(workspace, "after_launch", record_property)
    finally:
        workspace.close()


@_WINDOWS_NATIVE
def test_native_lpac_denies_other_run_workspace(native_acl_root: Path, native_probe_template: Path, record_property) -> None:
    from workspace.windows_appcontainer_workspace import WindowsAppContainerWorkspace

    root = native_acl_root
    _create_protected_test_root(root)
    first = WindowsAppContainerWorkspace.create(root)
    second = None
    try:
        second = WindowsAppContainerWorkspace.create(root)
        assert first.run_id != second.run_id and first.sid_string != second.sid_string
        probe = _prepare_root_and_probe(root, first, native_probe_template, (second.sid_string,))
        # Existing, broker-created second-run file is explicitly LOW integrity so
        # only its DACL (not MIC) can explain denial by the first run identity.
        other_file = second.workspace_path / "cross-run-sentinel.bin"
        _make_file(other_file, b"second run stays intact", f"D:P(A;;FA;;;SY)(A;;FA;;;{_broker_sid()})(A;;0x{_FILE_REPORT:08X};;;{second.sid_string})S:(ML;;NW;;;LW)")
        first_report = first.workspace_path / "isolation-evidence.json"
        evidence = _launch(probe, first, "isolation", other_file, Path("ignored"), first_report, record_property)
        _assert_check(evidence, "environment_minimal")
        _assert_check(evidence, "other_workspace_read_denied", error=_ERROR_ACCESS_DENIED)
        _assert_check(evidence, "other_workspace_write_denied", error=_ERROR_ACCESS_DENIED)
        assert other_file.read_bytes() == b"second run stays intact"
        record_property("run_ids", f"{first.run_id},{second.run_id}")
        record_property("cross_run_evidence", json.dumps(evidence, sort_keys=True))
    finally:
        if second is not None:
            second.close()
        first.close()
        assert not first.cleanup_required and (second is None or not second.cleanup_required)


@_WINDOWS_NATIVE
def test_native_lpac_exit_cleanup_revokes_workspace(native_acl_root: Path, native_probe_template: Path, record_property, monkeypatch) -> None:
    from types import SimpleNamespace
    from workspace import windows_appcontainer_workspace as acl_module
    from workspace.windows_appcontainer_workspace import WindowsAppContainerWorkspace, AppContainerWorkspaceError

    root = native_acl_root
    _create_protected_test_root(root)
    workspace = WindowsAppContainerWorkspace.create(root)
    old_path = workspace.workspace_path
    stale_sid = workspace.sid_string
    broker = _broker_sid()
    evidence_dir: Path | None = None
    try:
        probe = _prepare_root_and_probe(root, workspace, native_probe_template)
        report = old_path / "before-close.json"
        live = _launch(probe, workspace, "rw", Path("ignored"), Path("ignored"), report, record_property)
        assert any(item["name"] == "workspace_write" and item["ok"] for item in live["checks"])
        # The native launcher has waited/reaped the child before returning. close()
        # may revoke the DACL and remove files now; it does not revoke open handles.
        evidence_dir = root / f"stale-evidence-{uuid.uuid4().hex}"
        _make_directory(evidence_dir, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})(A;OICI;0x{_FILE_REPORT:08X};;;{stale_sid})S:(ML;OICI;NW;;;LW)")
        # Hold real app-created files after native ACL revocation to prove that
        # cleanup failure cannot restore the owner's implicit WRITE_DAC rights.
        def retain_revoked_tree(_path):
            raise OSError("injected removal failure after actual native revocation")

        with monkeypatch.context() as held:
            held.setattr(acl_module._native, "remove_tree", retain_revoked_tree)
            with pytest.raises(AppContainerWorkspaceError) as caught:
                workspace.close()
            assert caught.value.workspace is workspace and workspace.cleanup_required
            assert workspace._access_revoked and old_path.exists()
            retained_entries, retained_owner, _, _ = _get_security(old_path / "probe.txt")
            assert retained_owner is not None
            record_property("retained_file_owner_sid", retained_owner)
            assert not any(entry["sid"] == stale_sid and entry["type"] == 0 for entry in retained_entries)
            assert any(entry["sid"] == "S-1-3-4" and entry["type"] == 0 and entry["mask"] == 0x00020000 for entry in retained_entries)
            # Permit only root traversal for this test so the following failures
            # prove the retained FILE's revoked DACL, not a denied parent walk.
            _apply_sddl(old_path, f"D:P(A;OICI;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;{broker})(A;;0x{_FILE_TRAVERSE:08X};;;{stale_sid})")
            revoked_context = SimpleNamespace(sid_string=stale_sid, workspace_path=evidence_dir)
            revoked_result = _launch(probe, revoked_context, "revoked", old_path / "probe.txt", Path("ignored"), evidence_dir / "revoked.json", record_property)
            for check in ("other_workspace_read_denied", "other_workspace_write_denied", "revoked_write_dac_denied", "revoked_write_owner_denied"):
                _assert_check(revoked_result, check, error=_ERROR_ACCESS_DENIED)
            record_property("post_revoke_retained_file_evidence", json.dumps(revoked_result, sort_keys=True))
        workspace.close()
        assert not workspace.cleanup_required and not old_path.exists()
        workspace.close()  # idempotent after the confirmed cleanup

        # Recreate the exact former workspace pathname with only a traversal grant
        # for the stale SID. The sentinel file itself is broker-only and LOW-labeled.
        _make_directory(old_path, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})(A;;0x{_FILE_TRAVERSE:08X};;;{stale_sid})S:(ML;OICI;NW;;;LW)")
        sentinel = old_path / "fresh-broker-only-sentinel.bin"
        sentinel_payload = b"new broker-only object after revocation"
        _make_file(sentinel, sentinel_payload, f"D:P(A;;FA;;;SY)(A;;FA;;;{broker})S:(ML;;NW;;;LW)")
        stale_report = evidence_dir / "stale-evidence.json"
        stale_result = _launch(probe, workspace, "stale", sentinel, Path("ignored"), stale_report, record_property)
        _assert_check(stale_result, "environment_minimal")
        _assert_check(stale_result, "other_workspace_read_denied", error=_ERROR_ACCESS_DENIED)
        _assert_check(stale_result, "other_workspace_write_denied", error=_ERROR_ACCESS_DENIED)
        assert sentinel.read_bytes() == sentinel_payload
        record_property("stale_sid", stale_sid)
        record_property("stale_access_evidence", json.dumps(stale_result, sort_keys=True))
        assert not workspace.cleanup_required
    finally:
        # All native processes have been waited/reaped by the launcher before any
        # cleanup. Calling close is idempotent if the intended revocation succeeded.
        workspace.close()
        if evidence_dir is not None and evidence_dir.exists():
            shutil.rmtree(evidence_dir)
        if old_path.exists():
            shutil.rmtree(old_path)
