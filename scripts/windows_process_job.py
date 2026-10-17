"""Launch-bound Windows Job Object lifecycle for the native installer acceptance harness.

This is process-tree ownership, not an application sandbox. It does not grant or
replace workspace, network, filesystem, or token isolation for untrusted commands.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


_JOB_OBJECT_QUERY = 0x0004
_JOB_OBJECT_TERMINATE = 0x0008
_JOB_OBJECT_ASSIGN_PROCESS = 0x0100
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
_ERROR_INSUFFICIENT_BUFFER = 122
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_INFINITE = 0xFFFFFFFF
_MAX_JOB_WAIT_TIMEOUT_SECONDS = 600.0
_MAX_JOB_TERMINATION_TIMEOUT_SECONDS = 30.0
_MAX_PROCESS_RUNTIME_TIMEOUT_SECONDS = 600.0


def _validated_timeout_seconds(
    timeout_seconds: object, *, max_seconds: float
) -> float:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("windows_job_timeout_invalid")
    try:
        normalized = float(timeout_seconds)
    except (OverflowError, TypeError, ValueError):
        raise ValueError("windows_job_timeout_invalid") from None
    if (
        not math.isfinite(normalized)
        or normalized < 0
        or normalized > max_seconds
    ):
        raise ValueError("windows_job_timeout_invalid")
    return normalized


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _BasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", ctypes.c_void_p)]


@contextmanager
def _job_attribute_list(kernel32, job_handle: int):
    """Keep the opaque list and its HANDLE value alive through CreateProcessW.

    Windows 10 / Server 2016 or newer is required. Any setup/assignment failure
    refuses launch; there is deliberately no post-creation assignment fallback.
    The Job handle is referenced by the attribute, never inherited by the child.
    """
    size = ctypes.c_size_t()
    if (
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
        or not size.value
    ):
        raise _win_error("windows_job_attribute_size_failed")
    storage = ctypes.create_string_buffer(size.value)
    attribute_list = ctypes.cast(storage, ctypes.c_void_p)
    jobs = (wintypes.HANDLE * 1)(job_handle)
    if not kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(size)):
        raise _win_error("windows_job_attribute_init_failed")
    try:
        if not kernel32.UpdateProcThreadAttribute(
            attribute_list, 0, _PROC_THREAD_ATTRIBUTE_JOB_LIST,
            ctypes.cast(jobs, ctypes.c_void_p), ctypes.sizeof(jobs), None, None,
        ):
            raise _win_error("windows_job_attribute_update_failed")
        yield attribute_list
    finally:
        kernel32.DeleteProcThreadAttributeList(attribute_list)


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


@dataclass(frozen=True)
class WindowsProcessIdentity:
    process_id: int
    image_path: str
    creation_time: int
    process_handle: int

    @property
    def pid(self) -> int:
        return self.process_id


class WindowsOwnedJob:
    """A unique Job Object bound to the app at creation, before it can execute."""

    def __init__(self, name: str, handle: int) -> None:
        self.name = name
        self._handle = handle
        self._kernel32 = _kernel32()
        self.current: WindowsProcessIdentity | None = None
        self._closed = False

    @classmethod
    def create(cls, name: str | None = None) -> "WindowsOwnedJob":
        kernel32 = _kernel32()
        job_name = name or f"Local\\CyberSentinelAcceptance-{uuid.uuid4().hex}"
        handle = kernel32.CreateJobObjectW(None, job_name)
        if not handle:
            raise _win_error("windows_job_create_failed")
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = _win_error("windows_job_close_policy_setup_failed")
            kernel32.CloseHandle(handle)
            raise error
        return cls(job_name, handle)

    def launch(
        self,
        executable: str | Path,
        arguments: Sequence[str],
        *,
        cwd: str | Path,
        environment: Mapping[str, str] | None = None,
    ) -> WindowsProcessIdentity:
        """Create in this Job suspended; validate identity/membership, then resume.

        Launch fails closed on unsupported attributes or rejected Job binding.
        This trusted-harness primitive is not a Mission isolation backend.
        """
        self._require_open()
        image = str(Path(executable).expanduser().resolve(strict=True))
        workdir = str(Path(cwd).expanduser().resolve(strict=True))
        command_line = subprocess.list2cmdline([image, *(str(arg) for arg in arguments)])
        command_buffer = ctypes.create_unicode_buffer(command_line)
        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        process_info = _ProcessInformation()
        env_buffer = _environment_block(environment) if environment is not None else None
        env_pointer = ctypes.cast(env_buffer, ctypes.c_void_p) if env_buffer is not None else None
        try:
            with _job_attribute_list(self._kernel32, self._handle) as attribute_list:
                startup.lpAttributeList = attribute_list
                created = self._kernel32.CreateProcessW(
                    image,
                    command_buffer,
                    None,
                    None,
                    False,
                    _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT | _EXTENDED_STARTUPINFO_PRESENT,
                    env_pointer,
                    workdir,
                    ctypes.byref(startup.StartupInfo),
                    ctypes.byref(process_info),
                )
                if not created:
                    raise _win_error("windows_job_process_create_failed")
            process_handle = process_info.hProcess
            identity = _identity_from_handle(
                self._kernel32, process_handle, int(process_info.dwProcessId)
            )
            if os.path.normcase(identity.image_path) != os.path.normcase(image):
                raise RuntimeError("windows_job_process_image_mismatch")
            if not _is_process_in_job(self._kernel32, process_handle, self._handle):
                raise RuntimeError("windows_job_membership_unverified")
            resume_result = self._kernel32.ResumeThread(process_info.hThread)
            if resume_result == 0xFFFFFFFF:
                raise _win_error("windows_job_process_resume_failed")
            self.current = identity
            return identity
        except BaseException:
            # CreateProcessW may have filled these handles before cancellation was
            # delivered. Never strand a suspended or just-resumed owned child.
            if process_info.hProcess:
                try:
                    self._kernel32.TerminateJobObject(self._handle, 1)
                    self._kernel32.TerminateProcess(process_info.hProcess, 1)
                    self._kernel32.WaitForSingleObject(process_info.hProcess, 5000)
                finally:
                    self._kernel32.CloseHandle(process_info.hProcess)
                    if self.current is not None and self.current.process_handle == process_info.hProcess:
                        self.current = None
            raise
        finally:
            if process_info.hThread:
                self._kernel32.CloseHandle(process_info.hThread)

    def bind_existing(self, process_id: int, expected_image: str | Path) -> WindowsProcessIdentity:
        self._require_open()
        process = self._kernel32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE, False, process_id
        )
        if not process:
            raise _win_error("windows_job_process_open_failed")
        try:
            identity = _identity_from_handle(self._kernel32, process, process_id)
            expected = str(Path(expected_image).expanduser().resolve(strict=True))
            if os.path.normcase(identity.image_path) != os.path.normcase(expected):
                raise RuntimeError("windows_job_process_image_mismatch")
            if not _is_process_in_job(self._kernel32, process, self._handle):
                raise RuntimeError("windows_job_membership_unverified")
            self._close_current()
            self.current = identity
            return identity
        except Exception:
            self._kernel32.CloseHandle(process)
            raise

    def verify_current(self, process_id: int, expected_image: str | Path) -> WindowsProcessIdentity:
        self._require_open()
        identity = self.current
        if identity is None or identity.process_id != process_id:
            raise RuntimeError("windows_job_process_identity_unavailable")
        actual = _identity_from_handle(self._kernel32, identity.process_handle, identity.process_id)
        expected = str(Path(expected_image).expanduser().resolve(strict=True))
        if (
            actual.creation_time != identity.creation_time
            or os.path.normcase(actual.image_path) != os.path.normcase(expected)
            or not _is_process_in_job(self._kernel32, identity.process_handle, self._handle)
        ):
            raise RuntimeError("windows_job_process_identity_mismatch")
        return identity

    def wait_current(self, timeout_seconds: float) -> bool:
        self._require_open()
        if self.current is None:
            raise RuntimeError("windows_job_process_identity_unavailable")
        timeout_seconds = _validated_timeout_seconds(
            timeout_seconds, max_seconds=_MAX_JOB_WAIT_TIMEOUT_SECONDS
        )
        timeout_ms = min(int(timeout_seconds * 1000), 0xFFFFFFFE)
        result = self._kernel32.WaitForSingleObject(self.current.process_handle, timeout_ms)
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        raise _win_error("windows_job_process_wait_failed")

    def exit_code_current(self) -> int:
        self._require_open()
        if self.current is None:
            raise RuntimeError("windows_job_process_identity_unavailable")
        if self._kernel32.WaitForSingleObject(self.current.process_handle, 0) != _WAIT_OBJECT_0:
            raise RuntimeError("windows_job_process_not_exited")
        exit_code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(
            self.current.process_handle, ctypes.byref(exit_code)
        ):
            raise _win_error("windows_job_process_exit_code_unavailable")
        return int(exit_code.value)

    def terminate_current(
        self,
        process_id: int,
        expected_image: str | Path,
        *,
        timeout_seconds: float = 30.0,
    ) -> dict[str, int | bool | str]:
        self._require_open()
        timeout_seconds = _validated_timeout_seconds(
            timeout_seconds, max_seconds=_MAX_JOB_TERMINATION_TIMEOUT_SECONDS
        )
        identity = self.verify_current(process_id, expected_image)
        initial_members = self.process_count()
        root_stopped = self.wait_current(0)
        if initial_members <= 0 and root_stopped:
            return {
                "job_name": self.name,
                "initial_member_count": 0,
                "remaining_member_count": 0,
                "root_process_stopped": True,
                "identity_verified": True,
                "termination_succeeded": True,
            }
        if not self._kernel32.TerminateJobObject(self._handle, 0xD):
            raise _win_error("windows_job_termination_failed")
        deadline = time.monotonic() + timeout_seconds
        remaining, root_stopped = self._wait_for_job_and_root_exit(deadline=deadline)
        result: dict[str, int | bool | str] = {
            "job_name": self.name,
            "initial_member_count": initial_members,
            "remaining_member_count": remaining,
            "root_process_stopped": root_stopped,
            "identity_verified": True,
            "termination_succeeded": remaining == 0 and root_stopped,
        }
        if result["termination_succeeded"]:
            self._close_current()
        return result

    def terminate_owned_job(self, *, timeout_seconds: float = 30.0) -> dict[str, int | bool | str]:
        """Terminate only this unique job; intended for final owned-job cleanup."""
        self._require_open()
        timeout_seconds = _validated_timeout_seconds(
            timeout_seconds, max_seconds=_MAX_JOB_TERMINATION_TIMEOUT_SECONDS
        )
        initial_members = self.process_count()
        root_stopped = self.current is None or self.wait_current(0)
        if (initial_members or not root_stopped) and not self._kernel32.TerminateJobObject(
            self._handle, 0xD
        ):
            raise _win_error("windows_job_termination_failed")
        deadline = time.monotonic() + timeout_seconds
        remaining, root_stopped = self._wait_for_job_and_root_exit(deadline=deadline)
        result: dict[str, int | bool | str] = {
            "job_name": self.name,
            "initial_member_count": initial_members,
            "remaining_member_count": remaining,
            "root_process_stopped": root_stopped,
            "termination_succeeded": remaining == 0 and root_stopped,
        }
        if result["termination_succeeded"]:
            self._close_current()
        return result

    def _wait_for_job_and_root_exit(self, *, deadline: float) -> tuple[int, bool]:
        """Wait for both Job Object emptiness and the retained root handle signal."""
        while True:
            remaining = self.process_count()
            root_stopped = self.current is None or self.wait_current(0)
            if remaining == 0 and root_stopped:
                return remaining, root_stopped
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                return remaining, root_stopped
            time.sleep(min(0.05, remaining_seconds))

    def process_count(self) -> int:
        self._require_open()
        info = _BasicAccountingInformation()
        returned = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            self._handle,
            _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(returned),
        ):
            raise _win_error("windows_job_process_count_unavailable")
        return int(info.ActiveProcesses)

    def close(self) -> None:
        if self._closed:
            return
        self._close_current()
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = 0
        self._closed = True

    def _close_current(self) -> None:
        if self.current is not None:
            self._kernel32.CloseHandle(self.current.process_handle)
            self.current = None

    def _require_open(self) -> None:
        if self._closed or not self._handle:
            raise RuntimeError("windows_job_handle_closed")

    def __enter__(self) -> "WindowsOwnedJob":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


def _environment_block(environment: Mapping[str, str]):
    items = sorted(
        ((str(key), str(value)) for key, value in environment.items()),
        key=lambda item: item[0].casefold(),
    )
    encoded = "\0".join(f"{key}={value}" for key, value in items) + "\0\0"
    return ctypes.create_unicode_buffer(encoded)


def _identity_from_handle(kernel32, process_handle, process_id: int) -> WindowsProcessIdentity:
    image_buffer = ctypes.create_unicode_buffer(32768)
    image_size = wintypes.DWORD(len(image_buffer))
    if not kernel32.QueryFullProcessImageNameW(process_handle, 0, image_buffer, ctypes.byref(image_size)):
        raise _win_error("windows_job_process_image_unavailable")
    creation = _FileTime()
    exit_time = _FileTime()
    kernel_time = _FileTime()
    user_time = _FileTime()
    if not kernel32.GetProcessTimes(
        process_handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise _win_error("windows_job_process_creation_time_unavailable")
    creation_time = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
    return WindowsProcessIdentity(
        process_id=int(process_id),
        image_path=image_buffer.value,
        creation_time=creation_time,
        process_handle=int(process_handle),
    )


def _is_process_in_job(kernel32, process_handle, job_handle) -> bool:
    result = wintypes.BOOL()
    if not kernel32.IsProcessInJob(process_handle, job_handle, ctypes.byref(result)):
        raise _win_error("windows_job_membership_query_failed")
    return bool(result.value)


def _kernel32():
    if os.name != "nt":
        raise RuntimeError("native_windows_process_job_required")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenJobObjectW.restype = wintypes.HANDLE
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)
    ]
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _win_error(code: str) -> OSError:
    return OSError(ctypes.get_last_error(), code)


def run_process_in_owned_job(
    executable: str | Path,
    arguments: Sequence[str],
    *,
    cwd: str | Path,
    timeout_seconds: float,
    job_factory: Callable[[], WindowsOwnedJob] | None = None,
) -> dict[str, object]:
    """Run a process created in a unique owned Job, suspended until validated.

    The process and descendants stay in that Job; completion always terminates
    remaining members and records whether the Job became empty before return.
    """
    try:
        timeout_seconds = _validated_timeout_seconds(
            timeout_seconds, max_seconds=_MAX_PROCESS_RUNTIME_TIMEOUT_SECONDS
        )
        if timeout_seconds <= 0:
            raise ValueError("windows_job_timeout_invalid")
    except ValueError:
        return {
            "status": "launch_failed",
            "process_started": False,
            "timed_out": False,
            "job_tree_termination_verified": False,
            "error_code": "windows_job_timeout_invalid",
        }

    try:
        job = (job_factory or WindowsOwnedJob.create)()
    except Exception:
        return {
            "status": "launch_failed",
            "process_started": False,
            "timed_out": False,
            "job_tree_termination_verified": False,
            "error_code": "windows_job_creation_failed",
        }

    identity: WindowsProcessIdentity | None = None
    waited: bool | None = None
    process_exit_code: int | None = None
    error_code: str | None = None
    cleanup: dict[str, object] = {}
    try:
        try:
            identity = job.launch(executable, arguments, cwd=cwd)
        except Exception:
            error_code = "windows_job_process_launch_failed"
        if identity is not None:
            try:
                waited = job.wait_current(timeout_seconds)
                if waited:
                    process_exit_code = job.exit_code_current()
                else:
                    error_code = "windows_job_process_timeout"
            except Exception:
                error_code = "windows_job_process_wait_failed"
    finally:
        # Cancellation propagates, but never bypasses owned-tree cleanup/close.
        try:
            try:
                cleanup = job.terminate_owned_job(timeout_seconds=30.0)
            except Exception:
                error_code = error_code or "windows_job_tree_termination_failed"
        finally:
            try:
                job.close()
            except Exception:
                error_code = error_code or "windows_job_close_failed"

    remaining_members = cleanup.get("remaining_member_count")
    tree_terminated = (
        cleanup.get("termination_succeeded") is True
        and type(remaining_members) is int
        and remaining_members == 0
    )
    if identity is None:
        status = "launch_failed"
    elif waited is False:
        status = "timed_out"
    elif waited is None:
        status = "wait_failed"
    elif not tree_terminated:
        status = "cleanup_failed"
    else:
        status = "completed"
    if not tree_terminated:
        error_code = error_code or "windows_job_tree_termination_unverified"
    return {
        "status": status,
        "process_started": identity is not None,
        "process_id": identity.process_id if identity is not None else None,
        "process_creation_time": identity.creation_time if identity is not None else None,
        "process_exit_code": process_exit_code,
        "timed_out": waited is False,
        "job_initial_member_count": cleanup.get("initial_member_count"),
        "job_remaining_member_count": remaining_members,
        "job_tree_termination_verified": tree_terminated,
        "error_code": error_code,
    }


def run_installer_in_owned_job(
    installer_path: str | Path,
    install_directory: str | Path,
    *,
    timeout_seconds: float = 600.0,
    job_factory: Callable[[], WindowsOwnedJob] | None = None,
) -> dict[str, object]:
    try:
        installer = Path(installer_path).expanduser().resolve(strict=True)
        install_target = Path(install_directory).expanduser().resolve(strict=False)
        if not installer.is_file() or installer.suffix.lower() != ".exe":
            raise ValueError("windows_installer_path_invalid")
    except (OSError, ValueError):
        return {
            "status": "launch_failed",
            "process_started": False,
            "timed_out": False,
            "job_tree_termination_verified": False,
            "error_code": "windows_installer_path_invalid",
        }
    return run_process_in_owned_job(
        installer,
        ["/S", f"/D={install_target}"],
        cwd=installer.parent,
        timeout_seconds=timeout_seconds,
        job_factory=job_factory,
    )


def _write_json_atomically(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=path.name + ".", suffix=".tmp", delete=False,
        ) as stream:
            temporary_path = stream.name
            json.dump(value, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch and clean up a Windows installer in an owned Job Object.")
    commands = parser.add_subparsers(dest="command", required=True)
    installer_parser = commands.add_parser("run-installer")
    installer_parser.add_argument("--installer-path", required=True)
    installer_parser.add_argument("--install-directory", required=True)
    installer_parser.add_argument("--timeout-seconds", type=float, default=600.0)
    installer_parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    result = run_installer_in_owned_job(
        args.installer_path,
        args.install_directory,
        timeout_seconds=args.timeout_seconds,
    )
    try:
        _write_json_atomically(Path(args.output), result)
    except OSError:
        return 3
    return 0 if (
        result.get("status") == "completed"
        and result.get("process_exit_code") == 0
        and result.get("job_tree_termination_verified") is True
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
