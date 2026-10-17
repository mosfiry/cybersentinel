from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import scripts.acceptance_process_tree as process_tree
import scripts.windows_process_job as windows_job_module


class _AttributeListApi:
    """Small Win32 stand-in to verify the helper's setup/update/delete contract."""

    def __init__(self, failure: str | None = None) -> None:
        self.failure = failure
        self.probe_calls = 0
        self.initialized = 0
        self.deleted = 0
        self.updated_handle: int | None = None

    def InitializeProcThreadAttributeList(
        self, attribute_list: Any, _count: int, _flags: int, size_pointer: Any
    ) -> int:
        size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_size_t))
        if not attribute_list:
            self.probe_calls += 1
            if self.failure == "probe":
                ctypes.set_last_error(87)
                return 0
            size.contents.value = 64
            ctypes.set_last_error(windows_job_module._ERROR_INSUFFICIENT_BUFFER)
            return 0
        if self.failure == "initialization":
            ctypes.set_last_error(8)
            return 0
        self.initialized += 1
        assert size.contents.value == 64
        return 1

    def UpdateProcThreadAttribute(
        self,
        attribute_list: Any,
        flags: int,
        attribute: int,
        value: Any,
        value_size: int,
        _previous: Any,
        _returned_size: Any,
    ) -> int:
        assert attribute_list
        assert flags == 0
        assert attribute == windows_job_module._PROC_THREAD_ATTRIBUTE_JOB_LIST
        assert value_size == ctypes.sizeof(windows_job_module.wintypes.HANDLE)
        handle_array = ctypes.cast(
            value, ctypes.POINTER(windows_job_module.wintypes.HANDLE)
        )
        self.updated_handle = int(handle_array[0])
        if self.failure == "update":
            ctypes.set_last_error(87)
            return 0
        return 1

    def DeleteProcThreadAttributeList(self, attribute_list: Any) -> None:
        assert attribute_list
        self.deleted += 1


def test_job_attribute_list_probes_updates_and_deletes_on_any_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    last_error = {"value": 0}
    monkeypatch.setattr(
        windows_job_module.ctypes,
        "set_last_error",
        lambda value: last_error.__setitem__("value", value),
        raising=False,
    )
    monkeypatch.setattr(
        windows_job_module.ctypes,
        "get_last_error",
        lambda: last_error["value"],
        raising=False,
    )
    api = _AttributeListApi()
    handle = 0x1234

    with windows_job_module._job_attribute_list(api, handle) as attribute_list:
        assert attribute_list.value
        assert api.probe_calls == 1
        assert api.initialized == 1
        assert api.updated_handle == handle
        assert api.deleted == 0

    assert api.deleted == 1


@pytest.mark.parametrize(
    ("failure", "error", "expected_initialized", "expected_deleted"),
    [
        ("probe", "windows_job_attribute_size_failed", 0, 0),
        ("initialization", "windows_job_attribute_init_failed", 0, 0),
        ("update", "windows_job_attribute_update_failed", 1, 1),
    ],
)
def test_job_attribute_list_failure_cleans_up_only_initialized_lists(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    error: str,
    expected_initialized: int,
    expected_deleted: int,
) -> None:
    last_error = {"value": 0}
    monkeypatch.setattr(
        windows_job_module.ctypes,
        "set_last_error",
        lambda value: last_error.__setitem__("value", value),
        raising=False,
    )
    monkeypatch.setattr(
        windows_job_module.ctypes,
        "get_last_error",
        lambda: last_error["value"],
        raising=False,
    )
    api = _AttributeListApi(failure)

    with pytest.raises(OSError, match=error):
        with windows_job_module._job_attribute_list(api, 0x1234):
            pytest.fail("the attribute list should not be yielded after setup failure")

    assert api.initialized == expected_initialized
    assert api.deleted == expected_deleted


def test_keyboard_interrupt_closes_owned_windows_process_and_empties_job(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FakeJob:
        members = 2
        terminated = False
        closed = False

        def wait_current(self, _timeout: float) -> bool:
            return False

        def terminate_owned_job(self, *, timeout_seconds: float) -> dict[str, bool]:
            assert timeout_seconds <= process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS
            self.terminated = True
            self.members = 0
            return {"termination_succeeded": self.members == 0}

        def close(self) -> None:
            self.closed = True

    job = FakeJob()
    owned = process_tree._WindowsOwnedProcess(job, SimpleNamespace(process_id=4321))

    def interrupt_wait(*, timeout: float) -> int:
        assert timeout == 1.0
        raise KeyboardInterrupt

    monkeypatch.setattr(owned, "wait", interrupt_wait)
    monkeypatch.setattr(process_tree, "start_owned_process", lambda *_args, **_kwargs: owned)

    with pytest.raises(KeyboardInterrupt):
        process_tree.run_owned_command(
            ["fixture"], cwd=tmp_path, timeout_seconds=1.0
        )

    assert job.terminated
    assert job.members == 0
    assert job.closed


class _NativeKernelProxy:
    """Intercept launch/resume while forwarding every other API to real kernel32."""

    def __init__(self, real_kernel32: Any, marker: Path, failure: str | None) -> None:
        self.real = real_kernel32
        self.marker = marker
        self.failure = failure
        self.job_handle: int | None = None
        self.create_calls = 0
        self.resume_calls = 0
        self.process_handle: Any = None
        self.process_wait_results: list[int] = []
        self.initialize_calls = 0
        self.update_calls = 0
        self.delete_calls = 0
        self.invalid_job_list_handle = 0x12345

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)

    def WaitForSingleObject(self, handle: Any, timeout: int) -> Any:
        result = self.real.WaitForSingleObject(handle, timeout)
        handle_value = getattr(handle, "value", handle)
        process_value = getattr(self.process_handle, "value", self.process_handle)
        if process_value is not None and int(handle_value) == int(process_value):
            self.process_wait_results.append(result)
        return result

    def AssignProcessToJobObject(self, *_args: Any) -> None:
        raise AssertionError("post-creation AssignProcessToJobObject is forbidden")

    def InitializeProcThreadAttributeList(self, *args: Any) -> Any:
        # The first call is the documented size probe; fail only actual initialization.
        if args[0] and self.failure == "initialization":
            self.initialize_calls += 1
            ctypes.set_last_error(8)
            return 0
        return self.real.InitializeProcThreadAttributeList(*args)

    def UpdateProcThreadAttribute(self, *args: Any) -> Any:
        self.update_calls += 1
        if self.failure == "update":
            ctypes.set_last_error(87)
            return 0
        result = self.real.UpdateProcThreadAttribute(*args)
        if result and self.failure == "create_rejected":
            # The attribute list retains this caller-owned HANDLE array through CreateProcessW.
            ctypes.cast(args[3], ctypes.POINTER(windows_job_module.wintypes.HANDLE))[0] = (
                self.invalid_job_list_handle
            )
        return result

    def DeleteProcThreadAttributeList(self, *args: Any) -> Any:
        self.delete_calls += 1
        return self.real.DeleteProcThreadAttributeList(*args)

    def CreateProcessW(self, *args: Any) -> Any:
        self.create_calls += 1
        assert not self.marker.exists()
        startup = ctypes.cast(
            args[8], ctypes.POINTER(windows_job_module._StartupInfoEx)
        ).contents
        assert startup.StartupInfo.cb == ctypes.sizeof(
            windows_job_module._StartupInfoEx
        )
        assert startup.lpAttributeList
        assert args[5] & windows_job_module._EXTENDED_STARTUPINFO_PRESENT
        assert args[5] & windows_job_module._CREATE_SUSPENDED

        created = self.real.CreateProcessW(*args)
        if self.failure == "create_rejected":
            assert not created, "real CreateProcessW unexpectedly accepted invalid JOB_LIST handle"
            return created
        assert created
        process_info = ctypes.cast(
            args[9], ctypes.POINTER(windows_job_module._ProcessInformation)
        ).contents
        self.process_handle = process_info.hProcess
        if self.failure == "create_return":
            raise KeyboardInterrupt
        in_job = windows_job_module.wintypes.BOOL()
        assert self.job_handle is not None
        assert self.real.IsProcessInJob(
            process_info.hProcess, self.job_handle, ctypes.byref(in_job)
        )
        assert in_job.value, "child was not in its owned job when CreateProcessW returned"
        assert not self.marker.exists(), "suspended child ran before launch validation/resume"
        return created

    def ResumeThread(self, thread_handle: Any) -> Any:
        self.resume_calls += 1
        assert self.job_handle is not None
        assert not self.marker.exists(), "marker appeared before ResumeThread"
        # The process handle is populated by CreateProcessW before the job records
        # its validated identity/current process.
        assert self.process_handle is not None
        assert windows_job_module._is_process_in_job(
            self.real, self.process_handle, self.job_handle
        )
        if self.failure == "resume":
            ctypes.set_last_error(5)
            return 0xFFFFFFFF
        result = self.real.ResumeThread(thread_handle)
        if self.failure == "resume_return":
            raise KeyboardInterrupt
        return result


def _native_proxy(
    monkeypatch: pytest.MonkeyPatch, marker: Path, failure: str | None
) -> _NativeKernelProxy:
    real_kernel32 = windows_job_module._kernel32()
    proxy = _NativeKernelProxy(real_kernel32, marker, failure)
    monkeypatch.setattr(windows_job_module, "_kernel32", lambda: proxy)
    return proxy


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
def test_native_job_list_binds_child_before_resume_and_runs_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran.marker"
    proxy = _native_proxy(monkeypatch, marker, None)
    executable = Path(sys.executable).resolve(strict=True)
    job = windows_job_module.WindowsOwnedJob.create()
    proxy.job_handle = job._handle
    proxy.job = job
    try:
        job.launch(
            executable,
            ["-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"],
            cwd=executable.parent,
        )
        assert proxy.create_calls == 1
        assert proxy.resume_calls == 1
        assert job.wait_current(15)
        assert marker.read_text() == "ran"
        assert job.process_count() == 0
    finally:
        if not job._closed:
            remaining = job.process_count()
            if remaining:
                job.terminate_owned_job(timeout_seconds=10)
            assert job.process_count() == 0
            job.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
@pytest.mark.parametrize(
    ("failure", "error"),
    [
        ("initialization", "windows_job_attribute_init_failed"),
        ("update", "windows_job_attribute_update_failed"),
        ("create_rejected", "windows_job_process_create_failed"),
        ("identity", "windows_job_process_image_mismatch"),
        ("membership", "windows_job_membership_unverified"),
        ("resume", "windows_job_process_resume_failed"),
    ],
    ids=("initialize", "update", "create-process", "identity", "membership", "resume"),
)
def test_native_job_launch_failures_never_run_marker_and_leave_empty_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    error: str,
) -> None:
    marker = tmp_path / "must-not-run.marker"
    proxy = _native_proxy(monkeypatch, marker, failure)
    executable = Path(sys.executable).resolve(strict=True)
    job = windows_job_module.WindowsOwnedJob.create()
    proxy.job_handle = job._handle
    proxy.job = job

    if failure == "identity":
        real_identity = windows_job_module._identity_from_handle

        def wrong_identity(kernel32: Any, process_handle: Any, pid: int) -> Any:
            identity = real_identity(kernel32, process_handle, pid)
            return windows_job_module.WindowsProcessIdentity(
                process_id=identity.process_id,
                image_path=str(tmp_path / "not-the-interpreter.exe"),
                creation_time=identity.creation_time,
                process_handle=identity.process_handle,
            )

        monkeypatch.setattr(windows_job_module, "_identity_from_handle", wrong_identity)
    elif failure == "membership":
        monkeypatch.setattr(windows_job_module, "_is_process_in_job", lambda *_args: False)

    try:
        with pytest.raises((OSError, RuntimeError), match=error):
            job.launch(
                executable,
                ["-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"],
                cwd=executable.parent,
            )
        assert not marker.exists()
        assert proxy.resume_calls == (1 if failure == "resume" else 0)
        if failure == "create_rejected":
            assert proxy.create_calls == 1
        if failure in {"initialization", "update"}:
            assert proxy.create_calls == 0
        remaining = job.process_count()
        assert remaining == 0, "failed launch left a process in the owned job"
    finally:
        if not job._closed:
            remaining = job.process_count()
            if remaining:
                job.terminate_owned_job(timeout_seconds=10)
            job.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
@pytest.mark.parametrize(
    ("failure", "identity_interrupts"),
    [
        ("create_return", False),
        ("identity", True),
        ("resume_return", False),
    ],
    ids=("create-return", "identity-validation", "resume-return"),
)
def test_native_job_launch_cancellation_closes_root_and_empties_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    identity_interrupts: bool,
) -> None:
    marker = tmp_path / "cancellation.marker"
    proxy = _native_proxy(monkeypatch, marker, failure)
    executable = Path(sys.executable).resolve(strict=True)
    job = windows_job_module.WindowsOwnedJob.create()
    proxy.job_handle = job._handle
    if identity_interrupts:
        def interrupt_identity(*_args: Any) -> Any:
            raise KeyboardInterrupt

        monkeypatch.setattr(windows_job_module, "_identity_from_handle", interrupt_identity)

    try:
        with pytest.raises(KeyboardInterrupt):
            job.launch(
                executable,
                ["-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')"],
                cwd=executable.parent,
            )
        assert proxy.process_handle is not None
        assert windows_job_module._WAIT_OBJECT_0 in proxy.process_wait_results
        if failure != "resume_return":
            assert not marker.exists()
        assert job.process_count() == 0
    finally:
        if not job._closed:
            remaining = job.process_count()
            if remaining:
                job.terminate_owned_job(timeout_seconds=10)
            job.close()


def test_start_owned_process_cleans_up_windows_job_on_keyboard_interrupt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeJob:
        terminated = False
        closed = False

        @classmethod
        def create(cls) -> "FakeJob":
            return cls()

        def launch(self, *_args: Any, **_kwargs: Any) -> Any:
            raise KeyboardInterrupt

        def terminate_owned_job(self, *, timeout_seconds: float) -> dict[str, bool]:
            assert timeout_seconds == 2.0
            self.terminated = True
            return {"termination_succeeded": True}

        def close(self) -> None:
            self.closed = True

    job = FakeJob()

    class FakeWindowsOwnedJob:
        @staticmethod
        def create() -> FakeJob:
            return job

    with monkeypatch.context() as scoped:
        # Preserve this platform's concrete paths while selecting the Windows branch.
        scoped.setattr(process_tree, "Path", type(tmp_path))
        scoped.setattr(process_tree.os, "name", "nt")
        scoped.setattr(windows_job_module, "WindowsOwnedJob", FakeWindowsOwnedJob)
        with pytest.raises(KeyboardInterrupt):
            process_tree.start_owned_process(["fixture"], cwd=tmp_path)

    assert job.terminated
    assert job.closed


@pytest.mark.parametrize("stage", ("launch", "wait"))
@pytest.mark.parametrize("cleanup_fails", (False, True))
def test_job_runner_cancellation_always_terminates_and_closes(stage, cleanup_fails, tmp_path):
    events = []

    class Job:
        def launch(self, *_args, **_kwargs):
            events.append("launch")
            if stage == "launch":
                raise KeyboardInterrupt
            return SimpleNamespace(process_id=123, creation_time=456)

        def wait_current(self, _timeout):
            events.append("wait")
            raise KeyboardInterrupt

        def terminate_owned_job(self, **_kwargs):
            events.append("terminate")
            if cleanup_fails:
                raise RuntimeError("termination_unavailable")
            return {"remaining_member_count": 0, "termination_succeeded": True}

        def close(self):
            events.append("close")

    with pytest.raises(KeyboardInterrupt):
        windows_job_module.run_process_in_owned_job(
            "fixture", [], cwd=tmp_path, timeout_seconds=1, job_factory=Job,
        )
    assert events == (["launch"] if stage == "launch" else ["launch", "wait"]) + ["terminate", "close"]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
@pytest.mark.parametrize("stage", ("create-return", "resume-return", "wait"))
def test_native_job_runner_cancellation_verifies_empty_tree_and_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str,
) -> None:
    import time

    marker = tmp_path / "runner-cancellation.marker"
    failure = {"create-return": "create_return", "resume-return": "resume_return"}.get(stage)
    proxy = _native_proxy(monkeypatch, marker, failure)
    job = windows_job_module.WindowsOwnedJob.create()
    proxy.job_handle = job._handle
    real_close = job.close
    counts_before_close = []

    def observed_close():
        counts_before_close.append(job.process_count())
        real_close()

    monkeypatch.setattr(job, "close", observed_close)
    if stage == "wait":
        real_wait = job.wait_current

        def interrupt_wait(_timeout):
            monkeypatch.setattr(job, "wait_current", real_wait)
            deadline = time.monotonic() + 10
            while job.process_count() < 2 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert job.process_count() >= 2
            raise KeyboardInterrupt

        monkeypatch.setattr(job, "wait_current", interrupt_wait)
    executable = Path(sys.executable).resolve(strict=True)
    try:
        with pytest.raises(KeyboardInterrupt):
            windows_job_module.run_process_in_owned_job(
                executable,
                ["-c", "import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(120)']); time.sleep(120)"],
                cwd=executable.parent, timeout_seconds=15, job_factory=lambda: job,
            )
        assert counts_before_close == [0]
        assert job._closed
    finally:
        if not job._closed:
            job.terminate_owned_job(timeout_seconds=10)
            real_close()
