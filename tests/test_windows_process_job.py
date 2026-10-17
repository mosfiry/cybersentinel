from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

import scripts.windows_process_job as windows_job_module
from scripts.windows_process_job import (
    WindowsOwnedJob,
    run_installer_in_owned_job,
    run_process_in_owned_job,
)


class _FakeIdentity:
    process_id = 1234
    creation_time = 5678


class _FakeOwnedJob:
    def __init__(self, *, waited: bool, exit_code: int, cleanup_succeeded: bool) -> None:
        self.waited = waited
        self.exit_code = exit_code
        self.cleanup_succeeded = cleanup_succeeded
        self.events: list[str] = []
        self.launch_arguments: tuple[str, list[str], str] | None = None

    def launch(self, executable, arguments, *, cwd):
        self.events.append("launch")
        self.launch_arguments = (str(executable), list(arguments), str(cwd))
        return _FakeIdentity()

    def wait_current(self, timeout_seconds):
        self.events.append("wait")
        return self.waited

    def exit_code_current(self):
        self.events.append("exit_code")
        return self.exit_code

    def terminate_owned_job(self, *, timeout_seconds):
        self.events.append("terminate_job")
        return {
            "initial_member_count": 2,
            "remaining_member_count": 0 if self.cleanup_succeeded else 1,
            "termination_succeeded": self.cleanup_succeeded,
        }

    def close(self):
        self.events.append("close")


def test_job_runner_assigns_before_wait_and_verifies_tree_cleanup(tmp_path: Path) -> None:
    job = _FakeOwnedJob(waited=True, exit_code=0, cleanup_succeeded=True)
    result = run_process_in_owned_job(
        "installer.exe", ["/S"], cwd=tmp_path, timeout_seconds=10, job_factory=lambda: job
    )

    assert job.events == ["launch", "wait", "exit_code", "terminate_job", "close"]
    assert result["status"] == "completed"
    assert result["process_started"] is True
    assert result["process_exit_code"] == 0
    assert result["job_initial_member_count"] == 2
    assert result["job_remaining_member_count"] == 0
    assert result["job_tree_termination_verified"] is True


def test_installer_helper_uses_fixed_silent_install_arguments(tmp_path: Path) -> None:
    installer = tmp_path / "setup.exe"
    installer.write_bytes(b"fixture installer")
    install_directory = tmp_path / "CyberSentinel"
    job = _FakeOwnedJob(waited=True, exit_code=0, cleanup_succeeded=True)

    result = run_installer_in_owned_job(
        installer,
        install_directory,
        timeout_seconds=10,
        job_factory=lambda: job,
    )

    assert job.launch_arguments == (
        str(installer.resolve()),
        ["/S", f"/D={install_directory.resolve()}"],
        str(tmp_path.resolve()),
    )
    assert result["status"] == "completed"
    assert result["job_tree_termination_verified"] is True


def test_job_runner_times_out_and_terminates_the_owned_tree(tmp_path: Path) -> None:
    job = _FakeOwnedJob(waited=False, exit_code=999, cleanup_succeeded=True)
    result = run_process_in_owned_job(
        "installer.exe", ["/S"], cwd=tmp_path, timeout_seconds=0.1, job_factory=lambda: job
    )

    assert job.events == ["launch", "wait", "terminate_job", "close"]
    assert result["status"] == "timed_out"
    assert result["timed_out"] is True
    assert result["process_exit_code"] is None
    assert result["job_tree_termination_verified"] is True


def test_job_runner_fails_closed_when_tree_emptiness_cannot_be_verified(tmp_path: Path) -> None:
    job = _FakeOwnedJob(waited=True, exit_code=0, cleanup_succeeded=False)
    result = run_process_in_owned_job(
        "installer.exe", ["/S"], cwd=tmp_path, timeout_seconds=10, job_factory=lambda: job
    )

    assert result["status"] == "cleanup_failed"
    assert result["job_tree_termination_verified"] is False
    assert result["job_remaining_member_count"] == 1


@pytest.mark.parametrize("termination_method", ["terminate_current", "terminate_owned_job"])
@pytest.mark.parametrize(
    ("initial_members", "process_counts", "wait_results"),
    [
        (1, (1, 0, 0), (windows_job_module._WAIT_TIMEOUT, windows_job_module._WAIT_TIMEOUT, windows_job_module._WAIT_OBJECT_0)),
        (0, (0, 0), (windows_job_module._WAIT_TIMEOUT, windows_job_module._WAIT_OBJECT_0)),
    ],
)
def test_termination_waits_for_root_handle_after_job_becomes_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_method: str,
    initial_members: int,
    process_counts: tuple[int, ...],
    wait_results: tuple[int, ...],
) -> None:
    executable = tmp_path / "CyberSentinel.exe"
    executable.write_bytes(b"fixture executable")
    identity = windows_job_module.WindowsProcessIdentity(
        process_id=1234,
        image_path=str(executable.resolve()),
        creation_time=5678,
        process_handle=99,
    )

    class FakeKernel32:
        def __init__(self) -> None:
            self.wait_results = iter(wait_results)
            self.terminated_jobs: list[tuple[int, int]] = []
            self.closed_handles: list[int] = []

        def TerminateJobObject(self, handle: int, exit_code: int) -> int:
            self.terminated_jobs.append((handle, exit_code))
            return 1

        def WaitForSingleObject(self, handle: int, _timeout_ms: int) -> int:
            assert handle == identity.process_handle
            return next(self.wait_results)

        def CloseHandle(self, handle: int) -> int:
            self.closed_handles.append(handle)
            return 1

    kernel32 = FakeKernel32()
    monkeypatch.setattr(windows_job_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(windows_job_module, "_identity_from_handle", lambda *_args: identity)
    monkeypatch.setattr(windows_job_module, "_is_process_in_job", lambda *_args: True)
    monkeypatch.setattr(windows_job_module.time, "sleep", lambda _seconds: None)
    job = WindowsOwnedJob("Local\\fixture-job", 77)
    job.current = identity
    member_counts = iter(process_counts)
    monkeypatch.setattr(job, "process_count", lambda: next(member_counts))

    if termination_method == "terminate_current":
        result = job.terminate_current(1234, executable, timeout_seconds=10)
    else:
        result = job.terminate_owned_job(timeout_seconds=10)

    assert result["initial_member_count"] == initial_members
    assert result["remaining_member_count"] == 0
    assert result["root_process_stopped"] is True
    assert result["termination_succeeded"] is True
    assert kernel32.terminated_jobs == [(77, 0xD)]
    assert job.current is None


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
def test_native_job_assigns_suspended_process_and_terminates_descendants() -> None:
    executable = Path(sys.executable).resolve(strict=True)
    job = WindowsOwnedJob.create()
    try:
        identity = job.launch(
            executable,
            [
                "-c",
                "import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(120)']); time.sleep(120)",
            ],
            cwd=executable.parent,
        )
        assert identity.process_id > 0
        assert identity.creation_time > 0
        assert Path(identity.image_path).resolve(strict=True) == executable
        assert job.verify_current(identity.process_id, executable).creation_time == identity.creation_time

        deadline = time.monotonic() + 10
        while job.process_count() < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert job.process_count() >= 2

        result = job.terminate_current(identity.process_id, executable, timeout_seconds=15)
        assert result["identity_verified"] is True
        assert result["termination_succeeded"] is True
        assert result["remaining_member_count"] == 0
        assert job.process_count() == 0
    finally:
        try:
            if job.process_count() > 0:
                job.terminate_owned_job(timeout_seconds=15)
        finally:
            job.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
def test_native_job_runner_kills_descendant_after_root_exits() -> None:
    executable = Path(sys.executable).resolve(strict=True)
    result = run_process_in_owned_job(
        executable,
        ["-c", "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(120)'])"],
        cwd=executable.parent,
        timeout_seconds=15,
    )

    assert result["status"] == "completed"
    assert result["process_exit_code"] == 0
    assert result["job_initial_member_count"] >= 1
    assert result["job_remaining_member_count"] == 0
    assert result["job_tree_termination_verified"] is True


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows Job Objects")
def test_native_job_runner_timeout_terminates_root_and_descendants() -> None:
    executable = Path(sys.executable).resolve(strict=True)
    result = run_process_in_owned_job(
        executable,
        ["-c", "import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(120)']); time.sleep(120)"],
        cwd=executable.parent,
        timeout_seconds=0.5,
    )

    assert result["status"] == "timed_out"
    assert result["timed_out"] is True
    assert result["job_remaining_member_count"] == 0
    assert result["job_tree_termination_verified"] is True
