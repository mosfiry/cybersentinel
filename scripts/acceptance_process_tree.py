"""Owned process-tree lifecycle for bounded local acceptance helpers.

Windows launches are created suspended and assigned to a unique Job Object
before resume. Linux can use an explicitly configured delegated cgroup v2 root;
otherwise fixtures use a dedicated process group and verified group teardown.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Mapping, Sequence, TextIO


MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS = 300.0
MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS = 30.0
MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS = 5.0


def _validated_execution_timeout(
    timeout_seconds: object,
    *,
    maximum_seconds: float,
    allow_zero: bool = True,
) -> float:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("acceptance_process_timeout_invalid")
    try:
        normalized = float(timeout_seconds)
    except (OverflowError, TypeError, ValueError):
        raise ValueError("acceptance_process_timeout_invalid") from None
    if (
        not math.isfinite(normalized)
        or normalized < 0
        or normalized > maximum_seconds
        or (not allow_zero and normalized == 0)
    ):
        raise ValueError("acceptance_process_timeout_invalid")
    return normalized


def _bounded_cleanup_timeout(timeout_seconds: object) -> float:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        return MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS
    try:
        normalized = float(timeout_seconds)
    except (OverflowError, TypeError, ValueError):
        return MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS
    if not math.isfinite(normalized):
        return MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS
    return min(MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS, max(0.0, normalized))


class _PosixOwnedProcess:
    def __init__(self, process: subprocess.Popen, *, cgroup_scope=None) -> None:
        self.process = process
        self.pid = process.pid
        self._cgroup_scope = cgroup_scope
        self._cgroup_removed = cgroup_scope is None
        self._closed = False
        self._stop_verified = False

    def poll(self):
        return self.process.poll()

    def wait(self, timeout: float | None = None):
        duration = (
            MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS
            if timeout is None
            else _validated_execution_timeout(
                timeout, maximum_seconds=MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS
            )
        )
        return self.process.wait(timeout=duration)

    def terminate(self) -> None:
        if not self.terminate_tree(timeout_seconds=MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS):
            raise RuntimeError("acceptance_process_tree_stop_unverified")

    def kill(self) -> None:
        if not self.terminate_tree(timeout_seconds=MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS):
            raise RuntimeError("acceptance_process_tree_stop_unverified")

    def terminate_tree(self, *, timeout_seconds: float = 5.0) -> bool:
        if self._closed:
            return self._stop_verified
        timeout_seconds = _bounded_cleanup_timeout(timeout_seconds)
        deadline = time.monotonic() + timeout_seconds
        cleanup_verified = True
        if self._cgroup_scope is not None:
            if not self._cgroup_removed:
                try:
                    self._cgroup_scope.cleanup(
                        kill_if_populated=True,
                        timeout=max(0.0, deadline - time.monotonic()),
                    )
                    self._cgroup_removed = True
                except Exception:
                    cleanup_verified = False
                    self._signal_group(signal.SIGKILL)
                    try:
                        self._cgroup_scope.cleanup(
                            kill_if_populated=True,
                            timeout=max(0.0, deadline - time.monotonic()),
                        )
                        self._cgroup_removed = True
                        cleanup_verified = True
                    except Exception:
                        cleanup_verified = False
            if not self._cgroup_removed:
                cleanup_verified = False
        else:
            self._signal_group(signal.SIGTERM)
            self._wait_group_until(deadline)
            if self._group_exists():
                self._signal_group(signal.SIGKILL)

        try:
            self.process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self._signal_group(signal.SIGKILL)
            remaining = max(0.0, deadline - time.monotonic())
            if remaining > 0:
                try:
                    self.process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass

        group_stopped = self._wait_group_until(deadline)
        cgroup_empty = self._cgroup_removed
        self._stop_verified = (
            cleanup_verified
            and self.process.poll() is not None
            and group_stopped
            and cgroup_empty
        )
        self._closed = self._stop_verified
        return self._stop_verified

    def close(self) -> bool:
        return self.terminate_tree(timeout_seconds=MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS)

    def _signal_group(self, sig: int) -> None:
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass

    def _group_exists(self) -> bool:
        try:
            os.killpg(self.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _wait_group_until(self, deadline: float) -> bool:
        while time.monotonic() < deadline:
            if not self._group_exists():
                return True
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.02, remaining))
        return not self._group_exists()


class _WindowsOwnedProcess:
    def __init__(self, job, identity) -> None:
        self._job = job
        self._identity = identity
        self.pid = identity.process_id
        self._closed = False
        self._stop_verified = False
        self._exit_code = None

    def poll(self):
        if self._closed:
            return self._exit_code if self._exit_code is not None else 1
        try:
            if not self._job.wait_current(0.0):
                return None
            self._exit_code = self._job.exit_code_current()
            return self._exit_code
        except Exception:
            return None

    def wait(self, timeout: float | None = None):
        if self._closed:
            return self._exit_code if self._exit_code is not None else 1
        duration = (
            MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS
            if timeout is None
            else _validated_execution_timeout(
                timeout, maximum_seconds=MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS
            )
        )
        if not self._job.wait_current(duration):
            raise subprocess.TimeoutExpired(["acceptance-owned-process", str(self.pid)], timeout)
        self._exit_code = self._job.exit_code_current()
        return self._exit_code

    def terminate(self) -> None:
        if not self.terminate_tree(timeout_seconds=MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS):
            raise RuntimeError("acceptance_process_tree_stop_unverified")

    def kill(self) -> None:
        self.terminate()

    def terminate_tree(self, *, timeout_seconds: float = 5.0) -> bool:
        if self._closed:
            return self._stop_verified
        try:
            result = self._job.terminate_owned_job(
                timeout_seconds=_bounded_cleanup_timeout(timeout_seconds)
            )
            self._stop_verified = result.get("termination_succeeded") is True
        except Exception:
            self._stop_verified = False
        finally:
            if not self._stop_verified:
                # KILL_ON_JOB_CLOSE is the last-resort teardown for this uniquely
                # owned job; report failure unless the member count was verified.
                try:
                    self._job.close()
                except Exception:
                    pass
                self._closed = True
            else:
                try:
                    self._job.close()
                finally:
                    self._closed = True
        return self._stop_verified

    def close(self) -> bool:
        return self.terminate_tree(timeout_seconds=MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS)


def start_owned_process(
    command: Sequence[str | Path],
    *,
    cwd: str | Path,
    stdout: int | TextIO | None = None,
    stderr: int | TextIO | None = None,
    use_cgroup_if_configured: bool = False,
    environment: Mapping[str, str] | None = None,
):
    """Start one process with an owned OS process-tree boundary."""
    argv = [str(item) for item in command]
    if not argv:
        raise ValueError("acceptance_command_empty")
    working_directory = str(Path(cwd).resolve(strict=True))
    if os.name == "nt":
        from scripts.windows_process_job import WindowsOwnedJob

        # WindowsOwnedJob uses a suspended CreateProcess/AssignProcessToJob
        # sequence; its public launcher does not redirect standard handles.
        job = WindowsOwnedJob.create()
        try:
            identity = job.launch(
                argv[0], argv[1:], cwd=working_directory, environment=environment
            )
            return _WindowsOwnedProcess(job, identity)
        except Exception:
            try:
                job.terminate_owned_job(timeout_seconds=2.0)
            except Exception:
                pass
            job.close()
            raise

    cgroup_scope = None
    if use_cgroup_if_configured and os.environ.get("CYBERSENTINEL_CGROUP_ROOT"):
        from workspace.cgroup_v2 import CgroupV2Manager

        manager = CgroupV2Manager.from_environment()
        if manager.availability_error() is not None:
            raise RuntimeError("acceptance_cgroup_unavailable")
        try:
            cgroup_scope = manager.create_scope(
                memory_bytes=256 * 1024 * 1024,
                process_count=16,
                cpu_seconds=10,
                timeout_seconds=15.0,
            )
        except Exception:
            raise RuntimeError("acceptance_cgroup_scope_creation_failed") from None
        argv = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "workspace" / "_cgroup_exec.py"),
            str(cgroup_scope.cgroup_procs),
            "--",
            *argv,
        ]
    try:
        process = subprocess.Popen(
            argv,
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            text=True,
            close_fds=True,
            start_new_session=True,
            env=dict(environment) if environment is not None else None,
        )
        return _PosixOwnedProcess(process, cgroup_scope=cgroup_scope)
    except Exception:
        if cgroup_scope is not None:
            try:
                cgroup_scope.cleanup(kill_if_populated=True, timeout=1.0)
            except Exception:
                pass
        raise


def run_owned_command(
    command: Sequence[str | Path],
    *,
    cwd: str | Path,
    timeout_seconds: float,
    check: bool = True,
    stdout: int | TextIO | None = subprocess.DEVNULL,
    stderr: int | TextIO | None = subprocess.DEVNULL,
):
    """Run a short acceptance helper with a timeout and verified tree cleanup."""
    timeout_seconds = _validated_execution_timeout(
        timeout_seconds,
        maximum_seconds=MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS,
        allow_zero=False,
    )
    if os.name == "nt":
        # WindowsOwnedJob currently inherits the caller's standard handles.
        stdout = None
        stderr = None
    process = start_owned_process(
        command,
        cwd=cwd,
        stdout=stdout,
        stderr=stderr,
        use_cgroup_if_configured=True,
    )
    timed_out = False
    return_code = None
    try:
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        if not process.close():
            raise RuntimeError("acceptance_process_tree_stop_unverified")
    if timed_out:
        raise subprocess.TimeoutExpired([str(part) for part in command], timeout_seconds) from None
    if check and return_code != 0:
        raise subprocess.CalledProcessError(return_code, [str(part) for part in command])
    return return_code


__all__ = ["run_owned_command", "start_owned_process"]
