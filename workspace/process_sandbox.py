"""Platform-specific process sandbox backends.

Windows intentionally fails closed until AppContainer capabilities, file/network
capabilities, resource limits, and child-process lifecycle are implemented and
verified on a native Windows runner.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence
import math
import os
import shutil
import subprocess
import sys


@dataclass(frozen=True)
class SandboxAvailability:
    available: bool
    backend: str
    reason_code: str | None = None
    detail_code: str | None = None
    reason: str | None = None


class ProcessSandboxBackend(Protocol):
    backend_id: str

    def availability(self) -> SandboxAvailability: ...

    def spawn(
        self,
        workspace: Any,
        command: Sequence[str],
        *,
        cwd: str | Path,
        artifact_fd: int,
        timeout: float,
        before_spawn: Callable[[str], None] | None = None,
    ) -> subprocess.Popen[bytes]: ...


class LinuxBubblewrapBackend:
    backend_id = "bubblewrap+prlimit"

    def availability(self) -> SandboxAvailability:
        if sys.platform != "linux" or os.name != "posix":
            return SandboxAvailability(False, self.backend_id, "backend_unavailable", "linux_only", "required rootless Linux process sandbox is unavailable")
        if os.geteuid() == 0:
            return SandboxAvailability(False, self.backend_id, "backend_unavailable", "rootless_linux_required", "required rootless Linux process sandbox is unavailable")
        if not shutil.which("bwrap", path="/usr/bin:/bin"):
            return SandboxAvailability(False, self.backend_id, "backend_unavailable", "bubblewrap_missing", "bubblewrap sandbox is unavailable; process dispatch denied")
        safe_path = os.pathsep.join((str(Path(sys.prefix) / "bin"), "/usr/local/bin", "/usr/bin", "/bin"))
        if not shutil.which("prlimit", path=safe_path):
            return SandboxAvailability(False, self.backend_id, "backend_unavailable", "prlimit_missing", "resource-limit launcher is unavailable; process dispatch denied")
        return SandboxAvailability(True, self.backend_id)

    def spawn(
        self,
        workspace: Any,
        command: Sequence[str],
        *,
        cwd: str | Path,
        artifact_fd: int,
        timeout: float,
        before_spawn: Callable[[str], None] | None = None,
    ) -> subprocess.Popen[bytes]:
        availability = self.availability()
        if not availability.available:
            from .environment import ProcessSandboxUnavailable
            raise ProcessSandboxUnavailable(availability.reason or "process sandbox unavailable", availability=availability)
        safe_path = os.pathsep.join((str(Path(sys.prefix) / "bin"), "/usr/local/bin", "/usr/bin", "/bin"))
        bwrap = shutil.which("bwrap", path="/usr/bin:/bin")
        prlimit = shutil.which("prlimit", path=safe_path)
        if not bwrap or not prlimit:
            current = self.availability()
            from .environment import ProcessSandboxUnavailable
            raise ProcessSandboxUnavailable(current.reason or "process sandbox unavailable", availability=current)

        try:
            root_fd = workspace._open_dir_fd(".")
        except Exception as exc:
            from .environment import ProcessSandboxSetupError
            raise ProcessSandboxSetupError(
                "workspace root could not be safely opened for process isolation",
                detail_code="workspace_root_unavailable",
                backend=self.backend_id,
            ) from exc
        cwd_fd = None
        if root_fd is None:
            from .environment import ProcessSandboxSetupError
            raise ProcessSandboxSetupError("race-resistant workspace handles are required for process isolation", detail_code="workspace_fd_unavailable", backend=self.backend_id)
        try:
            try:
                cwd_fd = workspace._open_dir_fd(cwd)
            except Exception as exc:
                from .environment import ProcessSandboxSetupError
                raise ProcessSandboxSetupError(
                    "working directory could not be safely opened for process isolation",
                    detail_code="working_directory_unavailable",
                    backend=self.backend_id,
                ) from exc
            if cwd_fd is None:
                from .environment import ProcessSandboxSetupError
                raise ProcessSandboxSetupError("race-resistant working-directory handle is required", detail_code="working_directory_fd_unavailable", backend=self.backend_id)

            args: list[str] = [
                bwrap,
                "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            ]
            mounted_roots: list[Path] = []
            for source in ("/usr", "/lib", "/lib64", "/bin"):
                if Path(source).exists():
                    args.extend(("--dir", source, "--ro-bind", source, source))
                    mounted_roots.append(Path(source).resolve())

            for prefix_value in dict.fromkeys((sys.prefix, sys.base_prefix)):
                prefix = Path(prefix_value).resolve()
                if prefix == Path("/") or any(prefix == root or root in prefix.parents for root in mounted_roots):
                    continue
                for parent in reversed(prefix.parents):
                    if parent == Path("/") or any(parent == root or root in parent.parents for root in mounted_roots):
                        continue
                    args.extend(("--dir", str(parent)))
                args.extend(("--dir", str(prefix), "--ro-bind", str(prefix), str(prefix)))
                mounted_roots.append(prefix)

            args.extend(("--dir", "/workspace", "--dir", "/workspace/project"))
            args.extend(("--ro-bind-fd", str(root_fd), "/workspace/project"))
            args.extend(("--dir", "/workspace/cwd", "--ro-bind-fd", str(cwd_fd), "/workspace/cwd"))
            args.extend(("--dev", "/dev", "--proc", "/proc"))
            args.extend(("--size", str(workspace.policy.max_temp_bytes), "--tmpfs", "/tmp"))
            args.extend(("--size", str(workspace.policy.max_total_artifact_bytes), "--tmpfs", "/artifacts"))
            args.extend(("--bind-fd", str(artifact_fd), "/artifacts/pytest.xml"))
            args.extend(("--chdir", "/workspace/cwd", "--clearenv"))
            for key, value in (
                ("PATH", safe_path),
                ("HOME", "/tmp"),
                ("TMPDIR", "/tmp"),
                ("LANG", "C.UTF-8"),
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("PYTHONNOUSERSITE", "1"),
                ("PYTEST_ADDOPTS", "-p no:cacheprovider"),
                ("CYBERSENTINEL_ARTIFACT_DIR", "/artifacts"),
            ):
                args.extend(("--setenv", key, value))

            from .environment import MAX_SANDBOX_PROCESS_SECONDS, ProcessSandboxSetupError
            cpu_limit = min(
                workspace.policy.max_cpu_seconds,
                int(MAX_SANDBOX_PROCESS_SECONDS),
                max(2, math.ceil(timeout)),
            )
            limit_argv = (
                prlimit,
                f"--cpu={cpu_limit}:{cpu_limit}",
                f"--as={workspace.policy.max_memory_bytes}:{workspace.policy.max_memory_bytes}",
                f"--fsize={min(workspace.policy.max_file_bytes, workspace.policy.max_total_artifact_bytes)}:{min(workspace.policy.max_file_bytes, workspace.policy.max_total_artifact_bytes)}",
                f"--nofile={workspace.policy.max_open_files}:{workspace.policy.max_open_files}",
                f"--nproc={workspace.policy.max_child_processes}:{workspace.policy.max_child_processes}",
                "--core=0:0",
                "--",
                *tuple(str(item) for item in command),
            )
            args.extend(("--", *limit_argv))
            if before_spawn is not None:
                # Write-ahead fence: if it fails, Popen is never called and
                # the untrusted command cannot execute.
                before_spawn(self.backend_id)
            try:
                return subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=False,
                    cwd="/",
                    env={"PATH": safe_path, "LANG": "C"},
                    start_new_session=True,
                    pass_fds=(root_fd, cwd_fd, artifact_fd),
                )
            except OSError as exc:
                raise ProcessSandboxSetupError("sandbox process could not be started", detail_code="sandbox_launcher_failed", backend=self.backend_id) from exc
        finally:
            if cwd_fd is not None:
                os.close(cwd_fd)
            os.close(root_fd)


class WindowsAppContainerBackend:
    backend_id = "windows-appcontainer-job"

    def availability(self) -> SandboxAvailability:
        if os.name != "nt":
            return SandboxAvailability(False, self.backend_id, "backend_unavailable", "windows_only", "Windows AppContainer backend is unavailable on this platform")
        return SandboxAvailability(False, self.backend_id, "backend_unavailable", "windows_appcontainer_backend_unimplemented", "Windows process dispatch is blocked: AppContainer, filesystem/network capabilities, resource limits, and job-bound cleanup are not implemented")

    def spawn(self, workspace: Any, command: Sequence[str], *, cwd: str | Path, artifact_fd: int, timeout: float, before_spawn: Callable[[str], None] | None = None) -> subprocess.Popen[bytes]:
        availability = self.availability()
        from .environment import ProcessSandboxUnavailable
        raise ProcessSandboxUnavailable(availability.reason or "Windows process sandbox unavailable", availability=availability)


class UnsupportedProcessSandboxBackend:
    backend_id = "unsupported"

    def __init__(self, platform: str) -> None:
        self.platform = platform

    def availability(self) -> SandboxAvailability:
        return SandboxAvailability(False, self.backend_id, "backend_unavailable", "unsupported_platform", f"no approved process sandbox backend for platform {self.platform}")

    def spawn(self, workspace: Any, command: Sequence[str], *, cwd: str | Path, artifact_fd: int, timeout: float, before_spawn: Callable[[str], None] | None = None) -> subprocess.Popen[bytes]:
        availability = self.availability()
        from .environment import ProcessSandboxUnavailable
        raise ProcessSandboxUnavailable(availability.reason or "process sandbox unavailable", availability=availability)


_PROCESS_SANDBOX_BACKENDS: dict[str, ProcessSandboxBackend] = {
    "linux": LinuxBubblewrapBackend(),
    "win32": WindowsAppContainerBackend(),
}


def get_process_sandbox_backend(platform: str | None = None) -> ProcessSandboxBackend:
    selected = sys.platform if platform is None else str(platform)
    backend = _PROCESS_SANDBOX_BACKENDS.get(selected)
    return backend if backend is not None else UnsupportedProcessSandboxBackend(selected)
