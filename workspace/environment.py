from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from shutil import move as shutil_move
from subprocess import PIPE, DEVNULL, Popen
from threading import Lock, Thread
from typing import Any, Callable, Iterable, Sequence
import errno
import hashlib
import os
import signal
import shlex
import stat
import subprocess
import time


class WorkspaceBoundaryError(PermissionError):
    """Raised when an operation attempts to leave the configured workspace."""


class WorkspacePolicyError(PermissionError):
    """Raised when an operation is not allowed by the deterministic policy."""


@dataclass(frozen=True)
class WorkspacePolicy:
    allowed_shell_commands: tuple[str, ...] = ("pytest", "python", "python3", "ruff", "mypy", "git")
    allow_network: bool = False
    allow_credentials: bool = False
    max_processes: int = 4
    max_output_bytes: int = 64_000
    default_timeout: float = 30.0

    def authorize(self, operation: str, *, command: Sequence[str] = (), network: bool = False, credentials: bool = False) -> None:
        if network and not self.allow_network:
            raise WorkspacePolicyError("network access denied by workspace policy")
        if credentials and not self.allow_credentials:
            raise WorkspacePolicyError("credential access denied by workspace policy")
        if operation == "shell":
            if not command or str(command[0]) not in self.allowed_shell_commands:
                raise WorkspacePolicyError("shell command denied by workspace policy")
        if operation == "process" and len(command) > self.max_processes * 1024:
            raise WorkspacePolicyError("process command is unreasonably large")


@dataclass(frozen=True)
class WorkspaceAuditEvent:
    operation: str
    path: str = ""
    command: tuple[str, ...] = ()
    command_hash: str = ""
    authorization: str = "allowed"
    input_hash: str = ""
    output_hash: str = ""
    mission_id: str = ""
    request_id: str = ""
    tool_id: str = ""
    authorization_hash: str = ""
    result: str = ""
    exit_code: int | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


def _hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def _drain_tail(stream, tail: bytearray, limit: int) -> None:
    while True:
        chunk = stream.read(8192)
        if not chunk:
            return
        tail.extend(chunk)
        if len(tail) > limit:
            del tail[: len(tail) - limit]


def _join_process_readers(process: Popen, readers: Sequence[Thread]) -> None:
    for reader in readers:
        reader.join(timeout=0.25)
    if any(reader.is_alive() for reader in readers):
        # A command that exits while leaving descendants holding stdout/stderr
        # open must not strand reader threads or an unbounded process tree.
        _stop_process_tree(process, grace_seconds=0.25)
    for reader in readers:
        reader.join(timeout=1)


def _stop_process_tree(process: Popen, *, grace_seconds: float = 2.0) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            if process.poll() is None:
                process.terminate()
        if process.poll() is None:
            try:
                process.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                pass
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    elif process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
    if process.poll() is None:
        process.wait(timeout=grace_seconds)


class Workspace:
    """A root-confined, auditable operating environment for AgentCore tools."""

    def __init__(self, root: str | Path, *, policy: WorkspacePolicy | None = None, mission_id: str = "", request_id: str = "", tool_id: str = "", authorization_snapshot: Any = None, evidence_store: Any = None):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._supports_dir_fd = os.name == "posix" and os.open in getattr(os, "supports_dir_fd", set())
        self._root_fd = None
        if self._supports_dir_fd:
            self._root_fd = os.open(
                self.root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
        self.policy = policy or WorkspacePolicy()
        self.audit: list[WorkspaceAuditEvent] = []
        self._lock = Lock()
        self.mission_id = mission_id
        self.request_id = request_id
        self.tool_id = tool_id
        self.authorization_snapshot = authorization_snapshot
        self.evidence_store = evidence_store

    def resolve(self, relative: str | Path = ".") -> Path:
        candidate = Path(relative)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.root / candidate).resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise WorkspaceBoundaryError("path escapes workspace root")
        return resolved

    def _relative_parts(self, relative: str | Path = ".") -> tuple[str, ...]:
        if isinstance(relative, tuple):
            if any(not isinstance(part, str) or part in {"", ".", ".."} or "/" in part or "\\" in part for part in relative):
                raise WorkspaceBoundaryError("path escapes workspace root")
            return relative
        candidate = Path(relative)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(self.root)
            except ValueError as exc:
                raise WorkspaceBoundaryError("path escapes workspace root") from exc
        if any(part in {"..", ""} for part in candidate.parts if part != "."):
            raise WorkspaceBoundaryError("path escapes workspace root")
        return tuple(part for part in candidate.parts if part not in {"", "."})

    def _logical_path(self, relative: str | Path = ".") -> Path:
        return self.root.joinpath(*self._relative_parts(relative))

    def _open_dir_fd(self, relative: str | Path = ".", *, create: bool = False) -> int | None:
        parts = self._relative_parts(relative)
        if not self._supports_dir_fd or self._root_fd is None:
            return None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.dup(self._root_fd)
        try:
            for part in parts:
                try:
                    child_fd = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child_fd = os.open(part, flags, dir_fd=fd)
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise WorkspaceBoundaryError("symlink or non-directory path component denied") from exc
                    raise
                os.close(fd)
                fd = child_fd
            return fd
        except Exception:
            os.close(fd)
            raise

    def _open_file_fd(self, relative: str | Path, flags: int, *, mode: int = 0o600, create_parents: bool = False) -> tuple[int, int] | None:
        parts = self._relative_parts(relative)
        if not parts:
            raise WorkspaceBoundaryError("a file path is required")
        parent_fd = self._open_dir_fd(parts[:-1], create=create_parents)
        if parent_fd is None:
            return None
        safe_flags = flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(parts[-1], safe_flags, mode, dir_fd=parent_fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise WorkspaceBoundaryError("workspace file operation requires a regular file")
            return parent_fd, fd
        except OSError as exc:
            os.close(parent_fd)
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise WorkspaceBoundaryError("symlink or non-file path denied") from exc
            raise
        except Exception:
            os.close(parent_fd)
            raise

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def bind(self, *, mission_id: str, request_id: str, tool_id: str, authorization_snapshot: Any, evidence_store: Any = None) -> "Workspace":
        self.mission_id, self.request_id, self.tool_id = mission_id, request_id, tool_id
        self.authorization_snapshot, self.evidence_store = authorization_snapshot, evidence_store
        return self

    def _authorize(self, operation: str, *, path: str = ".", command: Sequence[str] = (), network: str | None = None, credential: str | None = None) -> None:
        if self.authorization_snapshot is None:
            raise WorkspacePolicyError("mission authorization snapshot required")
        forbidden = set(self.authorization_snapshot.forbidden_actions)
        if operation in forbidden:
            raise WorkspacePolicyError("operation forbidden by mission authorization")
        action = self.tool_id if self.tool_id in set(self.authorization_snapshot.allowed_actions) or self.tool_id in set(self.authorization_snapshot.allowed_tools) else operation
        allowed, reason = self.authorization_snapshot.check(action=action, tool_id=self.tool_id, target_identity=self.authorization_snapshot.target_identity, network=network, credential=credential, workspace_path=str(self._logical_path(path)))
        if not allowed:
            if "workspace" in reason.casefold() and "boundar" in reason.casefold():
                raise WorkspaceBoundaryError(reason)
            raise WorkspacePolicyError(reason)
        self.policy.authorize("shell" if operation == "shell" else "process" if operation in {"process", "development"} else operation, command=command, network=bool(network), credentials=bool(credential))

    def _record(self, operation: str, *, path: Path | None = None, command: Sequence[str] = (), input_value: Any = None, output_value: Any = None, result: str = "success", exit_code: int | None = None) -> None:
        relative = str(path.relative_to(self.root)) if path and path != self.root else "." if path else ""
        auth_hash = str(getattr(self.authorization_snapshot, "authorization_hash", ""))
        safe_command = (str(command[0])[:128],) if command else ()
        event = WorkspaceAuditEvent(
            operation=operation,
            path=relative,
            command=safe_command,
            command_hash=_hash(tuple(command)) if command else "",
            authorization="allowed",
            input_hash=_hash(input_value) if input_value is not None else "",
            output_hash=_hash(output_value) if output_value is not None else "",
            mission_id=self.mission_id,
            request_id=self.request_id,
            tool_id=self.tool_id,
            authorization_hash=auth_hash,
            result=result,
            exit_code=exit_code,
            provenance={"mission_id": self.mission_id, "request_id": self.request_id, "tool_id": self.tool_id, "authorization_snapshot_hash": auth_hash, "workspace": str(self.root), "operation": operation},
        )
        self.audit.append(event)
        if self.evidence_store is not None:
            self.evidence_store.append_workspace_event(event)

    def list(self, relative: str | Path = ".") -> list[str]:
        self._authorize("read", path=str(relative))
        fd = self._open_dir_fd(relative)
        if fd is None:
            path = self.resolve(relative)
            if not path.is_dir():
                raise NotADirectoryError(str(relative))
            result = sorted(item.name for item in path.iterdir())
        else:
            try:
                result = sorted(os.listdir(fd))
            finally:
                os.close(fd)
            path = self._logical_path(relative)
        self._record("list", path=path, output_value=result)
        return result

    def read(self, relative: str | Path, *, encoding: str = "utf-8") -> str:
        self._authorize("read", path=str(relative))
        opened = self._open_file_fd(relative, os.O_RDONLY)
        if opened is None:
            path = self.resolve(relative)
            if not path.is_file():
                raise FileNotFoundError(str(relative))
            value = path.read_text(encoding=encoding)
        else:
            parent_fd, fd = opened
            try:
                with os.fdopen(fd, "r", encoding=encoding) as stream:
                    value = stream.read()
            finally:
                os.close(parent_fd)
            path = self._logical_path(relative)
        self._record("read", path=path, output_value=value)
        return value

    def write(self, relative: str | Path, content: str, *, encoding: str = "utf-8", create_parents: bool = True) -> Path:
        self._authorize("write", path=str(relative))
        opened = self._open_file_fd(relative, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, create_parents=create_parents)
        if opened is None:
            path = self.resolve(relative)
            if create_parents:
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding=encoding)
        else:
            parent_fd, fd = opened
            try:
                with os.fdopen(fd, "w", encoding=encoding) as stream:
                    stream.write(content)
            finally:
                os.close(parent_fd)
            path = self._logical_path(relative)
        self._record("write", path=path, input_value=content)
        return path

    def edit(self, relative: str | Path, old: str, new: str, *, expected_count: int = 1) -> Path:
        content = self.read(relative)
        count = content.count(old)
        if count != expected_count:
            raise ValueError(f"edit expected {expected_count} matches, found {count}")
        return self.write(relative, content.replace(old, new), create_parents=False)

    def create(self, relative: str | Path, *, directory: bool = False) -> Path:
        self._authorize("create", path=str(relative))
        parts = self._relative_parts(relative)
        if not parts:
            raise FileExistsError("workspace root already exists")
        parent_fd = self._open_dir_fd(parts[:-1], create=True)
        if parent_fd is None:
            path = self.resolve(relative)
            if directory:
                path.mkdir(parents=True, exist_ok=False)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=False)
        else:
            try:
                if directory:
                    os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
                else:
                    fd = os.open(
                        parts[-1],
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=parent_fd,
                    )
                    os.close(fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise WorkspaceBoundaryError("symlink path denied") from exc
                raise
            finally:
                os.close(parent_fd)
            path = self._logical_path(relative)
        self._record("create", path=path)
        return path

    def move(self, source: str | Path, destination: str | Path) -> Path:
        self._authorize("move", path=str(source))
        self._authorize("move", path=str(destination))
        source_parts = self._relative_parts(source)
        destination_parts = self._relative_parts(destination)
        if not source_parts or not destination_parts:
            raise WorkspaceBoundaryError("workspace root cannot be moved")
        source_parent = self._open_dir_fd(source_parts[:-1])
        try:
            destination_parent = self._open_dir_fd(destination_parts[:-1], create=True)
        except Exception:
            if source_parent is not None:
                os.close(source_parent)
            raise
        if source_parent is None or destination_parent is None:
            src, dst = self.resolve(source), self.resolve(destination)
            if not src.exists() and not src.is_symlink():
                raise FileNotFoundError(str(source))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil_move(str(src), str(dst))
        else:
            try:
                os.stat(source_parts[-1], dir_fd=source_parent, follow_symlinks=False)
                os.replace(
                    source_parts[-1], destination_parts[-1],
                    src_dir_fd=source_parent, dst_dir_fd=destination_parent,
                )
            finally:
                os.close(source_parent)
                os.close(destination_parent)
            src, dst = self._logical_path(source), self._logical_path(destination)
        self._record("move", path=src, input_value=str(destination))
        return dst

    @staticmethod
    def _remove_tree_contents(directory_fd: int) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for name in os.listdir(directory_fd):
            item_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(item_stat.st_mode):
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    Workspace._remove_tree_contents(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)

    def delete(self, relative: str | Path) -> None:
        self._authorize("delete", path=str(relative))
        parts = self._relative_parts(relative)
        if not parts:
            raise WorkspaceBoundaryError("cannot delete workspace root")
        parent_fd = self._open_dir_fd(parts[:-1])
        if parent_fd is None:
            path = self.resolve(relative)
            if path.is_dir():
                for child in sorted(path.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                path.rmdir()
            elif path.exists() or path.is_symlink():
                path.unlink()
        else:
            try:
                item_stat = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISDIR(item_stat.st_mode):
                    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    item_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
                    try:
                        self._remove_tree_contents(item_fd)
                    finally:
                        os.close(item_fd)
                    os.rmdir(parts[-1], dir_fd=parent_fd)
                else:
                    os.unlink(parts[-1], dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            path = self._logical_path(relative)
        self._record("delete", path=path)

    def run_shell(self, command: str, *, timeout: float | None = None, network: bool = False, credentials: bool = False) -> "ProcessResult":
        argv = tuple(shlex.split(command))
        self._authorize("shell", command=argv, network="network" if network else None, credential="credential" if credentials else None)
        self.policy.authorize("shell", command=argv, network=network, credentials=credentials)
        return self.run_process(argv, timeout=timeout, network=network, credentials=credentials)

    def run_process(self, argv: Sequence[str], *, timeout: float | None = None, network: bool = False, credentials: bool = False, cwd: str | Path = ".") -> "ProcessResult":
        command = tuple(str(item) for item in argv)
        if not command:
            raise ValueError("process command must not be empty")
        self._authorize("process", path=str(cwd), command=command, network="network" if network else None, credential="credential" if credentials else None)
        self.policy.authorize("process", command=command, network=network, credentials=credentials)
        workdir = self._logical_path(cwd)
        cwd_fd = self._open_dir_fd(cwd)
        popen_options: dict[str, Any] = {
            "stdin": DEVNULL,
            "stdout": PIPE,
            "stderr": PIPE,
            "text": False,
            "env": {"PATH": os.environ.get("PATH", "")},
            "start_new_session": os.name == "posix",
        }
        if cwd_fd is not None and os.path.isdir("/proc/self/fd"):
            popen_options["cwd"] = f"/proc/self/fd/{cwd_fd}"
            popen_options["pass_fds"] = (cwd_fd,)
        else:
            popen_options["cwd"] = self.resolve(cwd)
        started = time.time()
        try:
            process = Popen(command, **popen_options)
        finally:
            if cwd_fd is not None:
                os.close(cwd_fd)
        stdout_tail, stderr_tail = bytearray(), bytearray()
        readers = [
            Thread(target=_drain_tail, args=(process.stdout, stdout_tail, self.policy.max_output_bytes), daemon=True),
            Thread(target=_drain_tail, args=(process.stderr, stderr_tail, self.policy.max_output_bytes), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout or self.policy.default_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _stop_process_tree(process)
        finally:
            _join_process_readers(process, readers)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        stdout = bytes(stdout_tail).decode("utf-8", errors="replace")
        stderr = bytes(stderr_tail).decode("utf-8", errors="replace")
        result = ProcessResult(command, stdout, stderr, None if timed_out else process.returncode, timed_out, time.time() - started)
        self._record("process", path=workdir, command=command, output_value=result.to_dict(), result="success" if result.ok else "failure", exit_code=result.exit_code)
        return result

    def git(self, operation: str, *arguments: str, timeout: float | None = None) -> "ProcessResult":
        allowed = {"status", "diff", "log", "branch", "checkout", "commit", "apply", "revert"}
        if operation not in allowed:
            raise WorkspacePolicyError("unsupported git operation")
        self._authorize("git", command=("git", operation, *arguments))
        return self.run_process(("git", operation, *arguments), timeout=timeout, cwd=".")

    def develop(self, command: Sequence[str], *, timeout: float | None = None, cwd: str | Path = ".") -> "ProcessResult":
        self._authorize("development", path=str(cwd), command=command)
        return self.run_process(command, timeout=timeout, cwd=cwd)


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {"command": list(self.command), "stdout": self.stdout, "stderr": self.stderr, "exit_code": self.exit_code, "timed_out": self.timed_out, "duration_seconds": self.duration_seconds, "ok": self.ok}


class ProcessHandle:
    """Controlled asynchronous process handle with bounded output and termination."""

    def __init__(self, process: Popen[bytes], command: tuple[str, ...], max_output_bytes: int):
        self.process = process
        self.command = command
        self.max_output_bytes = max_output_bytes
        self._stdout_tail, self._stderr_tail = bytearray(), bytearray()
        self._readers = [
            Thread(target=_drain_tail, args=(process.stdout, self._stdout_tail, max_output_bytes), daemon=True),
            Thread(target=_drain_tail, args=(process.stderr, self._stderr_tail, max_output_bytes), daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def status(self) -> str:
        return "running" if self.process.poll() is None else "exited"

    def monitor(self, timeout: float | None = None) -> ProcessResult:
        started = time.time()
        timed_out = False
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.terminate()
        _join_process_readers(self.process, self._readers)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        stdout = bytes(self._stdout_tail).decode("utf-8", errors="replace")
        stderr = bytes(self._stderr_tail).decode("utf-8", errors="replace")
        return ProcessResult(self.command, stdout, stderr, None if timed_out else self.process.returncode, timed_out, time.time() - started)

    def terminate(self) -> None:
        _stop_process_tree(self.process)


class ProcessManager:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.active: set[ProcessHandle] = set()
        self._lock = Lock()
        self._starting = 0

    def start(self, argv: Sequence[str], *, cwd: str | Path = ".", network: bool = False, credentials: bool = False) -> ProcessHandle:
        command = tuple(str(item) for item in argv)
        if not command:
            raise ValueError("process command must not be empty")
        self.workspace._authorize(
            "process", path=str(cwd), command=command,
            network="network" if network else None,
            credential="credential" if credentials else None,
        )
        with self._lock:
            self.active = {handle for handle in self.active if handle.status() == "running"}
            if len(self.active) + self._starting >= self.workspace.policy.max_processes:
                raise WorkspacePolicyError("process limit reached")
            self._starting += 1
        cwd_fd = None
        try:
            cwd_fd = self.workspace._open_dir_fd(cwd)
            popen_options: dict[str, Any] = {
                "stdin": DEVNULL,
                "stdout": PIPE,
                "stderr": PIPE,
                "text": False,
                "env": {"PATH": os.environ.get("PATH", "")},
                "start_new_session": os.name == "posix",
            }
            if cwd_fd is not None and os.path.isdir("/proc/self/fd"):
                popen_options["cwd"] = f"/proc/self/fd/{cwd_fd}"
                popen_options["pass_fds"] = (cwd_fd,)
            else:
                popen_options["cwd"] = self.workspace.resolve(cwd)
            process = Popen(command, **popen_options)
        finally:
            if cwd_fd is not None:
                os.close(cwd_fd)
            with self._lock:
                self._starting -= 1
        handle = ProcessHandle(process, command, self.workspace.policy.max_output_bytes)
        with self._lock:
            self.active.add(handle)
        try:
            self.workspace._record("process_start", path=self.workspace._logical_path(cwd), command=command, result="started")
        except Exception:
            handle.terminate()
            raise
        return handle


__all__ = ["ProcessHandle", "ProcessManager", "ProcessResult", "Workspace", "WorkspaceAuditEvent", "WorkspaceBoundaryError", "WorkspacePolicy", "WorkspacePolicyError"]
