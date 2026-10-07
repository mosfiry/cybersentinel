from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from shutil import move as shutil_move
from subprocess import PIPE, DEVNULL, Popen
from threading import Lock, Thread
from typing import Any, Callable, Iterable, Sequence
import heapq
import errno
import hashlib
import math
import mimetypes
import os
import re
import signal
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

MAX_SANDBOX_PROCESS_SECONDS = 300.0


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
    max_timeout_seconds: float = MAX_SANDBOX_PROCESS_SECONDS
    max_cpu_seconds: int = int(MAX_SANDBOX_PROCESS_SECONDS)
    max_memory_bytes: int = 1_073_741_824
    max_file_bytes: int = 16_777_216
    max_open_files: int = 128
    max_child_processes: int = 32
    max_artifacts: int = 8
    max_artifact_bytes: int = 1_048_576
    max_total_artifact_bytes: int = 4_194_304
    max_temp_bytes: int = 67_108_864

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_shell_commands, tuple) or not self.allowed_shell_commands:
            raise ValueError("allowed process commands must be a non-empty tuple")
        if any(not isinstance(item, str) or not item.isidentifier() and not item.replace("-", "").isalnum() for item in self.allowed_shell_commands):
            raise ValueError("allowed process commands must be simple executable names")
        positive_ints = (
            self.max_processes, self.max_output_bytes, self.max_cpu_seconds,
            self.max_memory_bytes, self.max_file_bytes, self.max_open_files,
            self.max_child_processes, self.max_artifacts, self.max_artifact_bytes,
            self.max_total_artifact_bytes, self.max_temp_bytes,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in positive_ints):
            raise ValueError("workspace resource limits must be positive integers")
        for value in (self.default_timeout, self.max_timeout_seconds):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("workspace timeouts must be positive finite numbers")
        if self.default_timeout > self.max_timeout_seconds:
            raise ValueError("default timeout cannot exceed the maximum timeout")
        if self.max_timeout_seconds > MAX_SANDBOX_PROCESS_SECONDS or self.max_cpu_seconds > int(MAX_SANDBOX_PROCESS_SECONDS):
            raise ValueError("workspace process limits exceed the hard 300-second maximum")
        if self.max_artifact_bytes > 4 * 1024 * 1024:
            raise ValueError("single artifact limit exceeds ArtifactStore's hard cap")
        if self.max_total_artifact_bytes < self.max_artifact_bytes:
            raise ValueError("total artifact limit must cover at least one artifact")
        if self.max_temp_bytes > 512 * 1024 * 1024:
            raise ValueError("sandbox temporary storage exceeds its hard maximum")

    def authorize(self, operation: str, *, command: Sequence[str] = (), network: bool = False, credentials: bool = False) -> None:
        if network and not self.allow_network:
            raise WorkspacePolicyError("network access denied by workspace policy")
        if credentials and not self.allow_credentials:
            raise WorkspacePolicyError("credential access denied by workspace policy")
        if operation == "shell":
            if not command or Path(str(command[0])).name not in self.allowed_shell_commands:
                raise WorkspacePolicyError("shell command denied by workspace policy")
        if operation in {"process", "development"}:
            if not command or Path(str(command[0])).name not in self.allowed_shell_commands:
                raise WorkspacePolicyError("process command denied by workspace policy")
            if len(command) > 64 or any(not isinstance(item, str) or "\x00" in item or len(item) > 4096 for item in command) or sum(len(item) for item in command) > 16_384:
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

    def __init__(self, root: str | Path, *, policy: WorkspacePolicy | None = None, mission_id: str = "", request_id: str = "", tool_id: str = "", authorization_snapshot: Any = None, evidence_store: Any = None, execution_context: Any = None):
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
        self.execution_context = execution_context

    @property
    def supports_secure_public_workspace_access(self) -> bool:
        """Whether public workspace listing and file reads avoid path races."""
        return bool(
            self._supports_dir_fd
            and self._root_fd is not None
            and getattr(os, "O_DIRECTORY", 0)
            and getattr(os, "O_NOFOLLOW", 0)
            and os.scandir in getattr(os, "supports_fd", set())
        )

    @property
    def supports_secure_public_git_access(self) -> bool:
        """Whether Git can use the already-open cwd without a path fallback."""
        return self.supports_secure_public_workspace_access and os.path.isdir("/proc/self/fd")

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

    def bind(self, *, mission_id: str, request_id: str, tool_id: str, authorization_snapshot: Any, evidence_store: Any = None, execution_context: Any = None) -> "Workspace":
        self.mission_id, self.request_id, self.tool_id = mission_id, request_id, tool_id
        self.authorization_snapshot, self.evidence_store = authorization_snapshot, evidence_store
        self.execution_context = execution_context
        return self

    def _require_execution_context(self) -> Any:
        context = self.execution_context
        if context is None or not callable(getattr(context, "assert_active", None)):
            raise WorkspacePolicyError("process execution requires the canonical ToolRegistry ExecutionContext")
        context.assert_active()
        if (
            context.mission_id != self.mission_id
            or context.request_id != self.request_id
            or context.tool_id != self.tool_id
            or context.mission_authorization is not self.authorization_snapshot
            or context.evidence_store is not self.evidence_store
        ):
            raise WorkspacePolicyError("process ExecutionContext does not match this Mission Workspace")
        return context

    def _require_process_authority(self) -> Any:
        if self.tool_id != "git_read":
            return self._require_execution_context()
        snapshot = self.authorization_snapshot
        if snapshot is None or not self.mission_id or not self.request_id:
            raise WorkspacePolicyError("Owner-scoped Git reads require a bound Mission authorization snapshot")
        valid, reason = snapshot.validate_for_mission(
            mission_id=self.mission_id,
            owner_identity=snapshot.owner_identity,
            target_identity=snapshot.target_identity,
        )
        if not valid:
            raise WorkspacePolicyError("Mission authorization is not current: " + reason)
        allowed, reason = snapshot.check(
            action="git_read", tool_id="git_read", target_identity=snapshot.target_identity,
            workspace_path=str(self.root),
        )
        if not allowed:
            raise WorkspacePolicyError("Mission authorization blocked Git read: " + reason)
        return None

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

    def list_entries(self, relative: str | Path = ".", *, limit: int = 500) -> list[dict[str, Any]]:
        """List only regular files/directories without following symbolic links."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("directory listing limit must be between 1 and 1000")
        self._authorize("read", path=str(relative))
        fd = self._open_dir_fd(relative)

        def candidates(iterator):
            for item in iterator:
                try:
                    item_stat = item.stat(follow_symlinks=False)
                except OSError:
                    continue
                is_directory = stat.S_ISDIR(item_stat.st_mode)
                if not is_directory and not stat.S_ISREG(item_stat.st_mode):
                    continue
                yield {
                    "name": item.name,
                    "directory": is_directory,
                    "size": None if is_directory else item_stat.st_size,
                }

        def sort_key(item: dict[str, Any]):
            return (not item["directory"], item["name"].casefold(), item["name"])

        if fd is None:
            path = self.resolve(relative)
            if not path.is_dir():
                raise NotADirectoryError(str(relative))
            with os.scandir(path) as iterator:
                entries = heapq.nsmallest(limit, candidates(iterator), key=sort_key)
        else:
            try:
                with os.scandir(fd) as iterator:
                    entries = heapq.nsmallest(limit, candidates(iterator), key=sort_key)
            finally:
                os.close(fd)
            path = self._logical_path(relative)
        entries.sort(key=sort_key)
        self._record("list", path=path, output_value=entries)
        return entries

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

    def read_bounded(
        self, relative: str | Path, *, max_bytes: int = 262_144, encoding: str = "utf-8"
    ) -> str:
        """Read a regular file through a no-follow descriptor with a hard byte cap."""
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        self._authorize("read", path=str(relative))
        opened = self._open_file_fd(relative, os.O_RDONLY)
        if opened is None:
            path = self.resolve(relative)
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                raise ValueError("workspace_file_not_regular_or_too_large")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened_stat = os.fstat(descriptor)
                if not stat.S_ISREG(opened_stat.st_mode):
                    raise WorkspaceBoundaryError("workspace file operation requires a regular file")
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    raw = stream.read(max_bytes + 1)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        else:
            parent_fd, descriptor = opened
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                    raise ValueError("workspace_file_not_regular_or_too_large")
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    raw = stream.read(max_bytes + 1)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent_fd)
            path = self._logical_path(relative)
        if len(raw) > max_bytes:
            raise ValueError("workspace_file_not_regular_or_too_large")
        value = raw.decode(encoding)
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

    def _canonical_command(self, command: tuple[str, ...]) -> tuple[str, ...]:
        requested = command[0]
        name = Path(requested).name
        if self.tool_id == "git_read":
            prefix = ("git", "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false")
            allowed_git = {
                prefix + ("status", "--short", "--branch"),
                prefix + ("branch", "--show-current"),
                prefix + ("log", "-8", "--oneline", "--decorate"),
                prefix + ("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--", "."),
                prefix + ("rev-parse", "--show-toplevel"),
                prefix + ("rev-parse", "HEAD"),
                prefix + ("remote", "get-url", "origin"),
            }
            if command not in allowed_git or name != "git":
                raise WorkspacePolicyError("only fixed read-only Git queries are available")
            resolved_git = shutil.which("git", path="/usr/bin:/bin")
            if resolved_git is None:
                raise WorkspacePolicyError("approved Git executable is unavailable")
            if "/" in requested or "\\" in requested:
                try:
                    if Path(requested).resolve(strict=True) != Path(resolved_git).resolve(strict=True):
                        raise WorkspacePolicyError("Git executable path is not the approved runtime binary")
                except OSError as exc:
                    raise WorkspacePolicyError("Git executable path is unavailable") from exc
            return (str(Path(resolved_git).resolve()), *command[1:])
        expected = ("python3", "-m", "pytest", "-q", "--junitxml=/artifacts/pytest.xml")
        if self.tool_id != "run_project_tests" or name != expected[0] or command[1:] != expected[1:]:
            raise WorkspacePolicyError("only the fixed Mission-authorized pytest command is available")
        safe_path = os.pathsep.join((str(Path(sys.prefix) / "bin"), "/usr/local/bin", "/usr/bin", "/bin"))
        resolved = shutil.which(name, path=safe_path)
        if resolved is None and re.fullmatch(r"python(?:3)?(?:\.\d+)*", name):
            resolved = shutil.which("python3" if "3" in name else "python", path=safe_path)
        if resolved is None:
            raise WorkspacePolicyError("approved process executable is unavailable")
        if "/" in requested or "\\" in requested:
            try:
                if Path(requested).resolve(strict=True) != Path(resolved).resolve(strict=True):
                    raise WorkspacePolicyError("process executable path is not the approved runtime binary")
            except OSError as exc:
                raise WorkspacePolicyError("process executable path is unavailable") from exc
        return (str(Path(resolved)), *command[1:])

    def _sandbox_popen(
        self,
        command: tuple[str, ...],
        *,
        cwd: str | Path,
        artifact_fd: int,
        timeout: float,
    ) -> Popen[bytes]:
        self._require_process_authority()
        if sys.platform != "linux" or os.name != "posix" or os.geteuid() == 0:
            raise WorkspacePolicyError("required rootless Linux process sandbox is unavailable")
        bwrap = shutil.which("bwrap", path="/usr/bin:/bin")
        if not bwrap:
            raise WorkspacePolicyError("bubblewrap sandbox is unavailable; process dispatch denied")
        safe_path = os.pathsep.join((str(Path(sys.prefix) / "bin"), "/usr/local/bin", "/usr/bin", "/bin"))
        prlimit = shutil.which("prlimit", path=safe_path)
        if not prlimit:
            raise WorkspacePolicyError("resource-limit launcher is unavailable; process dispatch denied")

        root_fd = self._open_dir_fd(".")
        cwd_fd = None
        if root_fd is None:
            raise WorkspacePolicyError("race-resistant workspace handles are required for process isolation")
        try:
            cwd_fd = self._open_dir_fd(cwd)
            if cwd_fd is None:
                raise WorkspacePolicyError("race-resistant working-directory handle is required")

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
            args.extend(("--size", str(self.policy.max_temp_bytes), "--tmpfs", "/tmp"))
            args.extend(("--size", str(self.policy.max_total_artifact_bytes), "--tmpfs", "/artifacts"))
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

            cpu_limit = min(
                self.policy.max_cpu_seconds,
                int(MAX_SANDBOX_PROCESS_SECONDS),
                max(2, math.ceil(timeout)),
            )
            limit_argv = (
                prlimit,
                f"--cpu={cpu_limit}:{cpu_limit}",
                f"--as={self.policy.max_memory_bytes}:{self.policy.max_memory_bytes}",
                f"--fsize={min(self.policy.max_file_bytes, self.policy.max_total_artifact_bytes)}:{min(self.policy.max_file_bytes, self.policy.max_total_artifact_bytes)}",
                f"--nofile={self.policy.max_open_files}:{self.policy.max_open_files}",
                f"--nproc={self.policy.max_child_processes}:{self.policy.max_child_processes}",
                "--core=0:0",
                "--",
                *command,
            )
            args.extend(("--", *limit_argv))
            return Popen(
                args,
                stdin=DEVNULL,
                stdout=PIPE,
                stderr=PIPE,
                text=False,
                cwd="/",
                env={"PATH": safe_path, "LANG": "C"},
                start_new_session=True,
                pass_fds=(root_fd, cwd_fd, artifact_fd),
            )
        finally:
            if cwd_fd is not None:
                os.close(cwd_fd)
            os.close(root_fd)

    def _capture_artifacts(self, directory: str) -> tuple[tuple["ProcessArtifact", ...], bool]:
        artifacts: list[ProcessArtifact] = []
        total_bytes = 0
        scanned = 0
        truncated = False
        scan_cap = max(self.policy.max_artifacts * 16, 32)

        def walk(current: str, prefix: str, depth: int) -> None:
            nonlocal total_bytes, scanned, truncated
            try:
                entries = sorted(os.scandir(current), key=lambda entry: entry.name)
            except OSError:
                truncated = True
                return
            for entry in entries:
                scanned += 1
                if scanned > scan_cap or len(artifacts) >= self.policy.max_artifacts:
                    truncated = True
                    return
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                try:
                    if entry.is_symlink():
                        truncated = True
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth < 3:
                            walk(entry.path, relative, depth + 1)
                        else:
                            truncated = True
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if info.st_size > self.policy.max_artifact_bytes or total_bytes + info.st_size > self.policy.max_total_artifact_bytes:
                        truncated = True
                        continue
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(entry.path, flags)
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            continue
                        with os.fdopen(fd, "rb", closefd=False) as stream:
                            content = stream.read(self.policy.max_artifact_bytes + 1)
                    finally:
                        os.close(fd)
                    if len(content) > self.policy.max_artifact_bytes or total_bytes + len(content) > self.policy.max_total_artifact_bytes:
                        truncated = True
                        continue
                    filename = Path(entry.name).name[:200] or "sandbox-output"
                    artifacts.append(ProcessArtifact(relative, filename, content, hashlib.sha256(content).hexdigest()))
                    total_bytes += len(content)
                except OSError:
                    truncated = True

        walk(directory, "", 0)
        return tuple(artifacts), truncated

    def run_process(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        network: bool = False,
        credentials: bool = False,
        cwd: str | Path = ".",
        cancellation_event: Any = None,
    ) -> "ProcessResult":
        command = tuple(str(item) for item in argv)
        if not command:
            raise ValueError("process command must not be empty")
        execution_context = self._require_process_authority()
        if network or credentials:
            raise WorkspacePolicyError("sandboxed processes never receive network or host credentials")
        if cancellation_event is None and execution_context is not None:
            cancellation_event = execution_context.cancellation_event
        self._authorize("process", path=str(cwd), command=command, network="network" if network else None, credential="credential" if credentials else None)
        self.policy.authorize("process", command=command, network=network, credentials=credentials)
        command = self._canonical_command(command)
        return self._run_process_authorized(
            command, timeout=timeout, cwd=cwd, cancellation_event=cancellation_event,
        )

    def _run_process_authorized(
        self,
        command: tuple[str, ...],
        *,
        timeout: float | None,
        cwd: str | Path,
        cancellation_event: Any = None,
    ) -> "ProcessResult":
        execution_context = self._require_process_authority()
        if cancellation_event is None and execution_context is not None:
            cancellation_event = execution_context.cancellation_event
        effective_timeout = self.policy.default_timeout if timeout is None else timeout
        if isinstance(effective_timeout, bool) or not isinstance(effective_timeout, (int, float)) or not math.isfinite(effective_timeout) or effective_timeout <= 0:
            raise WorkspacePolicyError("process timeout must be a positive finite number")
        if effective_timeout > self.policy.max_timeout_seconds:
            raise WorkspacePolicyError("process timeout exceeds the workspace policy limit")
        workdir = self._logical_path(cwd)
        started = time.time()
        with tempfile.TemporaryDirectory(prefix="cybersentinel-process-artifacts-") as artifact_directory:
            os.chmod(artifact_directory, 0o700)
            artifact_path = Path(artifact_directory) / "pytest.xml"
            artifact_flags = os.O_CREAT | os.O_RDWR | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            artifact_fd = os.open(artifact_path, artifact_flags, 0o600)
            try:
                process = self._sandbox_popen(
                    command, cwd=cwd, artifact_fd=artifact_fd,
                    timeout=float(effective_timeout),
                )
            finally:
                os.close(artifact_fd)
            stdout_tail, stderr_tail = bytearray(), bytearray()
            readers = [
                Thread(target=_drain_tail, args=(process.stdout, stdout_tail, self.policy.max_output_bytes), daemon=True),
                Thread(target=_drain_tail, args=(process.stderr, stderr_tail, self.policy.max_output_bytes), daemon=True),
            ]
            for reader in readers:
                reader.start()
            timed_out = False
            cancelled = False
            deadline = time.monotonic() + float(effective_timeout)
            while process.poll() is None:
                if cancellation_event is not None and bool(getattr(cancellation_event, "is_set", lambda: False)()):
                    cancelled = True
                    _stop_process_tree(process, grace_seconds=0.25)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    _stop_process_tree(process, grace_seconds=0.25)
                    break
                try:
                    process.wait(timeout=min(0.1, remaining))
                except subprocess.TimeoutExpired:
                    continue
            _join_process_readers(process, readers)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
            artifacts, capture_truncated = self._capture_artifacts(artifact_directory)
            stdout = bytes(stdout_tail).decode("utf-8", errors="replace")
            stderr = bytes(stderr_tail).decode("utf-8", errors="replace")
            result = ProcessResult(
                command, stdout, stderr,
                None if timed_out or cancelled else process.returncode,
                timed_out, time.time() - started,
                cancelled=cancelled, artifacts=artifacts,
                artifact_capture_truncated=capture_truncated,
            )
        audit_summary = {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "duration_seconds": round(result.duration_seconds, 3),
            "sandbox_backend": result.sandbox_backend,
            "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
            "artifacts": [item.to_dict() for item in artifacts],
            "artifact_capture_truncated": capture_truncated,
        }
        self._record("process", path=workdir, command=command, output_value=audit_summary, result="success" if result.ok else "failure", exit_code=result.exit_code)
        return result

    def git(self, operation: str, *arguments: str, timeout: float | None = None) -> "ProcessResult":
        allowed = {"status", "diff", "log", "branch"}
        if operation not in allowed:
            raise WorkspacePolicyError("unsupported git operation")
        self._authorize("git", command=("git", operation, *arguments))
        return self.run_process(("git", operation, *arguments), timeout=timeout, cwd=".")

    def git_readonly(self, operation: str, *, timeout: float | None = None) -> "ProcessResult":
        """Expose fixed, read-only Git queries for the authenticated Owner UI."""
        commands = {
            "status": ("status", "--short", "--branch"),
            "branch": ("branch", "--show-current"),
            "log": ("log", "-8", "--oneline", "--decorate"),
            "diff": ("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--", "."),
            "repository": ("rev-parse", "--show-toplevel"),
            "head": ("rev-parse", "HEAD"),
            "remote": ("remote", "get-url", "origin"),
        }
        arguments = commands.get(operation)
        if arguments is None:
            raise WorkspacePolicyError("unsupported read-only git operation")
        command = (
            "git",
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        )
        self._authorize("git", command=command)
        self.policy.authorize("process", command=command)
        context = self._require_process_authority()
        return self._run_process_authorized(
            self._canonical_command(command), timeout=timeout, cwd=".",
            cancellation_event=context.cancellation_event if context is not None else None,
        )

    def develop(
        self,
        command: Sequence[str],
        *,
        timeout: float | None = None,
        cwd: str | Path = ".",
        cancellation_event: Any = None,
    ) -> "ProcessResult":
        self._authorize("development", path=str(cwd), command=command)
        return self.run_process(command, timeout=timeout, cwd=cwd, cancellation_event=cancellation_event)


@dataclass(frozen=True)
class ProcessArtifact:
    relative_path: str
    filename: str
    content: bytes = field(repr=False)
    sha256: str = ""

    @property
    def size_bytes(self) -> int:
        return len(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": len(self.content),
        }


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    cancelled: bool = False
    sandbox_backend: str = "bubblewrap+prlimit"
    artifacts: tuple[ProcessArtifact, ...] = ()
    artifact_capture_truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "duration_seconds": self.duration_seconds,
            "sandbox_backend": self.sandbox_backend,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "artifact_capture_truncated": self.artifact_capture_truncated,
            "ok": self.ok,
        }


class ProcessHandle:
    """Controlled asynchronous process handle with bounded output and termination."""

    def __init__(self, process: Popen[bytes], command: tuple[str, ...], max_output_bytes: int, *, temporary_directory: Any = None, max_timeout_seconds: float = MAX_SANDBOX_PROCESS_SECONDS, cancellation_event: Any = None):
        self.process = process
        self.command = command
        self.max_output_bytes = max_output_bytes
        self.max_timeout_seconds = max_timeout_seconds
        self.temporary_directory = temporary_directory
        self.cancellation_event = cancellation_event
        self._cancelled = False
        self._cleaned = False
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
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0 or timeout > self.max_timeout_seconds):
            raise WorkspacePolicyError("process monitor timeout is outside the workspace policy limit")
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.process.poll() is None:
            if self.cancellation_event is not None and bool(getattr(self.cancellation_event, "is_set", lambda: False)()):
                self._cancelled = True
                self.terminate()
                break
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                timed_out = True
                self.terminate()
                break
            try:
                self.process.wait(timeout=0.1 if remaining is None else min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
        _join_process_readers(self.process, self._readers)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        stdout = bytes(self._stdout_tail).decode("utf-8", errors="replace")
        stderr = bytes(self._stderr_tail).decode("utf-8", errors="replace")
        result = ProcessResult(
            self.command, stdout, stderr,
            None if timed_out or self._cancelled else self.process.returncode,
            timed_out, time.time() - started, cancelled=self._cancelled,
        )
        self._cleanup()
        return result

    def terminate(self) -> None:
        self._cancelled = self.process.poll() is None
        _stop_process_tree(self.process)
        self._cleanup()

    def _cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        if self.temporary_directory is not None:
            self.temporary_directory.cleanup()
            self.temporary_directory = None


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
        if network or credentials:
            raise WorkspacePolicyError("sandboxed processes never receive network or host credentials")
        execution_context = self.workspace._require_execution_context()
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
        temporary_directory = tempfile.TemporaryDirectory(prefix="cybersentinel-managed-process-")
        try:
            command = self.workspace._canonical_command(command)
            self.workspace.policy.authorize("process", command=command)
            artifact_path = Path(temporary_directory.name) / "pytest.xml"
            artifact_fd = os.open(
                artifact_path,
                os.O_CREAT | os.O_RDWR | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                process = self.workspace._sandbox_popen(
                    command, cwd=cwd, artifact_fd=artifact_fd,
                    timeout=self.workspace.policy.max_timeout_seconds,
                )
            finally:
                os.close(artifact_fd)
        finally:
            with self._lock:
                self._starting -= 1
            if "process" not in locals():
                temporary_directory.cleanup()
        handle = ProcessHandle(
            process, command, self.workspace.policy.max_output_bytes,
            temporary_directory=temporary_directory,
            max_timeout_seconds=self.workspace.policy.max_timeout_seconds,
            cancellation_event=execution_context.cancellation_event,
        )
        with self._lock:
            self.active.add(handle)
        try:
            self.workspace._record("process_start", path=self.workspace._logical_path(cwd), command=command, result="started")
        except Exception:
            handle.terminate()
            raise
        return handle


__all__ = ["MAX_SANDBOX_PROCESS_SECONDS", "ProcessHandle", "ProcessManager", "ProcessResult", "Workspace", "WorkspaceAuditEvent", "WorkspaceBoundaryError", "WorkspacePolicy", "WorkspacePolicyError"]
