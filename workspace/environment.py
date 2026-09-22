from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from shutil import move as shutil_move
from subprocess import PIPE, DEVNULL, Popen, CompletedProcess, run
from threading import Lock
from typing import Any, Callable, Iterable, Sequence
import hashlib
import os
import shlex
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


class Workspace:
    """A root-confined, auditable operating environment for AgentCore tools."""

    def __init__(self, root: str | Path, *, policy: WorkspacePolicy | None = None, mission_id: str = "", request_id: str = "", tool_id: str = "", authorization_snapshot: Any = None, evidence_store: Any = None):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
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
        allowed, reason = self.authorization_snapshot.check(action=action, tool_id=self.tool_id, target_identity=self.authorization_snapshot.target_identity, network=network, credential=credential, workspace_path=str(self.resolve(path)))
        if not allowed:
            raise WorkspacePolicyError(reason)
        self.policy.authorize("shell" if operation == "shell" else "process" if operation in {"process", "development"} else operation, command=command, network=bool(network), credentials=bool(credential))

    def _record(self, operation: str, *, path: Path | None = None, command: Sequence[str] = (), input_value: Any = None, output_value: Any = None, result: str = "success", exit_code: int | None = None) -> None:
        relative = str(path.relative_to(self.root)) if path and path != self.root else "." if path else ""
        auth_hash = str(getattr(self.authorization_snapshot, "authorization_hash", ""))
        event = WorkspaceAuditEvent(operation, relative, tuple(command), "allowed", _hash(input_value) if input_value is not None else "", _hash(output_value) if output_value is not None else "", self.mission_id, self.request_id, self.tool_id, auth_hash, result, exit_code, {"mission_id": self.mission_id, "request_id": self.request_id, "tool_id": self.tool_id, "authorization_snapshot_hash": auth_hash, "workspace": str(self.root), "operation": operation})
        self.audit.append(event)
        if self.evidence_store is not None:
            self.evidence_store.append_workspace_event(event)

    def list(self, relative: str | Path = ".") -> list[str]:
        self._authorize("read", path=str(relative))
        path = self.resolve(relative)
        if not path.is_dir():
            raise NotADirectoryError(str(relative))
        result = sorted(item.name for item in path.iterdir())
        self._record("list", path=path, output_value=result)
        return result

    def read(self, relative: str | Path, *, encoding: str = "utf-8") -> str:
        self._authorize("read", path=str(relative))
        path = self.resolve(relative)
        if not path.is_file():
            raise FileNotFoundError(str(relative))
        value = path.read_text(encoding=encoding)
        self._record("read", path=path, output_value=value)
        return value

    def write(self, relative: str | Path, content: str, *, encoding: str = "utf-8", create_parents: bool = True) -> Path:
        self._authorize("write", path=str(relative))
        path = self.resolve(relative)
        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding=encoding)
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
        path = self.resolve(relative)
        if directory:
            path.mkdir(parents=True, exist_ok=False)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=False)
        self._record("create", path=path)
        return path

    def move(self, source: str | Path, destination: str | Path) -> Path:
        self._authorize("move", path=str(source))
        self._authorize("move", path=str(destination))
        src, dst = self.resolve(source), self.resolve(destination)
        if not src.exists():
            raise FileNotFoundError(str(source))
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil_move(str(src), str(dst))
        self._record("move", path=src, input_value=str(destination))
        return dst

    def delete(self, relative: str | Path) -> None:
        self._authorize("delete", path=str(relative))
        path = self.resolve(relative)
        if path == self.root:
            raise WorkspaceBoundaryError("cannot delete workspace root")
        if path.is_dir():
            for child in sorted(path.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
            path.rmdir()
        elif path.exists():
            path.unlink()
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
        workdir = self.resolve(cwd)
        started = time.time()
        try:
            completed = run(command, cwd=workdir, capture_output=True, text=True, timeout=timeout or self.policy.default_timeout, check=False, env={"PATH": os.environ.get("PATH", "")})
            result = ProcessResult(command, completed.stdout[-self.policy.max_output_bytes:], completed.stderr[-self.policy.max_output_bytes:], completed.returncode, False, time.time() - started)
        except subprocess.TimeoutExpired as exc:
            result = ProcessResult(command, str(exc.stdout or "")[-self.policy.max_output_bytes:], str(exc.stderr or "")[-self.policy.max_output_bytes:], None, True, time.time() - started)
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

    def __init__(self, process: Popen[str], command: tuple[str, ...], max_output_bytes: int):
        self.process = process
        self.command = command
        self.max_output_bytes = max_output_bytes

    def status(self) -> str:
        return "running" if self.process.poll() is None else "exited"

    def monitor(self, timeout: float | None = None) -> ProcessResult:
        started = time.time()
        try:
            stdout, stderr = self.process.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            self.terminate()
            stdout, stderr = self.process.communicate()
            stdout = exc.stdout or stdout
            stderr = exc.stderr or stderr
            timed_out = True
        return ProcessResult(self.command, str(stdout or "")[-self.max_output_bytes:], str(stderr or "")[-self.max_output_bytes:], None if timed_out else self.process.returncode, timed_out, time.time() - started)

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)


class ProcessManager:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.active: set[ProcessHandle] = set()

    def start(self, argv: Sequence[str], *, cwd: str | Path = ".", network: bool = False, credentials: bool = False) -> ProcessHandle:
        command = tuple(str(item) for item in argv)
        self.workspace.policy.authorize("process", command=command, network=network, credentials=credentials)
        if len(self.active) >= self.workspace.policy.max_processes:
            raise WorkspacePolicyError("process limit reached")
        process = Popen(command, cwd=self.workspace.resolve(cwd), stdout=PIPE, stderr=PIPE, text=True, env={"PATH": os.environ.get("PATH", "")})
        handle = ProcessHandle(process, command, self.workspace.policy.max_output_bytes)
        self.active.add(handle)
        return handle


__all__ = ["ProcessHandle", "ProcessManager", "ProcessResult", "Workspace", "WorkspaceAuditEvent", "WorkspaceBoundaryError", "WorkspacePolicy", "WorkspacePolicyError"]
