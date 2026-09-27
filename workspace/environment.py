from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from shutil import move as shutil_move
from subprocess import CompletedProcess, run
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
        return result

    def read(self, relative: str | Path, *, encoding: str = "utf-8") -> str:
        self._authorize("read", path=str(relative))
        path = self.resolve(relative)
        if not path.is_file():
            raise FileNotFoundError(str(relative))
        return value

    def write(self, relative: str | Path, content: str, *, encoding: str = "utf-8", create_parents: bool = True) -> Path:
        self._authorize("write", path=str(relative))
        path = self.resolve(relative)
        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        return self.write(relative, content.replace(old, new), create_parents=False)

    def create(self, relative: str | Path, *, directory: bool = False) -> Path:
        self._authorize("create", path=str(relative))
        path = self.resolve(relative)
        if directory:
            path.mkdir(parents=True, exist_ok=False)
        return path

    def move(self, source: str | Path, destination: str | Path) -> Path:
        self._authorize("move", path=str(source))
        self._authorize("move", path=str(destination))
        src, dst = self.resolve(source), self.resolve(destination)
        if not src.exists():
            raise FileNotFoundError(str(source))
        return dst

    def delete(self, relative: str | Path) -> None:
        self._authorize("delete", path=str(relative))
        path = self.resolve(relative)
        if path == self.root:
            raise WorkspaceBoundaryError("cannot delete workspace root")

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
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {"command": list(self.command), "stdout": self.stdout, "stderr": self.stderr, "exit_code": self.exit_code, "timed_out": self.timed_out, "duration_seconds": self.duration_seconds, "ok": self.ok}


__all__ = ["ProcessResult", "Workspace", "WorkspaceAuditEvent", "WorkspaceBoundaryError", "WorkspacePolicy", "WorkspacePolicyError"]
