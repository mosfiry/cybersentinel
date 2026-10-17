"""Fail-closed cgroup v2 scopes for bounded Linux process trees.

The service must receive a dedicated, empty, delegated cgroup below
/sys/fs/cgroup with cpu/memory/pids controllers enabled and finite aggregate
limits. Each sandbox launch gets a child cgroup whose hard limits apply to the
whole process tree; descendants inherit membership across exec/fork.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
import os
import re
import time
import uuid


_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
_CGROUP_ROOT_ENV = "CYBERSENTINEL_CGROUP_ROOT"
_CGROUP_MOUNT = Path("/sys/fs/cgroup")


class CgroupV2Error(RuntimeError):
    """The delegated cgroup cannot enforce the complete process-tree contract."""


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise CgroupV2Error("required cgroup control file is unavailable") from exc


def _write_text(path: Path, value: str) -> None:
    try:
        with path.open("w", encoding="ascii") as stream:
            stream.write(value)
    except OSError as exc:
        raise CgroupV2Error("required cgroup control file is not writable") from exc


def _finite_int(path: Path, *, minimum: int = 1) -> int:
    value = _read_text(path)
    if not value.isdecimal() or int(value) < minimum:
        raise CgroupV2Error("aggregate cgroup limit must be finite and positive")
    return int(value)


def _events(path: Path, *, required_keys: frozenset[str] = frozenset()) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if (
                len(parts) != 2
                or not re.fullmatch(r"[a-z_]+", parts[0])
                or not parts[1].isdecimal()
                or parts[0] in result
            ):
                raise CgroupV2Error("cgroup resource event counters are malformed")
            result[parts[0]] = int(parts[1])
    except (OSError, UnicodeError):
        if required_keys:
            raise CgroupV2Error("required cgroup resource event counters are unavailable") from None
        return {}
    if not required_keys.issubset(result):
        raise CgroupV2Error("required cgroup resource event counters are incomplete")
    return result


def _cpu_max(path: Path) -> tuple[int, int]:
    parts = _read_text(path).split()
    if len(parts) != 2 or parts[0] == "max" or not all(item.isdecimal() for item in parts):
        raise CgroupV2Error("aggregate cgroup CPU limit must be finite")
    quota, period = map(int, parts)
    if quota < 1000 or period < 1000:
        raise CgroupV2Error("aggregate cgroup CPU quota is below the supported minimum")
    return quota, period


@dataclass
class CgroupV2Scope:
    path: Path
    memory_events_before: Mapping[str, int]
    pids_events_before: Mapping[str, int]

    @property
    def cgroup_procs(self) -> Path:
        return self.path / "cgroup.procs"

    def resource_limit_reason(self) -> str | None:
        memory_path = self.path / "memory.events.local"
        if not memory_path.exists():
            memory_path = self.path / "memory.events"
        current_memory = _events(memory_path, required_keys=frozenset({"oom", "oom_kill"}))
        if not {"oom", "oom_kill"}.issubset(self.memory_events_before):
            raise CgroupV2Error("baseline cgroup memory event counters are incomplete")
        if any(current_memory.get(key, 0) > self.memory_events_before.get(key, 0) for key in ("oom", "oom_kill")):
            return "cgroup_memory_limit"
        current_pids = _events(self.path / "pids.events", required_keys=frozenset({"max"}))
        if "max" not in self.pids_events_before:
            raise CgroupV2Error("baseline cgroup process event counters are incomplete")
        if current_pids.get("max", 0) > self.pids_events_before.get("max", 0):
            return "cgroup_process_count_limit"
        return None

    def populated(self) -> bool:
        events = _events(self.path / "cgroup.events")
        if "populated" in events:
            return events["populated"] == 1
        try:
            return bool(self.cgroup_procs.read_text(encoding="ascii").strip())
        except OSError as exc:
            raise CgroupV2Error("sandbox cgroup membership cannot be inspected") from exc

    def kill(self) -> None:
        if not (self.path / "cgroup.kill").exists():
            raise CgroupV2Error("cgroup.kill is unavailable; process-tree cleanup cannot be guaranteed")
        _write_text(self.path / "cgroup.kill", "1")

    def wait_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while self.populated():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def cleanup(self, *, kill_if_populated: bool = True, timeout: float = 2.0) -> None:
        if self.populated():
            if not kill_if_populated:
                raise CgroupV2Error("sandbox cgroup still contains processes")
            self.kill()
            if not self.wait_empty(timeout):
                raise CgroupV2Error("sandbox process tree did not exit after cgroup.kill")
        try:
            self.path.rmdir()
        except OSError as exc:
            raise CgroupV2Error("empty sandbox cgroup could not be removed") from exc


class CgroupV2Manager:
    """Validates a delegated aggregate parent and creates bounded child scopes."""

    def __init__(self, root: str | Path | None = None, *, require_system_mount: bool = True):
        configured = root if root is not None else os.environ.get(_CGROUP_ROOT_ENV)
        self.root = Path(configured) if configured else None
        self.require_system_mount = bool(require_system_mount)

    @classmethod
    def from_environment(cls) -> "CgroupV2Manager":
        return cls(os.environ.get(_CGROUP_ROOT_ENV))

    def _validate_root(self) -> tuple[int, int, int, int]:
        root = self.root
        if root is None:
            raise CgroupV2Error("delegated_cgroup_not_configured")
        lexical = Path(os.path.abspath(str(root)))
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise CgroupV2Error("delegated_cgroup_root_unavailable") from exc
        if lexical != resolved or not resolved.is_dir():
            raise CgroupV2Error("delegated_cgroup_root_must_not_be_a_symlink")
        if self.require_system_mount:
            try:
                relative = resolved.relative_to(_CGROUP_MOUNT)
            except ValueError as exc:
                raise CgroupV2Error("delegated_cgroup_must_be_under_the_cgroup_v2_mount") from exc
            if not relative.parts:
                raise CgroupV2Error("the_cgroup_mount_root_is_not_a_delegated_sandbox")
        controllers = set(_read_text(resolved / "cgroup.controllers").split())
        subtree = set(_read_text(resolved / "cgroup.subtree_control").replace("+", "").split())
        if not _REQUIRED_CONTROLLERS.issubset(controllers) or not _REQUIRED_CONTROLLERS.issubset(subtree):
            raise CgroupV2Error("cpu_memory_and_pids_controllers_must_be_enabled_for_children")
        if _read_text(resolved / "cgroup.procs"):
            raise CgroupV2Error("delegated_parent_must_be_an_empty_inner_cgroup")
        memory_limit = _finite_int(resolved / "memory.max")
        pids_limit = _finite_int(resolved / "pids.max")
        cpu_quota, cpu_period = _cpu_max(resolved / "cpu.max")
        if _read_text(resolved / "memory.oom.group") != "1":
            raise CgroupV2Error("aggregate_memory_oom_must_kill_the_delegated_process_group")
        if not (resolved / "cgroup.kill").exists():
            raise CgroupV2Error("cgroup.kill_is_required_for_descendant_cleanup")
        return memory_limit, pids_limit, cpu_quota, cpu_period

    def availability_error(self) -> str | None:
        try:
            self._validate_root()
            return None
        except CgroupV2Error as exc:
            return str(exc)

    def create_scope(self, *, memory_bytes: int, process_count: int, cpu_seconds: int, timeout_seconds: float) -> CgroupV2Scope:
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in (memory_bytes, process_count, cpu_seconds)):
            raise CgroupV2Error("sandbox cgroup limits must be positive integers")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise CgroupV2Error("sandbox cgroup wall-clock limit is invalid")
        root_memory, root_pids, root_cpu_quota, root_cpu_period = self._validate_root()
        root = self.root.resolve(strict=True)  # type: ignore[union-attr]
        scope_path = root / ("cybersentinel-" + uuid.uuid4().hex)
        try:
            scope_path.mkdir(mode=0o700)
        except OSError as exc:
            raise CgroupV2Error("a per-execution cgroup could not be created") from exc
        scope = CgroupV2Scope(scope_path, {}, {})
        try:
            memory = min(memory_bytes, root_memory)
            pids = min(process_count, root_pids)
            period = root_cpu_period
            desired_quota = max(1000, int(period * min(4.0, cpu_seconds / float(timeout_seconds))))
            quota = min(root_cpu_quota * period // root_cpu_period, desired_quota)
            quota = max(1000, quota)
            _write_text(scope_path / "memory.max", str(memory))
            _write_text(scope_path / "pids.max", str(pids))
            _write_text(scope_path / "cpu.max", f"{quota} {period}")
            _write_text(scope_path / "memory.oom.group", "1")
            if not (scope_path / "cgroup.kill").exists():
                raise CgroupV2Error("per-execution cgroup.kill is unavailable")
            memory_events = scope_path / "memory.events.local"
            if not memory_events.exists():
                memory_events = scope_path / "memory.events"
            scope.memory_events_before = _events(
                memory_events,
                required_keys=frozenset({"oom", "oom_kill"}),
            )
            scope.pids_events_before = _events(
                scope_path / "pids.events",
                required_keys=frozenset({"max"}),
            )
            return scope
        except Exception:
            try:
                scope.cleanup(kill_if_populated=True, timeout=0.2)
            except Exception:
                pass
            raise

    def probe(self) -> str | None:
        """Exercise create/configure/kill/remove using only the configured subtree."""
        try:
            memory, pids, cpu, _period = self._validate_root()
            scope = self.create_scope(
                memory_bytes=min(memory, 1024 * 1024),
                process_count=min(pids, 2),
                cpu_seconds=1,
                timeout_seconds=1.0,
            )
            scope.cleanup(kill_if_populated=True, timeout=0.2)
            return None
        except CgroupV2Error as exc:
            return str(exc)
        except OSError:
            return "delegated_cgroup_probe_failed"


__all__ = ["CgroupV2Error", "CgroupV2Manager", "CgroupV2Scope"]
