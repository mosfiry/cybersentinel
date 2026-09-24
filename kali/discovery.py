from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from kali.registry import KaliToolRegistry, KaliToolSpec


class CapabilityStatus(str, Enum):
    """Deterministic capability states. No state may ever be invented or
    upgraded by a model or by external data."""

    AVAILABLE = "AVAILABLE"
    AVAILABLE_WITH_LIMITATIONS = "AVAILABLE_WITH_LIMITATIONS"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuntimeDescriptor:
    """Description of what a concrete runtime actually provides.

    Facts about the runtime come from TOOL_RUNTIME (or lower) provenance only;
    they can never assert authority of any kind.
    """

    runtime_kind: str = "local"  # local | kali_vm | container | remote_worker | dedicated_security_worker
    available_executables: frozenset[str] = frozenset()
    available_privileges: frozenset[str] = frozenset({"NONE"})
    network_available: bool = False
    workspace_root: str | None = None
    unknown_executables: frozenset[str] = frozenset()
    runtime_version: str = "unknown"

    def executable_state(self, executable: str) -> CapabilityStatus:
        if executable in self.available_executables:
            return CapabilityStatus.AVAILABLE
        if executable in self.unknown_executables:
            return CapabilityStatus.UNKNOWN
        return CapabilityStatus.NOT_AVAILABLE


@dataclass(frozen=True)
class ToolCapability:
    """Capability finding for one tool. Capability != Authorization."""

    tool_id: str
    status: CapabilityStatus
    reasons: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def executable_now(self) -> bool:
        return self.status in (CapabilityStatus.AVAILABLE, CapabilityStatus.AVAILABLE_WITH_LIMITATIONS)


class KaliCapabilityProbe:
    """Deterministic capability discovery against a runtime descriptor.

    Rules (fixed, no override):
      - executable missing from the runtime        -> NOT_AVAILABLE
      - executable present but privilege missing   -> AVAILABLE_WITH_LIMITATIONS
      - executable present but network unavailable -> AVAILABLE_WITH_LIMITATIONS
      - runtime reports the executable as unknown  -> UNKNOWN
      - otherwise                                  -> AVAILABLE
    There is no EXECUTE_ANYWAY. UNKNOWN never becomes AVAILABLE.
    """

    def __init__(self, registry: KaliToolRegistry, runtime: RuntimeDescriptor) -> None:
        self._registry = registry
        self._runtime = runtime

    @property
    def runtime(self) -> RuntimeDescriptor:
        return self._runtime

    def probe(self, tool_id: str) -> ToolCapability:
        tool = self._registry.get(tool_id)
        if tool is None:
            # A tool unknown to the registry is not a capability the agent may
            # claim. It stays UNKNOWN and can never be executed by this path.
            return ToolCapability(tool_id, CapabilityStatus.UNKNOWN, ("tool_not_in_registry",))
        reasons: list[str] = []
        limitations: list[str] = []
        exe_state = self._runtime.executable_state(tool.executable)
        if exe_state is CapabilityStatus.NOT_AVAILABLE:
            return ToolCapability(tool_id, CapabilityStatus.NOT_AVAILABLE, ("executable_missing",))
        if exe_state is CapabilityStatus.UNKNOWN:
            return ToolCapability(tool_id, CapabilityStatus.UNKNOWN, ("executable_presence_unknown",))
        missing_privs = [p for p in tool.privileges_required if p != "NONE" and p not in self._runtime.available_privileges]
        if missing_privs:
            limitations.append("missing_privileges:" + ",".join(missing_privs))
        if tool.network_required and not self._runtime.network_available:
            limitations.append("network_unavailable")
        if limitations:
            return ToolCapability(tool_id, CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, reasons=tuple(reasons), limitations=tuple(limitations))
        return ToolCapability(tool_id, CapabilityStatus.AVAILABLE, reasons=tuple(reasons))

    def probe_all(self) -> tuple[ToolCapability, ...]:
        return tuple(self.probe(t.tool_id) for t in self._registry.all_tools())

    def summarize(self) -> dict[str, Any]:
        counts = {status.value: 0 for status in CapabilityStatus}
        for capability in self.probe_all():
            counts[capability.status.value] += 1
        return {"runtime_kind": self._runtime.runtime_kind, "counts": counts, "total": sum(counts.values())}


def capability_grants_authority(status: CapabilityStatus) -> bool:
    """Structural guard: no capability status ever grants authority."""
    return False


__all__ = [
    "CapabilityStatus",
    "RuntimeDescriptor",
    "ToolCapability",
    "KaliCapabilityProbe",
    "capability_grants_authority",
]
