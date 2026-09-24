from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from kali.registry import KaliToolSpec


class ToolTimeout(TimeoutError):
    pass


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_id: str
    execution_id: str
    exit_status: int | None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    artifacts: tuple[str, ...] = ()
    timed_out: bool = False
    error: str | None = None
    started_at: float = 0.0
    duration_seconds: float = 0.0
    runtime_kind: str = "unknown"

    @property
    def succeeded(self) -> bool:
        return not self.timed_out and self.error is None and self.exit_status == 0


class KaliRuntimeAdapter(ABC):
    """Abstraction over where Kali tools actually run.

    Supported (now or later): Kali Linux host, Kali VM, container, remote
    worker, dedicated security worker. The runtime is NEVER a decision maker:
    it only executes what the deterministic governance gate has already
    authorized, and it reports observations at TOOL_RUNTIME provenance.
    """

    runtime_kind: str = "abstract"

    @abstractmethod
    def executable_present(self, executable: str) -> bool: ...

    @abstractmethod
    def available_privileges(self) -> tuple[str, ...]: ...

    @abstractmethod
    def network_available(self) -> bool: ...

    @abstractmethod
    def execute(
        self,
        tool: KaliToolSpec,
        *,
        arguments: Sequence[str],
        execution_id: str,
        timeout: int,
        workspace_root: str | None = None,
    ) -> ToolExecutionResult: ...


class LocalKaliRuntime(KaliRuntimeAdapter):
    """Local-host runtime. Uses shutil.which for availability probing.

    NOTE: during the architecture/inventory phase no real target is ever
    contacted; tests use SimulatedKaliRuntime instead.
    """

    runtime_kind = "local"

    def __init__(self, *, allow_execution: bool = False) -> None:
        self._allow_execution = allow_execution

    def executable_present(self, executable: str) -> bool:
        import shutil

        return shutil.which(executable) is not None

    def available_privileges(self) -> tuple[str, ...]:
        import os

        if os.geteuid() == 0:
            return ("CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "NONE")
        return ("NONE",)

    def network_available(self) -> bool:
        return False  # conservative default for the build phase

    def execute(self, tool: KaliToolSpec, *, arguments: Sequence[str], execution_id: str, timeout: int, workspace_root: str | None = None) -> ToolExecutionResult:
        if not self._allow_execution:
            return ToolExecutionResult(
                tool_id=tool.tool_id,
                execution_id=execution_id,
                exit_status=None,
                error="local_execution_disabled_in_build_phase",
                runtime_kind=self.runtime_kind,
            )
        raise NotImplementedError("real local execution is intentionally not wired in the architecture phase")


class SimulatedKaliRuntime(KaliRuntimeAdapter):
    """Deterministic, hermetic runtime for tests and dry-runs.

    Executes nothing external. Every outcome is scripted via scenario tables,
    which makes tool failure, timeout, and success fully deterministic.
    """

    runtime_kind = "simulated"

    def __init__(
        self,
        *,
        executables: Sequence[str] = (),
        privileges: Sequence[str] = ("NONE",),
        network: bool = True,
        scenarios: Mapping[str, Mapping[str, Any]] | None = None,
        clock_scale: float = 1.0,
    ) -> None:
        self._executables = frozenset(executables)
        self._privileges = frozenset(privileges)
        self._network = network
        self._scenarios = dict(scenarios or {})
        self._clock_scale = clock_scale
        self.executed: list[dict[str, Any]] = []

    def executable_present(self, executable: str) -> bool:
        return executable in self._executables

    def available_privileges(self) -> tuple[str, ...]:
        return tuple(sorted(self._privileges))

    def network_available(self) -> bool:
        return self._network

    def scenario_for(self, tool: KaliToolSpec) -> Mapping[str, Any]:
        return self._scenarios.get(tool.tool_id, {"exit_status": 0, "stdout": "simulated-ok"})

    def execute(self, tool: KaliToolSpec, *, arguments: Sequence[str], execution_id: str, timeout: int, workspace_root: str | None = None) -> ToolExecutionResult:
        started = time.monotonic()
        scenario = dict(self.scenario_for(tool))
        self.executed.append({"tool_id": tool.tool_id, "execution_id": execution_id, "arguments": list(arguments)})
        delay = float(scenario.get("delay_seconds", 0.0)) * self._clock_scale
        if scenario.get("raise_runtime_error"):
            return ToolExecutionResult(
                tool_id=tool.tool_id,
                execution_id=execution_id,
                exit_status=None,
                error=str(scenario["raise_runtime_error"]),
                started_at=started,
                duration_seconds=0.0,
                runtime_kind=self.runtime_kind,
            )
        if delay > float(timeout):
            return ToolExecutionResult(
                tool_id=tool.tool_id,
                execution_id=execution_id,
                exit_status=None,
                timed_out=True,
                error="timeout",
                started_at=started,
                duration_seconds=float(timeout),
                runtime_kind=self.runtime_kind,
            )
        return ToolExecutionResult(
            tool_id=tool.tool_id,
            execution_id=execution_id,
            exit_status=int(scenario.get("exit_status", 0)),
            stdout_excerpt=str(scenario.get("stdout", ""))[:4000],
            stderr_excerpt=str(scenario.get("stderr", ""))[:4000],
            artifacts=tuple(scenario.get("artifacts", ())),
            started_at=started,
            duration_seconds=delay,
            runtime_kind=self.runtime_kind,
        )


__all__ = [
    "ToolTimeout",
    "ToolExecutionResult",
    "KaliRuntimeAdapter",
    "LocalKaliRuntime",
    "SimulatedKaliRuntime",
]
