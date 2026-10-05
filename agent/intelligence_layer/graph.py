"""Deterministic, bounded task-graph control plane; it never executes tools."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable

from security.mission_authorization import MissionAuthorizationSnapshot

from .models import (
    AgentLifecycle,
    AgentRecord,
    DelegationDenied,
    DelegationScope,
    InvalidTransition,
    TaskLifecycle,
    TaskRecord,
)


class TaskGraphError(ValueError):
    pass


class TaskGraphConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentGraphPolicy:
    max_agents: int = 16
    max_tasks: int = 128
    max_parallel_tasks: int = 4
    max_retries: int = 2
    max_task_result_bytes: int = 65536
    max_task_objective_chars: int = 10000

    def __post_init__(self) -> None:
        for name in ("max_agents", "max_tasks", "max_parallel_tasks", "max_task_result_bytes", "max_task_objective_chars"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AgentGraphPolicy":
        return cls(**dict(value))


class TaskGraph:
    """Owner/mission-bound graph state. Authorization remains with MissionRuntime."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        *,
        mission_id: str,
        owner_identity_ref: str,
        target_identity: str,
        authorization_hash: str,
        policy: AgentGraphPolicy | None = None,
        agents: Iterable[AgentRecord] = (),
        tasks: Iterable[TaskRecord] = (),
        revision: int = 0,
    ) -> None:
        if not all(str(value).strip() for value in (mission_id, owner_identity_ref, target_identity, authorization_hash)):
            raise ValueError("graph must bind mission, owner, target, and authorization hash")
        if revision < 0:
            raise ValueError("graph revision must be non-negative")
        self.mission_id = str(mission_id)
        self.owner_identity_ref = str(owner_identity_ref)
        self.target_identity = str(target_identity)
        self.authorization_hash = str(authorization_hash)
        self.policy = policy or AgentGraphPolicy()
        self.agents = {item.agent_id: item for item in agents}
        self.tasks = {item.task_id: item for item in tasks}
        self.revision = int(revision)
        self.validate()

    @classmethod
    def create(
        cls,
        snapshot: MissionAuthorizationSnapshot,
        *,
        owner_identity_ref: str | None = None,
        policy: AgentGraphPolicy | None = None,
        at: str | None = None,
    ) -> "TaskGraph":
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise TypeError("a typed MissionAuthorizationSnapshot is required")
        owner_ref = str(owner_identity_ref or snapshot.owner_identity)
        valid, reason = snapshot.validate_for_mission(
            mission_id=snapshot.mission_id,
            owner_identity=snapshot.owner_identity,
            target_identity=snapshot.target_identity,
            at=at,
        )
        if not valid:
            raise DelegationDenied(reason)
        if owner_ref != snapshot.owner_identity:
            raise DelegationDenied("owner identity reference must match mission authorization owner")
        return cls(
            mission_id=snapshot.mission_id,
            owner_identity_ref=owner_ref,
            target_identity=snapshot.target_identity,
            authorization_hash=snapshot.authorization_hash,
            policy=policy,
        )

    def validate_current_authorization(self, snapshot: MissionAuthorizationSnapshot, *, at: str | None = None) -> None:
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise TypeError("a typed current MissionAuthorizationSnapshot is required")
        valid, reason = snapshot.validate_for_mission(
            mission_id=self.mission_id,
            owner_identity=self.owner_identity_ref,
            target_identity=self.target_identity,
            at=at,
        )
        if not valid:
            raise DelegationDenied(reason)
        if snapshot.authorization_hash != self.authorization_hash:
            raise DelegationDenied("mission authorization snapshot changed")

    def root_scope(self, snapshot: MissionAuthorizationSnapshot, *, at: str | None = None) -> DelegationScope:
        self.validate_current_authorization(snapshot, at=at)
        return DelegationScope.from_snapshot(snapshot, owner_identity_ref=self.owner_identity_ref, at=at)

    def add_agent(self, agent: AgentRecord) -> None:
        if agent.agent_id in self.agents:
            raise TaskGraphError("duplicate agent id")
        if len(self.agents) >= self.policy.max_agents:
            raise TaskGraphError("maximum agent count exceeded")
        if agent.mission_id != self.mission_id or agent.owner_identity_ref != self.owner_identity_ref:
            raise TaskGraphError("agent mission/owner mismatch")
        if agent.permission_scope.root_authorization_hash != self.authorization_hash:
            raise TaskGraphError("agent root authorization binding mismatch")
        if agent.parent_agent_id:
            parent = self.agents.get(agent.parent_agent_id)
            if parent is None:
                raise TaskGraphError("parent agent must exist before child agent")
            if not agent.permission_scope.is_subset_of(parent.permission_scope):
                raise TaskGraphError("child agent scope is not a strict parent-bound subset")
        else:
            if any(existing.parent_agent_id is None for existing in self.agents.values()):
                raise TaskGraphError("task graph may have only one root agent")
            if agent.permission_scope.parent_grant_hash != self.authorization_hash:
                raise TaskGraphError("root agent is not bound directly to mission authorization")
        self.agents[agent.agent_id] = agent
        try:
            self.validate()
        except Exception:
            del self.agents[agent.agent_id]
            raise

    def add_tasks(self, tasks: Iterable[TaskRecord]) -> None:
        items = tuple(tasks)
        if len(self.tasks) + len(items) > self.policy.max_tasks:
            raise TaskGraphError("maximum task count exceeded")
        ids = [item.task_id for item in items]
        if len(set(ids)) != len(ids) or any(task_id in self.tasks for task_id in ids):
            raise TaskGraphError("duplicate task id")
        if any(item.mission_id != self.mission_id for item in items):
            raise TaskGraphError("task mission mismatch")
        if any(item.assigned_agent_id not in self.agents for item in items):
            raise TaskGraphError("task assigned agent is not registered")
        for item in items:
            if len(item.objective) > self.policy.max_task_objective_chars:
                raise TaskGraphError("task objective exceeds policy limit")
            self.tasks[item.task_id] = item
        try:
            self.validate()
        except Exception:
            for task_id in ids:
                self.tasks.pop(task_id, None)
            raise

    def _check_dependency_cycles(self) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise TaskGraphError("task dependency cycle detected")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dependency in self.tasks[task_id].dependencies:
                if dependency not in self.tasks:
                    raise TaskGraphError(f"unknown task dependency: {dependency}")
                if dependency == task_id:
                    raise TaskGraphError("task cannot depend on itself")
                visit(dependency)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in sorted(self.tasks):
            visit(task_id)

    def validate(self) -> None:
        if len(self.agents) > self.policy.max_agents or len(self.tasks) > self.policy.max_tasks:
            raise TaskGraphError("graph exceeds resource policy")
        roots = [agent for agent in self.agents.values() if agent.parent_agent_id is None]
        if len(roots) > 1:
            raise TaskGraphError("task graph may have only one root agent")
        for agent_id, agent in self.agents.items():
            if agent_id != agent.agent_id or agent.mission_id != self.mission_id or agent.owner_identity_ref != self.owner_identity_ref:
                raise TaskGraphError("agent identity binding mismatch")
            if agent.permission_scope.root_authorization_hash != self.authorization_hash:
                raise TaskGraphError("agent authorization binding mismatch")
            if agent.parent_agent_id:
                parent = self.agents.get(agent.parent_agent_id)
                if parent is None or not agent.permission_scope.is_subset_of(parent.permission_scope):
                    raise TaskGraphError("agent hierarchy or delegated scope is invalid")
            elif agent.permission_scope.parent_grant_hash != self.authorization_hash:
                raise TaskGraphError("root agent grant is not tied to mission authorization")
        for task_id, task in self.tasks.items():
            if task_id != task.task_id or task.mission_id != self.mission_id:
                raise TaskGraphError("task identity binding mismatch")
            if task.assigned_agent_id not in self.agents:
                raise TaskGraphError("task assigned agent is not registered")
            if task.attempt_count > self.policy.max_retries + 1:
                raise TaskGraphError("task attempt count exceeds resource policy")
            if len(task.objective) > self.policy.max_task_objective_chars:
                raise TaskGraphError("task objective exceeds policy limit")
            if task.result is not None:
                result_bytes = json.dumps(task.result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
                if len(result_bytes) > self.policy.max_task_result_bytes:
                    raise TaskGraphError("task result exceeds policy byte limit")
            if task.parent_task_id and task.parent_task_id not in self.tasks:
                raise TaskGraphError("unknown parent task")
        self._check_dependency_cycles()

    def activate_agent(self, agent_id: str) -> None:
        agent = self.agents.get(agent_id)
        if agent is None:
            raise KeyError("unknown_agent")
        if agent.lifecycle is AgentLifecycle.CREATED:
            agent.transition(AgentLifecycle.READY)
        elif agent.lifecycle not in {AgentLifecycle.READY, AgentLifecycle.RUNNING}:
            raise InvalidTransition("agent is not eligible to accept tasks")

    def refresh_ready_tasks(self) -> tuple[str, ...]:
        """Promote dependency-ready CREATED tasks assigned to activated agents."""
        self.validate()
        promoted: list[str] = []
        for task_id in sorted(self.tasks):
            task = self.tasks[task_id]
            agent = self.agents[task.assigned_agent_id]
            dependency_ready = all(self.tasks[dependency].lifecycle is TaskLifecycle.COMPLETED for dependency in task.dependencies)
            eligible_state = task.lifecycle is TaskLifecycle.CREATED or (
                task.lifecycle is TaskLifecycle.BLOCKED and task.error == "dependency_failed"
            )
            if (
                eligible_state
                and agent.lifecycle in {AgentLifecycle.READY, AgentLifecycle.RUNNING}
                and dependency_ready
            ):
                task.transition(TaskLifecycle.READY)
                task.error = ""
                promoted.append(task_id)
        return tuple(promoted)

    def ready_task_ids(self) -> tuple[str, ...]:
        running = sum(task.lifecycle is TaskLifecycle.RUNNING for task in self.tasks.values())
        capacity = max(0, self.policy.max_parallel_tasks - running)
        if not capacity:
            return ()
        ready = [
            task_id for task_id, task in self.tasks.items()
            if task.lifecycle is TaskLifecycle.READY
            and self.agents[task.assigned_agent_id].lifecycle in {AgentLifecycle.READY, AgentLifecycle.RUNNING}
            and all(self.tasks[dependency].lifecycle is TaskLifecycle.COMPLETED for dependency in task.dependencies)
        ]
        return tuple(sorted(ready)[:capacity])

    def claim_task(self, task_id: str, snapshot: MissionAuthorizationSnapshot, *, at: str | None = None) -> TaskRecord:
        """Claim a graph node only after current Owner authorization is revalidated."""
        self.validate_current_authorization(snapshot, at=at)
        self.refresh_ready_tasks()
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if task_id not in self.ready_task_ids():
            raise TaskGraphError("task is not dependency-ready or concurrency capacity is exhausted")
        if task.attempt_count >= self.policy.max_retries + 1:
            raise TaskGraphError("task retry limit exhausted")
        agent = self.agents[task.assigned_agent_id]
        if agent.lifecycle is AgentLifecycle.READY:
            agent.transition(AgentLifecycle.RUNNING)
        task.transition(TaskLifecycle.RUNNING)
        task.attempt_count += 1
        return task

    def complete_task(self, task_id: str, result: Any, *, evidence_refs: Iterable[str] = (), artifacts: Iterable[str] = ()) -> TaskRecord:
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if task.lifecycle is not TaskLifecycle.RUNNING:
            raise InvalidTransition("only a running task can complete")
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) > self.policy.max_task_result_bytes:
            raise TaskGraphError("task result exceeds policy byte limit")
        refs = tuple(str(ref).strip() for ref in evidence_refs)
        if any(not ref for ref in refs) or len(set(refs)) != len(refs):
            raise TaskGraphError("evidence references must be non-empty and unique")
        task.result = json.loads(encoded.decode("utf-8"))
        task.evidence_refs = refs
        artifact_ids = tuple(str(ref).strip() for ref in artifacts)
        if any(not ref for ref in artifact_ids) or len(set(artifact_ids)) != len(artifact_ids):
            raise TaskGraphError("artifact references must be non-empty and unique")
        task.artifacts = artifact_ids
        task.result_validation_state = "PENDING_VALIDATION" if refs else "UNVERIFIED"
        task.transition(TaskLifecycle.COMPLETED)
        self.refresh_ready_tasks()
        return task

    def fail_task(self, task_id: str, reason: str, *, propagate: bool = True) -> TaskRecord:
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if task.lifecycle not in {TaskLifecycle.RUNNING, TaskLifecycle.READY, TaskLifecycle.WAITING, TaskLifecycle.BLOCKED}:
            raise InvalidTransition("task cannot fail from its current state")
        task.error = str(reason)[:1024]
        task.transition(TaskLifecycle.FAILED)
        if propagate:
            blocked = {task_id}
            changed = True
            while changed:
                changed = False
                for dependent in self.tasks.values():
                    if dependent.lifecycle in {TaskLifecycle.CREATED, TaskLifecycle.READY, TaskLifecycle.WAITING} and any(dep in blocked for dep in dependent.dependencies):
                        dependent.error = "dependency_failed"
                        dependent.transition(TaskLifecycle.BLOCKED)
                        blocked.add(dependent.task_id)
                        changed = True
        return task

    def retry_task(self, task_id: str) -> TaskRecord:
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError("unknown_task")
        if task.lifecycle is not TaskLifecycle.FAILED:
            raise InvalidTransition("only failed tasks can be retried")
        if task.attempt_count > self.policy.max_retries:
            raise TaskGraphError("task retry limit exhausted")
        if any(self.tasks[dependency].lifecycle is not TaskLifecycle.COMPLETED for dependency in task.dependencies):
            raise TaskGraphError("task dependencies are not complete")
        task.retry(max_retries=self.policy.max_retries)
        return task

    def cancel_task(self, task_id: str, *, propagate: bool = True) -> tuple[str, ...]:
        """Request cancellation; running work remains RUNNING until its executor confirms stop."""
        if task_id not in self.tasks:
            raise KeyError("unknown_task")
        affected = {task_id}
        if propagate:
            changed = True
            while changed:
                changed = False
                for task in self.tasks.values():
                    if task.task_id not in affected and any(dep in affected for dep in task.dependencies):
                        affected.add(task.task_id)
                        changed = True
        for affected_id in sorted(affected):
            task = self.tasks[affected_id]
            if task.lifecycle is TaskLifecycle.RUNNING:
                task.cancel_requested = True
                continue
            if task.lifecycle not in {TaskLifecycle.COMPLETED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED}:
                task.transition(TaskLifecycle.CANCELLED)
        return tuple(sorted(affected))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "mission_id": self.mission_id,
            "owner_identity_ref": self.owner_identity_ref,
            "target_identity": self.target_identity,
            "authorization_hash": self.authorization_hash,
            "policy": self.policy.to_dict(),
            "agents": [self.agents[key].to_dict() for key in sorted(self.agents)],
            "tasks": [self.tasks[key].to_dict() for key in sorted(self.tasks)],
            "revision": self.revision,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskGraph":
        version = data.get("schema_version")
        if version != cls.SCHEMA_VERSION:
            raise TaskGraphError(f"unsupported task graph schema version: {version}")
        return cls(
            mission_id=str(data["mission_id"]),
            owner_identity_ref=str(data["owner_identity_ref"]),
            target_identity=str(data["target_identity"]),
            authorization_hash=str(data["authorization_hash"]),
            policy=AgentGraphPolicy.from_dict(data["policy"]),
            agents=[AgentRecord.from_dict(item) for item in data.get("agents", ())],
            tasks=[TaskRecord.from_dict(item) for item in data.get("tasks", ())],
            revision=int(data.get("revision", 0)),
        )


__all__ = ["AgentGraphPolicy", "TaskGraph", "TaskGraphConflict", "TaskGraphError"]
