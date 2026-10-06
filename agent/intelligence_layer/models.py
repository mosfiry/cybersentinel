"""Typed, authority-subordinate agent intelligence domain records.

This module contains no tool executor. DelegationScope is a derived, narrower
constraint set, never an Owner authorization or a replacement for revalidation
against the current MissionAuthorizationSnapshot at dispatch time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
import uuid

from security.mission_authorization import MissionAuthorizationSnapshot


class AgentLifecycle(str, Enum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TaskLifecycle(str, Enum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class InvalidTransition(ValueError):
    """Raised when an agent or task attempts a non-deterministic state change."""


class DelegationDenied(PermissionError):
    """Raised when a requested child scope is not a strict bounded delegation."""


_AGENT_TRANSITIONS = {
    AgentLifecycle.CREATED: {AgentLifecycle.READY, AgentLifecycle.BLOCKED, AgentLifecycle.CANCELLED},
    AgentLifecycle.READY: {AgentLifecycle.RUNNING, AgentLifecycle.BLOCKED, AgentLifecycle.CANCELLED},
    AgentLifecycle.RUNNING: {AgentLifecycle.WAITING, AgentLifecycle.BLOCKED, AgentLifecycle.COMPLETED, AgentLifecycle.FAILED, AgentLifecycle.CANCELLED},
    AgentLifecycle.WAITING: {AgentLifecycle.READY, AgentLifecycle.BLOCKED, AgentLifecycle.FAILED, AgentLifecycle.CANCELLED},
    AgentLifecycle.BLOCKED: {AgentLifecycle.READY, AgentLifecycle.FAILED, AgentLifecycle.CANCELLED},
    AgentLifecycle.COMPLETED: set(),
    AgentLifecycle.FAILED: set(),
    AgentLifecycle.CANCELLED: set(),
}
_TASK_TRANSITIONS = {
    TaskLifecycle.CREATED: {TaskLifecycle.READY, TaskLifecycle.BLOCKED, TaskLifecycle.CANCELLED},
    TaskLifecycle.READY: {TaskLifecycle.RUNNING, TaskLifecycle.BLOCKED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED},
    TaskLifecycle.RUNNING: {TaskLifecycle.WAITING, TaskLifecycle.BLOCKED, TaskLifecycle.COMPLETED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED},
    TaskLifecycle.WAITING: {TaskLifecycle.READY, TaskLifecycle.BLOCKED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED},
    TaskLifecycle.BLOCKED: {TaskLifecycle.READY, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED},
    TaskLifecycle.COMPLETED: set(),
    TaskLifecycle.FAILED: set(),
    TaskLifecycle.CANCELLED: set(),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strings(values: Iterable[str], *, field_name: str, allow_empty: bool = True) -> tuple[str, ...]:
    result = tuple(str(value).strip() for value in values)
    if any(not value for value in result):
        raise ValueError(f"{field_name} values must be non-empty strings")
    if len(set(result)) != len(result):
        raise ValueError(f"{field_name} values must be unique")
    if not allow_empty and not result:
        raise ValueError(f"{field_name} must not be empty")
    return result


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class DelegationScope:
    """Non-authoritative tool/action/target constraints derived from Owner scope."""

    owner_identity_ref: str
    mission_id: str
    target_identity: str
    root_authorization_hash: str
    parent_grant_hash: str
    scope: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    allowed_credentials: tuple[str, ...] = ()
    workspace_root: str = ""

    def __post_init__(self) -> None:
        required = (self.owner_identity_ref, self.mission_id, self.target_identity, self.root_authorization_hash, self.parent_grant_hash)
        if not all(str(item).strip() for item in required):
            raise ValueError("delegation scope is missing mission, owner, target, or authorization binding")
        for name in ("scope", "allowed_tools", "allowed_actions", "allowed_networks", "allowed_credentials"):
            object.__setattr__(self, name, _strings(getattr(self, name), field_name=name))
        if self.workspace_root:
            object.__setattr__(self, "workspace_root", str(Path(self.workspace_root).expanduser().resolve()))

    @classmethod
    def from_snapshot(
        cls,
        snapshot: MissionAuthorizationSnapshot,
        *,
        owner_identity_ref: str | None = None,
        authorization_version: int = 1,
        at: str | None = None,
    ) -> "DelegationScope":
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise TypeError("delegation requires a typed MissionAuthorizationSnapshot")
        owner = str(owner_identity_ref or snapshot.owner_identity)
        if owner != snapshot.owner_identity:
            raise DelegationDenied("owner identity reference must match mission authorization owner")
        valid, reason = snapshot.validate_for_mission(
            mission_id=snapshot.mission_id,
            owner_identity=snapshot.owner_identity,
            target_identity=snapshot.target_identity,
            version=authorization_version,
            at=at,
        )
        if not valid:
            raise DelegationDenied(reason)
        return cls(
            owner_identity_ref=owner,
            mission_id=snapshot.mission_id,
            target_identity=snapshot.target_identity,
            root_authorization_hash=snapshot.authorization_hash,
            parent_grant_hash=snapshot.authorization_hash,
            # Owner snapshots are set-valued grants, but legacy fixtures and
            # persisted authorization records may contain redundant entries.
            # Stable de-duplication cannot widen a grant and keeps the derived
            # scope canonical; child scopes continue to reject duplicates.
            scope=tuple(dict.fromkeys(snapshot.scope)),
            allowed_tools=tuple(dict.fromkeys(snapshot.allowed_tools)),
            allowed_actions=tuple(dict.fromkeys(snapshot.allowed_actions)),
            allowed_networks=tuple(dict.fromkeys(snapshot.network_boundary.get("allowed", ()))),
            allowed_credentials=tuple(dict.fromkeys(snapshot.credential_boundary.get("allowed", ()))),
            workspace_root=str(snapshot.workspace_boundary.get("root", "") or ""),
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_identity_ref": self.owner_identity_ref,
            "mission_id": self.mission_id,
            "target_identity": self.target_identity,
            "root_authorization_hash": self.root_authorization_hash,
            "parent_grant_hash": self.parent_grant_hash,
            "scope": list(self.scope),
            "allowed_tools": list(self.allowed_tools),
            "allowed_actions": list(self.allowed_actions),
            "allowed_networks": list(self.allowed_networks),
            "allowed_credentials": list(self.allowed_credentials),
            "workspace_root": self.workspace_root,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationScope":
        values = dict(data)
        for name in ("scope", "allowed_tools", "allowed_actions", "allowed_networks", "allowed_credentials"):
            values[name] = tuple(values.get(name, ()))
        return cls(**values)

    def narrow(
        self,
        *,
        target_identity: str,
        scope: Iterable[str],
        allowed_tools: Iterable[str],
        allowed_actions: Iterable[str],
        allowed_networks: Iterable[str] = (),
        allowed_credentials: Iterable[str] = (),
        workspace_root: str | None = None,
    ) -> "DelegationScope":
        """Return explicit child limits; empty parent grants authorize no expansion."""
        if str(target_identity) != self.target_identity:
            raise DelegationDenied("child target must equal the authorized target")
        child_scope = _strings(scope, field_name="scope", allow_empty=False)
        child_tools = _strings(allowed_tools, field_name="allowed_tools", allow_empty=False)
        child_actions = _strings(allowed_actions, field_name="allowed_actions", allow_empty=False)
        child_networks = _strings(allowed_networks, field_name="allowed_networks")
        child_credentials = _strings(allowed_credentials, field_name="allowed_credentials")
        for requested, permitted, label in (
            (child_scope, self.scope, "scope"),
            (child_tools, self.allowed_tools, "tool"),
            (child_actions, self.allowed_actions, "action"),
            (child_networks, self.allowed_networks, "network"),
            (child_credentials, self.allowed_credentials, "credential"),
        ):
            if not set(requested).issubset(permitted):
                raise DelegationDenied(f"child {label} exceeds parent delegation")
        child_workspace = "" if workspace_root is None else str(Path(workspace_root).expanduser().resolve())
        if self.workspace_root:
            parent_path = Path(self.workspace_root)
            candidate = Path(child_workspace) if child_workspace else parent_path
            if candidate != parent_path and parent_path not in candidate.parents:
                raise DelegationDenied("child workspace exceeds parent workspace")
        elif child_workspace:
            raise DelegationDenied("child cannot create a workspace grant absent from its parent")
        return DelegationScope(
            owner_identity_ref=self.owner_identity_ref,
            mission_id=self.mission_id,
            target_identity=self.target_identity,
            root_authorization_hash=self.root_authorization_hash,
            parent_grant_hash=self.fingerprint,
            scope=child_scope,
            allowed_tools=child_tools,
            allowed_actions=child_actions,
            allowed_networks=child_networks,
            allowed_credentials=child_credentials,
            workspace_root=child_workspace,
        )

    def is_subset_of(self, parent: "DelegationScope") -> bool:
        if not isinstance(parent, DelegationScope):
            return False
        if (self.owner_identity_ref, self.mission_id, self.target_identity, self.root_authorization_hash) != (
            parent.owner_identity_ref, parent.mission_id, parent.target_identity, parent.root_authorization_hash
        ):
            return False
        if self.parent_grant_hash != parent.fingerprint:
            return False
        for child_values, parent_values in (
            (self.scope, parent.scope),
            (self.allowed_tools, parent.allowed_tools),
            (self.allowed_actions, parent.allowed_actions),
            (self.allowed_networks, parent.allowed_networks),
            (self.allowed_credentials, parent.allowed_credentials),
        ):
            if not set(child_values).issubset(parent_values):
                return False
        if parent.workspace_root:
            root = Path(parent.workspace_root)
            candidate = Path(self.workspace_root or parent.workspace_root)
            if candidate != root and root not in candidate.parents:
                return False
        elif self.workspace_root:
            return False
        return True

    def validate_current(
        self,
        snapshot: MissionAuthorizationSnapshot,
        *,
        authorization_version: int = 1,
        at: str | None = None,
    ) -> None:
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise TypeError("current Owner authorization snapshot is required")
        valid, reason = snapshot.validate_for_mission(
            mission_id=self.mission_id,
            owner_identity=self.owner_identity_ref,
            target_identity=self.target_identity,
            version=authorization_version,
            at=at,
        )
        if not valid or snapshot.authorization_hash != self.root_authorization_hash:
            raise DelegationDenied(reason if not valid else "mission authorization snapshot changed")

    def is_within_owner_authorization(self, snapshot: MissionAuthorizationSnapshot) -> bool:
        """Check every delegated capability against the immutable Owner grant."""
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            return False
        try:
            owner_grant = type(self).from_snapshot(
                snapshot,
                owner_identity_ref=self.owner_identity_ref,
                authorization_version=snapshot.version,
            )
        except (TypeError, ValueError, DelegationDenied):
            return False
        if (
            self.owner_identity_ref != owner_grant.owner_identity_ref
            or self.mission_id != owner_grant.mission_id
            or self.target_identity != owner_grant.target_identity
            or self.root_authorization_hash != owner_grant.root_authorization_hash
        ):
            return False
        for child_values, owner_values in (
            (self.scope, owner_grant.scope),
            (self.allowed_tools, owner_grant.allowed_tools),
            (self.allowed_actions, owner_grant.allowed_actions),
            (self.allowed_networks, owner_grant.allowed_networks),
            (self.allowed_credentials, owner_grant.allowed_credentials),
        ):
            if not set(child_values).issubset(owner_values):
                return False
        if owner_grant.workspace_root:
            root = Path(owner_grant.workspace_root)
            candidate = Path(self.workspace_root or owner_grant.workspace_root).expanduser().resolve()
            if candidate != root and root not in candidate.parents:
                return False
        elif self.workspace_root:
            return False
        return True

    def permits(
        self,
        *,
        tool: str,
        action: str,
        scope_ref: str,
        target_identity: str,
        network: str | None = None,
        credential: str | None = None,
        workspace_path: str | None = None,
    ) -> bool:
        """Check only this derived constraint; the parent authorization must also be checked."""
        if not (
            target_identity == self.target_identity
            and tool in self.allowed_tools
            and action in self.allowed_actions
            and scope_ref in self.scope
        ):
            return False
        if network and network not in self.allowed_networks:
            return False
        if credential and credential not in self.allowed_credentials:
            return False
        if workspace_path:
            if not self.workspace_root:
                return False
            root = Path(self.workspace_root)
            candidate = Path(workspace_path).expanduser().resolve()
            if candidate != root and root not in candidate.parents:
                return False
        return True


@dataclass
class AgentRecord:
    agent_id: str
    mission_id: str
    owner_identity_ref: str
    role: str
    capabilities: tuple[str, ...]
    permission_scope: DelegationScope
    parent_agent_id: str | None = None
    parent_task_id: str | None = None
    lifecycle: AgentLifecycle = AgentLifecycle.CREATED
    context_ref: str = ""
    memory_scope: str = "mission"
    skill_scope: tuple[str, ...] = ()
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not all(str(value).strip() for value in (self.agent_id, self.mission_id, self.owner_identity_ref, self.role)):
            raise ValueError("agent identity, mission, owner, and role are required")
        self.capabilities = _strings(self.capabilities, field_name="capabilities")
        self.skill_scope = _strings(self.skill_scope, field_name="skill_scope")
        if self.permission_scope.mission_id != self.mission_id or self.permission_scope.owner_identity_ref != self.owner_identity_ref:
            raise ValueError("agent delegation binding mismatch")
        if not isinstance(self.lifecycle, AgentLifecycle):
            self.lifecycle = AgentLifecycle(self.lifecycle)

    @classmethod
    def create(
        cls,
        *,
        mission_id: str,
        owner_identity_ref: str,
        role: str,
        capabilities: Iterable[str],
        permission_scope: DelegationScope,
        parent_agent_id: str | None = None,
        parent_task_id: str | None = None,
        context_ref: str = "",
        memory_scope: str = "mission",
        skill_scope: Iterable[str] = (),
        agent_id: str | None = None,
    ) -> "AgentRecord":
        return cls(
            agent_id=agent_id or uuid.uuid4().hex,
            mission_id=mission_id,
            owner_identity_ref=owner_identity_ref,
            role=role.strip(),
            capabilities=tuple(capabilities),
            permission_scope=permission_scope,
            parent_agent_id=parent_agent_id,
            parent_task_id=parent_task_id,
            context_ref=str(context_ref),
            memory_scope=str(memory_scope),
            skill_scope=tuple(skill_scope),
        )

    def transition(self, target: AgentLifecycle) -> None:
        target = AgentLifecycle(target)
        if target is self.lifecycle:
            return
        if target not in _AGENT_TRANSITIONS[self.lifecycle]:
            raise InvalidTransition(f"agent transition {self.lifecycle.value}->{target.value} is not allowed")
        self.lifecycle = target
        self.updated_at = _now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "mission_id": self.mission_id, "owner_identity_ref": self.owner_identity_ref,
            "role": self.role, "capabilities": list(self.capabilities), "permission_scope": self.permission_scope.to_dict(),
            "parent_agent_id": self.parent_agent_id, "parent_task_id": self.parent_task_id,
            "lifecycle": self.lifecycle.value, "context_ref": self.context_ref, "memory_scope": self.memory_scope,
            "skill_scope": list(self.skill_scope), "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentRecord":
        values = dict(data)
        values["permission_scope"] = DelegationScope.from_dict(values["permission_scope"])
        values["capabilities"] = tuple(values.get("capabilities", ()))
        values["skill_scope"] = tuple(values.get("skill_scope", ()))
        values["lifecycle"] = AgentLifecycle(values.get("lifecycle", AgentLifecycle.CREATED.value))
        return cls(**values)


@dataclass
class TaskRecord:
    task_id: str
    mission_id: str
    assigned_agent_id: str
    objective: str
    parent_task_id: str | None = None
    constraints: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    lifecycle: TaskLifecycle = TaskLifecycle.CREATED
    artifacts: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    memory_refs: tuple[str, ...] = ()
    result: Any = None
    result_validation_state: str = "UNVERIFIED"
    error: str = ""
    attempt_count: int = 0
    cancel_requested: bool = False
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not all(str(value).strip() for value in (self.task_id, self.mission_id, self.assigned_agent_id, self.objective)):
            raise ValueError("task identity, mission, assigned agent, and objective are required")
        if len(self.objective) > 10000:
            raise ValueError("task objective exceeds the maximum length")
        self.constraints = _strings(self.constraints, field_name="constraints")
        self.dependencies = _strings(self.dependencies, field_name="dependencies")
        self.artifacts = _strings(self.artifacts, field_name="artifacts")
        self.evidence_refs = _strings(self.evidence_refs, field_name="evidence_refs")
        self.memory_refs = _strings(self.memory_refs, field_name="memory_refs")
        if len(self.memory_refs) > 1 or any(len(ref) > 96 or not ref.startswith("specialist-memory:") for ref in self.memory_refs):
            raise ValueError("task memory references must be a single bounded specialist-memory reference")
        if not isinstance(self.lifecycle, TaskLifecycle):
            self.lifecycle = TaskLifecycle(self.lifecycle)
        if self.attempt_count < 0:
            raise ValueError("task attempt_count must be non-negative")

    @classmethod
    def create(
        cls,
        *,
        mission_id: str,
        assigned_agent_id: str,
        objective: str,
        parent_task_id: str | None = None,
        constraints: Iterable[str] = (),
        dependencies: Iterable[str] = (),
        task_id: str | None = None,
    ) -> "TaskRecord":
        return cls(
            task_id=task_id or uuid.uuid4().hex,
            mission_id=mission_id,
            assigned_agent_id=assigned_agent_id,
            objective=objective.strip(),
            parent_task_id=parent_task_id,
            constraints=tuple(constraints),
            dependencies=tuple(dependencies),
        )

    def transition(self, target: TaskLifecycle) -> None:
        target = TaskLifecycle(target)
        if target is self.lifecycle:
            return
        if target not in _TASK_TRANSITIONS[self.lifecycle]:
            raise InvalidTransition(f"task transition {self.lifecycle.value}->{target.value} is not allowed")
        self.lifecycle = target
        self.updated_at = _now()

    def retry(self, *, max_retries: int) -> None:
        """Requeue a failed task through an explicit bounded-retry operation."""
        if self.lifecycle is not TaskLifecycle.FAILED:
            raise InvalidTransition("only a failed task can be retried")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        if self.attempt_count > max_retries:
            raise InvalidTransition("task retry limit exhausted")
        self.lifecycle = TaskLifecycle.READY
        self.error = ""
        self.result = None
        self.evidence_refs = ()
        self.result_validation_state = "UNVERIFIED"
        self.updated_at = _now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "mission_id": self.mission_id, "assigned_agent_id": self.assigned_agent_id,
            "objective": self.objective, "parent_task_id": self.parent_task_id, "constraints": list(self.constraints),
            "dependencies": list(self.dependencies), "lifecycle": self.lifecycle.value, "artifacts": list(self.artifacts),
            "evidence_refs": list(self.evidence_refs), "memory_refs": list(self.memory_refs), "result": self.result,
            "result_validation_state": self.result_validation_state, "error": self.error,
            "attempt_count": self.attempt_count, "cancel_requested": self.cancel_requested,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskRecord":
        values = dict(data)
        for name in ("constraints", "dependencies", "artifacts", "evidence_refs", "memory_refs"):
            values[name] = tuple(values.get(name, ()))
        values["lifecycle"] = TaskLifecycle(values.get("lifecycle", TaskLifecycle.CREATED.value))
        return cls(**values)


__all__ = [
    "AgentLifecycle", "AgentRecord", "DelegationDenied", "DelegationScope", "InvalidTransition",
    "TaskLifecycle", "TaskRecord",
]
