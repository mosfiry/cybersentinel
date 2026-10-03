from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Mapping
import hashlib
import json


class ExecutionFenceError(RuntimeError):
    """A worker, task, authorization, or execution fence is stale or mismatched."""


def authorization_digest(snapshot: Any) -> str:
    if hasattr(snapshot, "to_dict"):
        snapshot = snapshot.to_dict()
    if not isinstance(snapshot, Mapping) or not snapshot:
        raise ExecutionFenceError("execution fence requires an authorization snapshot")
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionFence:
    """Immutable proof tying one execution operation to its current durable owner.

    Queue and execution code use the same token. The queue supplies authoritative
    current-state facts; this object applies the identity, generation, lease,
    task-version, authorization, request, and execution comparisons centrally.
    """

    queue: Any = field(repr=False, compare=False)
    worker_id: str
    worker_instance_id: str
    runtime_generation: int
    mission_id: str | None = None
    lease_epoch: int | None = None
    task_id: str | None = None
    task_version: int | None = None
    authorization_hash: str = ""
    execution_id: str = ""
    request_id: str = ""

    @classmethod
    def for_worker(cls, queue: Any, identity: Any) -> "ExecutionFence":
        return cls(
            queue=queue,
            worker_id=str(identity.worker_id),
            worker_instance_id=str(identity.worker_instance_id),
            runtime_generation=int(identity.runtime_generation),
        )

    def with_lease(self, item: Any) -> "ExecutionFence":
        if str(item.mission_id) == "" or int(item.lease_epoch) <= 0:
            raise ExecutionFenceError("queue claim does not contain a current lease epoch")
        return replace(
            self,
            mission_id=str(item.mission_id),
            lease_epoch=int(item.lease_epoch),
        )

    def for_mission(
        self,
        mission: Any,
        *,
        task_id: str | None = None,
        execution_id: str | None = None,
    ) -> "ExecutionFence":
        mission_id = str(getattr(mission, "mission_id", ""))
        if not mission_id or (self.mission_id is not None and mission_id != self.mission_id):
            raise ExecutionFenceError("execution fence mission mismatch")
        plan = getattr(mission, "plan", None)
        if plan is None or not isinstance(getattr(plan, "version", None), int):
            raise ExecutionFenceError("execution fence task version unavailable")
        if task_id is None:
            step = getattr(mission, "current_plan_step", None)
            checkpoint = getattr(mission, "checkpoint", {})
            task_id = str(getattr(step, "step_id", "") or (checkpoint.get("step_id") if isinstance(checkpoint, dict) else "") or "__mission__")
        if execution_id is None:
            checkpoint = getattr(mission, "checkpoint", {})
            if isinstance(checkpoint, dict):
                execution_id = str(checkpoint.get("action_id") or checkpoint.get("tool_call_id") or "")
            execution_id = execution_id or f"{mission_id}:plan:{plan.version}:state"
        return replace(
            self,
            mission_id=mission_id,
            task_id=str(task_id),
            task_version=int(plan.version),
            authorization_hash=authorization_digest(getattr(mission, "authorization_snapshot", None)),
            execution_id=str(execution_id),
            request_id=str(getattr(mission, "request_id", "")),
        )

    @property
    def fence_id(self) -> str:
        payload = {
            "mission_id": self.mission_id,
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "runtime_generation": self.runtime_generation,
            "lease_epoch": self.lease_epoch,
            "task_id": self.task_id,
            "task_version": self.task_version,
            "authorization_hash": self.authorization_hash,
            "execution_id": self.execution_id,
            "request_id": self.request_id,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @property
    def lease_binding_id(self) -> str:
        if not self.mission_id or self.lease_epoch is None:
            raise ExecutionFenceError("lease binding requires a mission and lease epoch")
        payload = {
            "mission_id": self.mission_id,
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "runtime_generation": self.runtime_generation,
            "lease_epoch": self.lease_epoch,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def metadata(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id or "",
            "task_id": self.task_id or "",
            "execution_id": self.execution_id,
            "request_id": self.request_id,
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "runtime_generation": self.runtime_generation,
            "lease_epoch": self.lease_epoch or 0,
            "task_version": self.task_version or 0,
            "authorization_hash": self.authorization_hash,
            "fence_id": self.fence_id,
        }

    def assert_queue_state(self, state: Mapping[str, Any], *, allow_claimed: bool = False) -> None:
        expected = {
            "worker_id": self.worker_id,
            "worker_instance_id": self.worker_instance_id,
            "runtime_generation": self.runtime_generation,
        }
        observed = {
            "worker_id": state.get("registered_worker_id"),
            "worker_instance_id": state.get("registered_worker_instance_id"),
            "runtime_generation": state.get("registered_runtime_generation"),
        }
        if (
            observed != expected
            or state.get("worker_state") != "ACTIVE"
            or state.get("current_worker_instance_id") != self.worker_instance_id
            or state.get("current_runtime_generation") != self.runtime_generation
            or state.get("current_worker_state") != "ACTIVE"
        ):
            raise ExecutionFenceError("worker generation is not the active registered execution identity")
        if self.lease_epoch is None:
            if self.mission_id is not None:
                raise ExecutionFenceError("execution fence lease epoch is missing")
            return
        if not self.mission_id:
            raise ExecutionFenceError("execution fence mission is missing")
        if (
            state.get("queue_mission_id") != self.mission_id
            or state.get("queue_state") != "executing"
            or state.get("lease_owner") != self.worker_id
            or state.get("lease_epoch") != self.lease_epoch
            or state.get("queue_worker_instance_id") != self.worker_instance_id
            or state.get("queue_runtime_generation") != self.runtime_generation
        ):
            raise ExecutionFenceError("mission lease is no longer owned by this execution fence")
        allowed_claim_phases = {"CLAIMED", "BOUND"} if allow_claimed else {"BOUND"}
        if (
            state.get("claim_phase") not in allowed_claim_phases
            or state.get("claim_fence_id") != self.lease_binding_id
        ):
            raise ExecutionFenceError("mission claim is not durably bound to this execution fence")
        expiry = state.get("lease_expires_at")
        if not isinstance(expiry, str):
            raise ExecutionFenceError("mission lease expiry is missing")
        try:
            expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ExecutionFenceError("mission lease expiry is invalid") from exc
        if expires_at <= datetime.now(timezone.utc):
            raise ExecutionFenceError("mission lease has expired")

    def assert_current(
        self,
        *,
        mission: Any | None = None,
        mission_id: str | None = None,
        request_id: str | None = None,
        task_id: str | None = None,
        task_version: int | None = None,
        execution_id: str | None = None,
        authorization_snapshot: Any | None = None,
        db: Any | None = None,
        allow_claimed: bool = False,
    ) -> "ExecutionFence":
        if mission is not None:
            mission_id = str(getattr(mission, "mission_id", ""))
            request_id = str(getattr(mission, "request_id", ""))
            task_version = int(getattr(getattr(mission, "plan", None), "version", -1))
            authorization_snapshot = getattr(mission, "authorization_snapshot", None)
        if mission_id is not None and mission_id != self.mission_id:
            raise ExecutionFenceError("execution fence mission mismatch")
        if request_id is not None and request_id != self.request_id:
            raise ExecutionFenceError("execution fence request mismatch")
        if task_id is not None and task_id != self.task_id:
            raise ExecutionFenceError("execution fence task mismatch")
        if task_version is not None and task_version != self.task_version:
            raise ExecutionFenceError("execution fence task version mismatch")
        if execution_id is not None and execution_id != self.execution_id:
            raise ExecutionFenceError("execution fence execution identity mismatch")
        if authorization_snapshot is not None and authorization_digest(authorization_snapshot) != self.authorization_hash:
            raise ExecutionFenceError("execution fence authorization snapshot mismatch")
        self.queue.validate_execution_fence(self, db=db, allow_claimed=allow_claimed)
        return self

    def assert_dispatch(
        self,
        *,
        mission_id: str,
        request_id: str,
        execution_id: str,
        authorization_snapshot: Any,
    ) -> "ExecutionFence":
        if not self.task_id or self.task_version is None or not self.authorization_hash:
            raise ExecutionFenceError("tool dispatch requires a task-bound execution fence")
        return self.assert_current(
            mission_id=mission_id,
            request_id=request_id,
            execution_id=execution_id,
            authorization_snapshot=authorization_snapshot,
        )

    def assert_evidence(self, item: Mapping[str, Any]) -> dict[str, Any]:
        if not self.task_id or self.task_version is None or not self.authorization_hash or not self.execution_id:
            raise ExecutionFenceError("evidence append requires a task-bound execution fence")
        supplied_mission = item.get("mission_id")
        supplied_request = item.get("request_id")
        if supplied_mission and str(supplied_mission) != self.mission_id:
            raise ExecutionFenceError("evidence mission does not match execution fence")
        if supplied_request and str(supplied_request) != self.request_id:
            raise ExecutionFenceError("evidence request does not match execution fence")
        self.assert_current(mission_id=self.mission_id, request_id=self.request_id)
        stamped = dict(item)
        for name, value in self.metadata().items():
            existing = stamped.get(name)
            if existing not in (None, "", 0, value):
                raise ExecutionFenceError(f"evidence {name} does not match execution fence")
            stamped[name] = value
        return stamped

    def assert_effect_reservation(self, reservation: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and stamp a durable effect reservation before any provider call."""
        if not self.task_id or self.task_version is None or not self.authorization_hash or not self.execution_id:
            raise ExecutionFenceError("effect reservation requires a task-bound execution fence")
        self.assert_current(
            mission_id=str(reservation.get("mission_id", self.mission_id or "")),
            request_id=str(reservation.get("request_id", self.request_id)),
            task_id=str(reservation.get("task_id", self.task_id)),
            task_version=int(reservation.get("task_version", self.task_version)),
            execution_id=str(reservation.get("execution_id", self.execution_id)),
            authorization_snapshot=reservation.get("authorization_snapshot") if reservation.get("authorization_snapshot") is not None else None,
        )
        stamped = dict(reservation)
        for name, value in self.metadata().items():
            existing = stamped.get(name)
            if existing not in (None, "", 0, value):
                raise ExecutionFenceError(f"effect reservation {name} does not match execution fence")
            stamped[name] = value
        return stamped


__all__ = ["ExecutionFence", "ExecutionFenceError", "authorization_digest"]
