from __future__ import annotations

from typing import Any

from agent.mission import Mission, MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker, WorkerMissionState
from agent.planning import Plan


class MissionService:
    """Canonical long-horizon mission API facade; execution remains MissionRuntime-owned."""

    def __init__(self, runtime: MissionRuntime, queue: MissionQueue, scheduler: MissionScheduler | None = None):
        self.runtime = runtime
        self.queue = queue
        self.scheduler = scheduler

    def create_mission(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> dict[str, Any]:
        from security.authorization_context import AuthorizationContext
        authorization_context = kwargs.pop("authorization_context", None)
        if not isinstance(authorization_context, AuthorizationContext):
            raise PermissionError("mission creation requires typed Owner AuthorizationContext")
        instruction = str(owner_request or objective).strip()
        if instruction != str(authorization_context.policy_snapshot.owner_instruction).strip():
            raise PermissionError("mission objective must match the authenticated Owner instruction")
        from agent.agent_core import AgentCore
        unauthorized = [step.step_id for step in plan.steps if not AgentCore._owner_proposal_allowed(instruction, step)[0]]
        if not plan.steps or unauthorized:
            raise PermissionError("plan actions or arguments exceed the deterministic Owner-instruction boundary")
        kwargs.setdefault("completion_criteria", [
            {"criterion_id": step.step_id, "description": f"Owner-requested step {step.step_id} completed", "check": "tool observation", "required": True}
            for step in plan.steps
        ])
        kwargs["owner_identity_ref"] = authorization_context.owner_evidence.proof_fingerprint
        mission = self.runtime.create_owner_graph(
            instruction,
            plan,
            authorization_context=authorization_context,
            **kwargs,
        )
        return mission.to_dict()

    def start_mission(self, mission_id: str, *, authorization_context: Any = None) -> dict[str, Any]:
        mission = self._load(mission_id)
        self.runtime._require_owner_graph_control(mission, authorization_context)
        if mission.progress.get("execution_mode") != "dag":
            raise ValueError("only authenticated graph missions can be started by the durable worker")
        return self.queue.enqueue(mission_id).__dict__.copy()

    def control_mission(self, mission_id: str, command: str, *, authorization_context: Any) -> dict[str, Any]:
        mission = self._load(mission_id)
        self.runtime._require_owner_graph_control(mission, authorization_context)
        if mission.progress.get("execution_mode") != "dag":
            raise ValueError("mission has no authenticated deterministic execution graph")
        worker = MissionWorker(self.queue, lambda: self.runtime, worker_id="mission-api")
        return worker.control_graph(mission_id, command, authorization_context=authorization_context).to_dict()

    def pause_mission(self, mission_id: str, *, authorization_context: Any) -> dict[str, Any]:
        return self.control_mission(mission_id, "pause", authorization_context=authorization_context)

    def resume_mission(self, mission_id: str, *, authorization_context: Any) -> dict[str, Any]:
        return self.control_mission(mission_id, "resume", authorization_context=authorization_context)

    def cancel_mission(self, mission_id: str, *, authorization_context: Any) -> dict[str, Any]:
        return self.control_mission(mission_id, "cancel", authorization_context=authorization_context)

    def status(self, mission_id: str) -> dict[str, Any]:
        return self._load(mission_id).to_dict()

    def timeline(self, mission_id: str) -> list[dict[str, Any]]:
        return list(self._load(mission_id).trajectory)

    def evidence(self, mission_id: str) -> list[dict[str, Any]]:
        return list(self._load(mission_id).evidence)

    def artifacts(self, mission_id: str) -> list[dict[str, Any]]:
        return list(self._load(mission_id).artifacts)

    def logs(self, mission_id: str) -> list[dict[str, Any]]:
        mission = self._load(mission_id)
        return list(mission.progress.get("logs", ()))

    def schedule_mission(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None, authorization_context: Any = None) -> dict[str, Any]:
        if self.scheduler is None:
            raise RuntimeError("scheduler is not configured")
        mission = self._load(mission_id)
        self.runtime._require_owner_graph_control(mission, authorization_context)
        if mission.progress.get("execution_mode") != "dag":
            raise ValueError("only graph missions can be scheduled for durable execution")
        return self.scheduler.schedule(mission_id, run_at=run_at, interval_seconds=interval_seconds, retry_limit=retry_limit, schedule_id=schedule_id).__dict__.copy()

    def _load(self, mission_id: str) -> Mission:
        mission = self.runtime.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission


__all__ = ["MissionService"]
