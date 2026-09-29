from __future__ import annotations

from typing import Any

from agent.mission import Mission, MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionScheduler, WorkerMissionState
from agent.planning import Plan


class MissionService:
    """Canonical long-horizon mission API facade; execution remains MissionRuntime-owned."""

    def __init__(self, runtime: MissionRuntime, queue: MissionQueue, scheduler: MissionScheduler | None = None):
        self.runtime = runtime
        self.queue = queue
        self.scheduler = scheduler

    def create_mission(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> dict[str, Any]:
        mission = self.runtime.create(owner_request, objective, plan, **kwargs)
        return mission.to_public_dict()

    def start_mission(self, mission_id: str, *, owner_identity: str | None = None) -> dict[str, Any]:
        self._load(mission_id, owner_identity=owner_identity)
        return self.queue.enqueue(mission_id).__dict__.copy()

    def pause_mission(self, mission_id: str, *, owner_identity: str | None = None) -> dict[str, Any]:
        mission = self._load(mission_id, owner_identity=owner_identity)
        if mission.is_terminal:
            return mission.to_public_dict()
        try:
            queue_item = self.queue.get(mission_id)
        except KeyError:
            queue_item = None
        checkpoint_status = str((mission.checkpoint or {}).get("status", ""))
        if (queue_item is not None and queue_item.state is WorkerMissionState.EXECUTING) or checkpoint_status in {"in_flight", "in_flight_parallel"}:
            mission.progress["pause_requested"] = True
        else:
            mission.progress.pop("pause_requested", None)
            mission.transition(MissionStatus.PAUSED, "Owner requested mission pause")
            mission.checkpoint = {**mission.checkpoint, "status": "paused"}
            if queue_item is not None:
                self.queue.update(mission_id, WorkerMissionState.PAUSED)
        return self.runtime.store.save(mission).to_public_dict()

    def resume_mission(self, mission_id: str, *, owner_identity: str | None = None) -> dict[str, Any]:
        mission = self._load(mission_id, owner_identity=owner_identity)
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("in-flight mission requires reconciliation before resume")
        mission.progress.pop("pause_requested", None)
        if mission.status is MissionStatus.PAUSED:
            mission.transition(MissionStatus.READY, "Owner resumed mission")
            mission.checkpoint = {**mission.checkpoint, "status": "resumed"}
        self.runtime.store.save(mission)
        self.queue.enqueue(mission_id)
        return mission.to_public_dict()

    def cancel_mission(self, mission_id: str, *, owner_identity: str | None = None) -> dict[str, Any]:
        mission = self._load(mission_id, owner_identity=owner_identity)
        if not mission.is_terminal:
            checkpoint_status = str((mission.checkpoint or {}).get("status", ""))
            if checkpoint_status in {"in_flight", "in_flight_parallel"}:
                mission.progress["cancel_requested"] = True
            else:
                mission.transition(MissionStatus.CANCELLED, "Owner requested mission cancellation")
                mission.checkpoint = {**mission.checkpoint, "status": "cancelled"}
                try:
                    queue_item = self.queue.get(mission_id)
                except KeyError:
                    queue_item = None
                if queue_item is not None and queue_item.state is not WorkerMissionState.EXECUTING:
                    self.queue.update(mission_id, WorkerMissionState.CANCELLED)
            self.runtime.store.save(mission)
        return mission.to_public_dict()

    def status(self, mission_id: str, *, owner_identity: str | None = None) -> dict[str, Any]:
        mission = self._load(mission_id, owner_identity=owner_identity)
        value = mission.to_public_dict()
        try:
            item = self.queue.get(mission_id)
            value["queue"] = {"state": item.state.value, "attempts": item.attempts, "available_at": item.available_at}
        except KeyError:
            value["queue"] = {"state": "not_queued"}
        return value

    def timeline(self, mission_id: str, *, owner_identity: str | None = None) -> list[dict[str, Any]]:
        return list(self._load(mission_id, owner_identity=owner_identity).trajectory)

    def evidence(self, mission_id: str, *, owner_identity: str | None = None) -> list[dict[str, Any]]:
        return list(self._load(mission_id, owner_identity=owner_identity).evidence)

    def artifacts(self, mission_id: str, *, owner_identity: str | None = None) -> list[dict[str, Any]]:
        return list(self._load(mission_id, owner_identity=owner_identity).artifacts)

    def logs(self, mission_id: str, *, owner_identity: str | None = None) -> list[dict[str, Any]]:
        mission = self._load(mission_id, owner_identity=owner_identity)
        return list(mission.progress.get("logs", ()))

    def list_missions(self, owner_identity: str, *, limit: int = 100) -> list[dict[str, Any]]:
        return self.runtime.store.list_for_owner(owner_identity, limit=limit)

    def mission(self, mission_id: str, *, owner_identity: str) -> Mission:
        return self._load(mission_id, owner_identity=owner_identity)

    def schedule_mission(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None) -> dict[str, Any]:
        if self.scheduler is None:
            raise RuntimeError("scheduler is not configured")
        return self.scheduler.schedule(mission_id, run_at=run_at, interval_seconds=interval_seconds, retry_limit=retry_limit, schedule_id=schedule_id).__dict__.copy()

    def _load(self, mission_id: str, *, owner_identity: str | None = None) -> Mission:
        mission = self.runtime.store.load_for_owner(mission_id, owner_identity) if owner_identity is not None else self.runtime.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission


__all__ = ["MissionService"]
