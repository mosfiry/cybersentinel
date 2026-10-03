from __future__ import annotations

import uuid
from typing import Any, Callable

from agent.mission import Mission, MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionScheduler
from agent.planning import Plan
from security.owner_policy import OwnerAuthenticationEvidence


class MissionService:
    """Canonical long-horizon mission API facade; execution remains MissionRuntime-owned."""

    def __init__(
        self,
        runtime: MissionRuntime,
        queue: MissionQueue,
        scheduler: MissionScheduler | None = None,
        *,
        owner_revalidator: Callable[[str, str], OwnerAuthenticationEvidence] | None = None,
    ):
        self.runtime = runtime
        self.queue = queue
        self.scheduler = scheduler
        self.owner_revalidator = owner_revalidator

    def create_mission(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> dict[str, Any]:
        if not str(kwargs.get("request_id") or "").strip():
            context_request_id = getattr(kwargs.get("authorization_context"), "request_id", "")
            kwargs["request_id"] = str(context_request_id or uuid.uuid4().hex)
        mission = self.runtime.create(owner_request, objective, plan, **kwargs)
        return mission.to_dict()

    def start_mission(self, mission_id: str, *, owner_session_token: str | None = None) -> dict[str, Any]:
        self._reauthorize_before_enqueue(mission_id, owner_session_token)
        return self.queue.enqueue(mission_id).__dict__.copy()

    def pause_mission(self, mission_id: str) -> dict[str, Any]:
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission.to_dict()
        mission.progress["pause_requested"] = True
        mission.checkpoint = {**mission.checkpoint, "status": "paused"}
        return self.runtime.store.save(mission).to_dict()

    def resume_mission(self, mission_id: str, *, owner_session_token: str | None = None) -> dict[str, Any]:
        mission = self._reauthorize_before_enqueue(mission_id, owner_session_token)
        mission.progress.pop("pause_requested", None)
        mission = self.runtime.store.save(mission)
        self.queue.enqueue(mission_id)
        return mission.to_dict()

    def cancel_mission(self, mission_id: str) -> dict[str, Any]:
        mission = self._load(mission_id)
        if not mission.is_terminal:
            mission.transition(MissionStatus.CANCELLED, "Owner requested mission cancellation")
            mission.checkpoint = {**mission.checkpoint, "status": "cancelled"}
            self.runtime.store.save(mission)
        return mission.to_dict()

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

    def schedule_mission(self, mission_id: str, *, run_at: str, interval_seconds: int | None = None, retry_limit: int = 0, schedule_id: str | None = None) -> dict[str, Any]:
        if self.scheduler is None:
            raise RuntimeError("scheduler is not configured")
        return self.scheduler.schedule(mission_id, run_at=run_at, interval_seconds=interval_seconds, retry_limit=retry_limit, schedule_id=schedule_id).__dict__.copy()

    def _reauthorize_before_enqueue(self, mission_id: str, owner_session_token: str | None) -> Mission:
        if not isinstance(owner_session_token, str) or not owner_session_token.strip():
            raise PermissionError("owner revalidation required before queueing")
        if self.owner_revalidator is None:
            raise PermissionError("owner revalidation is unavailable")
        mission = self._load(mission_id)
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("in-flight mission requires reconciliation before resume")
        if mission.is_terminal and mission.status is not MissionStatus.OWNER_INPUT_REQUIRED:
            raise ValueError("terminal mission cannot be queued")

        evidence = self.owner_revalidator(mission_id, owner_session_token)
        mission = self._load(mission_id)
        if not isinstance(evidence, OwnerAuthenticationEvidence) or not evidence.is_valid(
            mission.request_id,
            session_id=owner_session_token,
        ):
            raise PermissionError("owner revalidation evidence is invalid")
        if (mission.authorization_snapshot or {}).get("owner_approval") != evidence.proof_fingerprint:
            raise PermissionError("owner authorization is not bound to the queued mission")
        authentication = (mission.policy_snapshot or {}).get("authentication", {})
        if not isinstance(authentication, dict) or authentication.get("proof_fingerprint") != evidence.proof_fingerprint:
            raise PermissionError("owner policy snapshot is not bound to the current session")
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("in-flight mission requires reconciliation before resume")
        if mission.is_terminal:
            raise ValueError("mission cannot be queued in its current terminal state")
        return mission

    def _load(self, mission_id: str) -> Mission:
        mission = self.runtime.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission


__all__ = ["MissionService"]
