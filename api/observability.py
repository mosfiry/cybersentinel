"""Owner-only, bounded Mission progress projection for the Desktop UI.

This API deliberately returns identifiers, lifecycle states and evidence receipt
references only. Mission/task prompts, raw tool arguments, task results, credentials,
and exception text are never serialized here.
"""
from __future__ import annotations

import json
import re
from typing import Any

from agent.intelligence_layer.events import EventError, EventIntegrityError, EventStore
from agent.intelligence_layer.graph import TaskGraph, TaskGraphError
from agent.mission import Mission
from agent.planning import FailureClass
from agent.trajectory import EventType, verify_trajectory


class MissionObservabilityError(ValueError):
    """The stored Mission progress cannot be safely projected."""


class MissionObservabilityTooLarge(MissionObservabilityError):
    """The requested projection exceeds a strict resource/response bound."""


_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_TOOL = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_FAILURE_CLASSES = {item.value for item in FailureClass}
_EVENT_TYPES = {item.value for item in EventType}
_TASK_STATUSES = {"CREATED", "WAITING", "READY", "RUNNING", "COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}
_AGENT_STATUSES = {"CREATED", "READY", "RUNNING", "WAITING", "BLOCKED", "COMPLETED", "FAILED", "CANCELLED"}
_RESULT_STATES = {"UNVERIFIED", "PENDING_VALIDATION"}


class MissionObservabilityService:
    MAX_TASKS = 128
    MAX_AGENTS = 16
    MAX_TRAJECTORY_EVENTS = 20_000
    MAX_TIMELINE_PAGE = 50
    MAX_TIMELINE_OFFSET = MAX_TRAJECTORY_EVENTS
    MAX_EVENT_SEQUENCE = 2_147_483_647
    MAX_EVIDENCE_REFS = 100
    MAX_RESPONSE_BYTES = 65_536

    def __init__(self, mission_service: Any, *, event_store: EventStore | None = None):
        self.mission_service = mission_service
        self.event_store = event_store

    @staticmethod
    def _int(value: Any, name: str, *, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"{name} is outside the allowed range")
        return value

    @staticmethod
    def _safe_ref(value: Any) -> str | None:
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            return None
        return value

    @staticmethod
    def _safe_tool(value: Any) -> str | None:
        if not isinstance(value, str) or not _SAFE_TOOL.fullmatch(value):
            return None
        return value

    def get(
        self,
        mission_id: str,
        *,
        owner_session_token: str | None,
        timeline_offset: int = 0,
        timeline_limit: int = 25,
        event_after_sequence: int = 0,
        event_limit: int = 25,
    ) -> dict[str, Any]:
        offset = self._int(timeline_offset, "timeline_offset", minimum=0, maximum=self.MAX_TIMELINE_OFFSET)
        page_size = self._int(timeline_limit, "timeline_limit", minimum=1, maximum=self.MAX_TIMELINE_PAGE)
        event_after = self._int(event_after_sequence, "event_after_sequence", minimum=0, maximum=self.MAX_EVENT_SEQUENCE)
        event_page_size = self._int(event_limit, "event_limit", minimum=1, maximum=self.MAX_TIMELINE_PAGE)
        if not isinstance(mission_id, str) or not mission_id or len(mission_id) > 128:
            raise KeyError("unknown_mission")

        # The service resolves the canonical Owner and applies an Owner filter
        # in SQLite before deserializing. A foreign and absent Mission share 404.
        try:
            mission, owner_ref = self.mission_service.load_authorized_mission(
                mission_id, owner_session_token
            )
        except (KeyError, PermissionError) as exc:
            raise KeyError("unknown_mission") from exc
        except ValueError as exc:
            if str(exc) == "mission_observability_too_large":
                raise MissionObservabilityTooLarge("mission_observability_too_large") from exc
            raise MissionObservabilityError("mission_integrity_invalid") from exc
        if mission.mission_id != mission_id or mission.owner_identity_ref != owner_ref:
            raise KeyError("unknown_mission")
        if not mission.verify_integrity():
            raise MissionObservabilityError("mission_integrity_invalid")
        if not isinstance(mission.trajectory, list) or len(mission.trajectory) > self.MAX_TRAJECTORY_EVENTS:
            raise MissionObservabilityTooLarge("mission_observability_too_large")
        try:
            trajectory_valid = verify_trajectory(mission.trajectory)
        except (KeyError, TypeError, ValueError):
            trajectory_valid = False
        if not trajectory_valid:
            raise MissionObservabilityError("mission_timeline_integrity_invalid")
        steps = mission.plan.steps
        if len(steps) > self.MAX_TASKS:
            raise MissionObservabilityTooLarge("mission_plan_exceeds_observability_limit")

        graph, step_to_task = self._graph_projection(mission, owner_ref)
        evidence_refs = self._evidence_projection(mission, step_to_task)
        evidence_by_task: dict[str, list[str]] = {}
        for evidence_ref in evidence_refs:
            evidence_by_task.setdefault(evidence_ref["task_id"], []).append(evidence_ref["evidence_id"])
        for task_view in graph["tasks"]:
            task_view["evidence_refs"] = evidence_by_task.get(task_view["task_id"], [])
        current_step = None
        if isinstance(mission.current_step, int) and not isinstance(mission.current_step, bool) and 0 <= mission.current_step < len(steps):
            step = steps[mission.current_step]
            step_id = self._safe_ref(getattr(step, "step_id", ""))
            task_id = step_to_task.get(step_id or "")
            action = self._safe_tool(getattr(step, "action", ""))
            task_status = None
            if task_id:
                task_status = next((item["status"] for item in graph["tasks"] if item["task_id"] == task_id), None)
            current_step = {
                "index": mission.current_step,
                "step_id": step_id,
                "action": action,
                "task_id": task_id,
                "task_status": task_status,
            }

        timeline_slice = mission.trajectory[offset:offset + page_size]
        timeline_events = [self._trajectory_event(item, sequence=offset + index + 1) for index, item in enumerate(timeline_slice)]
        timeline_next = offset + len(timeline_events)
        timeline = {
            "offset": offset,
            "limit": page_size,
            "events": timeline_events,
            "next_offset": timeline_next if timeline_next < len(mission.trajectory) else None,
            "has_more": timeline_next < len(mission.trajectory),
        }
        event_log = self._event_projection(
            mission,
            owner_ref,
            after_sequence=event_after,
            limit=event_page_size,
        )
        status_value = mission.status.value
        result: dict[str, Any] = {
            "mission_id": mission_id,
            "stage": {
                "status": status_value,
                "current_step": current_step,
                "step_count": len(steps),
                "error_category": self._mission_error_category(mission),
            },
            "graph": graph,
            "evidence_refs": evidence_refs,
            "evidence_ref_count": self._safe_evidence_count(mission),
            "timeline": timeline,
            "event_log": event_log,
        }
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.MAX_RESPONSE_BYTES:
            raise MissionObservabilityTooLarge("mission_observability_response_too_large")
        return result

    def _graph_projection(self, mission: Mission, owner_ref: str) -> tuple[dict[str, Any], dict[str, str]]:
        state = mission.agent_task_graph_state
        empty = {"available": False, "reason": "not_initialized", "revision": None, "tasks": [], "agents": []}
        if state in (None, {}):
            return empty, {}
        if (
            not isinstance(state, dict)
            or isinstance(state.get("schema_version"), bool)
            or not isinstance(state.get("schema_version"), int)
            or state.get("schema_version") != 1
        ):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        raw_graph = state.get("graph")
        raw_mapping = state.get("step_task_ids")
        revision = state.get("revision")
        graph_revision = raw_graph.get("revision") if isinstance(raw_graph, dict) else None
        if (
            not isinstance(raw_graph, dict)
            or not isinstance(raw_mapping, dict)
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 1
            or isinstance(raw_graph.get("schema_version"), bool)
            or not isinstance(raw_graph.get("schema_version"), int)
            or raw_graph.get("schema_version") != TaskGraph.SCHEMA_VERSION
            or isinstance(graph_revision, bool)
            or not isinstance(graph_revision, int)
            or graph_revision < 1
            or graph_revision != revision
        ):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        agents_raw = raw_graph.get("agents")
        tasks_raw = raw_graph.get("tasks")
        policy_raw = raw_graph.get("policy")
        if (
            not isinstance(agents_raw, list)
            or not isinstance(tasks_raw, list)
            or not isinstance(policy_raw, dict)
            or len(agents_raw) > self.MAX_AGENTS
            or len(tasks_raw) > self.MAX_TASKS
            or len(raw_mapping) > self.MAX_TASKS
        ):
            raise MissionObservabilityTooLarge("mission_graph_exceeds_observability_limit")

        def string_list(value: Any) -> bool:
            return (
                isinstance(value, (list, tuple))
                and len(value) <= 512
                and all(isinstance(item, str) and 0 < len(item) <= 1_024 for item in value)
            )

        for raw_agent in agents_raw:
            if (
                not isinstance(raw_agent, dict)
                or self._safe_ref(raw_agent.get("agent_id")) is None
                or raw_agent.get("mission_id") != mission.mission_id
                or raw_agent.get("owner_identity_ref") != owner_ref
                or not isinstance(raw_agent.get("role"), str)
                or len(raw_agent["role"]) > 256
                or not string_list(raw_agent.get("capabilities", ()))
                or not isinstance(raw_agent.get("permission_scope"), dict)
                or raw_agent.get("lifecycle") not in _AGENT_STATUSES
                or (raw_agent.get("parent_agent_id") is not None and self._safe_ref(raw_agent.get("parent_agent_id")) is None)
                or (raw_agent.get("parent_task_id") is not None and self._safe_ref(raw_agent.get("parent_task_id")) is None)
            ):
                raise MissionObservabilityError("mission_graph_integrity_invalid")
        for raw_task in tasks_raw:
            attempt_count = raw_task.get("attempt_count") if isinstance(raw_task, dict) else None
            if (
                not isinstance(raw_task, dict)
                or self._safe_ref(raw_task.get("task_id")) is None
                or raw_task.get("mission_id") != mission.mission_id
                or self._safe_ref(raw_task.get("assigned_agent_id")) is None
                or not isinstance(raw_task.get("objective"), str)
                or len(raw_task["objective"]) > 10_000
                or raw_task.get("lifecycle") not in _TASK_STATUSES
                or not string_list(raw_task.get("dependencies", ()))
                or not string_list(raw_task.get("constraints", ()))
                or not string_list(raw_task.get("artifacts", ()))
                or not string_list(raw_task.get("evidence_refs", ()))
                or isinstance(attempt_count, bool)
                or not isinstance(attempt_count, int)
                or not 0 <= attempt_count <= policy_raw["max_retries"] + 1
                or not isinstance(raw_task.get("cancel_requested"), bool)
                or not isinstance(raw_task.get("result_validation_state"), str)
                or not isinstance(raw_task.get("error", ""), str)
                or len(raw_task.get("error", "")) > 4_096
            ):
                raise MissionObservabilityError("mission_graph_integrity_invalid")
        try:
            policy_bounds = {
                "max_agents": self.MAX_AGENTS,
                "max_tasks": self.MAX_TASKS,
                "max_parallel_tasks": self.MAX_AGENTS,
                "max_retries": 8,
                "max_task_result_bytes": 65_536,
                "max_task_objective_chars": 10_000,
            }
            for name, ceiling in policy_bounds.items():
                value = policy_raw[name]
                minimum = 0 if name == "max_retries" else 1
                if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= ceiling:
                    raise MissionObservabilityError("mission_graph_integrity_invalid")
            graph = TaskGraph.from_dict(raw_graph)
            graph.validate()
        except MissionObservabilityError:
            raise
        except (KeyError, TypeError, ValueError, TaskGraphError) as exc:
            raise MissionObservabilityError("mission_graph_integrity_invalid") from exc
        if (
            graph.mission_id != mission.mission_id
            or graph.owner_identity_ref != owner_ref
            or graph.revision != revision
            or state.get("graph", {}).get("revision") != revision
        ):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        plan_fingerprint = state.get("plan_fingerprint")
        plan_version = state.get("plan_version")
        if (
            not isinstance(plan_fingerprint, str)
            or len(plan_fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in plan_fingerprint)
            or not isinstance(plan_version, int)
            or isinstance(plan_version, bool)
            or plan_version < 1
        ):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        if plan_fingerprint != mission.plan.fingerprint or plan_version != mission.plan.version:
            return {"available": False, "reason": "stale_plan", "revision": revision, "tasks": [], "agents": []}, {}

        mapping: dict[str, str] = {}
        for step_id, task_id in raw_mapping.items():
            safe_step = self._safe_ref(step_id)
            safe_task = self._safe_ref(task_id)
            if safe_step is None or safe_task is None or safe_task not in graph.tasks:
                raise MissionObservabilityError("mission_graph_integrity_invalid")
            mapping[safe_step] = safe_task
        if len(set(mapping.values())) != len(mapping):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        expected_steps = {
            safe_id
            for safe_id in (self._safe_ref(getattr(step, "step_id", "")) for step in mission.plan.steps)
            if safe_id is not None
        }
        if set(mapping) != expected_steps or set(mapping.values()) != set(graph.tasks):
            raise MissionObservabilityError("mission_graph_integrity_invalid")
        task_views: list[dict[str, Any]] = []
        agent_current_tasks: dict[str, list[str]] = {agent_id: [] for agent_id in graph.agents}
        for task_id in sorted(graph.tasks):
            task = graph.tasks[task_id]
            safe_task_id = self._safe_ref(task_id)
            safe_agent_id = self._safe_ref(task.assigned_agent_id)
            if safe_task_id is None or safe_agent_id is None or task.lifecycle.value not in _TASK_STATUSES:
                raise MissionObservabilityError("mission_graph_integrity_invalid")
            agent = graph.agents.get(task.assigned_agent_id)
            if agent is None or agent.lifecycle.value not in _AGENT_STATUSES:
                raise MissionObservabilityError("mission_graph_integrity_invalid")
            dependencies = [self._safe_ref(value) for value in task.dependencies]
            if any(value is None for value in dependencies):
                raise MissionObservabilityError("mission_graph_integrity_invalid")
            if task.lifecycle.value == "RUNNING":
                agent_current_tasks[safe_agent_id].append(safe_task_id)
            task_views.append({
                "task_id": safe_task_id,
                "status": task.lifecycle.value,
                "dependencies": dependencies,
                "agent_id": safe_agent_id,
                "agent_role": str(agent.role)[:64],
                "agent_status": agent.lifecycle.value,
                "attempt_count": task.attempt_count,
                "result_state": task.result_validation_state if task.result_validation_state in _RESULT_STATES else "UNKNOWN",
                "error_category": self._task_error_category(task),
                "evidence_refs": [],
            })
        agent_views = [{
            "agent_id": self._safe_ref(agent_id),
            "role": str(agent.role)[:64],
            "status": agent.lifecycle.value,
            "current_task_ids": sorted(agent_current_tasks[agent_id]),
        } for agent_id, agent in sorted(graph.agents.items())]
        return {"available": True, "reason": "", "revision": revision, "tasks": task_views, "agents": agent_views}, mapping

    def _evidence_projection(self, mission: Mission, step_to_task: dict[str, str]) -> list[dict[str, Any]]:
        raw = mission.progress.get("execution_evidence_refs", [])
        if not isinstance(raw, list):
            raise MissionObservabilityError("mission_evidence_refs_invalid")
        valid: list[dict[str, Any]] = []
        plan_step_ids = {
            safe_id
            for safe_id in (self._safe_ref(getattr(step, "step_id", "")) for step in mission.plan.steps)
            if safe_id is not None
        }
        allowed_tasks = set(step_to_task) | set(step_to_task.values()) | plan_step_ids
        for item in raw[-self.MAX_EVIDENCE_REFS:]:
            if not isinstance(item, dict):
                continue
            evidence_id = self._safe_ref(item.get("evidence_id"))
            task_ref = self._safe_ref(item.get("task_id"))
            sequence = item.get("sequence")
            if (
                evidence_id is None
                or task_ref is None
                or task_ref not in allowed_tasks
                or item.get("mission_id") != mission.mission_id
                or item.get("request_id") != mission.request_id
                or not isinstance(item.get("fence_id"), str)
                or not _SHA256_HEX.fullmatch(item["fence_id"])
                or not isinstance(item.get("current_hash"), str)
                or not _SHA256_HEX.fullmatch(item["current_hash"])
                or isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 1
            ):
                continue
            valid.append({
                "evidence_id": evidence_id,
                "sequence": sequence,
                "task_id": step_to_task.get(task_ref, task_ref),
                "reference_type": "execution_fenced_receipt",
            })
        return valid

    @staticmethod
    def _safe_evidence_count(mission: Mission) -> int:
        raw = mission.progress.get("execution_evidence_refs", [])
        return len(raw) if isinstance(raw, list) else 0

    def _trajectory_event(self, item: dict[str, Any], *, sequence: int) -> dict[str, Any]:
        event_type = item.get("event")
        if event_type not in _EVENT_TYPES:
            raise MissionObservabilityError("mission_timeline_integrity_invalid")
        step_ref = self._safe_ref(item.get("step_id"))
        category = None
        if event_type in {EventType.FAILURE_DETECTED.value, EventType.FAILURE_DIAGNOSED.value}:
            failure_class = item.get("data", {}).get("class") if isinstance(item.get("data"), dict) else None
            category = f"FAILURE_{failure_class}" if failure_class in _FAILURE_CLASSES else "MISSION_FAILURE"
        elif event_type == EventType.RECOVERY_REQUIRED.value:
            category = "RECOVERY_REQUIRED"
        return {
            "sequence": sequence,
            "type": event_type,
            "timestamp": str(item.get("timestamp", ""))[:64],
            "step_ref": step_ref,
            "error_category": category,
        }

    def _event_projection(self, mission: Mission, owner_ref: str, *, after_sequence: int, limit: int) -> dict[str, Any]:
        if self.event_store is None:
            return {"after_sequence": after_sequence, "limit": limit, "events": [], "next_after_sequence": None, "has_more": False}
        try:
            records = self.event_store.list(
                owner_identity_ref=owner_ref,
                mission_id=mission.mission_id,
                after_sequence=after_sequence,
                limit=limit + 1,
            )
        except EventIntegrityError as exc:
            raise MissionObservabilityError("mission_event_log_integrity_invalid") from exc
        except EventError as exc:
            raise ValueError("invalid_event_cursor") from exc
        has_more = len(records) > limit
        page = records[:limit]
        events = []
        for record in page:
            payload = dict(record.payload)
            tool_id = self._safe_tool(payload.get("tool_id"))
            risk_class = payload.get("risk_class")
            if risk_class not in {"read", "write", "network", "process", "unknown", None}:
                risk_class = None
            success = payload.get("success") if isinstance(payload.get("success"), bool) else None
            event_type = record.event_type.value
            if event_type not in {"MissionCreated", "TaskStarted", "TaskCompleted", "AgentStarted", "AgentCompleted", "ToolCalled", "EvidenceCreated", "FindingCreated", "SkillUsed", "SkillLearned", "ProviderChanged", "RuntimeStarted", "RuntimeStopped", "MissionPaused", "MissionResumed", "HookInvoked", "HookBlocked", "HookFailed"}:
                raise MissionObservabilityError("mission_event_log_integrity_invalid")
            events.append({
                "sequence": record.sequence,
                "type": event_type,
                "timestamp": str(record.created_at)[:64],
                "task_ref": self._safe_ref(record.task_id),
                "agent_ref": self._safe_ref(record.agent_id),
                "tool": tool_id,
                "risk_class": risk_class,
                "success": success,
            })
        next_sequence = events[-1]["sequence"] if events else None
        return {
            "after_sequence": after_sequence,
            "limit": limit,
            "events": events,
            "next_after_sequence": next_sequence if has_more else None,
            "has_more": has_more,
        }

    @staticmethod
    def _mission_error_category(mission: Mission) -> str | None:
        status = mission.status.value
        if status in {"AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "SAFETY_BLOCKED", "RESOURCE_BLOCKED", "RECOVERY_REQUIRED"}:
            return status
        if status == "FAILED_RETRY_EXHAUSTED":
            return "MISSION_FAILED"
        return None

    @staticmethod
    def _task_error_category(task: Any) -> str | None:
        if task.lifecycle.value == "FAILED":
            return "TASK_FAILED"
        if task.lifecycle.value == "BLOCKED":
            return "DEPENDENCY_BLOCKED" if task.error == "dependency_failed" else "TASK_BLOCKED"
        return None


__all__ = [
    "MissionObservabilityError",
    "MissionObservabilityService",
    "MissionObservabilityTooLarge",
]
