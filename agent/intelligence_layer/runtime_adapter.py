"""Mission-atomic TaskGraph adapter for canonical MissionRuntime dispatch.

The graph is scheduling state, not authority. It is serialized inside the Mission
record so each claim/completion is committed in the same MissionStore transaction
as the existing checkpoint and action history.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from security.mission_authorization import MissionAuthorizationSnapshot

from .graph import AgentGraphPolicy, TaskGraph, TaskGraphError
from .models import AgentLifecycle, AgentRecord, DelegationDenied, TaskLifecycle, TaskRecord


class MissionTaskGraphError(RuntimeError):
    """A graph could not safely authorize the next MissionRuntime dispatch."""


class MissionTaskGraphAdapter:
    STATE_SCHEMA_VERSION = 1

    def __init__(self, policy: AgentGraphPolicy | None = None):
        self.policy = policy or AgentGraphPolicy()

    @staticmethod
    def _fingerprint(value: Any) -> str:
        return hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _task_id(index: int, step_id: str) -> str:
        suffix = hashlib.sha256(step_id.encode("utf-8")).hexdigest()[:16]
        return f"{index:04d}:{suffix}"

    @staticmethod
    def _expected_authorization_version(mission: Any) -> int:
        provenance = getattr(mission, "provenance", {})
        value = provenance.get("authorization_snapshot_version", 1) if isinstance(provenance, dict) else None
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise MissionTaskGraphError("mission authorization version is invalid")
        return value

    def _build(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        authorization_version: int,
    ) -> tuple[TaskGraph, dict[str, str]]:
        graph = TaskGraph.create(
            snapshot,
            owner_identity_ref=mission.owner_identity_ref,
            policy=self.policy,
            authorization_version=authorization_version,
        )
        agent_id = "mission-coordinator-" + hashlib.sha256(mission.mission_id.encode("utf-8")).hexdigest()[:20]
        root = AgentRecord.create(
            mission_id=mission.mission_id,
            owner_identity_ref=mission.owner_identity_ref,
            role="mission_runtime_coordinator",
            capabilities=("canonical_tool_dispatch", "plan_step_scheduling"),
            permission_scope=graph.root_scope(snapshot, authorization_version=authorization_version),
            agent_id=agent_id,
        )
        graph.add_agent(root)
        graph.activate_agent(agent_id)
        root_scope = root.permission_scope
        step_ids = [step.step_id for step in mission.plan.steps]
        if len(set(step_ids)) != len(step_ids) or any(not str(step_id).strip() for step_id in step_ids):
            raise MissionTaskGraphError("mission plan has invalid or duplicate step identities")
        task_ids = {step.step_id: self._task_id(index, step.step_id) for index, step in enumerate(mission.plan.steps)}
        tasks = []
        for step in mission.plan.steps:
            tasks.append(TaskRecord.create(
                task_id=task_ids[step.step_id],
                mission_id=mission.mission_id,
                assigned_agent_id=agent_id,
                objective=step.objective,
                dependencies=tuple(task_ids[item] for item in step.prerequisites if item in task_ids),
                constraints=tuple(filter(None, (
                    f"step_id:{step.step_id}",
                    f"tool:{step.action}" if step.action else "",
                    f"authorization:{step.authorization_requirement}" if step.authorization_requirement else "",
                    f"scope:{step.scope_requirement}" if step.scope_requirement else "",
                ))),
            ))
            if any(item not in task_ids for item in step.prerequisites):
                raise MissionTaskGraphError("mission plan prerequisite refers to an unknown step")
        graph.add_tasks(tasks)
        # Each delegated worker is bound to exactly one task and one canonical
        # tool/action. Steps without a valid narrow grant, or beyond policy agent
        # capacity, stay assigned to the coordinator and therefore run serially.
        from tools.registry import get_tool

        for step in (mission.plan.steps if graph.policy.enable_task_delegation else ()):
            action = str(step.action or "").strip()
            if not action or action == "__planning_failure__" or len(graph.agents) >= graph.policy.max_agents:
                continue
            tool_spec = get_tool(action)
            if tool_spec is None or tool_spec.parallel_execution_safe is not True:
                continue
            if root_scope.allowed_tools and action not in root_scope.allowed_tools:
                continue
            if root_scope.allowed_actions and action not in root_scope.allowed_actions:
                continue
            if step.scope_requirement:
                if root_scope.scope and step.scope_requirement not in root_scope.scope:
                    continue
                child_scope_values = (step.scope_requirement,)
            else:
                child_scope_values = root_scope.scope or (f"task:{step.step_id}",)
            task_id = task_ids[step.step_id]
            child_scope = root_scope.narrow(
                target_identity=root_scope.target_identity,
                scope=child_scope_values,
                allowed_tools=(action,),
                allowed_actions=(action,),
                allowed_networks=(),
                allowed_credentials=(),
                workspace_root=None,
            )
            child_id = "mission-step-agent-" + hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:20]
            child = AgentRecord.create(
                mission_id=mission.mission_id,
                owner_identity_ref=mission.owner_identity_ref,
                role="mission_plan_step_executor",
                capabilities=("canonical_tool_dispatch",),
                permission_scope=child_scope,
                parent_agent_id=agent_id,
                parent_task_id=task_id,
                context_ref=f"mission:{mission.mission_id}:step:{step.step_id}",
                memory_scope=f"task:{step.step_id}",
                agent_id=child_id,
            )
            graph.add_agent(child)
            graph.activate_agent(child_id)
            graph.tasks[task_id].assigned_agent_id = child_id
        graph.refresh_ready_tasks()
        graph.validate()
        return graph, task_ids

    def _decode(self, mission: Any) -> tuple[TaskGraph, dict[str, str], str, int, int] | None:
        raw = getattr(mission, "agent_task_graph_state", None)
        if raw in (None, {}):
            return None
        if (
            not isinstance(raw, dict)
            or isinstance(raw.get("schema_version"), bool)
            or not isinstance(raw.get("schema_version"), int)
            or raw.get("schema_version") != self.STATE_SCHEMA_VERSION
        ):
            raise MissionTaskGraphError("persisted mission task graph envelope is invalid")
        try:
            plan_fingerprint = raw["plan_fingerprint"]
            plan_version_value = raw["plan_version"]
            revision_value = raw["revision"]
            graph_raw = raw["graph"]
            mapping_raw = raw["step_task_ids"]
            if (
                not isinstance(plan_fingerprint, str)
                or len(plan_fingerprint) != 64
                or any(char not in "0123456789abcdef" for char in plan_fingerprint)
                or isinstance(plan_version_value, bool)
                or not isinstance(plan_version_value, int)
                or isinstance(revision_value, bool)
                or not isinstance(revision_value, int)
                or not isinstance(graph_raw, dict)
                or not isinstance(mapping_raw, dict)
                or any(not isinstance(key, str) or not isinstance(value, str) or not key or not value for key, value in mapping_raw.items())
            ):
                raise MissionTaskGraphError("persisted mission task graph envelope values are invalid")
            plan_version = plan_version_value
            revision = revision_value
            graph = TaskGraph.from_dict(dict(graph_raw))
            mapping = dict(mapping_raw)
        except MissionTaskGraphError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionTaskGraphError("persisted mission task graph cannot be decoded") from exc
        if revision < 1 or graph.revision != revision:
            raise MissionTaskGraphError("persisted mission task graph revision mismatch")
        if plan_version < 1:
            raise MissionTaskGraphError("persisted mission task graph plan version is invalid")
        if plan_fingerprint == mission.plan.fingerprint and plan_version != mission.plan.version:
            raise MissionTaskGraphError("persisted mission task graph plan version mismatch")
        if graph.mission_id != mission.mission_id or graph.owner_identity_ref != mission.owner_identity_ref:
            raise MissionTaskGraphError("persisted mission task graph owner/mission mismatch")
        expected_steps = {step.step_id for step in mission.plan.steps}
        if len(mapping) != len(set(mapping.values())) or set(mapping.values()) != set(graph.tasks):
            raise MissionTaskGraphError("persisted graph task mapping is invalid")
        if plan_fingerprint == mission.plan.fingerprint and set(mapping) != expected_steps:
            raise MissionTaskGraphError("persisted graph task mapping does not match the mission plan")
        graph.validate()
        return graph, mapping, plan_fingerprint, revision, plan_version

    def _store(self, mission: Any, graph: TaskGraph, mapping: dict[str, str], plan_fingerprint: str, revision: int) -> None:
        next_revision = revision + 1
        graph.revision = next_revision
        mission.agent_task_graph_state = {
            "schema_version": self.STATE_SCHEMA_VERSION,
            "plan_fingerprint": plan_fingerprint,
            "plan_version": mission.plan.version,
            "revision": next_revision,
            "step_task_ids": dict(mapping),
            "graph": graph.to_dict(),
        }

    @staticmethod
    def _action_record(mission: Any, step_id: str) -> dict[str, Any] | None:
        prefix = f"{mission.mission_id}:{mission.plan.version}:{step_id}:"
        matches = [
            item for item in mission.action_history
            if isinstance(item, dict)
            and item.get("step_id") == step_id
            and str(item.get("action_id", "")).startswith(prefix)
            and item.get("status") in {"completed", "failed"}
        ]
        return matches[-1] if matches else None

    def _compact_result(self, *, step_id: str, result: Any, success: bool, action_id: str = "") -> dict[str, Any]:
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return {
            "step_id": step_id,
            "action_id": action_id,
            "success": bool(success),
            "result_sha256": hashlib.sha256(encoded).hexdigest(),
            "result_bytes": len(encoded),
        }

    def _complete(self, graph: TaskGraph, task_id: str, *, step_id: str, result: Any, action_id: str = "") -> None:
        graph.complete_task(
            task_id,
            self._compact_result(step_id=step_id, result=result, success=True, action_id=action_id),
        )
        agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
        if agent.parent_agent_id is not None and agent.lifecycle in {AgentLifecycle.READY, AgentLifecycle.RUNNING}:
            agent.transition(AgentLifecycle.COMPLETED)

    def _restore_completed_prefix(
        self,
        mission: Any,
        graph: TaskGraph,
        mapping: dict[str, str],
        *,
        authorization_version: int,
        from_index: int = 0,
    ) -> None:
        completed_indices = set(range(min(max(int(mission.current_step), 0), len(mission.plan.steps))))
        if mission.current_step < len(mission.plan.steps):
            current = mission.plan.steps[mission.current_step]
            record = self._action_record(mission, current.step_id)
            if record is not None and record.get("status") == "completed":
                completed_indices.add(mission.current_step)
        for index, step in enumerate(mission.plan.steps):
            if index < from_index or index not in completed_indices:
                continue
            task_id = mapping[step.step_id]
            task = graph.tasks[task_id]
            if task.lifecycle is TaskLifecycle.COMPLETED:
                continue
            if task.lifecycle is TaskLifecycle.FAILED:
                graph.retry_task(task_id)
                agent = graph.agents[task.assigned_agent_id]
                if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.WAITING:
                    agent.transition(AgentLifecycle.READY)
            graph.refresh_ready_tasks()
            if task_id not in graph.ready_task_ids():
                raise MissionTaskGraphError("mission cursor conflicts with task-graph dependencies")
            graph.claim_task(
                task_id,
                MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {})),
                authorization_version=authorization_version,
            )
            action_record = self._action_record(mission, step.step_id)
            result = action_record.get("observation", {}) if action_record else {"recovered_from_mission_cursor": True}
            action_id = str(action_record.get("action_id", "")) if action_record else ""
            self._complete(graph, task_id, step_id=step.step_id, result=result, action_id=action_id)

    def _reconcile_running(self, mission: Any, graph: TaskGraph, mapping: dict[str, str]) -> bool:
        changed = False
        for step in mission.plan.steps:
            task_id = mapping.get(step.step_id)
            if task_id is None or graph.tasks[task_id].lifecycle is not TaskLifecycle.RUNNING:
                continue
            record = self._action_record(mission, step.step_id)
            if record is None:
                raise MissionTaskGraphError("running graph task has no reconciled canonical action result")
            result = record.get("observation", {})
            if record.get("status") == "completed":
                self._complete(graph, task_id, step_id=step.step_id, result=result, action_id=str(record.get("action_id", "")))
            else:
                reason = str(result.get("error", "reconciled action failure")) if isinstance(result, dict) else "reconciled action failure"
                graph.fail_task(task_id, reason)
                agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
                if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.RUNNING:
                    agent.transition(AgentLifecycle.WAITING)
            changed = True
        return changed

    @staticmethod
    def _all_tasks_completed(graph: TaskGraph) -> None:
        root = next((item for item in graph.agents.values() if item.parent_agent_id is None), None)
        if root is not None and graph.tasks and all(item.lifecycle is TaskLifecycle.COMPLETED for item in graph.tasks.values()):
            if root.lifecycle.value in {"READY", "RUNNING"}:
                root.transition("COMPLETED")

    def _restore_prior_states(
        self,
        mission: Any,
        old_graph: TaskGraph,
        old_mapping: dict[str, str],
        graph: TaskGraph,
        mapping: dict[str, str],
        snapshot: MissionAuthorizationSnapshot,
        authorization_version: int,
    ) -> None:
        reverse_old = {step: task_id for step, task_id in old_mapping.items()}
        for index, step in enumerate(mission.plan.steps):
            old_id = reverse_old.get(step.step_id)
            if old_id is None:
                continue
            previous = old_graph.tasks[old_id]
            current = graph.tasks[mapping[step.step_id]]
            if previous.lifecycle is TaskLifecycle.RUNNING:
                raise MissionTaskGraphError("running graph task requires authenticated mission recovery before authorization rebinding")
            if previous.lifecycle not in {TaskLifecycle.COMPLETED, TaskLifecycle.FAILED}:
                continue
            if previous.attempt_count > self.policy.max_retries + 1:
                raise MissionTaskGraphError("persisted graph attempts exceed the current retry policy")
            graph.refresh_ready_tasks()
            if current.task_id not in graph.ready_task_ids():
                raise MissionTaskGraphError("persisted graph outcome conflicts with current dependencies")
            current.attempt_count = max(0, previous.attempt_count - 1)
            graph.claim_task(current.task_id, snapshot, authorization_version=authorization_version)
            if previous.lifecycle is TaskLifecycle.COMPLETED:
                graph.complete_task(current.task_id, previous.result, evidence_refs=previous.evidence_refs, artifacts=previous.artifacts)
            else:
                graph.fail_task(current.task_id, previous.error or "restored failed task state")
                graph.tasks[current.task_id].attempt_count = previous.attempt_count
                agent = graph.agents[current.assigned_agent_id]
                if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.RUNNING:
                    agent.transition(AgentLifecycle.WAITING)

    def ensure(self, mission: Any, snapshot: MissionAuthorizationSnapshot) -> TaskGraph:
        if not isinstance(snapshot, MissionAuthorizationSnapshot):
            raise TypeError("MissionTaskGraphAdapter requires a typed current authorization snapshot")
        try:
            if not mission.owner_identity_ref or mission.owner_identity_ref != snapshot.owner_identity:
                raise MissionTaskGraphError("mission Owner identity does not match current authorization")
            authorization_version = self._expected_authorization_version(mission)
            valid, reason = snapshot.validate_for_mission(
                mission_id=mission.mission_id,
                owner_identity=mission.owner_identity_ref,
                target_identity=snapshot.target_identity,
                version=authorization_version,
            )
            if not valid:
                raise MissionTaskGraphError(reason)
            prior = self._decode(mission)
            fingerprint = mission.plan.fingerprint
            if prior is not None:
                old_graph, old_mapping, old_fingerprint, old_revision, old_plan_version = prior
                if old_fingerprint == fingerprint and old_graph.authorization_hash == snapshot.authorization_hash and old_graph.policy == self.policy:
                    old_graph.validate_current_authorization(snapshot, authorization_version=authorization_version)
                    before = old_graph.to_dict()
                    self._reconcile_running(mission, old_graph, old_mapping)
                    self._restore_completed_prefix(
                        mission,
                        old_graph,
                        old_mapping,
                        authorization_version=authorization_version,
                    )
                    self._all_tasks_completed(old_graph)
                    if old_graph.to_dict() != before:
                        self._store(mission, old_graph, old_mapping, fingerprint, old_revision)
                    return old_graph

            graph, mapping = self._build(mission, snapshot, authorization_version)
            revision = prior[3] if prior is not None else 0
            same_plan = prior is not None and prior[2] == fingerprint
            if same_plan:
                old_graph, old_mapping, _old_fp, _old_revision, _old_plan_version = prior
                old_graph.validate()
                self._reconcile_running(mission, old_graph, old_mapping)
                self._restore_prior_states(
                    mission,
                    old_graph,
                    old_mapping,
                    graph,
                    mapping,
                    snapshot,
                    authorization_version,
                )
            else:
                if prior is not None and any(item.lifecycle is TaskLifecycle.RUNNING for item in prior[0].tasks.values()):
                    checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
                    authorized_no_effect = (
                        checkpoint.get("status") == "reconciled_no_effect"
                        and checkpoint.get("prior_plan_version") == prior[4]
                        and checkpoint.get("plan_version") == mission.plan.version
                    )
                    if not authorized_no_effect:
                        raise MissionTaskGraphError("plan changed while a graph task remained in flight")
                self._restore_completed_prefix(
                    mission,
                    graph,
                    mapping,
                    authorization_version=authorization_version,
                )
            self._all_tasks_completed(graph)
            self._store(mission, graph, mapping, fingerprint, revision)
            return graph
        except MissionTaskGraphError:
            raise
        except (DelegationDenied, TaskGraphError, KeyError, TypeError, ValueError) as exc:
            raise MissionTaskGraphError(f"mission task graph rejected: {type(exc).__name__}") from exc

    def ready_steps(self, mission: Any, snapshot: MissionAuthorizationSnapshot) -> tuple[dict[str, Any], ...]:
        """Return authorized graph-ready child tasks in stable plan order."""
        graph = self.ensure(mission, snapshot)
        state = mission.agent_task_graph_state
        mapping = dict(state["step_task_ids"])
        ready_ids = set(graph.ready_task_ids())
        entries: list[dict[str, Any]] = []
        for index, step in enumerate(mission.plan.steps):
            task_id = mapping.get(step.step_id)
            if task_id not in ready_ids:
                continue
            task = graph.tasks[task_id]
            agent = graph.agents[task.assigned_agent_id]
            if agent.parent_task_id != task_id or agent.role != "mission_plan_step_executor":
                continue
            agent.permission_scope.validate_current(
                snapshot,
                authorization_version=self._expected_authorization_version(mission),
            )
            entries.append({
                "index": index,
                "step": step,
                "task_id": task_id,
                "agent_id": agent.agent_id,
                "delegation_scope": agent.permission_scope,
            })
        return tuple(entries)

    def delegation_scope_for_step(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        step_id: str,
    ):
        graph = self.ensure(mission, snapshot)
        state = mission.agent_task_graph_state
        mapping = dict(state["step_task_ids"])
        task_id = mapping.get(step_id)
        if not task_id or task_id not in graph.tasks:
            raise MissionTaskGraphError("mission plan step has no graph task")
        agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
        if agent.parent_task_id != task_id or agent.role != "mission_plan_step_executor":
            return None
        agent.permission_scope.validate_current(
            snapshot,
            authorization_version=self._expected_authorization_version(mission),
        )
        return agent.permission_scope

    def claim_steps(self, mission: Any, snapshot: MissionAuthorizationSnapshot, step_ids: tuple[str, ...] | list[str]) -> TaskGraph:
        """Claim a ready batch and persist one graph revision before any dispatch."""
        ids = tuple(str(item) for item in step_ids)
        if not ids or len(set(ids)) != len(ids):
            raise MissionTaskGraphError("graph batch claim requires unique step identities")
        graph = self.ensure(mission, snapshot)
        state = mission.agent_task_graph_state
        mapping = dict(state["step_task_ids"])
        steps = {step.step_id: step for step in mission.plan.steps}
        if any(step_id not in steps for step_id in ids):
            raise MissionTaskGraphError("graph batch claim refers to an unknown plan step")
        for step_id in ids:
            task_id = mapping.get(step_id)
            if not task_id or task_id not in graph.tasks:
                raise MissionTaskGraphError("current plan step has no graph task")
            task = graph.tasks[task_id]
            if task.lifecycle is TaskLifecycle.FAILED:
                graph.retry_task(task_id)
                agent = graph.agents[task.assigned_agent_id]
                if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.WAITING:
                    agent.transition(AgentLifecycle.READY)
            graph.claim_task(
                task_id,
                snapshot,
                authorization_version=self._expected_authorization_version(mission),
            )
        self._store(mission, graph, mapping, str(state["plan_fingerprint"]), int(state["revision"]))
        return graph

    def claim_step(self, mission: Any, snapshot: MissionAuthorizationSnapshot, step_id: str) -> TaskGraph:
        return self.claim_steps(mission, snapshot, (step_id,))

    def complete_steps(self, mission: Any, outcomes: list[dict[str, Any]]) -> None:
        state = mission.agent_task_graph_state
        if not isinstance(state, dict) or not isinstance(outcomes, list) or not outcomes:
            raise MissionTaskGraphError("mission graph batch completion is malformed")
        graph = TaskGraph.from_dict(dict(state["graph"]))
        mapping = {str(key): str(value) for key, value in dict(state["step_task_ids"]).items()}
        seen: set[str] = set()
        for item in outcomes:
            if not isinstance(item, dict):
                raise MissionTaskGraphError("mission graph batch outcome is malformed")
            step_id = str(item.get("step_id", ""))
            if not step_id or step_id in seen:
                raise MissionTaskGraphError("mission graph batch has duplicate or missing step identity")
            seen.add(step_id)
            task_id = mapping.get(step_id)
            if task_id is None or graph.tasks[task_id].lifecycle is not TaskLifecycle.RUNNING:
                raise MissionTaskGraphError("only claimed graph tasks can complete a batch")
            if item.get("success") is True:
                self._complete(
                    graph,
                    task_id,
                    step_id=step_id,
                    result=item.get("result", {}),
                    action_id=str(item.get("action_id", "")),
                )
            elif item.get("success") is False:
                graph.fail_task(task_id, str(item.get("error", "mission step failed")))
                agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
                if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.RUNNING:
                    agent.transition(AgentLifecycle.WAITING)
            else:
                raise MissionTaskGraphError("mission graph batch outcome has no boolean success value")
        self._all_tasks_completed(graph)
        self._store(mission, graph, mapping, str(state["plan_fingerprint"]), int(state["revision"]))

    def complete_step(self, mission: Any, step_id: str, result: Any, action_id: str) -> None:
        state = mission.agent_task_graph_state
        if not isinstance(state, dict):
            raise MissionTaskGraphError("mission task graph is missing during completion")
        graph = TaskGraph.from_dict(dict(state["graph"]))
        mapping = {str(key): str(value) for key, value in dict(state["step_task_ids"]).items()}
        task_id = mapping.get(step_id)
        if task_id is None or graph.tasks[task_id].lifecycle is not TaskLifecycle.RUNNING:
            raise MissionTaskGraphError("only the currently claimed graph task can complete")
        self.complete_steps(mission, [{"step_id": step_id, "result": result, "success": True, "action_id": action_id}])

    def fail_step(self, mission: Any, step_id: str, reason: str) -> None:
        state = mission.agent_task_graph_state
        if not isinstance(state, dict):
            raise MissionTaskGraphError("mission task graph is missing during failure recording")
        graph = TaskGraph.from_dict(dict(state["graph"]))
        mapping = {str(key): str(value) for key, value in dict(state["step_task_ids"]).items()}
        task_id = mapping.get(step_id)
        if task_id is None or graph.tasks[task_id].lifecycle is not TaskLifecycle.RUNNING:
            raise MissionTaskGraphError("only the currently claimed graph task can fail")
        graph.fail_task(task_id, reason)
        agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
        if agent.parent_agent_id is not None and agent.lifecycle is AgentLifecycle.RUNNING:
            agent.transition(AgentLifecycle.WAITING)
        self._store(mission, graph, mapping, str(state["plan_fingerprint"]), int(state["revision"]))

    def cancel(self, mission: Any) -> None:
        state = getattr(mission, "agent_task_graph_state", None)
        if not isinstance(state, dict) or not state:
            return
        try:
            graph = TaskGraph.from_dict(dict(state["graph"]))
            mapping = {str(key): str(value) for key, value in dict(state["step_task_ids"]).items()}
            if (
                graph.mission_id != mission.mission_id
                or graph.owner_identity_ref != mission.owner_identity_ref
                or graph.revision != int(state["revision"])
            ):
                raise MissionTaskGraphError("mission graph cancellation identity or revision mismatch")
            for task_id in sorted(graph.tasks):
                graph.cancel_task(task_id, propagate=False)
                task = graph.tasks[task_id]
                agent = graph.agents[task.assigned_agent_id]
                if (
                    task.lifecycle is TaskLifecycle.CANCELLED
                    and agent.parent_agent_id is not None
                    and agent.lifecycle in {AgentLifecycle.CREATED, AgentLifecycle.READY, AgentLifecycle.RUNNING, AgentLifecycle.WAITING, AgentLifecycle.BLOCKED}
                ):
                    agent.transition(AgentLifecycle.CANCELLED)
            root = next((item for item in graph.agents.values() if item.parent_agent_id is None), None)
            if root is not None and not any(item.lifecycle is TaskLifecycle.RUNNING for item in graph.tasks.values()):
                if root.lifecycle.value in {"CREATED", "READY", "RUNNING", "WAITING", "BLOCKED"}:
                    root.transition("CANCELLED")
            self._store(mission, graph, mapping, str(state["plan_fingerprint"]), int(state["revision"]))
        except (KeyError, TypeError, ValueError, TaskGraphError) as exc:
            raise MissionTaskGraphError("mission graph cancellation could not be persisted safely") from exc


__all__ = ["MissionTaskGraphAdapter", "MissionTaskGraphError"]
