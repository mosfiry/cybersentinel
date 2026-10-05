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
        previous = getattr(mission, "agent_task_graph_state", {})
        specialist_state = None
        if isinstance(previous, dict) and previous.get("plan_fingerprint") == plan_fingerprint:
            specialist_state = previous.get("specialist_graph")
        mission.agent_task_graph_state = {
            "schema_version": self.STATE_SCHEMA_VERSION,
            "plan_fingerprint": plan_fingerprint,
            "plan_version": mission.plan.version,
            "revision": next_revision,
            "step_task_ids": dict(mapping),
            "graph": graph.to_dict(),
        }
        if specialist_state is not None:
            # The analytic subgraph is separately revisioned and authorization
            # checked; ordinary tool-task checkpoints must not erase its claims.
            mission.agent_task_graph_state["specialist_graph"] = specialist_state

    @staticmethod
    def _specialist_task_id(step_id: str) -> str:
        digest = hashlib.sha256(step_id.encode("utf-8")).hexdigest()[:24]
        return f"specialist:{digest}"

    def _build_specialist_graph(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        authorization_version: int,
    ) -> tuple[TaskGraph, dict[str, str]] | None:
        """Build a separate analytic DAG; its child grants contain no tools."""
        from .models import DelegationScope

        max_children = min(15, self.policy.max_agents - 1, self.policy.max_tasks)
        if max_children < 2 or self.policy.max_parallel_tasks < 2:
            return None
        selected: list[Any] = []
        selected_ids: set[str] = set()
        for step in mission.plan.steps:
            step_id = str(step.step_id)
            if not step_id or len(str(step.objective)) > min(2000, self.policy.max_task_objective_chars):
                continue
            prerequisites = tuple(str(item) for item in step.prerequisites)
            if any(item not in selected_ids for item in prerequisites):
                continue
            selected.append(step)
            selected_ids.add(step_id)
            if len(selected) >= max_children:
                break
        if len(selected) < 2:
            return None

        mapping = {str(step.step_id): self._specialist_task_id(str(step.step_id)) for step in selected}
        child_count = len(selected)
        policy = AgentGraphPolicy(
            max_agents=child_count + 1,
            max_tasks=child_count,
            max_parallel_tasks=min(2, self.policy.max_parallel_tasks, child_count),
            max_retries=0,
            max_task_result_bytes=min(8192, self.policy.max_task_result_bytes),
            max_task_objective_chars=min(2000, self.policy.max_task_objective_chars),
            enable_task_delegation=False,
        )
        graph = TaskGraph.create(
            snapshot,
            owner_identity_ref=mission.owner_identity_ref,
            policy=policy,
            authorization_version=authorization_version,
        )
        coordinator_id = "specialist-coordinator-" + hashlib.sha256(mission.mission_id.encode("utf-8")).hexdigest()[:20]
        coordinator = AgentRecord.create(
            mission_id=mission.mission_id,
            owner_identity_ref=mission.owner_identity_ref,
            role="mission_specialist_coordinator",
            capabilities=("bounded_analytic_task_management",),
            permission_scope=graph.root_scope(snapshot, authorization_version=authorization_version),
            agent_id=coordinator_id,
        )
        graph.add_agent(coordinator)
        graph.activate_agent(coordinator_id)
        tasks: list[TaskRecord] = []
        by_step = {str(step.step_id): step for step in selected}
        for step in selected:
            step_id = str(step.step_id)
            task_id = mapping[step_id]
            parent_scope = coordinator.permission_scope
            child_scope = DelegationScope(
                owner_identity_ref=parent_scope.owner_identity_ref,
                mission_id=parent_scope.mission_id,
                target_identity=parent_scope.target_identity,
                root_authorization_hash=parent_scope.root_authorization_hash,
                parent_grant_hash=parent_scope.fingerprint,
                scope=(),
                allowed_tools=(),
                allowed_actions=(),
                allowed_networks=(),
                allowed_credentials=(),
                workspace_root="",
            )
            child_id = "specialist-agent-" + hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:20]
            child = AgentRecord.create(
                mission_id=mission.mission_id,
                owner_identity_ref=mission.owner_identity_ref,
                role="mission_specialist_analyst",
                capabilities=("untrusted_analysis_only", "no_tools", "no_evidence", "no_owner_authority"),
                permission_scope=child_scope,
                parent_agent_id=coordinator_id,
                parent_task_id=task_id,
                context_ref=f"mission:{mission.mission_id}:specialist:{step_id}",
                memory_scope=f"task:{step_id}",
                agent_id=child_id,
            )
            graph.add_agent(child)
            graph.activate_agent(child_id)
            dependencies = tuple(
                mapping[item] for item in step.prerequisites if item in mapping and item in by_step
            )
            tasks.append(TaskRecord.create(
                task_id=task_id,
                mission_id=mission.mission_id,
                assigned_agent_id=child_id,
                objective=str(step.objective),
                dependencies=dependencies,
                constraints=("analytic_proposal_only", "no_tool_dispatch", "no_evidence_creation"),
            ))
        graph.add_tasks(tasks)
        graph.refresh_ready_tasks()
        graph.validate()
        return graph, mapping

    def _specialist_envelope(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
    ) -> tuple[TaskGraph, dict[str, str], dict[str, Any]] | None:
        if not isinstance(mission.agent_task_graph_state, dict):
            raise MissionTaskGraphError("mission plan task graph is unavailable")
        state = mission.agent_task_graph_state
        raw = state.get("specialist_graph")
        if raw is None:
            version = self._expected_authorization_version(mission)
            built = self._build_specialist_graph(mission, snapshot, version)
            if built is None:
                return None
            graph, mapping = built
            graph.revision = 1
            raw = {
                "schema_version": 1,
                "plan_fingerprint": mission.plan.fingerprint,
                "plan_version": mission.plan.version,
                "revision": 1,
                "authorization_hash": snapshot.authorization_hash,
                "step_task_ids": mapping,
                "graph": graph.to_dict(),
            }
            state["specialist_graph"] = raw
            return graph, mapping, raw
        try:
            if (
                not isinstance(raw, dict)
                or raw.get("schema_version") != 1
                or raw.get("plan_fingerprint") != mission.plan.fingerprint
                or isinstance(raw.get("plan_version"), bool)
                or raw.get("plan_version") != mission.plan.version
                or isinstance(raw.get("revision"), bool)
                or not isinstance(raw.get("revision"), int)
                or raw.get("revision") < 1
                or not isinstance(raw.get("graph"), dict)
                or not isinstance(raw.get("step_task_ids"), dict)
                or not isinstance(raw.get("authorization_hash"), str)
            ):
                raise MissionTaskGraphError("specialist graph envelope is invalid")
            graph = TaskGraph.from_dict(dict(raw["graph"]))
            mapping = {str(key): str(value) for key, value in dict(raw["step_task_ids"]).items()}
            if graph.revision != raw["revision"] or graph.mission_id != mission.mission_id or graph.owner_identity_ref != mission.owner_identity_ref:
                raise MissionTaskGraphError("specialist graph identity or revision mismatch")
            if len(mapping) != len(set(mapping.values())) or set(mapping.values()) != set(graph.tasks):
                raise MissionTaskGraphError("specialist task mapping is invalid")
            if not set(mapping).issubset({str(step.step_id) for step in mission.plan.steps}):
                raise MissionTaskGraphError("specialist mapping is not bound to the Mission plan")
            if raw["authorization_hash"] != snapshot.authorization_hash:
                # Existing proposals/claims remain historical and untrusted, but
                # are never rebound or replayed under a renewed Owner snapshot.
                return None
            graph.validate_current_authorization(
                snapshot,
                authorization_version=self._expected_authorization_version(mission),
            )
            steps = {str(step.step_id): step for step in mission.plan.steps}
            agents = graph.agents
            for step_id, task_id in mapping.items():
                task = graph.tasks[task_id]
                step = steps[step_id]
                agent = agents[task.assigned_agent_id]
                scope = agent.permission_scope
                scope.validate_current(snapshot, authorization_version=self._expected_authorization_version(mission))
                if (
                    agent.role != "mission_specialist_analyst"
                    or task.objective != str(step.objective)
                    or scope.allowed_tools
                    or scope.allowed_actions
                    or scope.allowed_networks
                    or scope.allowed_credentials
                    or scope.workspace_root
                    or scope.scope
                ):
                    raise MissionTaskGraphError("specialist child authority or task context is not tool-less")
            return graph, mapping, raw
        except MissionTaskGraphError:
            raise
        except (KeyError, TypeError, ValueError, PermissionError, TaskGraphError) as exc:
            raise MissionTaskGraphError("specialist graph cannot be decoded safely") from exc

    def ready_specialist_steps(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
    ) -> tuple[tuple[str, str], ...]:
        """Return analytic tasks that are also ready in the canonical plan graph."""
        main_graph = self.ensure(mission, snapshot)
        main_state = mission.agent_task_graph_state
        main_mapping = dict(main_state["step_task_ids"])
        main_ready = set(main_graph.ready_task_ids())
        nested = self._specialist_envelope(mission, snapshot)
        if nested is None:
            return ()
        graph, mapping, _raw = nested
        graph.refresh_ready_tasks()
        specialist_ready = set(graph.ready_task_ids())
        result = []
        for step in mission.plan.steps:
            step_id = str(step.step_id)
            specialist_id = mapping.get(step_id)
            main_id = main_mapping.get(step_id)
            if specialist_id in specialist_ready and main_id in main_ready:
                result.append((step_id, specialist_id))
        return tuple(result[: min(2, self.policy.max_parallel_tasks)])

    def claim_specialist_batch(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        step_ids: tuple[str, ...],
        *,
        batch_id: str,
        provider_name: str,
        model_name: str,
        execution_ids: tuple[str, ...],
    ) -> dict[str, str]:
        if not step_ids or len(step_ids) < 2 or len(step_ids) > min(2, self.policy.max_parallel_tasks):
            raise MissionTaskGraphError("specialist batch size is outside its concurrency bound")
        if len(set(step_ids)) != len(step_ids) or len(execution_ids) != len(step_ids):
            raise MissionTaskGraphError("specialist batch identities are invalid")
        main_graph = self.ensure(mission, snapshot)
        main_mapping = dict(mission.agent_task_graph_state["step_task_ids"])
        main_ready = set(main_graph.ready_task_ids())
        nested = self._specialist_envelope(mission, snapshot)
        if nested is None:
            raise MissionTaskGraphError("current authorization does not permit a specialist batch")
        graph, mapping, envelope = nested
        if envelope.get("active_batch"):
            raise MissionTaskGraphError("previous specialist batch requires recovery")
        graph.refresh_ready_tasks()
        running_map: dict[str, str] = {}
        for step_id in step_ids:
            task_id = mapping.get(step_id)
            if task_id is None or task_id not in graph.ready_task_ids() or main_mapping.get(step_id) not in main_ready:
                raise MissionTaskGraphError("specialist task is not independently dependency-ready")
            agent = graph.agents[graph.tasks[task_id].assigned_agent_id]
            if agent.permission_scope.allowed_tools or agent.permission_scope.allowed_actions or agent.permission_scope.allowed_credentials or agent.permission_scope.allowed_networks or agent.permission_scope.workspace_root:
                raise MissionTaskGraphError("specialist task has non-analytic authority")
            graph.claim_task(task_id, snapshot, authorization_version=self._expected_authorization_version(mission))
            running_map[step_id] = task_id
        envelope["active_batch"] = {
            "batch_id": batch_id,
            "step_ids": list(step_ids),
            "task_ids": [running_map[item] for item in step_ids],
            "execution_ids": list(execution_ids),
            "task_execution_bindings": [
                {"task_id": running_map[step_id], "execution_id": execution_id}
                for step_id, execution_id in zip(step_ids, execution_ids)
            ],
            "provider_name": provider_name,
            "model_name": model_name,
        }
        self._store_specialist_graph(mission, graph, mapping, envelope)
        return running_map

    def _store_specialist_graph(
        self,
        mission: Any,
        graph: TaskGraph,
        mapping: dict[str, str],
        envelope: dict[str, Any],
    ) -> None:
        if not isinstance(mission.agent_task_graph_state, dict):
            raise MissionTaskGraphError("main task graph disappeared during specialist checkpoint")
        revision = int(envelope.get("revision", 0)) + 1
        graph.revision = revision
        envelope.update({
            "schema_version": 1,
            "plan_fingerprint": mission.plan.fingerprint,
            "plan_version": mission.plan.version,
            "revision": revision,
            "authorization_hash": graph.authorization_hash,
            "step_task_ids": dict(mapping),
            "graph": graph.to_dict(),
        })
        mission.agent_task_graph_state["specialist_graph"] = envelope

    def finish_specialist_batch(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        *,
        batch_id: str,
        outcomes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        nested = self._specialist_envelope(mission, snapshot)
        if nested is None:
            raise MissionTaskGraphError("specialist authorization changed during provider batch")
        graph, mapping, envelope = nested
        active = envelope.get("active_batch")
        if not isinstance(active, dict) or active.get("batch_id") != batch_id:
            raise MissionTaskGraphError("specialist batch claim changed before completion")
        expected = {str(item) for item in active.get("task_ids", ())}
        observed: set[str] = set()
        proposals: list[dict[str, Any]] = []
        for outcome in outcomes:
            task_id = str(outcome.get("task_id", ""))
            if task_id not in expected or task_id in observed or graph.tasks[task_id].lifecycle is not TaskLifecycle.RUNNING:
                raise MissionTaskGraphError("specialist outcome does not match a running child claim")
            observed.add(task_id)
            task = graph.tasks[task_id]
            agent = graph.agents[task.assigned_agent_id]
            if task.cancel_requested:
                task.transition(TaskLifecycle.CANCELLED)
                task.result_validation_state = "CANCELLED_RESULT_DISCARDED"
                if agent.lifecycle in {AgentLifecycle.RUNNING, AgentLifecycle.READY, AgentLifecycle.WAITING}:
                    agent.transition(AgentLifecycle.CANCELLED)
                continue
            if outcome.get("success") is True:
                proposal = dict(outcome["proposal"])
                result = {
                    "record_type": "UNTRUSTED_SPECIALIST_PROPOSAL",
                    "authority": "none",
                    "provider": str(outcome["provider_name"]),
                    "model": str(outcome["model_name"]),
                    "proposal": proposal,
                }
                graph.complete_task(task_id, result, evidence_refs=(), artifacts=())
                task.result_validation_state = "UNTRUSTED_PROPOSAL"
                if agent.lifecycle is AgentLifecycle.RUNNING:
                    agent.transition(AgentLifecycle.COMPLETED)
                proposals.append({"step_id": str(outcome["step_id"]), "task_id": task_id, **result})
            else:
                failure_code = str(outcome.get("failure_code", "provider_failure"))[:64]
                graph.fail_task(task_id, failure_code, propagate=True)
                task.result = {
                    "record_type": "SPECIALIST_PROVIDER_FAILURE",
                    "authority": "none",
                    "provider": str(outcome.get("provider_name", ""))[:80],
                    "model": str(outcome.get("model_name", ""))[:120],
                    "failure_code": failure_code,
                }
                task.result_validation_state = str(outcome.get("validation_state", "PROVIDER_UNAVAILABLE"))[:64]
                if agent.lifecycle in {AgentLifecycle.RUNNING, AgentLifecycle.READY}:
                    agent.transition(AgentLifecycle.FAILED)
                for dependent in graph.tasks.values():
                    if dependent.lifecycle is TaskLifecycle.BLOCKED and dependent.error == "dependency_failed":
                        child = graph.agents[dependent.assigned_agent_id]
                        if child.lifecycle in {AgentLifecycle.READY, AgentLifecycle.RUNNING, AgentLifecycle.WAITING}:
                            child.transition(AgentLifecycle.BLOCKED)
        if observed != expected:
            raise MissionTaskGraphError("specialist batch omitted one or more child outcomes")
        envelope["active_batch"] = None
        envelope["last_batch"] = {
            "batch_id": batch_id,
            "provider_name": str(active.get("provider_name", ""))[:80],
            "model_name": str(active.get("model_name", ""))[:120],
            "task_ids": sorted(expected),
            "outcome_count": len(outcomes),
        }
        self._store_specialist_graph(mission, graph, mapping, envelope)
        return proposals

    def quarantine_specialist_batch(
        self,
        mission: Any,
        snapshot: MissionAuthorizationSnapshot,
        *,
        batch_id: str,
    ) -> None:
        state = getattr(mission, "agent_task_graph_state", None)
        raw = state.get("specialist_graph") if isinstance(state, dict) else None
        try:
            if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("graph"), dict):
                raise MissionTaskGraphError("specialist recovery graph envelope is invalid")
            graph = TaskGraph.from_dict(dict(raw["graph"]))
            mapping = {str(key): str(value) for key, value in dict(raw.get("step_task_ids", {})).items()}
            if (
                graph.mission_id != mission.mission_id
                or graph.owner_identity_ref != mission.owner_identity_ref
                or graph.revision != raw.get("revision")
                or set(mapping.values()) != set(graph.tasks)
            ):
                raise MissionTaskGraphError("specialist recovery graph identity or revision mismatch")
            envelope = raw
        except MissionTaskGraphError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionTaskGraphError("specialist recovery graph cannot be decoded") from exc
        active = envelope.get("active_batch")
        if not isinstance(active, dict) or active.get("batch_id") != batch_id:
            raise MissionTaskGraphError("specialist recovery does not match the persisted batch claim")
        checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
        if (
            checkpoint.get("status") != "in_flight_specialists"
            or checkpoint.get("batch_id") != batch_id
            or list(checkpoint.get("task_ids", ())) != list(active.get("task_ids", ()))
            or list(checkpoint.get("execution_ids", ())) != list(active.get("execution_ids", ()))
            or list(checkpoint.get("task_execution_bindings", ())) != list(active.get("task_execution_bindings", ()))
        ):
            raise MissionTaskGraphError("specialist recovery checkpoint is not bound to the durable child claims")
        task_ids = {str(item) for item in active.get("task_ids", ())}
        for task_id in task_ids:
            task = graph.tasks.get(task_id)
            if task is None or task.lifecycle is not TaskLifecycle.RUNNING:
                continue
            agent = graph.agents[task.assigned_agent_id]
            if task.cancel_requested:
                task.transition(TaskLifecycle.CANCELLED)
                task.result_validation_state = "CANCELLED_RESULT_QUARANTINED"
                if agent.lifecycle in {AgentLifecycle.RUNNING, AgentLifecycle.READY}:
                    agent.transition(AgentLifecycle.CANCELLED)
            else:
                task.error = "provider_outcome_unknown"
                task.result = {
                    "record_type": "SPECIALIST_RESULT_QUARANTINED",
                    "authority": "none",
                    "provider": str(active.get("provider_name", ""))[:80],
                    "model": str(active.get("model_name", ""))[:120],
                }
                task.transition(TaskLifecycle.FAILED)
                task.result_validation_state = "QUARANTINED_PROVIDER_OUTCOME_UNKNOWN"
                if agent.lifecycle in {AgentLifecycle.RUNNING, AgentLifecycle.READY}:
                    agent.transition(AgentLifecycle.FAILED)
        envelope["active_batch"] = None
        envelope["last_batch"] = {
            "batch_id": batch_id,
            "provider_name": str(active.get("provider_name", ""))[:80],
            "model_name": str(active.get("model_name", ""))[:120],
            "task_ids": sorted(task_ids),
            "outcome_count": 0,
            "status": "quarantined_unknown_no_replay",
        }
        self._store_specialist_graph(mission, graph, mapping, envelope)

    def abort_specialist_batch_before_dispatch(
        self,
        mission: Any,
        *,
        batch_id: str,
        failure_code: str,
    ) -> None:
        """Fail claimed children when pre-call authorization revalidation denies dispatch."""
        state = getattr(mission, "agent_task_graph_state", None)
        raw = state.get("specialist_graph") if isinstance(state, dict) else None
        try:
            if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("graph"), dict):
                raise MissionTaskGraphError("specialist pre-dispatch graph envelope is invalid")
            graph = TaskGraph.from_dict(dict(raw["graph"]))
            mapping = {str(key): str(value) for key, value in dict(raw.get("step_task_ids", {})).items()}
            if (
                graph.mission_id != mission.mission_id
                or graph.owner_identity_ref != mission.owner_identity_ref
                or graph.revision != raw.get("revision")
                or set(mapping.values()) != set(graph.tasks)
            ):
                raise MissionTaskGraphError("specialist pre-dispatch graph identity or revision mismatch")
        except MissionTaskGraphError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise MissionTaskGraphError("specialist pre-dispatch graph cannot be decoded") from exc
        active = raw.get("active_batch")
        checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
        if (
            not isinstance(active, dict)
            or active.get("batch_id") != batch_id
            or checkpoint.get("status") != "in_flight_specialists"
            or checkpoint.get("batch_id") != batch_id
            or list(checkpoint.get("task_ids", ())) != list(active.get("task_ids", ()))
            or list(checkpoint.get("execution_ids", ())) != list(active.get("execution_ids", ()))
            or list(checkpoint.get("task_execution_bindings", ())) != list(active.get("task_execution_bindings", ()))
        ):
            raise MissionTaskGraphError("specialist pre-dispatch abort does not match the durable child claim")
        task_ids = {str(item) for item in active.get("task_ids", ())}
        for task_id in task_ids:
            task = graph.tasks.get(task_id)
            if task is None or task.lifecycle is not TaskLifecycle.RUNNING:
                raise MissionTaskGraphError("specialist pre-dispatch child is not running")
            graph.fail_task(task_id, "authorization_blocked_before_provider_call", propagate=True)
            task.result = {
                "record_type": "SPECIALIST_DISPATCH_ABORTED",
                "authority": "none",
                "failure_code": str(failure_code)[:64],
            }
            task.result_validation_state = "AUTHORIZATION_BLOCKED"
            agent = graph.agents[task.assigned_agent_id]
            if agent.lifecycle in {AgentLifecycle.RUNNING, AgentLifecycle.READY}:
                agent.transition(AgentLifecycle.FAILED)
        raw["active_batch"] = None
        raw["last_batch"] = {
            "batch_id": batch_id,
            "task_ids": sorted(task_ids),
            "outcome_count": 0,
            "status": "aborted_before_provider_dispatch",
        }
        self._store_specialist_graph(mission, graph, mapping, raw)
        mission.checkpoint = {"status": "specialists_aborted", "batch_id": batch_id, "task_ids": sorted(task_ids)}

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
            specialist = mission.agent_task_graph_state.get("specialist_graph")
            if isinstance(specialist, dict) and isinstance(specialist.get("graph"), dict):
                specialist_graph = TaskGraph.from_dict(dict(specialist["graph"]))
                specialist_mapping = {str(key): str(value) for key, value in dict(specialist.get("step_task_ids", {})).items()}
                if (
                    specialist_graph.mission_id != mission.mission_id
                    or specialist_graph.owner_identity_ref != mission.owner_identity_ref
                    or specialist_graph.revision != int(specialist.get("revision", -1))
                    or set(specialist_mapping.values()) != set(specialist_graph.tasks)
                ):
                    raise MissionTaskGraphError("specialist graph cancellation identity or revision mismatch")
                for task_id in sorted(specialist_graph.tasks):
                    specialist_graph.cancel_task(task_id, propagate=False)
                    task = specialist_graph.tasks[task_id]
                    agent = specialist_graph.agents[task.assigned_agent_id]
                    if task.lifecycle is TaskLifecycle.CANCELLED and agent.lifecycle in {
                        AgentLifecycle.CREATED, AgentLifecycle.READY, AgentLifecycle.WAITING,
                        AgentLifecycle.BLOCKED,
                    }:
                        agent.transition(AgentLifecycle.CANCELLED)
                self._store_specialist_graph(mission, specialist_graph, specialist_mapping, specialist)
        except (KeyError, TypeError, ValueError, TaskGraphError) as exc:
            raise MissionTaskGraphError("mission graph cancellation could not be persisted safely") from exc


__all__ = ["MissionTaskGraphAdapter", "MissionTaskGraphError"]
