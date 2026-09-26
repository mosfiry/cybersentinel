from __future__ import annotations

"""Deterministic DAG scheduling primitives for the durable MissionRuntime.

A plan is a proposal, never authority. The runtime must revalidate the current
mission authorization and scope immediately before dispatching every node.
"""

from dataclasses import dataclass
from functools import cached_property
from enum import Enum
import hashlib
import heapq
import json
import time
from collections import deque
from typing import Any, Iterable


class GraphValidationError(ValueError):
    """The proposed execution graph is not a valid DAG."""


class NodeState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY_WAIT = "retry_wait"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    step_id: str
    dependencies: tuple[str, ...]
    priority: int = 0
    resources_read: tuple[str, ...] = ()
    resources_write: tuple[str, ...] = ()
    idempotent: bool = False
    retry_limit: int = 0
    retryable_failure_classes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "step_id": self.step_id,
            "dependencies": list(self.dependencies),
            "priority": self.priority,
            "resources_read": list(self.resources_read),
            "resources_write": list(self.resources_write),
            "idempotent": self.idempotent,
            "retry_limit": self.retry_limit,
            "retryable_failure_classes": list(self.retryable_failure_classes),
        }


@dataclass(frozen=True)
class ExecutionGraph:
    mission_id: str
    execution_run_id: str
    plan_hash: str
    policy_hash: str
    nodes: tuple[ExecutionNode, ...]
    depth_by_step: dict[str, int]

    @classmethod
    def from_plan(cls, mission_id: str, execution_run_id: str, plan: Any, *, retry_policy_by_step: dict[str, dict[str, Any]] | None = None, resource_policy_by_step: dict[str, dict[str, Any]] | None = None) -> "ExecutionGraph":
        if not mission_id or not execution_run_id:
            raise GraphValidationError("mission_id and execution_run_id are required")
        steps = tuple(plan.steps)
        if not steps:
            raise GraphValidationError("execution graph must contain at least one node")
        step_ids = [str(step.step_id) for step in steps]
        if any(not item for item in step_ids):
            raise GraphValidationError("step_id must not be empty")
        if len(step_ids) != len(set(step_ids)):
            raise GraphValidationError("duplicate node identity")
        known = set(step_ids)
        nodes: list[ExecutionNode] = []
        dependencies_by_step: dict[str, tuple[str, ...]] = {}
        for step in steps:
            step_id = str(step.step_id)
            dependencies = tuple(str(item) for item in step.prerequisites)
            if len(dependencies) != len(set(dependencies)):
                raise GraphValidationError(f"duplicate dependency for {step_id}")
            if step_id in dependencies:
                raise GraphValidationError(f"self-cycle at {step_id}")
            missing = sorted(set(dependencies) - known)
            if missing:
                raise GraphValidationError(f"missing dependency for {step_id}: {', '.join(missing)}")
            dependencies_by_step[step_id] = dependencies
            identity = hashlib.sha256(f"{mission_id}\0{execution_run_id}\0{step_id}".encode()).hexdigest()
            # Plan metadata is a proposal. Retry/idempotency and resource claims
            # come only from deterministic runtime policy passed by the caller.
            retry_policy = dict((retry_policy_by_step or {}).get(step_id, {}))
            resource_policy = dict((resource_policy_by_step or {}).get(step_id, {}))
            retry_limit = int(retry_policy.get("max_retries", 0))
            priority = int(getattr(step, "priority", 0))
            if not 0 <= retry_limit <= 10:
                raise GraphValidationError("runtime retry limit must be between zero and ten per node")
            if not -1000 <= priority <= 1000:
                raise GraphValidationError("node priority must be between -1000 and 1000")
            if step_id not in (resource_policy_by_step or {}):
                resource_policy = {"resources_write": ("__unclassified__",)}
            nodes.append(ExecutionNode(
                node_id=identity,
                step_id=step_id,
                dependencies=tuple(sorted(dependencies)),
                priority=priority,
                resources_read=tuple(sorted(set(str(v) for v in resource_policy.get("resources_read", ())))),
                resources_write=tuple(sorted(set(str(v) for v in resource_policy.get("resources_write", ())))),
                idempotent=bool(retry_policy.get("idempotent", False)),
                retry_limit=retry_limit,
                retryable_failure_classes=tuple(sorted(set(str(v) for v in retry_policy.get("retryable_failure_classes", ())))),
            ))
        depth: dict[str, int] = {}
        indegree = {item: len(dependencies_by_step[item]) for item in step_ids}
        dependents: dict[str, list[str]] = {item: [] for item in step_ids}
        for child, parents in dependencies_by_step.items():
            for parent in parents:
                dependents[parent].append(child)
        ready = [item for item, count in indegree.items() if count == 0]
        heapq.heapify(ready)
        while ready:
            item = heapq.heappop(ready)
            depth[item] = 0 if not dependencies_by_step[item] else 1 + max(depth[parent] for parent in dependencies_by_step[item])
            for child in sorted(dependents[item]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(ready, child)
        pending = set(step_ids) - set(depth)
        if pending:
            cycle = cls._find_cycle(dependencies_by_step, pending)
            raise GraphValidationError("dependency cycle: " + " -> ".join(cycle))
        policy_payload = [
            {"step_id": node.step_id, "resources_read": node.resources_read, "resources_write": node.resources_write,
             "idempotent": node.idempotent, "retry_limit": node.retry_limit,
             "retryable_failure_classes": node.retryable_failure_classes}
            for node in sorted(nodes, key=lambda item: item.step_id)
        ]
        policy_hash = hashlib.sha256(repr(policy_payload).encode()).hexdigest()
        return cls(str(mission_id), str(execution_run_id), str(plan.fingerprint), policy_hash, tuple(nodes), depth)

    @staticmethod
    def _find_cycle(dependencies: dict[str, tuple[str, ...]], candidates: set[str]) -> list[str]:
        color: dict[str, int] = {}
        path: list[str] = []
        path_index: dict[str, int] = {}
        for root in sorted(candidates):
            if color.get(root, 0):
                continue
            color[root] = 1
            path_index[root] = len(path)
            path.append(root)
            stack: list[tuple[str, Any]] = [(root, iter(sorted(item for item in dependencies[root] if item in candidates)))]
            while stack:
                node, children = stack[-1]
                try:
                    parent = next(children)
                except StopIteration:
                    stack.pop()
                    color[node] = 2
                    path_index.pop(node, None)
                    path.pop()
                    continue
                state = color.get(parent, 0)
                if state == 1:
                    return path[path_index[parent]:] + [parent]
                if state == 0:
                    color[parent] = 1
                    path_index[parent] = len(path)
                    path.append(parent)
                    stack.append((parent, iter(sorted(item for item in dependencies[parent] if item in candidates))))
        return sorted(candidates)

    @cached_property
    def by_step(self) -> dict[str, ExecutionNode]:
        return {node.step_id: node for node in self.nodes}

    @cached_property
    def by_id(self) -> dict[str, ExecutionNode]:
        return {node.node_id: node for node in self.nodes}

    @cached_property
    def dependents_by_step(self) -> dict[str, tuple[str, ...]]:
        dependents: dict[str, list[str]] = {node.step_id: [] for node in self.nodes}
        for node in self.nodes:
            for dependency in node.dependencies:
                dependents[dependency].append(node.step_id)
        return {step_id: tuple(sorted(children)) for step_id, children in dependents.items()}

    @cached_property
    def total_retry_limit(self) -> int:
        return sum(node.retry_limit for node in self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "execution_run_id": self.execution_run_id,
            "plan_hash": self.plan_hash,
            "policy_hash": self.policy_hash,
            "nodes": [node.to_dict() for node in sorted(self.nodes, key=lambda item: item.step_id)],
            "depth_by_step": dict(sorted(self.depth_by_step.items())),
        }


class DeterministicScheduler:
    """Pure, persistable scheduling decisions; tool execution stays in MissionRuntime."""

    FAILURE_DEPENDENTS = {NodeState.FAILED.value, NodeState.BLOCKED.value, NodeState.REJECTED.value, NodeState.UNKNOWN.value, NodeState.CANCELLED.value}

    @staticmethod
    def initial_state(graph: ExecutionGraph, *, authorization_hash: str, node_budget: int | None = None, max_parallel: int = 1, max_runs: int = 50, tool_budget: int | None = None, retry_budget: int | None = None, max_duration_seconds: int | None = 3600) -> dict[str, Any]:
        if max_parallel < 1 or max_parallel > 32:
            raise ValueError("max_parallel must be between one and the hard runtime cap of 32")
        if node_budget is not None and node_budget < 0:
            raise ValueError("node_budget cannot be negative")
        if max_runs < 1 or (tool_budget is not None and tool_budget < 0) or (retry_budget is not None and retry_budget < 0) or (max_duration_seconds is not None and max_duration_seconds < 1):
            raise ValueError("run, tool, retry, and time budgets must be non-negative with at least one run")
        if retry_budget is None:
            retry_budget = sum(node.retry_limit for node in graph.nodes)
        if tool_budget is None:
            tool_budget = node_budget if node_budget is not None else len(graph.nodes) + retry_budget
        state = {
            "schema_version": 2,
            "scheduler_index_version": 1,
            "mission_id": graph.mission_id,
            "execution_run_id": graph.execution_run_id,
            "plan_hash": graph.plan_hash,
            "authorization_hash": authorization_hash,
            "graph": graph.to_dict(),
            "nodes": {node.node_id: {"step_id": node.step_id, "state": NodeState.PENDING.value, "attempts": 0, "error": "", "result": None} for node in sorted(graph.nodes, key=lambda item: item.step_id)},
            "ready_nodes": {},
            "ready_heap": [],
            "dependency_state": {
                node.node_id: {"remaining": len(node.dependencies), "dependents": [graph.by_step[step_id].node_id for step_id in graph.dependents_by_step[node.step_id]], "step_id": node.step_id, "priority": node.priority, "depth": graph.depth_by_step[node.step_id]}
                for node in graph.nodes
            },
            "running_nodes": [],
            "completed_nodes": [],
            "failed_nodes": [],
            "blocked_nodes": [],
            "retry_queue": [],
            "resource_locks": {},
            "budget_state": {
                "mission_budget": {"node_limit": node_budget, "nodes_started": 0},
                "run_budget": {"run_limit": max_runs, "runs_started": 0},
                "node_budget": node_budget,
                "nodes_started": 0,
                "tool_budget": {"dispatch_limit": tool_budget, "dispatches_started": 0},
                "retry_budget": {"retry_limit": retry_budget, "retries_started": 0},
                "parallelism_budget": {"max_parallel": max_parallel},
                "max_parallel": max_parallel,
                "time_budget": {"deadline_at": None if max_duration_seconds is None else time.time() + max_duration_seconds},
            },
            "paused": False,
            "cancel_requested": False,
            "recovery_required": False,
            "events": [],
            "ready_since": {},
        }
        for node in graph.nodes:
            if not node.dependencies:
                DeterministicScheduler._enqueue_ready(graph, state, node)
        return state

    @staticmethod
    def _enqueue_ready(graph: ExecutionGraph, state: dict[str, Any], node: ExecutionNode) -> None:
        ready = state.setdefault("ready_nodes", {})
        if node.node_id in ready:
            return
        clock = int(state["budget_state"]["nodes_started"])
        ready_since = state.setdefault("ready_since", {})
        ready_since.setdefault(node.node_id, clock)
        ready[node.node_id] = {"step_id": node.step_id, "ready_since": int(ready_since[node.node_id])}
        heapq.heappush(state.setdefault("ready_heap", []), (int(ready_since[node.node_id]) - node.priority, graph.depth_by_step[node.step_id], node.node_id))
        DeterministicScheduler._event(state, "NODE_READY", node.node_id, step_id=node.step_id)

    @staticmethod
    def _enqueue_from_state(state: dict[str, Any], node_id: str) -> None:
        dependency = state["dependency_state"][node_id]
        if node_id in state["ready_nodes"]:
            return
        clock = int(state["budget_state"]["nodes_started"])
        ready_since = state.setdefault("ready_since", {})
        ready_since.setdefault(node_id, clock)
        step_id = dependency["step_id"]
        state["ready_nodes"][node_id] = {"step_id": step_id, "ready_since": int(ready_since[node_id])}
        heapq.heappush(state["ready_heap"], (int(ready_since[node_id]) - int(dependency["priority"]), int(dependency["depth"]), node_id))
        DeterministicScheduler._event(state, "NODE_READY", node_id, step_id=step_id)

    @staticmethod
    def _block_dependents(state: dict[str, Any], node_id: str) -> None:
        queue = deque(state.get("dependency_state", {}).get(node_id, {}).get("dependents", []))
        while queue:
            dependent_id = queue.popleft()
            item = state["nodes"].get(dependent_id)
            if item is None or item.get("state") not in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value}:
                continue
            state["ready_nodes"].pop(dependent_id, None)
            item["state"] = NodeState.BLOCKED.value
            item["error"] = f"dependency did not complete: {node_id}"
            state.setdefault("blocked_nodes", []).append(dependent_id)
            if dependent_id in state.get("retry_queue", []):
                state["retry_queue"].remove(dependent_id)
            DeterministicScheduler._event(state, "NODE_BLOCKED", dependent_id, reason=item["error"])
            queue.extend(state.get("dependency_state", {}).get(dependent_id, {}).get("dependents", []))

    @staticmethod
    def _complete_node(state: dict[str, Any], node_id: str) -> None:
        state["completed_nodes"].append(node_id)
        for dependent_id in state.get("dependency_state", {}).get(node_id, {}).get("dependents", []):
            dependency = state["dependency_state"][dependent_id]
            dependency["remaining"] = max(0, int(dependency["remaining"]) - 1)
            item = state["nodes"][dependent_id]
            if dependency["remaining"] == 0 and item.get("state") in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value}:
                DeterministicScheduler._enqueue_from_state(state, dependent_id)

    @staticmethod
    def _ensure_indexes(graph: ExecutionGraph, state: dict[str, Any]) -> None:
        budget = state.setdefault("budget_state", {})
        legacy_parallel = max(1, min(32, int(budget.get("max_parallel", 1))))
        budget.setdefault("parallelism_budget", {"max_parallel": legacy_parallel})
        budget["parallelism_budget"]["max_parallel"] = max(1, min(32, int(budget["parallelism_budget"].get("max_parallel", legacy_parallel))))
        budget.setdefault("run_budget", {"run_limit": max(1, len(graph.nodes) + graph.total_retry_limit), "runs_started": 0})
        retry_limit = graph.total_retry_limit
        budget.setdefault("retry_budget", {"retry_limit": retry_limit, "retries_started": 0})
        budget.setdefault("tool_budget", {"dispatch_limit": budget.get("node_budget") if budget.get("node_budget") is not None else len(graph.nodes) + retry_limit, "dispatches_started": int(budget.get("nodes_started", 0))})
        budget.setdefault("mission_budget", {"node_limit": budget.get("node_budget"), "nodes_started": int(budget.get("nodes_started", 0))})
        budget.setdefault("time_budget", {"deadline_at": None})
        if state.get("scheduler_index_version") == 1 and isinstance(state.get("ready_nodes"), dict):
            return
        ready_since = state.setdefault("ready_since", {})
        state["ready_nodes"] = {}
        state["ready_heap"] = []
        state["dependency_state"] = {
            node.node_id: {"remaining": 0, "dependents": [graph.by_step[step_id].node_id for step_id in graph.dependents_by_step[node.step_id]], "step_id": node.step_id, "priority": node.priority, "depth": graph.depth_by_step[node.step_id]}
            for node in graph.nodes
        }
        for node in graph.nodes:
            item = state["nodes"][node.node_id]
            remaining = sum(state["nodes"][graph.by_step[step_id].node_id].get("state") != NodeState.COMPLETED.value for step_id in node.dependencies)
            state["dependency_state"][node.node_id]["remaining"] = remaining
            if item.get("state") in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value} and remaining == 0:
                DeterministicScheduler._enqueue_ready(graph, state, node)
        for node in graph.nodes:
            if state["nodes"][node.node_id].get("state") in DeterministicScheduler.FAILURE_DEPENDENTS:
                DeterministicScheduler._block_dependents(state, node.node_id)
        state["scheduler_index_version"] = 1
        DeterministicScheduler._refresh_indexes(state)

    @staticmethod
    def check_identity(state: dict[str, Any], graph: ExecutionGraph, authorization_hash: str) -> None:
        if state.get("mission_id") != graph.mission_id or state.get("execution_run_id") != graph.execution_run_id:
            raise GraphValidationError("cross-run or cross-mission scheduler state rejected")
        if state.get("plan_hash") != graph.plan_hash:
            raise GraphValidationError("stale plan hash; graph changes require a new authorized execution run")
        if state.get("graph", {}).get("policy_hash") != graph.policy_hash:
            raise GraphValidationError("runtime execution policy changed; scheduler state cannot inherit old policy")
        if state.get("authorization_hash") != authorization_hash:
            raise GraphValidationError("authorization changed; existing scheduler state cannot inherit new authority")

    @staticmethod
    def recover(state: dict[str, Any]) -> list[str]:
        """Mark dispatched-but-unresolved work UNKNOWN; never blindly replay it."""
        affected: list[str] = []
        for node_id in sorted(state.get("nodes", {})):
            item = state["nodes"][node_id]
            if item.get("state") == NodeState.RUNNING.value:
                item["state"] = NodeState.UNKNOWN.value
                item["error"] = "worker restarted while node outcome was in flight; reconcile before retry"
                affected.append(node_id)
        if affected:
            state["recovery_required"] = True
            state["resource_locks"] = {}
            DeterministicScheduler._refresh_indexes(state)
            for node_id in affected:
                DeterministicScheduler._event(state, "RECOVERY_RECONCILED", node_id, reason="unknown_outcome_requires_reconciliation")
        return affected

    @staticmethod
    def ready_nodes(graph: ExecutionGraph, state: dict[str, Any]) -> list[ExecutionNode]:
        DeterministicScheduler._ensure_indexes(graph, state)
        nodes = graph.by_id
        ready = state["ready_nodes"]
        stale = [node_id for node_id in ready if state["nodes"].get(node_id, {}).get("state") not in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value}]
        for node_id in stale:
            ready.pop(node_id, None)
        ordered = sorted(ready, key=lambda node_id: (ready[node_id]["ready_since"] - nodes[node_id].priority, graph.depth_by_step[nodes[node_id].step_id], node_id))
        return [nodes[node_id] for node_id in ordered]

    @staticmethod
    def reserve_batch(graph: ExecutionGraph, state: dict[str, Any], *, allowed_node_ids: Iterable[str] | None = None, limit: int | None = None) -> list[ExecutionNode]:
        if state.get("paused") or state.get("cancel_requested") or state.get("recovery_required"):
            return []
        DeterministicScheduler._ensure_indexes(graph, state)
        allowed = None if allowed_node_ids is None else set(allowed_node_ids)
        budget = state["budget_state"]
        max_parallel = max(1, int(budget["parallelism_budget"]["max_parallel"]))
        effective_limit = max_parallel if limit is None else min(max_parallel, max(0, int(limit)))
        if effective_limit == 0:
            return []
        deadline_at = budget["time_budget"].get("deadline_at")
        if deadline_at is not None and time.time() >= float(deadline_at):
            state["budget_expired"] = True
            DeterministicScheduler._event(state, "BUDGET_BLOCKED", "", budget="time", deadline_at=deadline_at)
            return []
        node_budget = budget.get("node_budget")
        remaining_budget = len(state["ready_nodes"]) if node_budget is None else max(0, int(node_budget) - int(budget["nodes_started"]))
        tool_remaining = max(0, int(budget["tool_budget"]["dispatch_limit"]) - int(budget["tool_budget"]["dispatches_started"]))
        remaining_budget = min(remaining_budget, tool_remaining)
        if remaining_budget == 0 and state["ready_nodes"]:
            DeterministicScheduler._event(state, "BUDGET_BLOCKED", "", remaining=0)
            return []
        selected: list[ExecutionNode] = []
        reads: set[str] = set()
        writes: set[str] = set()
        retries_selected = 0
        deferred: list[tuple[int, int, str]] = []
        by_id = graph.by_id
        heap = state["ready_heap"]
        while heap and len(selected) < effective_limit and len(selected) < remaining_budget:
            entry = heapq.heappop(heap)
            node_id = entry[2]
            if node_id not in state["ready_nodes"]:
                continue
            node = by_id[node_id]
            if allowed is not None and node.node_id not in allowed:
                deferred.append(entry)
                continue
            item = state["nodes"][node.node_id]
            retry_candidate = int(item.get("attempts", 0)) > 0
            if retry_candidate:
                retry_state = budget["retry_budget"]
                if int(retry_state["retries_started"]) + retries_selected >= int(retry_state["retry_limit"]):
                    state["ready_nodes"].pop(node_id, None)
                    item["state"] = NodeState.FAILED.value
                    item["error"] = "retry budget exhausted"
                    item["failure_class"] = "BUDGET"
                    state["failed_nodes"].append(node_id)
                    DeterministicScheduler._event(state, "RETRY_BUDGET_BLOCKED", node.node_id, step_id=node.step_id)
                    DeterministicScheduler._block_dependents(state, node.node_id)
                    continue
            node_reads = set(node.resources_read)
            node_writes = set(node.resources_write)
            if node_writes & (reads | writes) or writes & node_reads:
                deferred.append(entry)
                continue
            selected.append(node)
            state["ready_nodes"].pop(node_id, None)
            retries_selected += int(retry_candidate)
            reads.update(node_reads)
            writes.update(node_writes)
        for entry in deferred:
            heapq.heappush(heap, entry)
        locks = {resource: [node.node_id for node in selected if resource in set(node.resources_read) | set(node.resources_write)] for resource in sorted(reads | writes)}
        state["resource_locks"] = locks
        for node in selected:
            item = state["nodes"][node.node_id]
            state.get("ready_since", {}).pop(node.node_id, None)
            item["state"] = NodeState.RUNNING.value
            item["attempts"] = int(item.get("attempts", 0)) + 1
            budget["nodes_started"] = int(budget["nodes_started"]) + 1
            budget["mission_budget"]["nodes_started"] += 1
            budget["tool_budget"]["dispatches_started"] += 1
            if item["attempts"] > 1:
                budget["retry_budget"]["retries_started"] += 1
            DeterministicScheduler._event(state, "NODE_STARTED", node.node_id, step_id=node.step_id, attempt=item["attempts"])
            state["running_nodes"].append(node.node_id)
        return selected

    @staticmethod
    def start_run(state: dict[str, Any]) -> bool:
        budget = state["budget_state"]["run_budget"]
        if int(budget["runs_started"]) >= int(budget["run_limit"]):
            state["run_budget_exhausted"] = True
            DeterministicScheduler._event(state, "BUDGET_BLOCKED", "", budget="run", remaining=0)
            return False
        budget["runs_started"] += 1
        return True

    @staticmethod
    def reject(state: dict[str, Any], node: ExecutionNode, reason: str) -> None:
        item = state.get("nodes", {}).get(node.node_id)
        if item is None or item.get("step_id") != node.step_id:
            raise GraphValidationError("unknown node identity")
        if item["state"] not in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value}:
            return
        state.get("ready_nodes", {}).pop(node.node_id, None)
        item["state"] = NodeState.REJECTED.value
        item["error"] = str(reason)
        item["failure_class"] = "AUTHORIZATION"
        state["blocked_nodes"].append(node.node_id)
        DeterministicScheduler._event(state, "NODE_REJECTED", node.node_id, step_id=node.step_id, reason=str(reason))
        DeterministicScheduler._block_dependents(state, node.node_id)

    @staticmethod
    def finish(state: dict[str, Any], node: ExecutionNode, *, success: bool, result: Any = None, error: str = "", failure_class: str = "UNKNOWN") -> None:
        item = state.get("nodes", {}).get(node.node_id)
        if item is None or item.get("step_id") != node.step_id:
            raise GraphValidationError("unknown node identity")
        if item["state"] != NodeState.RUNNING.value:
            raise GraphValidationError("only a running node can be completed")
        item["result"] = result
        item["error"] = str(error or "")
        item["failure_class"] = "" if success else str(failure_class)
        if node.node_id in state["running_nodes"]:
            state["running_nodes"].remove(node.node_id)
        if success:
            item["state"] = NodeState.COMPLETED.value
            DeterministicScheduler._complete_node(state, node.node_id)
            DeterministicScheduler._event(state, "NODE_COMPLETED", node.node_id, step_id=node.step_id)
        elif str(failure_class) in {"AUTHORIZATION", "SCOPE", "VALIDATION"}:
            item["state"] = NodeState.REJECTED.value
            state["blocked_nodes"].append(node.node_id)
            DeterministicScheduler._event(state, "AUTHORIZATION_BLOCKED" if str(failure_class) == "AUTHORIZATION" else "NODE_REJECTED", node.node_id, step_id=node.step_id, failure_class=str(failure_class), reason=str(error or "node rejected"))
            DeterministicScheduler._block_dependents(state, node.node_id)
        elif str(failure_class) == "UNKNOWN_OUTCOME":
            item["state"] = NodeState.UNKNOWN.value
            state["recovery_required"] = True
            DeterministicScheduler._event(state, "NODE_FAILED", node.node_id, step_id=node.step_id, failure_class=str(failure_class), reason=str(error or "unknown outcome"))
        else:
            retryable = node.idempotent and item["attempts"] <= node.retry_limit and str(failure_class) in node.retryable_failure_classes
            if retryable:
                item["state"] = NodeState.RETRY_WAIT.value
                state["retry_queue"] = sorted(set(state.get("retry_queue", [])) | {node.node_id})
                DeterministicScheduler._enqueue_from_state(state, node.node_id)
                DeterministicScheduler._event(state, "NODE_RETRIED", node.node_id, step_id=node.step_id, attempt=item["attempts"], failure_class=str(failure_class))
            else:
                item["state"] = NodeState.FAILED.value
                state["failed_nodes"].append(node.node_id)
                DeterministicScheduler._event(state, "NODE_FAILED", node.node_id, step_id=node.step_id, failure_class=str(failure_class), reason=str(error or "node failed"))
                DeterministicScheduler._block_dependents(state, node.node_id)
        if node.node_id in state.get("retry_queue", []) and item["state"] != NodeState.RETRY_WAIT.value:
            state["retry_queue"].remove(node.node_id)
        if not state.get("running_nodes"):
            state["resource_locks"] = {}

    @staticmethod
    def reconcile(state: dict[str, Any], graph: ExecutionGraph, node_id: str, *, executed: bool, result: Any = None) -> None:
        item = state.get("nodes", {}).get(node_id)
        if item is None or item.get("state") != NodeState.UNKNOWN.value:
            raise GraphValidationError("node has no unknown outcome to reconcile")
        if executed:
            if not isinstance(result, dict) or result.get("success") is not True:
                raise GraphValidationError("executed reconciliation requires explicit successful verification evidence")
            item["state"] = NodeState.COMPLETED.value
            item["result"] = result
            item["error"] = ""
            DeterministicScheduler._complete_node(state, node_id)
        else:
            node = graph.by_id[node_id]
            if not node.idempotent or int(item.get("attempts", 0)) > node.retry_limit:
                raise GraphValidationError("unknown outcome cannot be retried without an idempotent, budgeted retry rule")
            item["state"] = NodeState.RETRY_WAIT.value
            item["error"] = "reconciled as not executed"
            state["retry_queue"] = sorted(set(state.get("retry_queue", [])) | {node_id})
            DeterministicScheduler._enqueue_ready(graph, state, node)
        if not any(value.get("state") == NodeState.UNKNOWN.value for value in state["nodes"].values()):
            state["recovery_required"] = False
        result_hash = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest() if executed else ""
        DeterministicScheduler._event(state, "RECOVERY_RECONCILED", node_id, outcome="executed" if executed else "not_executed", result_hash=result_hash)

    @staticmethod
    def set_control(state: dict[str, Any], command: str) -> None:
        if command == "pause":
            state["paused"] = True
        elif command == "resume":
            if state.get("recovery_required"):
                raise GraphValidationError("unknown outcomes must be reconciled before resume")
            if state.get("cancel_requested"):
                raise GraphValidationError("cancelled execution cannot be resumed")
            state["paused"] = False
        elif command == "cancel":
            state["cancel_requested"] = True
            for node_id in sorted(state.get("nodes", {})):
                item = state["nodes"][node_id]
                if item["state"] in {NodeState.PENDING.value, NodeState.RETRY_WAIT.value}:
                    item["state"] = NodeState.CANCELLED.value
                    state.get("ready_nodes", {}).pop(node_id, None)
                    if node_id in state.get("retry_queue", []):
                        state["retry_queue"].remove(node_id)
                    DeterministicScheduler._event(state, "NODE_CANCELLED", node_id)
        else:
            raise ValueError("unknown orchestration control")

    @staticmethod
    def _event(state: dict[str, Any], event: str, node_id: str, **data: Any) -> None:
        state.setdefault("events", []).append({"event": event, "node_id": node_id, **data})

    @staticmethod
    def _refresh_indexes(state: dict[str, Any]) -> None:
        values = state.get("nodes", {})
        state["running_nodes"] = sorted(node_id for node_id, item in values.items() if item.get("state") == NodeState.RUNNING.value)
        state["completed_nodes"] = sorted(node_id for node_id, item in values.items() if item.get("state") == NodeState.COMPLETED.value)
        state["failed_nodes"] = sorted(node_id for node_id, item in values.items() if item.get("state") == NodeState.FAILED.value)
        state["blocked_nodes"] = sorted(node_id for node_id, item in values.items() if item.get("state") in {NodeState.BLOCKED.value, NodeState.REJECTED.value})
        state["retry_queue"] = sorted(node_id for node_id, item in values.items() if item.get("state") == NodeState.RETRY_WAIT.value)


__all__ = ["DeterministicScheduler", "ExecutionGraph", "ExecutionNode", "GraphValidationError", "NodeState"]
