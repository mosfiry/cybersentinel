"""Fail-closed bounded fan-out for independent, explicitly safe Mission tasks.

This is deliberately narrower than autonomous child-model execution: workers run
one canonical read-only tool step under a graph child scope. All graph claims are
saved before dispatch, all observations are folded in plan order, and an unknown
batch outcome remains quarantined by MissionRuntime's in-flight checkpoint.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import inspect
import json
from typing import Any

from agent.mission import Mission, MissionStatus
from agent.observation import Observation
from agent.planning import FailureClass, RecoveryAction
from agent.trajectory import EventType


_PARALLEL_RECOVERY_PRIORITY = {
    RecoveryAction.OWNER_INPUT_REQUIRED: 0,
    RecoveryAction.SCOPE_BLOCKED: 1,
    RecoveryAction.RESOURCE_BLOCKED: 2,
    RecoveryAction.REPLAN: 3,
    RecoveryAction.RETRY: 4,
    RecoveryAction.FAIL: 5,
}


def _accepts_keyword(executor: Any, keyword: str) -> bool:
    try:
        parameters = inspect.signature(executor).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == keyword or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _scope_enforcement_declared(executor: Any) -> bool:
    function = getattr(executor, "__func__", executor)
    return getattr(function, "task_delegation_scope_enforced", False) is True


def _task_mission_copy(mission: Mission, step: Any, delegation_scope: Any) -> Mission:
    """Create a per-task Mission view without sibling observations or plan context."""
    worker = Mission.from_dict(mission.to_dict())
    worker.owner_request = ""
    worker.objective = str(step.objective)
    worker.owner_instruction = ""
    worker.plan = type(mission.plan)(version=mission.plan.version, objective=str(step.objective), steps=(step,))
    worker.current_step = 0
    worker.progress = {
        "active_execution_claim": dict(mission.progress.get("active_execution_claim", {})),
        "delegation_scope_fingerprint": str(delegation_scope.fingerprint),
    }
    worker.observations = []
    worker.evidence = []
    worker.artifacts = []
    worker.failures = []
    worker.completion_criteria = []
    worker.verification_state = {}
    worker.plan_history = []
    worker.action_history = []
    worker.transitions = []
    worker.provenance = {"delegated_step_id": step.step_id}
    worker.trajectory = []
    worker.hypotheses = []
    worker.strategy_state = {}
    worker.knowledge_context = []
    worker.interpretations = []
    worker.strategy_decisions = []
    worker.replan_history = []
    worker.verification_history = []
    worker.recovery_events = []
    worker.agent_task_graph_state = {}
    worker.semantic_intent = {}
    worker.scope_snapshot = {"target_id": delegation_scope.target_identity}
    # Round-trip recomputes the integrity hash for this task-local view. The
    # canonical tool dispatcher still validates against the durable mission.
    return Mission.from_dict(worker.to_dict())


def _action_id(mission: Mission, index: int, step: Any) -> str:
    return f"{mission.mission_id}:{mission.plan.version}:{step.step_id}:{index}"


def _failure_class(value: Any) -> FailureClass:
    try:
        return FailureClass(str(value))
    except ValueError:
        return FailureClass.UNKNOWN


def _recover_unknown_batch(runtime: Any, mission: Mission, fence: Any, entries: list[dict[str, Any]], reason: str) -> Mission:
    action_ids = [_action_id(mission, item["index"], item["step"]) for item in entries]
    step_ids = [str(item["step"].step_id) for item in entries]
    mission.error = "parallel task outcome is unknown; reconciliation required"
    failure = {
        "class": FailureClass.UNKNOWN.value,
        "reason": mission.error,
        "detail": str(reason)[:128],
        "action_ids": action_ids,
        "step_ids": step_ids,
    }
    mission.failures.append(failure)
    mission.emit(
        EventType.FAILURE_DIAGNOSED,
        step_id=step_ids[0] if step_ids else "",
        data={**failure, "recovery": "reconciliation_required"},
    )
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "plan_version": mission.plan.version,
        "step_ids": step_ids,
        "task_ids": step_ids,
        "graph_task_ids": [str(item["task_id"]) for item in entries],
        "action_ids": action_ids,
        "execution_ids": action_ids,
        "ambiguous_execution_ids": action_ids,
    }
    mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
    return runtime._save(mission, execution_fence=fence)


def run_parallel_graph_steps(runtime: Any, mission: Mission, snapshot: Any) -> Mission | None:
    """Run a contiguous independent batch of task-scoped, safe read tools.

    Returning ``None`` means normal single-step dispatch should proceed. A
    returned Mission means this helper claimed or processed a batch and the
    caller must stop this slice.
    """
    adapter = runtime.task_graph_adapter
    if (
        adapter is None
        or not adapter.policy.enable_task_delegation
        or adapter.policy.max_parallel_tasks <= 1
        or not runtime.require_execution_fence
        or runtime.execution_fence is None
        or runtime.event_bus is not None
        or runtime.hook_registry is not None
        or not _accepts_keyword(runtime.executor, "execution_fence")
        or not _accepts_keyword(runtime.executor, "delegation_scope")
        or not _scope_enforcement_declared(runtime.executor)
    ):
        return None

    from tools.registry import get_tool

    try:
        ready = adapter.ready_steps(mission, snapshot)
    except Exception as exc:
        return runtime._block_on_task_graph(mission, exc)
    by_index = {int(item["index"]): item for item in ready}
    first = by_index.get(int(mission.current_step))
    if first is None:
        return None

    # The current step and every following member must be ready and safe. A
    # dependency gap ends the batch rather than skipping over plan order.
    available_iterations = max(0, mission.max_iterations - (mission.iteration_count - 1))
    limit = min(adapter.policy.max_parallel_tasks, available_iterations)
    if limit <= 1:
        return None
    selected: list[dict[str, Any]] = []
    loop_signatures = mission.progress.setdefault("loop_signatures", {})
    for index in range(mission.current_step, mission.current_step + limit):
        item = by_index.get(index)
        if item is None:
            break
        step = item["step"]
        spec = get_tool(step.action)
        if (
            spec is None
            or spec.parallel_execution_safe is not True
            or spec.risk_class != "read"
            or spec.effect_provider
            or spec.idempotency_supported
            or spec.scope_required
            or spec.network_access != "none"
            or spec.filesystem_access != "none"
            or spec.process_access != "none"
            or spec.credential_access != "none"
            or step.scope_requirement
        ):
            break
        arguments = dict(step.retry_policy).get("arguments", {})
        if not isinstance(arguments, dict) or set(arguments) - {"query"}:
            break
        argument = arguments.get("query")
        valid, _reason = spec.validate(argument)
        if not valid:
            break
        delegated = item["delegation_scope"]
        if (
            tuple(delegated.allowed_tools) != (step.action,)
            or tuple(delegated.allowed_actions) != (step.action,)
            or delegated.allowed_networks
            or delegated.allowed_credentials
            or delegated.workspace_root
        ):
            break
        allowed, _reason = runtime.authorizer(mission, step)
        if not allowed:
            break
        signature = hashlib.sha256(
            json.dumps(
                {"plan": mission.plan.fingerprint, "step": step.step_id, "action": step.action},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if int(loop_signatures.get(signature, 0)) >= 3:
            break
        item = dict(item)
        item["signature"] = signature
        item["action_id"] = _action_id(mission, index, step)
        selected.append(item)
    if len(selected) < 2:
        return None

    # Claims, signatures, and checkpoint become one integrity-covered Mission
    # save before any thread can enter a tool handler.
    try:
        adapter.claim_steps(mission, snapshot, [str(item["step"].step_id) for item in selected])
    except Exception as exc:
        return runtime._block_on_task_graph(mission, exc)
    for item in selected:
        loop_signatures[item["signature"]] = int(loop_signatures.get(item["signature"], 0)) + 1
        step = item["step"]
        mission.emit(
            EventType.STEP_SELECTED,
            step_id=step.step_id,
            data={"action_id": item["action_id"], "plan_version": mission.plan.version, "delegated_agent_id": item["agent_id"]},
        )
        mission.emit(
            EventType.AUTHORIZATION_CHECKED,
            step_id=step.step_id,
            data={"allowed": True, "reason": "authorized task-scoped parallel read"},
        )
    mission.iteration_count += len(selected) - 1
    mission.transition(MissionStatus.RUNNING, "independent graph tasks started", step_ids=[item["step"].step_id for item in selected])
    mission.checkpoint = {
        "status": "in_flight_parallel",
        "plan_version": mission.plan.version,
        "step_ids": [str(item["step"].step_id) for item in selected],
        "task_ids": [str(item["step"].step_id) for item in selected],
        "graph_task_ids": [str(item["task_id"]) for item in selected],
        "action_ids": [str(item["action_id"]) for item in selected],
        "execution_ids": [str(item["action_id"]) for item in selected],
    }
    first_fence = runtime._fence_for(
        mission,
        task_id=str(selected[0]["step"].step_id),
        execution_id=str(selected[0]["action_id"]),
    )
    if first_fence is None:
        return runtime._block_on_task_graph(mission, RuntimeError("parallel graph dispatch requires an execution fence"))
    try:
        runtime._save(mission, execution_fence=first_fence)
    except Exception:
        # A failed durable claim/checkpoint prevents any worker dispatch.
        raise

    def execute_one(item: dict[str, Any]) -> Any:
        step = item["step"]
        action_id = str(item["action_id"])
        task_fence = runtime._fence_for(mission, task_id=str(step.step_id), execution_id=action_id)
        if task_fence is None:
            raise RuntimeError("parallel worker lost its execution fence")
        task_fence.assert_active_execution(mission)
        worker_mission = _task_mission_copy(mission, step, item["delegation_scope"])
        return runtime.executor(
            worker_mission,
            step,
            action_id,
            execution_fence=task_fence,
            delegation_scope=item["delegation_scope"],
        )

    raw_by_action: dict[str, Any] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(adapter.policy.max_parallel_tasks, len(selected)), thread_name_prefix="cybersentinel-mission-task") as pool:
        futures = {pool.submit(execute_one, item): item for item in selected}
        for future in as_completed(futures):
            item = futures[future]
            try:
                raw_by_action[str(item["action_id"])] = future.result()
            except Exception as exc:
                errors.append(f"{item['step'].step_id}:{type(exc).__name__}")
                for pending in futures:
                    if pending is not future:
                        pending.cancel()
    if errors or len(raw_by_action) != len(selected):
        latest = runtime.store.load(mission.mission_id)
        if latest is not None and latest.progress.get("owner_cancel_requested"):
            return latest
        return _recover_unknown_batch(runtime, mission, first_fence, selected, ",".join(sorted(errors)) or "worker_cancelled")

    results: list[dict[str, Any]] = []
    for item in selected:
        step = item["step"]
        action_id = str(item["action_id"])
        raw = raw_by_action[action_id]
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            return _recover_unknown_batch(runtime, mission, first_fence, selected, "invalid_worker_result")
        try:
            encoded = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        except (TypeError, ValueError):
            return _recover_unknown_batch(runtime, mission, first_fence, selected, "unserializable_worker_result")
        if len(encoded) > adapter.policy.max_task_result_bytes:
            raw = {
                "success": False,
                "failure_class": FailureClass.RESOURCE.value,
                "error": "parallel task result exceeded the durable result bound",
                "result_sha256": hashlib.sha256(encoded).hexdigest(),
                "result_bytes": len(encoded),
            }
        if raw.get("effect_id") or raw.get("effect_state"):
            return _recover_unknown_batch(runtime, mission, first_fence, selected, "unexpected_effect_marker")
        observation = dict(raw)
        observation.setdefault("type", "tool_observation")
        observation.setdefault("action_id", action_id)
        observation.setdefault("step_id", step.step_id)
        observation.setdefault("mission_id", mission.mission_id)
        try:
            typed = Observation.from_result(
                step.action,
                action_id,
                observation,
                request_id=mission.request_id,
                scope=mission.scope_snapshot,
            )
        except (TypeError, ValueError, KeyError) as exc:
            return _recover_unknown_batch(runtime, mission, first_fence, selected, f"observation_rejected:{type(exc).__name__}")
        observation["observation"] = typed.to_dict()
        results.append({"item": item, "observation": observation})

    graph_outcomes: list[dict[str, Any]] = []
    strategy_replans: list[tuple[int, Any, dict[str, Any]]] = []
    failure_recoveries: list[tuple[int, RecoveryAction, dict[str, Any], FailureClass]] = []
    scope_violations: list[tuple[int, Any]] = []
    interpretation_error: tuple[Any, Exception] | None = None
    for entry in results:
        item = entry["item"]
        step = item["step"]
        index = int(item["index"])
        action_id = str(item["action_id"])
        observation = entry["observation"]
        success = bool(observation.get("success", observation.get("ok", False)))
        mission.transition(MissionStatus.OBSERVING, "parallel task observation accepted", step_id=step.step_id, action_id=action_id)
        mission.record_observation(observation)
        mission.record_action(action_id, step.step_id, "completed" if success else "failed", observation)
        graph_outcomes.append({
            "step_id": step.step_id,
            "action_id": action_id,
            "success": success,
            "result": observation,
            "error": str(observation.get("error", "mission step failed")),
        })
        try:
            decision = runtime._interpret_observation(mission, step, observation, success=success)
        except (TypeError, ValueError, KeyError) as exc:
            if interpretation_error is None:
                interpretation_error = (step, exc)
            decision = None
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        if (
            observation.get("target")
            and isinstance(allowed_targets, (list, tuple, set))
            and str(observation.get("target")) not in {str(value) for value in allowed_targets}
        ):
            scope_violations.append((index, observation.get("target")))
        if success:
            arguments = dict(step.retry_policy).get("arguments", {})
            tool_argument = arguments.get("query") if isinstance(arguments, dict) else None
            verified = runtime._successful_observation_evidence(
                mission,
                observation,
                tool_name=step.action,
                tool_argument=tool_argument,
            )
            if verified:
                criterion_id, verified_result = verified
                mission.evidence.append({
                    "criterion_id": criterion_id,
                    "passed": True,
                    "source": step.action,
                    "result": {"source": step.action, "result": verified_result},
                    "provenance": {
                        "mission_id": mission.mission_id,
                        "step_id": step.step_id,
                        "action_id": action_id,
                        "verification_authority": runtime._verification_authority(step.action),
                    },
                })
                mission.emit(EventType.EVIDENCE_ADDED, step_id=step.step_id, data={"criterion_id": criterion_id})
            if decision is not None and decision.decision.value in {"REPLAN", "CHANGE_HYPOTHESIS", "ADD_EVIDENCE"}:
                strategy_replans.append((index, decision, observation))
        else:
            failure = _failure_class(observation.get("failure_class", FailureClass.UNKNOWN.value))
            failure_reason = str(observation.get("error", "action failed"))
            mission.failures.append({
                "class": failure.value,
                "reason": failure_reason,
                "step_id": step.step_id,
                "action_id": action_id,
            })
            mission.emit(EventType.FAILURE_DETECTED, step_id=step.step_id, data={"class": failure.value, "reason": failure_reason})
            mission.retry_count += 1
            recovery = runtime.recovery_policy.action_for(failure, mission.retry_count - 1)
            mission.emit(EventType.FAILURE_DIAGNOSED, step_id=step.step_id, data={"class": failure.value, "recovery": recovery.value})
            failure_recoveries.append((index, recovery, observation, failure))

    try:
        adapter.complete_steps(mission, graph_outcomes)
    except Exception as exc:
        return runtime._block_on_task_graph(mission, exc)

    batch_checkpoint = {
        "status": "completed",
        "plan_version": mission.plan.version,
        "step_ids": [str(item["step"].step_id) for item in selected],
        "task_ids": [str(item["step"].step_id) for item in selected],
        "graph_task_ids": [str(item["task_id"]) for item in selected],
        "action_ids": [str(item["action_id"]) for item in selected],
        "fan_in": "completed_in_plan_order",
    }
    mission.checkpoint = batch_checkpoint

    if interpretation_error is not None:
        step, exc = interpretation_error
        mission.error = f"observation interpretation rejected: {type(exc).__name__}"
        mission.recovery_events.append({"event": "interpretation_rejected", "reason": str(exc)[:256]})
        mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
        return runtime._save(mission, execution_fence=first_fence)
    if scope_violations:
        _index, target = min(scope_violations, key=lambda item: item[0])
        mission.error = "observation proposed a target outside deterministic scope"
        mission.failures.append({"class": FailureClass.SCOPE.value, "reason": mission.error, "target": target})
        mission.transition(MissionStatus.SCOPE_BLOCKED, mission.error)
        return runtime._save(mission, execution_fence=first_fence)

    if failure_recoveries:
        selected_recovery = min(failure_recoveries, key=lambda item: (_PARALLEL_RECOVERY_PRIORITY[item[1]], item[0]))
        _index, recovery, observation, _failure = selected_recovery
    elif strategy_replans:
        _index, _decision, observation = min(strategy_replans, key=lambda item: item[0])
        recovery = RecoveryAction.REPLAN
    else:
        recovery = None
        observation = {}

    if recovery is RecoveryAction.OWNER_INPUT_REQUIRED:
        mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, "parallel task authorization requires Owner input")
    elif recovery is RecoveryAction.SCOPE_BLOCKED:
        mission.transition(MissionStatus.SCOPE_BLOCKED, "parallel task scope blocked")
    elif recovery is RecoveryAction.RESOURCE_BLOCKED:
        mission.transition(MissionStatus.RESOURCE_BLOCKED, "parallel task resource bound exceeded")
    elif recovery is RecoveryAction.REPLAN:
        mission.transition(MissionStatus.REPLANNING, "parallel observation invalidated current plan")
        mission.emit(EventType.REPLAN_TRIGGERED, data={"reason": "parallel task observation"})
        new_plan = runtime.replanner(mission, observation)
        if new_plan.objective != mission.objective:
            mission.error = "replanner attempted to change Owner objective"
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            return runtime._save(mission, execution_fence=first_fence)
        mission.replan_history.append({"from_version": mission.plan.version, "to_version": new_plan.version, "reason": "parallel observation", "trigger": observation})
        mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": "parallel observation"})
        mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint})
        mission.plan = new_plan
        mission.current_step = 0
        mission.retry_count = 0
        mission.transition(MissionStatus.READY, "parallel observation caused replan", plan_version=new_plan.version)
    elif recovery is RecoveryAction.RETRY:
        completed = {
            str(item.get("step_id"))
            for item in mission.action_history
            if item.get("status") == "completed"
            and str(item.get("action_id", "")).startswith(f"{mission.mission_id}:{mission.plan.version}:")
        }
        mission.current_step = next((i for i, step in enumerate(mission.plan.steps) if step.step_id not in completed), len(mission.plan.steps))
        mission.transition(MissionStatus.READY, "bounded retry selected for failed parallel task")
    elif recovery is RecoveryAction.FAIL:
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, "parallel task recovery budget exhausted")
    else:
        completed = {
            str(item.get("step_id"))
            for item in mission.action_history
            if item.get("status") == "completed"
            and str(item.get("action_id", "")).startswith(f"{mission.mission_id}:{mission.plan.version}:")
        }
        mission.current_step = next((i for i, step in enumerate(mission.plan.steps) if step.step_id not in completed), len(mission.plan.steps))
        mission.retry_count = 0
        mission.transition(MissionStatus.READY, "parallel observations accepted", completed_steps=len(selected))
    return runtime._save(mission, execution_fence=first_fence)


__all__ = ["run_parallel_graph_steps"]
