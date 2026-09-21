from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from core.config import DB_PATH
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.owner_policy import (
    authenticate_owner,
    authentication_from_session,
    capture_policy_snapshot,
    policy_context_from_snapshot,
    verify_owner,
    OwnerPolicySnapshot,
)
from security.owner_session import consume_owner_challenge
from security.scope_store import get_snapshot
from tools.registry import REGISTRY, execute as execute_tool, get_tool

from .mission import Mission, MissionStore
from .mission_runtime import MissionRuntime
from .planning import Plan, PlanStep, RecoveryPolicy, TaskProfile, select_reasoning_profile
from .provider_api import ToolCall
from .context import ContextEngine, ExecutionState


class AgentCore:
    """CyberSentinel-native long-horizon facade over the durable MissionRuntime."""

    def __init__(self, router: Any, *, store: MissionStore | None = None, db_path: str | Path | None = None, max_iterations: int = 50):
        self.router = router
        self.store = store or MissionStore(db_path or DB_PATH.with_name("missions.sqlite3"))
        self.max_iterations = max_iterations

    @staticmethod
    def _schemas() -> list[dict[str, Any]]:
        result = []
        for spec in REGISTRY.values():
            parameters: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}
            if spec.argument_type is str:
                parameters["properties"]["query"] = {"type": "string", "maxLength": 256}
                parameters["required"] = ["query"]
            result.append({"type": "function", "function": {"name": spec.name, "description": spec.description[:512], "parameters": parameters}})
        return result

    @staticmethod
    def _calls(response: dict[str, Any]) -> list[ToolCall]:
        calls: list[ToolCall] = []
        for item in response.get("tool_calls") or []:
            if isinstance(item, ToolCall):
                calls.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                args = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
                calls.append(ToolCall(item["name"], args, str(item.get("id") or uuid.uuid4().hex)))
        if calls:
            return calls
        content = str(response.get("content", "") or "")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict) and isinstance(payload.get("tool"), str):
            return [ToolCall(payload["tool"], payload.get("arguments") or {}, str(payload.get("id") or uuid.uuid4().hex))]
        if isinstance(payload, dict) and payload.get("type") == "tool_call" and isinstance(payload.get("name"), str):
            return [ToolCall(payload["name"], payload.get("arguments") or {}, str(payload.get("id") or uuid.uuid4().hex))]
        return []

    def _ask(self, objective: str, observation: dict[str, Any] | None = None, *, policy_context: str = "", request_id: str = "", conversation_id: str = "") -> dict[str, Any]:
        profile = select_reasoning_profile(objective)
        context = ContextEngine.build(
            user_text=objective,
            conversation_id=conversation_id or "agent-core",
            owner_policy_context=policy_context,
            tool_results=[("observation", observation)] if observation else None,
            execution_state=ExecutionState.initial(request_id, conversation_id or "agent-core"),
        )
        messages = context.messages
        try:
            return self.router.tool_calling(messages, self._schemas(), reasoning_profile=profile)
        except (AttributeError, NotImplementedError):
            return self.router.generate(messages, reasoning_profile=profile)

    def _plan(self, objective: str, observation: dict[str, Any] | None = None, *, policy_context: str = "", request_id: str = "", conversation_id: str = "") -> Plan:
        calls = self._calls(self._ask(objective, observation, policy_context=policy_context, request_id=request_id, conversation_id=conversation_id))
        steps: list[PlanStep] = []
        for index, call in enumerate(calls, start=1):
            spec = get_tool(call.name)
            if spec is None:
                continue
            steps.append(PlanStep(
                step_id=f"step-{index}-{call.name}",
                objective=f"Execute proposed tool {call.name} and capture an observation",
                action=call.name,
                expected_observation="tool observation",
                authorization_requirement="owner" if spec.requires_owner else "",
                scope_requirement="scope" if spec.scope_required else "",
                retry_policy={"arguments": dict(call.arguments), "tool_call_id": call.call_id},
                verification=(f"step-{index}-{call.name}",),
            ))
        if not steps:
            # No model call is an explicit planning failure, not a silent success.
            steps.append(PlanStep("planning-failure", "Recover from malformed or empty model proposal", action="__planning_failure__", expected_observation="replanned action"))
        return Plan.initial(objective, created_from="agent_core").replan(steps=steps, reason="initial agent-core plan")

    @staticmethod
    def _auth(text: str, owner_token: str, request_id: str, owner_session_id: str | None, owner_challenge: str | None) -> tuple[AuthorizationContext, dict[str, Any]]:
        if owner_session_id or owner_challenge:
            if not owner_session_id or not owner_challenge:
                raise PermissionError("owner challenge required")
            session_context = consume_owner_challenge(owner_session_id, owner_challenge, text, request_id)
            evidence = authentication_from_session(session_context, request_id)
            session_id = session_context.get("owner_session_id")
        else:
            evidence = authenticate_owner(text, owner_token, request_id)
            session_id = None
        snapshot = capture_policy_snapshot(request_id, evidence)
        return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=snapshot, session_id=session_id), policy_context_from_snapshot(snapshot)

    @staticmethod
    def _executor(mission: Mission, step: PlanStep, action_id: str) -> dict[str, Any]:
        if step.action == "__planning_failure__":
            return {"success": False, "failure_class": "LOGIC", "error": "malformed, empty, or unknown tool proposal"}
        arguments = dict(step.retry_policy).get("arguments", {})
        argument = arguments.get("query") if isinstance(arguments, dict) else None
        raw = mission.authorization_context or {}
        context = AuthorizationContext.from_dict(raw)
        spec = get_tool(step.action)
        if spec is None:
            return {"success": False, "failure_class": "TOOL", "error": "unknown tool"}
        valid, reason = spec.validate(argument)
        if isinstance(arguments, dict) and set(arguments) - {"query"}:
            return {"success": False, "failure_class": "TOOL", "error": "invalid tool arguments"}
        if not valid:
            return {"success": False, "failure_class": "TOOL", "error": reason}
        item = step.action if argument is None else [step.action, argument]
        decision = authorize_tool(item, context=context)
        if not decision.allowed:
            return {"success": False, "failure_class": "AUTHORIZATION", "error": decision.reason}
        try:
            value = execute_tool(step.action, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot)
            return {"success": True, "source": step.action, "criterion_id": "mission-goal", "result": value, "execution_id": action_id}
        except Exception as exc:
            return {"success": False, "failure_class": "TOOL", "error": type(exc).__name__, "execution_id": action_id}

    def run_owner_mission(self, instruction: str, *, owner_token: str, owner_session_id: str | None = None, owner_challenge: str | None = None, request_id: str | None = None, scope_context: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None) -> Mission:
        request_id = request_id or uuid.uuid4().hex
        authorization_context, policy_context = self._auth(instruction, owner_token, request_id, owner_session_id, owner_challenge)
        if isinstance(scope_context, dict) and scope_context.get("scope_snapshot_id"):
            snapshot = get_snapshot(scope_context["scope_snapshot_id"])
            if snapshot is None:
                raise PermissionError("invalid_scope_context")
            authorization_context = AuthorizationContext(
                request_id=authorization_context.request_id,
                owner_evidence=authorization_context.owner_evidence,
                policy_snapshot=authorization_context.policy_snapshot,
                scope_snapshot=snapshot,
                session_id=authorization_context.session_id,
            )
        plan = self._plan(instruction, policy_context=policy_context, request_id=request_id, conversation_id=request_id)
        task_profile = TaskProfile.from_proposal(instruction, {"task_type": "owner_mission", "horizon": "long_horizon", "complexity": "multi_step", "likely_tools": [step.action for step in plan.steps if step.action != "__planning_failure__"]})
        runtime = MissionRuntime(
            self.store,
            executor=self._executor,
            replanner=lambda mission, observation: self._plan(mission.objective, observation, policy_context=policy_context, request_id=mission.request_id, conversation_id=mission.mission_id),
            recovery_policy=RecoveryPolicy(),
        )
        mission = runtime.create_from_owner_instruction(
            instruction,
            plan,
            authorization_context=authorization_context,
            scope_snapshot=scope_context,
            completion_criteria=completion_criteria or [{"criterion_id": "mission-goal", "description": "Owner objective has a verified successful observation", "check": "tool observation", "required": True}],
            provenance={"component": "AgentCore", "planner": "model_proposal", "task_profile": task_profile.to_dict()},
        )
        return runtime.run_to_completion(mission.mission_id, max_slices=self.max_iterations)

    def resume_mission(self, mission_id: str, *, owner_token: str, max_slices: int | None = None) -> Mission:
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        ok, reason = verify_owner("Owner resume mission", owner_token)
        if not ok:
            raise PermissionError(reason)
        policy_context = policy_context_from_snapshot(OwnerPolicySnapshot(**dict(mission.policy_snapshot or {}))) if mission.policy_snapshot else ""
        runtime = MissionRuntime(self.store, executor=self._executor, replanner=lambda current, observation: self._plan(current.objective, observation, policy_context=policy_context, request_id=current.request_id, conversation_id=current.mission_id), recovery_policy=RecoveryPolicy())
        return runtime.run_to_completion(mission_id, max_slices=max_slices or self.max_iterations)


__all__ = ["AgentCore"]
