from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
import hashlib
import inspect
import json
import re
import time

from .mission import Mission, MissionClaimBinding, MissionStatus, MissionStore
from .execution_fence import ExecutionFence, ExecutionFenceError
from .context import RuntimeLimits
from .planning import FailureClass, GoalVerification, Plan, PlanStep, RecoveryAction, RecoveryPolicy, VerificationCriterion, evidence_for
from .trajectory import EventType
from .observation import Observation
from .observation_intelligence import ObservationInterpreter, should_interpret_observation
from .hypotheses import HypothesisEngine, HypothesisState
from .strategy import StrategyState, decide as decide_strategy
from .model_protocol import ConversationTurn, NativeModel, RouterNativeModel, ToolCallResult, derive_action_id, validate_model_turn
from .provider_api import InvalidModelResponse, MAX_PROVIDER_LABEL_CHARS, ProviderError
from .model_intelligence.context import ContextAssembler
from .model_intelligence.tool_calls import execute_bounded_parallel, validate_proposals
from .intelligence_layer.graph import AgentGraphPolicy
from .intelligence_layer.runtime_adapter import MissionTaskGraphAdapter, MissionTaskGraphError
from security.mission_authorization import MissionAuthorizationError

MAX_TOOL_ERROR_CHARS = 128
MAX_TOOL_ERROR_OUTPUT_CHARS = MAX_TOOL_ERROR_CHARS + 2


class _MissionBudgetExceeded(RuntimeError):
    def __init__(self, budget: str, limit: int) -> None:
        super().__init__(budget)
        self.budget = budget
        self.limit = limit


class MissionRuntime:
    """Persistent autonomous mission loop. Every slice is restart-safe and bounded."""

    def __init__(self, store: MissionStore, *, executor: Callable[[Mission, PlanStep, str], dict[str, Any]], authorizer: Callable[[Mission, PlanStep], tuple[bool, str]] | None = None, replanner: Callable[[Mission, dict[str, Any]], Plan] | None = None, verifier: Callable[[Mission], GoalVerification] | None = None, recovery_policy: RecoveryPolicy | None = None, interpreter: ObservationInterpreter | None = None, require_authorization_snapshot: bool = True, authorization_snapshot_factory: Callable[[Mission], Any] | None = None, execution_fence: ExecutionFence | None = None, require_execution_fence: bool = False, runtime_limits: RuntimeLimits | None = None, event_bus: Any = None, hook_registry: Any = None, task_graph_policy: AgentGraphPolicy | None = None, skill_context_provider: Callable[[Mission], Any] | None = None, specialist_generate: Callable[..., dict[str, Any]] | None = None, mission_memory_writer: Callable[[Mission], Any] | None = None):
        self.store = store
        self.executor = executor
        self.authorizer = authorizer or self._default_authorizer
        self.replanner = replanner or self._default_replanner
        self.verifier = verifier or self._default_verifier
        self.recovery_policy = recovery_policy or RecoveryPolicy()
        self.interpreter = interpreter or ObservationInterpreter()
        self.require_authorization_snapshot = require_authorization_snapshot
        self.authorization_snapshot_factory = authorization_snapshot_factory
        self.execution_fence = execution_fence
        self.require_execution_fence = bool(require_execution_fence)
        self.runtime_limits = runtime_limits if runtime_limits is not None else RuntimeLimits.from_owner_policy()
        if not isinstance(self.runtime_limits, RuntimeLimits):
            raise TypeError("MissionRuntime requires RuntimeLimits")
        if event_bus is not None or hook_registry is not None:
            from .intelligence_layer.events import EventBus, HookRegistry
            if event_bus is not None and not isinstance(event_bus, EventBus):
                raise TypeError("MissionRuntime event_bus must be an EventBus")
            if hook_registry is not None and not isinstance(hook_registry, HookRegistry):
                raise TypeError("MissionRuntime hook_registry must be a HookRegistry")
        self.event_bus = event_bus
        self.hook_registry = hook_registry
        self.skill_context_provider = skill_context_provider
        self.specialist_generate = specialist_generate
        if mission_memory_writer is not None and not callable(mission_memory_writer):
            raise TypeError("mission_memory_writer must be callable")
        self.mission_memory_writer = mission_memory_writer
        if task_graph_policy is not None and not isinstance(task_graph_policy, AgentGraphPolicy):
            raise TypeError("MissionRuntime task_graph_policy must be an AgentGraphPolicy")
        self.task_graph_adapter = MissionTaskGraphAdapter(task_graph_policy) if task_graph_policy is not None else None

    @staticmethod
    def _limit_value(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return 0
        return value

    def _owner_execution_step_limit(self, mission: Mission) -> int:
        current_limit = self._limit_value(self.runtime_limits.max_execution_steps)
        if not isinstance(mission.provenance, dict):
            raise _MissionBudgetExceeded("owner_execution_step_policy", 0)
        snapshots = mission.provenance.get("owner_runtime_limits")
        if snapshots is None:
            snapshots = {}
        if not isinstance(snapshots, dict):
            raise _MissionBudgetExceeded("owner_execution_step_policy", 0)
        if "max_execution_steps" not in snapshots:
            saved_limit = current_limit
        else:
            saved_limit = snapshots["max_execution_steps"]
            if isinstance(saved_limit, bool) or not isinstance(saved_limit, int) or saved_limit < 0:
                raise _MissionBudgetExceeded("owner_execution_step_policy", 0)
        effective_limit = min(saved_limit, current_limit)
        if snapshots.get("max_execution_steps") != effective_limit:
            snapshots = dict(snapshots)
            snapshots["max_execution_steps"] = effective_limit
            mission.provenance["owner_runtime_limits"] = snapshots
            self._save(mission)
        return effective_limit

    def _context_limits(self, model: Any = None) -> tuple[int, int]:
        # This is the model-input budget. MAX_PROVIDER_TEXT_CHARS separately
        # limits model-returned text and must not be applied to the request.
        # The provider's token cap is translated conservatively into a character
        # ceiling so durable state is compacted before dispatch, not after a 4xx.
        max_chars = self._limit_value(self.runtime_limits.max_context_chars)
        context_length = getattr(model, "context_length", None)
        if isinstance(context_length, int) and not isinstance(context_length, bool) and context_length > 0:
            max_chars = min(max_chars, context_length * 2)
        max_messages = self._limit_value(self.runtime_limits.max_context_messages)
        return max_chars, max_messages

    def _skill_context_for(self, mission: Mission) -> Any:
        if not mission.skill_binding:
            return None
        from .intelligence_layer.skills import MissionSkillContext, SkillAuthorizationError
        if self.skill_context_provider is None:
            raise SkillAuthorizationError("selected Skill has no live context validator")
        context = self.skill_context_provider(mission)
        if not isinstance(context, MissionSkillContext):
            raise SkillAuthorizationError("selected Skill context validator returned an invalid result")
        return context

    @staticmethod
    def _skill_dispatch_scope(mission: Mission, skill_context: Any, tool_name: str) -> Any:
        from .intelligence_layer.models import DelegationScope
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        parent = DelegationScope.from_snapshot(snapshot, owner_identity_ref=mission.owner_identity_ref)
        return skill_context.narrow_task_scope(parent, tool_name=tool_name)

    def _block_on_skill_context(self, mission: Mission) -> Mission:
        mission.error = "selected Skill context failed live validation"
        mission.failures.append({
            "class": FailureClass.AUTHORIZATION.value,
            "reason_code": "mission_skill_context_invalid",
        })
        mission.emit(EventType.FAILURE_DIAGNOSED, data={
            "class": FailureClass.AUTHORIZATION.value,
            "reason_code": "mission_skill_context_invalid",
            "recovery": "owner_review_required",
        })
        if not mission.is_terminal:
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
        return self._save(mission)

    @staticmethod
    def _tool_output_payload(value: dict[str, Any]) -> dict[str, Any]:
        # These fields are attached by MissionRuntime, not returned by the tool.
        runtime_fields = {"type", "action_id", "step_id", "mission_id", "tool_call_id"}
        return {key: item for key, item in value.items() if key not in runtime_fields}

    @classmethod
    def _output_usage(cls, progress: dict[str, Any], max_chars: int) -> tuple[int, bool]:
        from tools.registry import canonical_json_stats

        turns = progress.get("turns")
        tool_results = progress.get("tool_results")
        if not isinstance(turns, list) or not isinstance(tool_results, list):
            raise InvalidModelResponse("mission output history is malformed")
        used = 0
        for turn in turns:
            if not isinstance(turn, dict) or not isinstance(turn.get("content", ""), str):
                raise InvalidModelResponse("mission model output history is malformed")
            content_chars = len(turn.get("content", ""))
            if content_chars > max_chars - used:
                return max_chars, True
            used += content_chars
            calls = turn.get("tool_calls", [])
            if not isinstance(calls, list):
                raise InvalidModelResponse("mission model tool-output history is malformed")
            if calls:
                call_payloads = []
                for call in calls:
                    if not isinstance(call, dict) or not isinstance(call.get("name"), str) or not isinstance(call.get("arguments"), dict):
                        raise InvalidModelResponse("mission model tool-output history is malformed")
                    call_payloads.append({"name": call["name"], "arguments": call["arguments"]})
                size, _digest, truncated = canonical_json_stats(call_payloads, max_chars=max_chars - used)
                if truncated:
                    return max_chars, True
                used += size
        for item in tool_results:
            if not isinstance(item, dict) or not isinstance(item.get("result", {}), dict):
                raise InvalidModelResponse("mission tool output history is malformed")
            error = item.get("error", "")
            if not isinstance(error, str):
                raise InvalidModelResponse("mission tool error history is malformed")
            payload = cls._tool_output_payload(item.get("result", {}))
            size, _digest, truncated = canonical_json_stats(payload, max_chars=max_chars - used)
            if truncated:
                return max_chars, True
            used += size
            error_size, _error_digest, error_truncated = canonical_json_stats(error, max_chars=max_chars - used)
            if error_truncated:
                return max_chars, True
            used += error_size
        return used, False

    def _remaining_output_chars(self, progress: dict[str, Any]) -> int:
        limit = self._limit_value(self.runtime_limits.max_total_output_chars)
        if limit < 1:
            raise _MissionBudgetExceeded("max_total_output_chars", limit)
        try:
            used, exceeded = self._output_usage(progress, limit)
        except InvalidModelResponse:
            raise _MissionBudgetExceeded("model_loop_state", 0) from None
        if exceeded:
            raise _MissionBudgetExceeded("max_total_output_chars", limit)
        return limit - used

    def _allocate_result_caps(self, count: int, remaining_chars: int) -> list[int]:
        if count == 0:
            return []
        total_limit = self._limit_value(self.runtime_limits.max_total_output_chars)
        result_limit = self._limit_value(self.runtime_limits.max_result_chars)
        if result_limit < 128:
            raise _MissionBudgetExceeded("max_result_chars", result_limit)
        reservation_per_call = 128 + MAX_TOOL_ERROR_OUTPUT_CHARS
        if remaining_chars < count * reservation_per_call:
            raise _MissionBudgetExceeded("max_total_output_chars", total_limit)
        caps: list[int] = []
        result_remaining = remaining_chars - count * MAX_TOOL_ERROR_OUTPUT_CHARS
        for index in range(count):
            cap = min(result_limit, result_remaining - 128 * (count - index - 1))
            if cap < 128:
                raise _MissionBudgetExceeded("max_total_output_chars", total_limit)
            caps.append(cap)
            result_remaining -= cap
        return caps

    @staticmethod
    def _bounded_tool_error(value: Any) -> str:
        if not isinstance(value, str):
            return "invalid tool error"
        safe_value = "".join(character if character.isprintable() and character not in {'"', "\\"} else " " for character in value)
        if len(safe_value) <= MAX_TOOL_ERROR_CHARS:
            return safe_value
        suffix = "...[truncated]"
        return safe_value[: MAX_TOOL_ERROR_CHARS - len(suffix)] + suffix

    @staticmethod
    def _remaining_seconds(deadline: float) -> float:
        return max(0.0, deadline - time.monotonic())

    @staticmethod
    def _complete_with_timeout(model: Any, messages: Any, tools: Any, *, mission_id: str, run_id: str, turn_id: str, plan_version: int, timeout_seconds: float) -> Any:
        complete = model.complete
        kwargs = {
            "mission_id": mission_id,
            "run_id": run_id,
            "turn_id": turn_id,
            "plan_version": plan_version,
        }
        try:
            parameters = inspect.signature(complete).parameters.values()
            if any(parameter.name == "timeout_seconds" or parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters):
                kwargs["timeout_seconds"] = timeout_seconds
        except (TypeError, ValueError):
            pass
        return complete(messages, tools, **kwargs)

    @staticmethod
    def _canonical_model_tools(tools: Any) -> tuple[list[dict[str, Any]], set[str]]:
        from tools.registry import model_tool_definitions

        if not isinstance(tools, (list, tuple)):
            raise InvalidModelResponse("model tool definitions must be a list")
        canonical = model_tool_definitions()
        by_name = {item["function"]["name"]: item for item in canonical}
        normalized: list[dict[str, Any]] = []
        names: set[str] = set()
        for definition in tools:
            if not isinstance(definition, dict) or not isinstance(definition.get("function"), dict):
                raise InvalidModelResponse("model tool definition is malformed")
            name = definition["function"].get("name")
            expected = by_name.get(name) if isinstance(name, str) else None
            if expected is None or name in names or definition != expected:
                raise InvalidModelResponse("model tool definition does not match the canonical registry")
            names.add(name)
            normalized.append(model_tool_definitions([name])[0])
        return normalized, names

    @staticmethod
    def _bind_model_provenance(model: Any, turn: Any) -> Any:
        if isinstance(model, RouterNativeModel):
            instance_attributes = getattr(model, "__dict__", {})
            if type(model).complete is not RouterNativeModel.complete or "complete" in instance_attributes:
                raise InvalidModelResponse("router adapter subclass overrides trusted completion")
            trusted = (
                model.trusted_provider,
                model.trusted_model,
                model.trusted_capability,
            )
            if any(not isinstance(value, str) or not value.strip() for value in trusted):
                raise InvalidModelResponse("router adapter has incomplete trusted provenance")
            provider, model_name, capability = trusted
        else:
            provider = "native"
            model_name = f"{type(model).__module__}.{type(model).__qualname__}"
            if len(model_name) > MAX_PROVIDER_LABEL_CHARS:
                model_name = type(model).__qualname__[:MAX_PROVIDER_LABEL_CHARS]
            capability = "native"

        if (
            not isinstance(provider, str)
            or not provider.strip()
            or provider == "unknown"
            or len(provider) > MAX_PROVIDER_LABEL_CHARS
            or not isinstance(model_name, str)
            or not model_name.strip()
            or model_name == "unknown"
            or len(model_name) > MAX_PROVIDER_LABEL_CHARS
            or capability not in {"native", "tool_calling", "generate"}
        ):
            raise InvalidModelResponse("model adapter provenance is invalid")
        if turn.provider and turn.provider != provider:
            raise InvalidModelResponse("model returned mismatched provider provenance")
        if turn.model and turn.model != model_name:
            raise InvalidModelResponse("model returned mismatched model provenance")
        if turn.capability and turn.capability != capability:
            raise InvalidModelResponse("model returned mismatched capability provenance")
        if capability == "generate" and turn.tool_calls:
            raise InvalidModelResponse("generate-only fallback cannot dispatch tool calls")
        return replace(turn, provider=provider, model=model_name, capability=capability)

    @staticmethod
    def _history_for_preflight(progress: dict[str, Any]) -> tuple[set[str], set[str], dict[str, int], int]:
        turns = progress.get("turns", [])
        seen_ids = progress.get("seen_call_ids", [])
        if not isinstance(turns, list) or not isinstance(seen_ids, list):
            raise InvalidModelResponse("mission model-loop history is malformed")
        if any(not isinstance(item, str) or not item for item in seen_ids) or len(set(seen_ids)) != len(seen_ids):
            raise InvalidModelResponse("mission model-loop identity history is malformed")
        call_ids: set[str] = set()
        action_ids: set[str] = set()
        tool_counts: dict[str, int] = {}
        history_count = 0
        for turn_record in turns:
            if not isinstance(turn_record, dict):
                raise InvalidModelResponse("mission model-loop turn history is malformed")
            calls = turn_record.get("tool_calls", [])
            if not isinstance(calls, list):
                raise InvalidModelResponse("mission model-loop proposal history is malformed")
            for call in calls:
                if not isinstance(call, dict):
                    raise InvalidModelResponse("mission model-loop proposal history is malformed")
                call_id = call.get("tool_call_id")
                name = call.get("name")
                arguments = call.get("arguments")
                action_id = call.get("action_id")
                if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not isinstance(arguments, dict):
                    raise InvalidModelResponse("mission model-loop proposal history is malformed")
                if call_id in call_ids:
                    raise InvalidModelResponse("mission model-loop history contains duplicate call identities")
                call_ids.add(call_id)
                if isinstance(action_id, str) and action_id:
                    if action_id in action_ids:
                        raise InvalidModelResponse("mission model-loop history contains duplicate action identities")
                    action_ids.add(action_id)
                tool_counts[name] = tool_counts.get(name, 0) + 1
                history_count += 1
        if len(seen_ids) != history_count or set(seen_ids) != call_ids:
            raise InvalidModelResponse("mission model-loop call history is incomplete")
        return call_ids, action_ids, tool_counts, history_count

    def _preflight_model_turn(
        self,
        mission: Mission,
        turn: Any,
        *,
        expected_turn_id: str,
        run_id: str,
        current_step: Any,
        allowed_tool_names: set[str],
        auth_context: Any,
        progress: dict[str, Any],
    ) -> Any:
        if turn.turn_id != expected_turn_id:
            raise InvalidModelResponse("model returned a stale turn identity")
        output_remaining = self._remaining_output_chars(progress)
        if len(turn.content) > output_remaining:
            raise _MissionBudgetExceeded("max_total_output_chars", self._limit_value(self.runtime_limits.max_total_output_chars))
        output_remaining -= len(turn.content)
        if not turn.tool_calls:
            return turn

        from tools.registry import canonical_json_stats, get_tool

        historical_ids, action_ids, tool_counts, prior_call_count = self._history_for_preflight(progress)
        context_id = str(getattr(auth_context, "owner_evidence_fingerprint", "") or "") if auth_context is not None else ""
        scope_id = str(getattr(getattr(auth_context, "scope_snapshot", None), "snapshot_id", "") or "") if auth_context is not None else ""
        expected_step_id = str(getattr(current_step, "step_id", "") or "")
        current_ids: set[str] = set()
        current_actions: set[str] = set()
        normalized: list[Any] = []

        for proposal in turn.tool_calls:
            # These four fields are explicit inputs to NativeModel.complete;
            # missing values are not wildcards and must never be rebound.
            if proposal.mission_id != mission.mission_id:
                raise InvalidModelResponse("model proposed a cross-mission tool call")
            if proposal.run_id != run_id:
                raise InvalidModelResponse("model proposed a stale run identity")
            if proposal.plan_version != mission.plan.version:
                raise InvalidModelResponse("model proposed a stale plan identity")
            # These identifiers are runtime-owned, not NativeModel inputs. Empty
            # fields are filled from authoritative state; supplied stale values
            # are rejected by the checks below.
            if proposal.request_id and proposal.request_id != mission.request_id:
                raise InvalidModelResponse("model proposed a stale request identity")
            if proposal.step_id and proposal.step_id != expected_step_id:
                raise InvalidModelResponse("model proposed a stale plan step")
            if proposal.authorization_context_id and proposal.authorization_context_id != context_id:
                raise InvalidModelResponse("model proposed a stale authorization identity")
            if proposal.scope_snapshot_id and proposal.scope_snapshot_id != scope_id:
                raise InvalidModelResponse("model proposed a stale scope identity")
            if proposal.tool_call_id in historical_ids or proposal.tool_call_id in current_ids:
                raise InvalidModelResponse("model proposed a duplicate tool-call identity")
            if proposal.name not in allowed_tool_names:
                raise InvalidModelResponse("model requested a tool not declared for this turn")
            spec = get_tool(proposal.name)
            if spec is None:
                raise InvalidModelResponse("model requested an unknown tool")
            valid, _reason, _argument = spec.validate_input(proposal.arguments)
            if not valid:
                raise InvalidModelResponse("model proposed arguments rejected by the registered schema")

            expected_action_id = derive_action_id(mission.mission_id, expected_turn_id, proposal.tool_call_id)
            if proposal.action_id and proposal.action_id != expected_action_id:
                raise InvalidModelResponse("model proposed an invalid action identity")
            action_id = expected_action_id
            if action_id in action_ids or action_id in current_actions:
                raise InvalidModelResponse("model proposed a duplicate action identity")
            tool_counts[proposal.name] = tool_counts.get(proposal.name, 0) + 1
            current_ids.add(proposal.tool_call_id)
            current_actions.add(action_id)
            normalized.append(replace(
                proposal,
                mission_id=mission.mission_id,
                run_id=run_id,
                request_id=mission.request_id,
                plan_version=mission.plan.version,
                step_id=proposal.step_id or expected_step_id,
                action_id=action_id,
                authorization_context_id=context_id,
                scope_snapshot_id=scope_id,
            ))

        max_tool_calls = self._limit_value(self.runtime_limits.max_tool_calls)
        if prior_call_count + len(normalized) > max_tool_calls:
            raise _MissionBudgetExceeded("max_tool_calls", max_tool_calls)
        max_same_tool_calls = self._limit_value(self.runtime_limits.max_same_tool_calls)
        if any(count > max_same_tool_calls for count in tool_counts.values()):
            raise _MissionBudgetExceeded("max_same_tool_calls", max_same_tool_calls)
        call_payloads = [{"name": item.name, "arguments": item.arguments} for item in normalized]
        call_output_chars, _call_output_sha256, truncated = canonical_json_stats(call_payloads, max_chars=output_remaining)
        if truncated:
            raise _MissionBudgetExceeded("max_total_output_chars", self._limit_value(self.runtime_limits.max_total_output_chars))
        output_remaining -= call_output_chars
        self._allocate_result_caps(len(normalized), output_remaining)
        return replace(turn, tool_calls=tuple(normalized))

    def set_execution_fence(self, execution_fence: ExecutionFence) -> None:
        if not isinstance(execution_fence, ExecutionFence) or execution_fence.lease_epoch is None:
            raise ExecutionFenceError("runtime requires a leased execution fence")
        self.execution_fence = execution_fence

    def bind_execution_claim(self, mission_id: str, execution_fence: ExecutionFence) -> MissionClaimBinding:
        """Persist a mission-side claim marker before MissionQueue permits tool dispatch."""
        self.set_execution_fence(execution_fence)
        mission = self._load(mission_id)
        claim_fence = self._fence_for(mission)
        if claim_fence is None:
            raise ExecutionFenceError("mission claim binding requires an execution fence")
        marker_id = self.store.bind_execution_claim(mission_id, claim_fence)
        self.execution_fence = claim_fence
        return marker_id

    def _fence_for(self, mission: Mission, *, task_id: str | None = None, execution_id: str | None = None) -> ExecutionFence | None:
        if self.execution_fence is None:
            if self.require_execution_fence:
                raise ExecutionFenceError("mission runtime execution fence is required")
            return None
        return self.execution_fence.for_mission(mission, task_id=task_id, execution_id=execution_id)

    def _save(self, mission: Mission, *, execution_fence: ExecutionFence | None = None) -> Mission:
        fence = execution_fence or self._fence_for(mission)
        if fence is None:
            if self.require_execution_fence:
                raise ExecutionFenceError("mission state mutation requires an execution fence")
            saved = self.store.save(mission)
        else:
            saved = self.store.save(mission, execution_fence=fence)
        if saved.is_terminal and self.mission_memory_writer is not None:
            try:
                self.mission_memory_writer(saved)
            except Exception:
                # Optional memory persistence must never change a committed
                # Mission outcome or cause a replay of its external effects.
                import logging
                logging.getLogger(__name__).warning("mission_episode_memory_persist_failed")
        return saved

    @staticmethod
    def _executor_accepts_fence(executor: Callable[..., Any]) -> bool:
        try:
            parameters = inspect.signature(executor).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(
            parameter.name == "execution_fence" or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )

    @staticmethod
    def _executor_accepts_delegation(executor: Callable[..., Any]) -> bool:
        try:
            parameters = inspect.signature(executor).parameters.values()
        except (TypeError, ValueError):
            return False
        accepts = any(
            parameter.name == "delegation_scope" or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        function = getattr(executor, "__func__", executor)
        return accepts and getattr(function, "task_delegation_scope_enforced", False) is True

    def persist_execution_state(self, mission: Mission) -> Mission:
        """Persist execution-owned metadata before the worker releases its lease."""
        return self._save(mission)

    def _mission_authorization(self, mission: Mission) -> tuple[bool, str]:
        if not self.require_authorization_snapshot:
            raise RuntimeError("authorization snapshot bypass is not supported")
        try:
            from security.mission_authorization import MissionAuthorizationSnapshot
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            scope = mission.scope_snapshot if isinstance(mission.scope_snapshot, dict) else {}
            target = str(scope.get("target_id") or snapshot.target_identity)
            expected_version = int(mission.provenance.get("authorization_snapshot_version", 1))
            valid, reason = snapshot.validate_for_mission(mission_id=mission.mission_id, owner_identity=mission.owner_identity_ref, target_identity=target, version=expected_version)
            if not valid:
                return False, reason
            actions = {step.action for step in mission.plan.steps if step.action != "__planning_failure__"}
            if actions - set(snapshot.allowed_actions) or actions - set(snapshot.allowed_tools) or actions.intersection(snapshot.forbidden_actions):
                return False, "mission actions or tools outside authorization snapshot"
            expected_root = str(scope.get("workspace_root", ""))
            if expected_root and str(snapshot.workspace_boundary.get("root", "")) != expected_root:
                return False, "workspace boundary mismatch"
            expected_network = set(scope.get("allowed_networks", ()))
            if expected_network != set(snapshot.network_boundary.get("allowed", ())):
                return False, "network boundary mismatch"
            expected_credentials = set(scope.get("allowed_credentials", ()))
            if expected_credentials != set(snapshot.credential_boundary.get("allowed", ())):
                return False, "credential boundary mismatch"
            return True, "authorized"
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return False, f"authorization snapshot invalid: {type(exc).__name__}"

    @staticmethod
    def _typed_mission_snapshot(mission: Mission) -> Any:
        from security.mission_authorization import MissionAuthorizationSnapshot
        return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))

    def _specialist_memory_context(self, mission: Mission) -> list[dict[str, Any]]:
        """Explicit parent read: validate persisted Mission, graph refs and each untrusted record."""
        if self.task_graph_adapter is None:
            return []
        from .intelligence_layer.specialist_memory import (
            MAX_SPECIALIST_MEMORY_PARENT_BYTES,
            MAX_SPECIALIST_MEMORY_PARENT_RECORDS,
            SpecialistChildMemoryStore,
            SpecialistMemoryError,
        )

        persisted = self.store.load(mission.mission_id)
        if (
            persisted is None
            or not persisted.verify_integrity()
            or persisted.mission_id != mission.mission_id
            or persisted.owner_identity_ref != mission.owner_identity_ref
            or persisted.plan.fingerprint != mission.plan.fingerprint
            or persisted.authorization_snapshot != mission.authorization_snapshot
        ):
            raise SpecialistMemoryError("parent_memory_mission_integrity_invalid")
        authorized, _reason = self._mission_authorization(persisted)
        if not authorized:
            raise SpecialistMemoryError("parent_memory_authorization_invalid")
        snapshot = self._typed_mission_snapshot(persisted)
        nested = self.task_graph_adapter._specialist_envelope(persisted, snapshot)
        if nested is None:
            return []
        graph, mapping, _envelope = nested
        memory_store = SpecialistChildMemoryStore()
        authorization_version = self.task_graph_adapter._expected_authorization_version(persisted)
        candidates: list[tuple[str, str, str]] = []
        for step in persisted.plan.steps:
            step_id = str(step.step_id)
            task_id = mapping.get(step_id)
            task = graph.tasks.get(task_id) if task_id else None
            if task is not None and task.lifecycle.value == "COMPLETED" and task.memory_refs:
                candidates.append((step_id, str(task_id), task.memory_refs[0]))

        selected = candidates[-MAX_SPECIALIST_MEMORY_PARENT_RECORDS:]
        records: list[dict[str, Any]] = []
        total_bytes = 0
        for step_id, task_id, memory_ref in selected:
            record = memory_store.retrieve_for_parent(
                mission=persisted,
                snapshot=snapshot,
                graph=graph,
                task_id=task_id,
                step_id=step_id,
                memory_ref=memory_ref,
                authorization_version=authorization_version,
            )
            record_bytes = len(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            if total_bytes + record_bytes > MAX_SPECIALIST_MEMORY_PARENT_BYTES:
                break
            records.append(record)
            total_bytes += record_bytes
        return records

    def _block_on_task_graph(self, mission: Mission, error: Exception) -> Mission:
        reason = f"agent task graph rejected dispatch: {type(error).__name__}"
        mission.error = reason
        mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": reason, "boundary": "agent_task_graph"})
        mission.emit(EventType.FAILURE_DIAGNOSED, step_id=str(getattr(mission.current_plan_step, "step_id", "")), data={
            "class": FailureClass.UNKNOWN.value,
            "reason": reason,
            "recovery": "owner_review_required",
        })
        mission.transition(MissionStatus.SAFETY_BLOCKED, reason)
        return self._save(mission)

    def request_agent_task_cancellation(self, mission: Mission) -> None:
        """Record graph cancellation after the caller has authenticated Owner control."""
        if self.task_graph_adapter is None:
            return
        try:
            self.task_graph_adapter.cancel(mission)
        except MissionTaskGraphError:
            # Mission cancellation/recovery remains authoritative; a graph audit
            # failure must never turn an Owner cancellation into permission to run.
            mission.recovery_events.append({"event": "agent_task_graph_cancellation_requires_review"})

    @staticmethod
    def _default_authorizer(mission: Mission, step: PlanStep) -> tuple[bool, str]:
        if step.authorization_requirement and not mission.authorization_context:
            return False, "owner authorization required"
        if step.authorization_requirement:
            try:
                from security.authorization_context import AuthorizationContext
                AuthorizationContext.from_dict(dict(mission.authorization_context or {}))
            except (KeyError, TypeError, ValueError, PermissionError):
                return False, "owner authorization evidence is invalid or stale"
        if step.scope_requirement and not mission.scope_snapshot:
            return False, "scope snapshot required"
        return True, "authorized"

    @staticmethod
    def _default_replanner(mission: Mission, observation: dict[str, Any]) -> Plan:
        step = mission.current_plan_step
        repair = PlanStep(step_id=f"repair-{mission.plan.version}-{mission.current_step + 1}", objective=f"Repair after observation: {observation.get('error', 'failure')}", action=step.action, expected_observation="successful retry", authorization_requirement=step.authorization_requirement, scope_requirement=step.scope_requirement, verification=step.verification) if step else PlanStep("repair", "recover mission", action="recover")
        return mission.plan.replan(steps=(repair,), assumptions=("previous action failed; repair strategy selected",), reason="observation invalidated prior assumption")

    @staticmethod
    def _default_verifier(mission: Mission) -> GoalVerification:
        criteria = tuple(VerificationCriterion(item["criterion_id"], item.get("description", item["criterion_id"]), item.get("check", "runtime"), item.get("required", True)) for item in mission.completion_criteria)
        evidence = tuple(evidence_for(item["criterion_id"], item.get("passed", False), item.get("source", "mission"), item.get("result", {}), provenance={"mission_id": mission.mission_id}) for item in mission.evidence)
        return GoalVerification.evaluate(mission.objective, criteria, evidence)

    @staticmethod
    def _verification_result_payload(observation: dict[str, Any]) -> dict[str, Any]:
        result = observation.get("result")
        return result if isinstance(result, dict) else observation

    @staticmethod
    def _successful_observation_evidence(
        mission: Mission,
        observation: dict[str, Any],
        *,
        tool_name: str,
        tool_argument: Any = None,
    ) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(observation, dict):
            return None
        criteria = [item for item in mission.completion_criteria if isinstance(item, dict)]
        objective_tokens = set(re.findall(r"[a-z]+", str(mission.objective or "").casefold()))
        explicitly_requests_tests = bool(objective_tokens & {"test", "tests", "testing", "pytest"}) and bool(
            objective_tokens & {"run", "execute", "verify"}
        )
        required = [item for item in criteria if item.get("required", True) is not False]
        result = MissionRuntime._verification_result_payload(observation)

        if tool_name == "run_project_tests" and explicitly_requests_tests:
            if isinstance(result, dict) and (
                result.get("ok") is True
                and type(result.get("returncode")) is int
                and result.get("returncode") == 0
                and result.get("timed_out") is False
            ):
                for item in required:
                    check = str(item.get("check", "runtime")).casefold()
                    criterion_id = str(item.get("criterion_id") or "")
                    if criterion_id and check in {"pytest", "pytest_success", "test_result"}:
                        return criterion_id, result

        status_requested = bool(objective_tokens & {"status", "health"}) or "حالة" in str(mission.objective or "")
        if tool_name == "status" and status_requested:
            try:
                from core.engine import status as read_independent_status

                independent_status = read_independent_status()
            except Exception:
                independent_status = None
            counts = independent_status.get("event_counts") if isinstance(independent_status, dict) else None
            status_valid = (
                isinstance(independent_status, dict)
                and isinstance(independent_status.get("service"), str)
                and bool(independent_status.get("service"))
                and isinstance(independent_status.get("version"), str)
                and independent_status.get("online") is True
                and isinstance(counts, dict)
                and all(isinstance(key, str) and type(value) is int and value >= 0 for key, value in counts.items())
                and type(independent_status.get("watch_count")) is int
                and independent_status.get("watch_count") >= 0
                and isinstance(independent_status.get("watches"), list)
                and isinstance(independent_status.get("llm"), list)
                and isinstance(independent_status.get("agent"), dict)
                and isinstance(independent_status.get("owner_policy"), dict)
                and isinstance(independent_status.get("recent_events"), list)
            )
            if status_valid:
                for item in required:
                    check = str(item.get("check", "runtime")).casefold()
                    criterion_id = str(item.get("criterion_id") or "")
                    if criterion_id and check in {"status_snapshot", "system_status"}:
                        return criterion_id, independent_status

        watch_requested = "watch" in objective_tokens and bool(objective_tokens & {"register", "add", "create", "monitor"})
        if tool_name == "watch" and watch_requested and isinstance(tool_argument, str) and tool_argument.strip():
            try:
                from core.db import watches

                persisted_watches = watches()
            except Exception:
                persisted_watches = []
            if any(isinstance(item, str) and item.casefold() == tool_argument.strip().casefold() for item in persisted_watches):
                for item in required:
                    check = str(item.get("check", "runtime")).casefold()
                    criterion_id = str(item.get("criterion_id") or "")
                    if criterion_id and check in {"watch_registered", "local_watch"}:
                        return criterion_id, {"keyword": tool_argument.strip(), "persisted": True}
        return None

    @staticmethod
    def _verification_authority(tool_name: str) -> str:
        return {
            "run_project_tests": "project_test_process_exit",
            "status": "validated_status_snapshot",
            "watch": "persisted_watch_store",
        }.get(tool_name, "")

    def create(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> Mission:
        snapshot_factory = kwargs.pop("authorization_snapshot_factory", None) or self.authorization_snapshot_factory
        planning_failures = kwargs.pop("planning_failures", None)
        planning_exhausted = bool(kwargs.pop("planning_exhausted", False))
        mission = Mission.create(owner_request, objective, plan, **kwargs)
        if mission.authorization_snapshot is None and snapshot_factory is not None:
            snapshot = snapshot_factory(mission)
            if snapshot is not None:
                mission.authorization_snapshot = snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot)
        if mission.authorization_snapshot:
            mission.provenance["authorization_snapshot_version"] = int(mission.authorization_snapshot.get("version", 1))
        mission.provenance["owner_runtime_limits"] = {
            "max_execution_steps": self._limit_value(self.runtime_limits.max_execution_steps),
        }
        if self.task_graph_adapter is not None:
            if not mission.authorization_snapshot:
                raise MissionTaskGraphError("graph-backed missions require a persisted authorization snapshot")
            self.task_graph_adapter.ensure(mission, self._typed_mission_snapshot(mission))
        if planning_failures:
            for item in planning_failures:
                if not isinstance(item, dict):
                    continue
                failure = dict(item)
                failure.setdefault("mission_id", mission.mission_id)
                failure.setdefault("request_id", mission.request_id)
                mission.failures.append(failure)
                mission.progress.setdefault("model_failures", []).append(failure)
                attempt_number = failure.get("provider_attempt")
                if isinstance(attempt_number, int) and not isinstance(attempt_number, bool):
                    mission.retry_count = max(mission.retry_count, attempt_number)
                mission.emit(EventType.FAILURE_DETECTED, data=failure)
                mission.emit(EventType.FAILURE_DIAGNOSED, data={
                    "class": failure.get("class", "PROVIDER"),
                    "kind": failure.get("kind", "PROVIDER_FAILURE"),
                    "recovery": failure.get("retry_policy", {}).get("action", "FAIL"),
                })
            if planning_exhausted:
                final_failure = next((item for item in reversed(mission.failures) if item.get("run_id")), mission.failures[-1])
                kind = str(final_failure.get("kind", "PROVIDER_FAILURE"))
                status_code = final_failure.get("http_status")
                error_prefix = "model planning failure" if final_failure.get("class") == "LOGIC" else "model provider failure"
                mission.error = f"{error_prefix}: {kind}" + (f" (HTTP {status_code})" if status_code is not None else "")
                mission.transition(
                    MissionStatus.FAILED_RETRY_EXHAUSTED,
                    "initial planning failed under bounded recovery policy",
                    failure_class=final_failure.get("class", "PROVIDER"),
                    kind=kind,
                    retry_count=mission.retry_count,
                    max_retries=final_failure.get("retry_policy", {}).get("max_retries", 0),
                )
            else:
                mission.transition(MissionStatus.READY, "plan persisted after bounded planning recovery", prior_provider_failures=len(planning_failures))
        else:
            mission.transition(MissionStatus.READY, "plan persisted")
        return self.store.save(mission)

    def create_from_owner_instruction(self, instruction: str, plan: Plan, *, authorization_context: Any, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, owner_identity_ref: str = "", provenance: dict[str, Any] | None = None, authorization_snapshot_factory: Callable[[Mission], Any] | None = None, planning_failures: list[dict[str, Any]] | None = None, planning_exhausted: bool = False, mission_id: str | None = None, skill_binding: dict[str, Any] | None = None) -> Mission:
        """Create a Mission without allowing model understanding to rewrite the Owner objective."""
        from security.authorization_context import AuthorizationContext
        if not isinstance(authorization_context, AuthorizationContext):
            raise TypeError("Owner Instruction requires typed AuthorizationContext")
        objective = str(instruction).strip()
        if not objective:
            raise ValueError("Owner Instruction cannot be empty")
        if authorization_context.session_id:
            from security.owner_password import authenticated_owner
            owner = authenticated_owner(authorization_context.session_id)
            if owner is None:
                raise PermissionError("active Owner session is required to bind mission identity")
            stable_owner_ref = f"owner:{int(owner['owner_id'])}"
            if owner_identity_ref and owner_identity_ref != stable_owner_ref:
                raise PermissionError("mission Owner identity does not match the authenticated account")
            owner_identity_ref = stable_owner_ref
        else:
            owner_identity_ref = owner_identity_ref or authorization_context.owner_evidence_fingerprint
        return self.create(
            objective,
            objective,
            plan,
            request_id=authorization_context.request_id,
            owner_identity_ref=owner_identity_ref,
            owner_instruction=objective,
            authorization_context=authorization_context.to_dict(),
            scope_snapshot=scope_snapshot,
            policy_snapshot=authorization_context.policy_snapshot.to_dict(),
            completion_criteria=completion_criteria,
            mission_id=mission_id,
            skill_binding=skill_binding,
            provenance={"source": "owner_instruction", **(provenance or {})},
            authorization_snapshot_factory=authorization_snapshot_factory,
            planning_failures=planning_failures,
            planning_exhausted=planning_exhausted,
        )

    def provide_owner_decision(self, mission_id: str, *, allow: bool, authorization_context: dict[str, Any] | None = None, execution_fence: ExecutionFence | None = None) -> Mission:
        if self.require_execution_fence and execution_fence is None:
            raise ExecutionFenceError("Owner decision requires its authorized control-plane workflow")
        mission = self._load(mission_id)
        if mission.status is not MissionStatus.OWNER_INPUT_REQUIRED:
            raise ValueError("mission is not waiting for owner input")
        if not allow:
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": "owner denied action"})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, "owner denied")
        else:
            mission.authorization_context = authorization_context or {"owner_decision": "allow"}
            mission.transition(MissionStatus.READY, "owner allowed action")
        return self._save(mission, execution_fence=execution_fence)

    def _load(self, mission_id: str) -> Mission:
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission

    def _interpret_observation(self, mission: Mission, step: PlanStep, observation: dict[str, Any], *, success: bool):
        previous = mission.observations[-2] if len(mission.observations) > 1 else None
        if not should_interpret_observation(observation, previous=previous):
            return None
        proposal = self.interpreter.interpret(
            mission=mission.to_dict(),
            plan=mission.plan.to_dict(),
            current_step=step.to_dict(),
            action=step.action,
            observation=observation,
            evidence=mission.evidence,
            hypothesis_state=mission.hypotheses,
            knowledge_context=mission.knowledge_context,
            conversation_context=(),
        )
        engine = HypothesisEngine(HypothesisState.from_dict(item) for item in mission.hypotheses)
        hypothesis_updates = engine.apply(proposal, goal_verified=False, deterministic_validation=False)
        mission.hypotheses = engine.snapshot()
        # Interpreter output is analysis only, regardless of whether its fields
        # originated in a model proposal or in untrusted tool output. Completion
        # evidence is issued only by tool-specific deterministic verifiers.
        mission.knowledge_context = list(mission.knowledge_context)
        mission.interpretations.append(proposal.to_dict())
        mission.emit(EventType.OBSERVATION_INTERPRETED, step_id=step.step_id, data=proposal.to_dict())
        if hypothesis_updates:
            mission.emit(EventType.HYPOTHESIS_UPDATED, step_id=step.step_id, data={"updates": hypothesis_updates})
        scope_blocked = False
        target = observation.get("target")
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        if target and isinstance(allowed_targets, (list, tuple, set)) and str(target) not in {str(item) for item in allowed_targets}:
            scope_blocked = True
        decision = decide_strategy(proposal, action_success=success, scope_blocked=scope_blocked)
        mission.strategy_decisions.append(decision.to_dict())
        strategy = StrategyState.from_dict(mission.strategy_state, objective=mission.objective)
        if decision.next_strategy:
            strategy.current_strategy = decision.next_strategy
            strategy.version += 1
        strategy.known_facts.extend(proposal.facts)
        strategy.unknowns.extend(proposal.unknowns)
        strategy.required_evidence.extend(proposal.required_next_evidence)
        mission.strategy_state = strategy.to_dict()
        mission.emit(EventType.STRATEGY_DECIDED, step_id=step.step_id, data=decision.to_dict())
        return decision

    def reconcile_in_flight(self, mission_id: str, *, executed: bool, observation: dict[str, Any] | None = None, execution_fence: ExecutionFence | None = None) -> Mission:
        """Reject unsigned boolean outcomes; use EffectReconciliationEngine.

        Retained as a fail-closed compatibility surface so old clients cannot
        turn a caller assertion into mission evidence or a retry permission.
        """
        raise ExecutionFenceError(
            "in-flight reconciliation requires authenticated Owner authorization through EffectReconciliationEngine"
        )

    def _execute_native_tool(
        self,
        name: str,
        argument: Any,
        authorization_decision: Any,
        mission: Mission,
        execution_fence: ExecutionFence | None,
        execution_id: str,
        *,
        timeout_seconds: float | None = None,
        max_result_chars: int | None = None,
        delegation_scope: Any = None,
    ) -> Any:
        """Dispatch native-model tools with the same strict workspace/evidence boundary."""
        from tools.registry import execute as execute_tool, get_tool

        spec = get_tool(name)
        if spec is None:
            raise ValueError("unknown tool")
        timeout = None
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise _MissionBudgetExceeded("max_execution_time_seconds", self._limit_value(self.runtime_limits.max_execution_time_seconds))
            timeout = min(timeout_seconds, spec.timeout)

        workspace = None
        evidence_store = None
        target_identity = None
        mission_authorization = mission.authorization_snapshot
        owner_authorization = None
        if name == "run_project_tests" or spec.execution_context_required:
            if execution_fence is None:
                raise ExecutionFenceError("native Mission tool dispatch requires an execution fence")
            if (
                not execution_fence.queue.require_execution_fence
                or execution_fence.queue.mission_store is not self.store
            ):
                raise ExecutionFenceError("native Mission tool dispatch requires its strict queue and MissionStore")
            execution_fence.assert_active_execution(mission)
            from security.mission_authorization import MissionAuthorizationSnapshot
            from .evidence import EvidenceChainStore

            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            mission_authorization = snapshot
            workspace_root = ""
            if spec.workspace_scope_required:
                workspace_root = str(snapshot.workspace_boundary.get("root", "")).strip()
                if not workspace_root:
                    raise ExecutionFenceError("native workspace dispatch requires the Owner-authorized workspace root")
            evidence_store = EvidenceChainStore(
                Path(self.store.db_path).with_name("evidence_chain.db"),
                execution_fence=execution_fence,
                mission_store=self.store,
                mission=mission,
                require_execution_fence=True,
            )
            if spec.workspace_scope_required:
                from workspace import Workspace
                workspace = Workspace(
                    workspace_root,
                    authorization_snapshot=snapshot,
                    mission_id=mission.mission_id,
                    request_id=mission.request_id,
                    tool_id=name,
                    evidence_store=evidence_store,
                )
            if spec.execution_context_required:
                from security.authorization_context import AuthorizationContext
                if not isinstance(mission.authorization_context, dict):
                    raise ExecutionFenceError("native context-required tool dispatch requires the persisted Owner authorization record")
                owner_authorization = AuthorizationContext.from_dict(dict(mission.authorization_context))
            target_identity = (
                str((mission.scope_snapshot or {}).get("target_id") or snapshot.target_identity)
                if isinstance(mission.scope_snapshot, dict)
                else snapshot.target_identity
            )

        return execute_tool(
            name,
            argument,
            authorization_decision=authorization_decision,
            scope_context=mission.scope_snapshot,
            request_id=mission.request_id,
            mission_authorization=mission_authorization,
            mission_authorization_version=int(mission.provenance.get("authorization_snapshot_version", 1)),
            owner_authorization=owner_authorization,
            owner_authorization_record=dict(mission.authorization_context or {}) if spec.execution_context_required else None,
            workspace=workspace,
            evidence_store=evidence_store,
            mission_id=mission.mission_id,
            target_identity=target_identity,
            execution_fence=execution_fence,
            execution_id=execution_id,
            timeout=timeout,
            max_result_chars=max_result_chars,
            event_bus=self.event_bus,
            hook_registry=self.hook_registry,
            delegation_scope=delegation_scope,
            scope_ref=(delegation_scope.scope[0] if delegation_scope is not None and delegation_scope.scope else None),
        )

    def _block_on_budget(self, mission: Mission, budget: str, limit: int) -> Mission:
        mission.error = f"mission runtime budget exceeded: {budget}"
        failure = {
            "class": FailureClass.RESOURCE.value,
            "reason": mission.error,
            "budget": budget,
            "limit": limit,
        }
        mission.failures.append(failure)
        mission.emit(EventType.FAILURE_DETECTED, data=failure)
        mission.emit(EventType.FAILURE_DIAGNOSED, data={
            "class": FailureClass.RESOURCE.value,
            "budget": budget,
            "recovery": RecoveryAction.RESOURCE_BLOCKED.value,
        })
        mission.transition(MissionStatus.RESOURCE_BLOCKED, mission.error)
        return self._save(mission)

    def _complete_from_verified_evidence_after_budget(self, mission: Mission, *, budget: str, limit: int, run_id: str, turn_id: str) -> Mission | None:
        """Complete only when required deterministic evidence already proves the goal."""
        verification = self.verifier(mission)
        if not verification.verified:
            return None
        mission.verification_state = {
            "verified": True,
            "missing_criteria": list(verification.missing_criteria),
            "evidence_count": len(verification.evidence),
        }
        reason = f"final model turn was not generated because {budget} exceeded its configured budget after required evidence was verified"
        failure = {
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
            "run_id": run_id,
            "turn_id": turn_id,
            "class": FailureClass.RESOURCE.value,
            "kind": "FINAL_MODEL_TURN_BUDGET",
            "reason": reason,
            "budget": budget,
            "limit": limit,
            "blocking": False,
            "retry_policy": {
                "configured_recovery": RecoveryAction.RESOURCE_BLOCKED.value,
                "action": "complete_from_verified_evidence",
                "retryable": False,
                "attempts": 0,
            },
        }
        mission.failures.append(failure)
        mission.progress.setdefault("nonblocking_finalization_failures", []).append(failure)
        mission.progress["final_model_turn"] = {
            "status": "not_generated_resource_limited",
            "reason": reason,
            "budget": budget,
            "limit": limit,
            "run_id": run_id,
            "turn_id": turn_id,
        }
        mission.emit(EventType.FAILURE_DETECTED, data=failure)
        mission.emit(EventType.FAILURE_DIAGNOSED, data={
            "class": FailureClass.RESOURCE.value,
            "kind": failure["kind"],
            "recovery": "complete_from_verified_evidence",
            "run_id": run_id,
            "turn_id": turn_id,
        })
        mission.transition(
            MissionStatus.GOAL_COMPLETED,
            "required deterministic evidence verified; final model turn was budget-blocked",
            run_id=run_id,
            turn_id=turn_id,
            budget=budget,
            limit=limit,
            final_model_generated=False,
        )
        mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
        mission.emit(EventType.MISSION_COMPLETED, data={
            "verification": mission.verification_state,
            "completion_source": "deterministic_evidence",
            "final_model_generated": False,
        })
        return self._save(mission)

    def run_model_loop(self, mission_id: str, model: NativeModel, *, tools: list[dict[str, Any]], run_id: str = "", max_turns: int = 20, heartbeat: Callable[[], None] | None = None) -> Mission:
        """Run a real model/tool/observation loop for a durable mission."""
        from security.authorization import authorize_tool
        from security.authorization_context import AuthorizationContext

        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        if (mission.checkpoint or {}).get("status") in {"in_flight", "in_flight_parallel"}:
            reference_mismatch = bool(mission.skill_binding) and (mission.checkpoint or {}).get("skill_reference") != mission.skill_binding
            mission.error = (
                "in-flight native Skill reference does not match the Mission binding; reconciliation required"
                if reference_mismatch
                else "in-flight native tool outcome is unknown; reconciliation required"
            )
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return self._save(mission)
        try:
            initial_skill_context = self._skill_context_for(mission)
        except Exception:
            return self._block_on_skill_context(mission)
        model_tools, allowed_tool_names = self._canonical_model_tools(tools)
        if initial_skill_context is not None:
            allowed_tool_names.intersection_update(initial_skill_context.binding.required_tools)
            model_tools = [item for item in model_tools if item.get("function", {}).get("name") in allowed_tool_names]
            if not allowed_tool_names:
                return self._block_on_skill_context(mission)
        run_id = run_id or str(mission.progress.get("model_run_id") or hashlib.sha256((mission.mission_id + mission.request_id).encode()).hexdigest()[:20])
        mission.progress["model_run_id"] = run_id
        progress = mission.progress.setdefault("model_loop", {"turns": [], "tool_results": [], "seen_call_ids": []})
        progress.setdefault("turns", [])
        progress.setdefault("tool_results", [])
        progress.setdefault("seen_call_ids", [])
        if (
            not isinstance(progress["turns"], list)
            or not isinstance(progress["tool_results"], list)
            or not isinstance(progress["seen_call_ids"], list)
            or any(not isinstance(item, str) or not item for item in progress["seen_call_ids"])
            or len(set(progress["seen_call_ids"])) != len(progress["seen_call_ids"])
        ):
            return self._block_on_budget(mission, "model_loop_state", 0)
        try:
            max_execution_steps = self._owner_execution_step_limit(mission)
        except _MissionBudgetExceeded as exc:
            return self._block_on_budget(mission, exc.budget, exc.limit)
        if max_execution_steps < 1 or len(progress["turns"]) >= max_execution_steps:
            return self._block_on_budget(mission, "max_execution_steps", max_execution_steps)
        if isinstance(max_turns, bool) or not isinstance(max_turns, int) or max_turns < 0:
            return self._block_on_budget(mission, "max_execution_steps", max_execution_steps)
        turn_budget = min(max_turns, max_execution_steps - len(progress["turns"]))
        seen = set(progress["seen_call_ids"])
        context_char_limit, context_message_limit = self._context_limits(model)
        if context_char_limit < 1:
            return self._block_on_budget(mission, "max_context_chars", context_char_limit)
        execution_time_limit = self._limit_value(self.runtime_limits.max_execution_time_seconds)
        if execution_time_limit < 1:
            return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
        deadline = time.monotonic() + execution_time_limit
        auth_context = None
        if mission.authorization_context:
            try:
                auth_context = AuthorizationContext.from_dict(dict(mission.authorization_context))
            except (KeyError, TypeError, ValueError, PermissionError):
                auth_context = None

        retryable_provider_failure = False
        for _ in range(turn_budget):
            if len(progress["turns"]) >= max_execution_steps:
                return self._block_on_budget(mission, "max_execution_steps", max_execution_steps)
            remaining_seconds = self._remaining_seconds(deadline)
            if remaining_seconds <= 0:
                return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
            try:
                if self._remaining_output_chars(progress) <= 0:
                    return self._block_on_budget(mission, "max_total_output_chars", self._limit_value(self.runtime_limits.max_total_output_chars))
            except _MissionBudgetExceeded as exc:
                return self._block_on_budget(mission, exc.budget, exc.limit)
            if heartbeat is not None:
                heartbeat()
            try:
                skill_context = self._skill_context_for(mission)
            except Exception:
                return self._block_on_skill_context(mission)
            if skill_context is not None:
                allowed_tool_names.intersection_update(skill_context.binding.required_tools)
                model_tools = [item for item in model_tools if item.get("function", {}).get("name") in allowed_tool_names]
                if not allowed_tool_names:
                    return self._block_on_skill_context(mission)
            turn_id = f"{run_id}:turn:{len(progress['turns']) + 1}"
            if mission.status is not MissionStatus.RUNNING:
                mission.transition(
                    MissionStatus.RUNNING,
                    "provider attempt started",
                    run_id=run_id,
                    turn_id=turn_id,
                    attempt_number=mission.retry_count + 1,
                )
                self._save(mission)
            current_step = mission.current_plan_step
            try:
                specialist_memory = self._specialist_memory_context(mission)
            except Exception as exc:
                return self._block_on_task_graph(mission, exc)
            assembled = ContextAssembler().build(
                mission,
                tool_results=progress.get("tool_results", ()),
                tools=model_tools,
                max_chars=context_char_limit,
                skill_guidance=skill_context.to_untrusted_context() if skill_context is not None else None,
                specialist_memory=specialist_memory,
            )
            if assembled.context_chars > context_char_limit:
                completed = self._complete_from_verified_evidence_after_budget(mission, budget="max_context_chars", limit=context_char_limit, run_id=run_id, turn_id=f"{run_id}:turn:{len(progress['turns']) + 1}")
                if completed is not None:
                    return completed
                return self._block_on_budget(mission, "max_context_chars", context_char_limit)
            if len(assembled.messages) > context_message_limit:
                completed = self._complete_from_verified_evidence_after_budget(mission, budget="max_context_messages", limit=context_message_limit, run_id=run_id, turn_id=f"{run_id}:turn:{len(progress['turns']) + 1}")
                if completed is not None:
                    return completed
                return self._block_on_budget(mission, "max_context_messages", context_message_limit)
            progress["last_context_hash"] = assembled.context_hash
            progress["context_compaction"] = {
                "compacted": assembled.compacted,
                "compacted_items": assembled.compacted_items,
                "owner_objective": mission.objective,
                "mission_id": mission.mission_id,
                "scope_snapshot": mission.scope_snapshot,
                "authorization_context": mission.authorization_context,
                "evidence_provenance": [item.get("provenance", {}) for item in mission.evidence],
                "tool_call_ids": [item.get("tool_call_id", "") for item in progress.get("tool_results", ())],
            }
            messages = assembled.messages
            try:
                remaining_seconds = self._remaining_seconds(deadline)
                if remaining_seconds <= 0:
                    raise _MissionBudgetExceeded("max_execution_time_seconds", execution_time_limit)
                response = self._complete_with_timeout(
                    model,
                    messages,
                    model_tools,
                    mission_id=mission.mission_id,
                    run_id=run_id,
                    turn_id=turn_id,
                    plan_version=mission.plan.version,
                    timeout_seconds=remaining_seconds,
                )
                if self._remaining_seconds(deadline) <= 0:
                    raise _MissionBudgetExceeded("max_execution_time_seconds", execution_time_limit)
                turn = self._bind_model_provenance(model, validate_model_turn(response))
                turn = self._preflight_model_turn(
                    mission,
                    turn,
                    expected_turn_id=turn_id,
                    run_id=run_id,
                    current_step=current_step,
                    allowed_tool_names=allowed_tool_names,
                    auth_context=auth_context,
                    progress=progress,
                )
                output_remaining = self._remaining_output_chars(progress) - len(turn.content)
                result_caps = self._allocate_result_caps(len(turn.tool_calls), output_remaining)
            except _MissionBudgetExceeded as exc:
                completed = self._complete_from_verified_evidence_after_budget(mission, budget=exc.budget, limit=exc.limit, run_id=run_id, turn_id=turn_id)
                if completed is not None:
                    return completed
                return self._block_on_budget(mission, exc.budget, exc.limit)
            except ProviderError as exc:
                kind = getattr(exc, "kind", "PROVIDER_FAILURE")
                kind_value = getattr(kind, "value", kind)
                attempts = []
                for item in getattr(exc, "attempts", ()):
                    if not isinstance(item, dict):
                        continue
                    attempt = {key: str(item.get(key, "")) for key in ("provider", "model", "kind")}
                    if item.get("http_status") is not None:
                        attempt["http_status"] = str(item["http_status"])
                    attempts.append(attempt)
                provider_name = str(
                    getattr(exc, "provider", "")
                    or (attempts[0].get("provider", "") if attempts else "")
                )
                model_name = str(
                    getattr(exc, "model", "")
                    or (attempts[0].get("model", "") if attempts else "")
                )
                status_code = getattr(exc, "status_code", None)
                if status_code is None and len(attempts) == 1 and attempts[0].get("http_status", "").isdigit():
                    status_code = int(attempts[0]["http_status"])
                if isinstance(status_code, bool) or not isinstance(status_code, int) or not 100 <= status_code <= 599:
                    status_code = None
                mission.retry_count += 1
                failure = {
                    "mission_id": mission.mission_id,
                    "request_id": mission.request_id,
                    "class": FailureClass.PROVIDER.value,
                    "kind": str(kind_value),
                    "provider": provider_name,
                    "model": model_name,
                    "provider_attempt": mission.retry_count,
                    "attempts": attempts,
                    "reason": (
                        f"provider request rejected (HTTP {status_code})"
                        if str(kind_value) == "REQUEST_REJECTED" and status_code is not None
                        else f"provider/model call failed (HTTP {status_code})"
                        if status_code is not None
                        else "provider/model call failed"
                    ),
                    "turn_id": turn_id,
                    "run_id": run_id,
                }
                if status_code is not None:
                    failure["http_status"] = status_code
                mission.failures.append(failure)
                mission.progress.setdefault("model_failures", []).append(failure)
                mission.emit(EventType.FAILURE_DETECTED, data=failure)
                mission.error = f"model provider failure: {kind_value}" + (f" (HTTP {status_code})" if status_code is not None else "")
                action = self.recovery_policy.action_for(FailureClass.PROVIDER, mission.retry_count - 1)
                kind_is_retryable = str(kind_value) in {"PROVIDER_FAILURE", "TIMEOUT"}
                retryable_provider_failure = (
                    action in {RecoveryAction.RETRY, RecoveryAction.REPLAN}
                    and kind_is_retryable
                )
                if action in {RecoveryAction.RETRY, RecoveryAction.REPLAN} and not kind_is_retryable:
                    action = RecoveryAction.FAIL
                mission.emit(EventType.FAILURE_DIAGNOSED, data={"class": FailureClass.PROVIDER.value, "kind": str(kind_value), "recovery": action.value})
                retry_data = {
                    "run_id": run_id,
                    "turn_id": turn_id,
                    "attempt_number": mission.retry_count,
                    "max_retries": self.recovery_policy.max_retries,
                }
                if action is RecoveryAction.RETRY:
                    mission.transition(MissionStatus.READY, "provider failure; bounded retry selected", **retry_data)
                elif action is RecoveryAction.REPLAN:
                    mission.transition(MissionStatus.REPLANNING, "provider failure; replan selected", **retry_data)
                else:
                    mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
                self._save(mission)
                if mission.is_terminal:
                    return mission
                continue
            retryable_provider_failure = False
            progress["turns"].append(turn.to_dict())
            mission.emit(EventType.MODEL_TURN, data={"turn_id": turn.turn_id, "provider": turn.provider, "model": turn.model, "tool_call_count": len(turn.tool_calls), "finish_reason": turn.finish_reason})
            if not turn.tool_calls:
                progress["last_model_content"] = turn.content
                progress["last_model_finish_reason"] = turn.finish_reason
                if self._remaining_seconds(deadline) <= 0:
                    return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
                verification = self.verifier(mission)
                mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
                if verification.verified:
                    mission.transition(MissionStatus.GOAL_COMPLETED, "model final accepted with deterministic evidence")
                    mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
                    mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state, "model_final": turn.content})
                else:
                    mission.error = "model final lacked deterministic goal evidence"
                    mission.transition(MissionStatus.READY, mission.error)
                return self._save(mission)
            if len(turn.tool_calls) > 1:
                self._run_parallel_model_calls(
                    mission,
                    turn.tool_calls,
                    auth_context=auth_context,
                    run_id=run_id,
                    current_step=current_step,
                    progress=progress,
                    seen=seen,
                    deadline=deadline,
                    result_caps={proposal.tool_call_id: cap for proposal, cap in zip(turn.tool_calls, result_caps)},
                    skill_context=skill_context,
                )
                self._save(mission)
                if mission.is_terminal:
                    return mission
                continue
            for index, proposal in enumerate(turn.tool_calls):
                seen.add(proposal.tool_call_id)
                progress["seen_call_ids"].append(proposal.tool_call_id)
                argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
                decision = authorize_tool([proposal.name, argument], context=auth_context)
                mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
                mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
                if not decision.allowed:
                    result = ToolCallResult(proposal, False, error=self._bounded_tool_error(decision.reason))
                else:
                    remaining_seconds = self._remaining_seconds(deadline)
                    if remaining_seconds <= 0:
                        mission.checkpoint = {"status": "not_dispatched", "tool_call_id": proposal.tool_call_id, "run_id": run_id}
                        if skill_context is not None:
                            mission.checkpoint["skill_reference"] = skill_context.reference
                        return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
                    from .intelligence_layer.skills import SkillAuthorizationError
                    try:
                        task_id = proposal.step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                        execution_id = proposal.action_id or proposal.tool_call_id
                        dispatch_skill_context = self._skill_context_for(mission)
                        if dispatch_skill_context is not None and proposal.name not in dispatch_skill_context.binding.required_tools:
                            from .intelligence_layer.skills import SkillAuthorizationError
                            raise SkillAuthorizationError("model call exceeds the selected Skill tool ceiling")
                        delegation_scope = self._skill_dispatch_scope(mission, dispatch_skill_context, proposal.name) if dispatch_skill_context is not None else None
                        mission.checkpoint = {"status": "in_flight", "tool_call_id": proposal.tool_call_id, "action_id": execution_id, "step_id": task_id, "run_id": run_id, "plan_version": mission.plan.version}
                        if dispatch_skill_context is not None:
                            mission.checkpoint["skill_reference"] = dispatch_skill_context.reference
                        dispatch_fence = self._fence_for(mission, task_id=task_id, execution_id=execution_id)
                        if dispatch_fence is not None:
                            dispatch_fence.assert_active_execution(mission)
                        self._save(mission)
                        if heartbeat is not None:
                            heartbeat()
                        if dispatch_fence is not None:
                            dispatch_fence.assert_active_execution(mission)
                        remaining_seconds = self._remaining_seconds(deadline)
                        if remaining_seconds <= 0:
                            mission.checkpoint = {"status": "not_dispatched", "tool_call_id": proposal.tool_call_id, "run_id": run_id}
                            if dispatch_skill_context is not None:
                                mission.checkpoint["skill_reference"] = dispatch_skill_context.reference
                            return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
                        dispatch_skill_context = self._skill_context_for(mission)
                        if dispatch_skill_context is not None:
                            delegation_scope = self._skill_dispatch_scope(mission, dispatch_skill_context, proposal.name)
                        raw = self._execute_native_tool(
                            proposal.name,
                            proposal.arguments,
                            decision.decision,
                            mission,
                            dispatch_fence,
                            execution_id,
                            timeout_seconds=remaining_seconds,
                            max_result_chars=result_caps[index],
                            delegation_scope=delegation_scope,
                        )
                        observation = dict(raw or {})
                        observation.update({"type": "tool_observation", "action_id": proposal.action_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
                        mission.record_observation(observation)
                        if current_step is not None:
                            self._interpret_observation(mission, current_step, observation, success=bool(observation.get("success", observation.get("ok", True))))
                        if bool(observation.get("success", observation.get("ok", True))):
                            verified_evidence = self._successful_observation_evidence(
                                mission,
                                observation,
                                tool_name=proposal.name,
                                tool_argument=argument,
                            )
                            if verified_evidence:
                                criterion_id, verified_result = verified_evidence
                                mission.evidence.append({"criterion_id": criterion_id, "passed": True, "source": proposal.name, "result": {"source": proposal.name, "result": verified_result}, "provenance": {"mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id, "verification_authority": self._verification_authority(proposal.name)}})
                        mission.record_action(proposal.action_id or proposal.tool_call_id, proposal.step_id or proposal.name, "completed", observation)
                        mission.checkpoint = {"status": "completed", "tool_call_id": proposal.tool_call_id, "action_id": proposal.action_id, "step_id": proposal.step_id, "run_id": run_id}
                        if dispatch_skill_context is not None:
                            mission.checkpoint["skill_reference"] = dispatch_skill_context.reference
                        result = ToolCallResult(proposal, True, result=observation)
                    except SkillAuthorizationError:
                        mission.checkpoint = {**dict(mission.checkpoint or {}), "status": "not_dispatched"}
                        return self._block_on_skill_context(mission)
                    except MissionAuthorizationError as exc:
                        authorization_expired = getattr(exc, "code", "authorization_denied") == "authorization_expired"
                        target_status = MissionStatus.OWNER_REAUTH_REQUIRED if authorization_expired else MissionStatus.AUTHORIZATION_BLOCKED
                        reason = str(exc)[:256] or "mission authorization rejected before tool dispatch"
                        reason_code = "authorization_expired" if authorization_expired else "authorization_denied"
                        mission.checkpoint = {
                            "status": "not_dispatched",
                            "tool_call_id": proposal.tool_call_id,
                            "action_id": execution_id,
                            "step_id": task_id,
                            "run_id": run_id,
                            "turn_id": turn_id,
                            "plan_version": mission.plan.version,
                            "reason_code": reason_code,
                        }
                        if dispatch_skill_context is not None:
                            mission.checkpoint["skill_reference"] = dispatch_skill_context.reference
                        failure = {
                            "mission_id": mission.mission_id,
                            "request_id": mission.request_id,
                            "run_id": run_id,
                            "turn_id": turn_id,
                            "tool_call_id": proposal.tool_call_id,
                            "action_id": execution_id,
                            "step_id": task_id,
                            "class": FailureClass.AUTHORIZATION.value,
                            "kind": "OWNER_REAUTH_REQUIRED" if authorization_expired else "MISSION_AUTHORIZATION_REJECTED",
                            "error_type": type(exc).__name__,
                            "reason": reason,
                            "retry_policy": {
                                "action": target_status.value,
                                "retryable": False,
                                "attempts": 0,
                                "requires_owner_reauth": authorization_expired,
                            },
                        }
                        mission.error = reason
                        mission.failures.append(failure)
                        mission.progress.setdefault("authorization_failures", []).append(failure)
                        mission.emit(EventType.FAILURE_DETECTED, step_id=task_id, data=failure)
                        mission.emit(EventType.FAILURE_DIAGNOSED, step_id=task_id, data={
                            "class": FailureClass.AUTHORIZATION.value,
                            "kind": failure["kind"],
                            "recovery": target_status.value,
                            "run_id": run_id,
                            "turn_id": turn_id,
                            "tool_call_id": proposal.tool_call_id,
                        })
                        mission.transition(
                            target_status,
                            reason,
                            run_id=run_id,
                            turn_id=turn_id,
                            tool_call_id=proposal.tool_call_id,
                            checkpoint_status="not_dispatched",
                        )
                        return self._save(mission)
                    except Exception as exc:
                        error_detail = self._bounded_tool_error(str(exc)) or "no exception detail"
                        reason = f"native tool outcome is ambiguous: {type(exc).__name__}"
                        failure = {
                            "mission_id": mission.mission_id,
                            "request_id": mission.request_id,
                            "run_id": run_id,
                            "turn_id": turn_id,
                            "tool_call_id": proposal.tool_call_id,
                            "action_id": execution_id,
                            "step_id": task_id,
                            "class": FailureClass.UNKNOWN.value,
                            "kind": "NATIVE_TOOL_OUTCOME_UNKNOWN",
                            "error_type": type(exc).__name__,
                            "error": error_detail,
                            "reason": reason,
                            "retry_policy": {
                                "action": "RECONCILIATION_REQUIRED",
                                "retryable": False,
                                "attempts": 0,
                            },
                        }
                        mission.error = reason
                        mission.failures.append(failure)
                        mission.progress.setdefault("native_tool_failures", []).append(failure)
                        mission.emit(EventType.FAILURE_DETECTED, step_id=task_id, data=failure)
                        mission.emit(EventType.FAILURE_DIAGNOSED, step_id=task_id, data={
                            "class": FailureClass.UNKNOWN.value,
                            "kind": failure["kind"],
                            "recovery": "reconciliation_required",
                            "run_id": run_id,
                            "turn_id": turn_id,
                            "tool_call_id": proposal.tool_call_id,
                            "action_id": execution_id,
                        })
                        mission.transition(
                            MissionStatus.RECOVERY_REQUIRED,
                            reason,
                            run_id=run_id,
                            turn_id=turn_id,
                            tool_call_id=proposal.tool_call_id,
                            action_id=execution_id,
                            checkpoint_status="in_flight",
                        )
                        return self._save(mission)
                progress["tool_results"].append(result.to_dict())
            self._save(mission)
        if len(progress["turns"]) >= max_execution_steps and not mission.is_terminal:
            return self._block_on_budget(mission, "max_execution_steps", max_execution_steps)
        if self._remaining_seconds(deadline) <= 0 and not mission.is_terminal:
            return self._block_on_budget(mission, "max_execution_time_seconds", execution_time_limit)
        if retryable_provider_failure and mission.status in {MissionStatus.READY, MissionStatus.REPLANNING}:
            return mission
        mission.error = "model turn budget exhausted"
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        return self._save(mission)

    def _run_parallel_model_calls(self, mission: Mission, proposals: tuple[Any, ...], *, auth_context: Any, run_id: str, current_step: Any, progress: dict[str, Any], seen: set[str], deadline: float, result_caps: dict[str, int], skill_context: Any = None) -> None:
        """Authorize and execute independent proposals concurrently, then fold results deterministically."""
        from security.authorization import authorize_tool
        if mission.skill_binding:
            try:
                current_skill_context = self._skill_context_for(mission)
                if skill_context is None or current_skill_context.reference != skill_context.reference:
                    return self._block_on_skill_context(mission)
                skill_context = current_skill_context
                if any(proposal.name not in skill_context.binding.required_tools for proposal in proposals):
                    return self._block_on_skill_context(mission)
            except Exception:
                return self._block_on_skill_context(mission)
        identity_errors = set(validate_proposals(proposals, mission_id=mission.mission_id, run_id=run_id, seen_call_ids=seen))
        authorized: list[tuple[Any, Any, Any]] = []
        results: list[ToolCallResult] = []
        staged_seen_ids: list[str] = []
        staged_seen = set(seen)
        for proposal in proposals:
            mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
            if any(proposal.tool_call_id == error.split(":", 1)[0] for error in identity_errors) or proposal.tool_call_id in staged_seen:
                results.append(ToolCallResult(proposal, False, error="invalid, stale, or duplicate tool call"))
                continue
            staged_seen.add(proposal.tool_call_id)
            staged_seen_ids.append(proposal.tool_call_id)
            argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
            decision = authorize_tool([proposal.name, argument], context=auth_context)
            mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
            if decision.allowed:
                authorized.append((proposal, argument, decision))
            else:
                results.append(ToolCallResult(proposal, False, error=self._bounded_tool_error(decision.reason)))
        if self._remaining_seconds(deadline) <= 0:
            results.extend(
                ToolCallResult(proposal, False, error="runtime deadline expired before parallel dispatch")
                for proposal, _argument, _decision in authorized
            )
            seen.update(staged_seen_ids)
            progress["seen_call_ids"].extend(staged_seen_ids)
            progress["tool_results"].extend(result.to_dict() for result in results)
            mission.checkpoint = {"status": "not_dispatched_parallel", "run_id": run_id, "tool_call_ids": list(staged_seen_ids)}
            if skill_context is not None:
                mission.checkpoint["skill_reference"] = skill_context.reference
            self._block_on_budget(mission, "max_execution_time_seconds", self._limit_value(self.runtime_limits.max_execution_time_seconds))
            return
        seen.update(staged_seen_ids)
        progress["seen_call_ids"].extend(staged_seen_ids)
        mission.checkpoint = {
            "status": "in_flight_parallel",
            "tool_call_ids": [item[0].tool_call_id for item in authorized],
            "execution_ids": [item[0].action_id or item[0].tool_call_id for item in authorized],
            "task_ids": [
                item[0].step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                for item in authorized
            ],
            "run_id": run_id,
            "plan_version": mission.plan.version,
        }
        if skill_context is not None:
            mission.checkpoint["skill_reference"] = skill_context.reference
        self._save(mission)
        def execute_one(item: tuple[Any, Any, Any]) -> dict[str, Any]:
            proposal, argument, decision = item
            try:
                from .intelligence_layer.skills import SkillAuthorizationError
                remaining_seconds = self._remaining_seconds(deadline)
                if remaining_seconds <= 0:
                    raise _MissionBudgetExceeded("max_execution_time_seconds", self._limit_value(self.runtime_limits.max_execution_time_seconds))
                task_id = proposal.step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                execution_id = proposal.action_id or proposal.tool_call_id
                dispatch_fence = self._fence_for(mission, task_id=task_id, execution_id=execution_id)
                if dispatch_fence is not None:
                    dispatch_fence.assert_active_execution(mission)
                worker_skill_context = self._skill_context_for(mission)
                if worker_skill_context is not None:
                    if worker_skill_context.reference != skill_context.reference or proposal.name not in worker_skill_context.binding.required_tools:
                        raise SkillAuthorizationError("selected Skill changed before parallel dispatch")
                    delegation_scope = self._skill_dispatch_scope(mission, worker_skill_context, proposal.name)
                else:
                    delegation_scope = None
                remaining_seconds = self._remaining_seconds(deadline)
                if remaining_seconds <= 0:
                    raise _MissionBudgetExceeded("max_execution_time_seconds", self._limit_value(self.runtime_limits.max_execution_time_seconds))
                return dict(self._execute_native_tool(
                    proposal.name,
                    proposal.arguments,
                    decision.decision,
                    mission,
                    dispatch_fence,
                    execution_id,
                    timeout_seconds=remaining_seconds,
                    max_result_chars=result_caps[proposal.tool_call_id],
                    delegation_scope=delegation_scope,
                ) or {})
            except _MissionBudgetExceeded as exc:
                return {"_budget_exceeded": True, "budget": exc.budget, "limit": exc.limit}
            except Exception as exc:
                # An exception after dispatch cannot prove that the external side effect did not happen.
                # Preserve ambiguity so recovery cannot blindly replay this proposal.
                return {"_ambiguous": True, "error": str(exc), "failure_class": FailureClass.UNKNOWN.value, "exception": type(exc).__name__}
        raw_results = execute_bounded_parallel(authorized, execute_one, max_workers=min(4, max(1, len(authorized))))
        ambiguous: list[tuple[Any, dict[str, Any]]] = []
        budget_exceeded: tuple[str, int] | None = None
        for item, raw in zip(authorized, raw_results):
            if raw.get("_ambiguous"):
                ambiguous.append((item[0], raw))
                continue
            proposal = item[0]
            if raw.get("_budget_exceeded"):
                budget_exceeded = (str(raw.get("budget", "max_execution_time_seconds")), self._limit_value(raw.get("limit", 0)))
                results.append(ToolCallResult(proposal, False, error="runtime resource budget exceeded before dispatch"))
                continue
            observation = dict(raw)
            observation.update({"type": "tool_observation", "action_id": proposal.action_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
            mission.record_observation(observation)
            success = bool(observation.get("success", observation.get("ok", True)))
            if current_step is not None:
                self._interpret_observation(mission, current_step, observation, success=success)
            if success:
                verified_evidence = self._successful_observation_evidence(
                    mission,
                    observation,
                    tool_name=proposal.name,
                    tool_argument=proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None,
                )
                if verified_evidence:
                    criterion_id, verified_result = verified_evidence
                    mission.evidence.append({"criterion_id": criterion_id, "passed": True, "source": proposal.name, "result": {"source": proposal.name, "result": verified_result}, "provenance": {"mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id, "verification_authority": self._verification_authority(proposal.name)}})
            mission.record_action(proposal.action_id or proposal.tool_call_id, proposal.step_id or proposal.name, "completed" if success else "failed", observation)
            results.append(ToolCallResult(proposal, success, result=observation, error=self._bounded_tool_error(observation.get("error", ""))))
        progress["tool_results"].extend(result.to_dict() for result in results)
        if ambiguous:
            ambiguous_ids = [proposal.tool_call_id for proposal, _ in ambiguous]
            mission.error = "parallel tool outcome is ambiguous; reconciliation required"
            mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": mission.error, "tool_call_ids": ambiguous_ids})
            mission.emit(EventType.FAILURE_DIAGNOSED, data={"class": FailureClass.UNKNOWN.value, "reason": mission.error, "recovery": "reconciliation_required", "tool_call_ids": ambiguous_ids})
            mission.checkpoint = {
                "status": "in_flight_parallel",
                "tool_call_ids": [item[0].tool_call_id for item in authorized],
                "ambiguous_tool_call_ids": ambiguous_ids,
                "execution_ids": [item[0].action_id or item[0].tool_call_id for item in authorized],
                "task_ids": [
                    item[0].step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                    for item in authorized
                ],
                "plan_version": mission.plan.version,
                "run_id": run_id,
            }
            if skill_context is not None:
                mission.checkpoint["skill_reference"] = skill_context.reference
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return
        if budget_exceeded is not None:
            budget_name, budget_limit = budget_exceeded
            mission.checkpoint = {"status": "budget_blocked", "run_id": run_id, "tool_call_ids": [proposal.tool_call_id for proposal, _ in authorized]}
            if skill_context is not None:
                mission.checkpoint["skill_reference"] = skill_context.reference
            self._block_on_budget(mission, budget_name, budget_limit)
            return
        mission.checkpoint = {"status": "completed", "tool_call_ids": [item[0].tool_call_id for item in authorized], "run_id": run_id}
        if skill_context is not None:
            mission.checkpoint["skill_reference"] = skill_context.reference

    def run_slice(self, mission_id: str) -> Mission:
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        checkpoint = dict(mission.checkpoint or {})
        checkpoint_status = checkpoint.get("status")
        if checkpoint_status == "in_flight_specialists":
            # Quarantine is a non-executing state transition. Do it before
            # current authorization validation so an expired/renewed Owner
            # snapshot cannot leave ambiguous provider calls marked RUNNING.
            if self.task_graph_adapter is None:
                return self._block_on_task_graph(mission, MissionTaskGraphError("specialist recovery has no task graph adapter"))
            try:
                graph_snapshot = self._typed_mission_snapshot(mission)
                batch_id = str(checkpoint.get("batch_id", ""))
                if not batch_id:
                    raise MissionTaskGraphError("specialist recovery checkpoint has no batch identity")
                self.task_graph_adapter.quarantine_specialist_batch(mission, graph_snapshot, batch_id=batch_id)
                mission.recovery_events.append({
                    "event": "specialist_batch_quarantined_no_replay",
                    "batch_id": batch_id,
                    "task_ids": list(checkpoint.get("task_ids", ()))[:2],
                })
                mission.checkpoint = {
                    "status": "specialists_quarantined",
                    "batch_id": batch_id,
                    "task_ids": list(checkpoint.get("task_ids", ()))[:2],
                }
                return self._save(mission)
            except (MissionTaskGraphError, KeyError, TypeError, ValueError, PermissionError) as exc:
                return self._block_on_task_graph(mission, exc)
        authorization_ok, authorization_reason = self._mission_authorization(mission)
        if not authorization_ok:
            mission.error = authorization_reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": authorization_reason})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, authorization_reason)
            return self._save(mission)
        checkpoint = dict(mission.checkpoint or {})
        checkpoint_status = checkpoint.get("status")
        if checkpoint_status in {"in_flight", "in_flight_parallel"}:
            if mission.skill_binding and checkpoint.get("skill_reference") != mission.skill_binding:
                mission.error = "in-flight Skill reference does not match the integrity-covered Mission binding"
                mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason_code": "skill_checkpoint_binding_mismatch"})
            if checkpoint_status == "in_flight_parallel":
                tool_call_ids = [
                    str(item)
                    for item in checkpoint.get("ambiguous_tool_call_ids", checkpoint.get("tool_call_ids", []))
                ]
                mission.error = "parallel in-flight action outcome is unknown; reconciliation required"
                failure = {"class": FailureClass.UNKNOWN.value, "reason": mission.error, "tool_call_ids": tool_call_ids}
                mission.failures.append(failure)
                mission.emit(
                    EventType.FAILURE_DIAGNOSED,
                    step_id=str(checkpoint.get("step_id", "")),
                    data={**failure, "recovery": "reconciliation_required"},
                )
                mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error, tool_call_ids=tool_call_ids)
            else:
                action_id = str(checkpoint.get("action_id", ""))
                mission.error = "in-flight action outcome is unknown; reconciliation required"
                failure = {"class": FailureClass.UNKNOWN.value, "reason": mission.error, "action_id": action_id}
                mission.failures.append(failure)
                mission.emit(
                    EventType.FAILURE_DIAGNOSED,
                    step_id=str(checkpoint.get("step_id", "")),
                    data={**failure, "recovery": "reconciliation_required"},
                )
                mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error, action_id=action_id)
            return self._save(mission)
        try:
            skill_context = self._skill_context_for(mission)
        except Exception:
            return self._block_on_skill_context(mission)
        if mission.iteration_count >= mission.max_iterations:
            mission.error = "iteration budget exhausted"
            mission.emit(EventType.FAILURE_DETECTED, data={"class": FailureClass.RESOURCE.value, "reason": mission.error})
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
            return self._save(mission)
        mission.iteration_count += 1
        if mission.current_step >= len(mission.plan.steps):
            mission.transition(MissionStatus.VERIFYING, "all plan steps observed")
            mission.emit(EventType.GOAL_VERIFICATION_STARTED)
            verification = self.verifier(mission)
            mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
            if verification.verified:
                mission.emit(EventType.GOAL_VERIFIED, data={"evidence_count": len(verification.evidence)})
                mission.transition(MissionStatus.GOAL_COMPLETED, "required verification evidence present")
                mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state})
            else:
                mission.transition(MissionStatus.RUNNING, "required verification evidence missing")
            return self._save(mission)

        step = mission.current_plan_step
        action_id = f"{mission.mission_id}:{mission.plan.version}:{step.step_id}:{mission.current_step}"
        mission.emit(EventType.STEP_SELECTED, step_id=step.step_id, data={"action_id": action_id, "plan_version": mission.plan.version})
        graph_snapshot = None
        if self.task_graph_adapter is not None:
            try:
                graph_snapshot = self._typed_mission_snapshot(mission)
                self.task_graph_adapter.ensure(mission, graph_snapshot)
            except (MissionTaskGraphError, KeyError, TypeError, ValueError) as exc:
                return self._block_on_task_graph(mission, exc)
            if self.specialist_generate is not None:
                try:
                    from .intelligence_layer.specialist_dispatch import run_ready_specialist_batch
                    specialist_result = run_ready_specialist_batch(self, mission, graph_snapshot)
                except Exception as exc:
                    return self._block_on_task_graph(mission, exc)
                if specialist_result is not None:
                    return specialist_result
            from .intelligence_layer.parallel_dispatch import run_parallel_graph_steps

            parallel_result = run_parallel_graph_steps(self, mission, graph_snapshot, skill_context=skill_context)
            if parallel_result is not None:
                return parallel_result
        signatures = mission.progress.setdefault("loop_signatures", {})
        signature = hashlib.sha256(json.dumps({"plan": mission.plan.fingerprint, "step": step.step_id, "action": step.action}, sort_keys=True).encode()).hexdigest()
        signatures[signature] = int(signatures.get(signature, 0)) + 1
        if signatures[signature] > 3:
            mission.error = "dead loop detected: repeated plan and action"
            mission.emit(EventType.FAILURE_DIAGNOSED, step_id=step.step_id, data={"class": FailureClass.LOGIC.value, "reason": mission.error})
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
            return self._save(mission)
        if any(item.get("action_id") == action_id and item.get("status") == "completed" for item in mission.action_history):
            mission.current_step += 1
            mission.transition(MissionStatus.READY, "idempotent action already completed")
            return self._save(mission)

        allowed, reason = self.authorizer(mission, step)
        mission.emit(EventType.AUTHORIZATION_CHECKED, step_id=step.step_id, data={"allowed": allowed, "reason": reason})
        if not allowed:
            mission.error = reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value if "authorization" in reason else FailureClass.SCOPE.value, "reason": reason, "step_id": step.step_id})
            mission.emit(EventType.OWNER_INPUT_REQUIRED if "authorization" in reason else EventType.FAILURE_DETECTED, step_id=step.step_id, data={"reason": reason})
            mission.transition(MissionStatus.OWNER_INPUT_REQUIRED if "authorization" in reason else MissionStatus.SCOPE_BLOCKED, reason)
            return self._save(mission)

        if self.require_execution_fence and not self._executor_accepts_fence(self.executor):
            raise ExecutionFenceError("strict runtime executor does not accept execution fences")

        delegation_scope = None
        if self.task_graph_adapter is not None:
            try:
                delegation_scope = self.task_graph_adapter.delegation_scope_for_step(
                    mission,
                    graph_snapshot,
                    step.step_id,
                )
                if delegation_scope is not None and not self._executor_accepts_delegation(self.executor):
                    raise MissionTaskGraphError("delegated mission task requires a scope-enforcing executor")
                if skill_context is not None:
                    if delegation_scope is None:
                        delegation_scope = self._skill_dispatch_scope(mission, skill_context, step.action)
                    else:
                        delegation_scope = skill_context.narrow_task_scope(delegation_scope, tool_name=step.action)
                    if not self._executor_accepts_delegation(self.executor):
                        raise MissionTaskGraphError("Skill-bound mission step requires a scope-enforcing executor")
                self.task_graph_adapter.claim_step(mission, graph_snapshot, step.step_id)
            except Exception as exc:
                from .intelligence_layer.skills import SkillAuthorizationError
                if isinstance(exc, SkillAuthorizationError):
                    return self._block_on_skill_context(mission)
                if not isinstance(exc, (MissionTaskGraphError, KeyError, TypeError, ValueError)):
                    return self._block_on_task_graph(mission, exc)
                return self._block_on_task_graph(mission, exc)

        mission.transition(MissionStatus.RUNNING, "step started", step_id=step.step_id)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "in_flight", "plan_version": mission.plan.version}
        if skill_context is not None:
            mission.checkpoint["skill_reference"] = skill_context.reference
        self._save(mission)
        dispatch_fence = self._fence_for(mission, task_id=step.step_id, execution_id=action_id)
        if dispatch_fence is not None:
            dispatch_fence.assert_active_execution(mission)
        try:
            if dispatch_fence is None:
                result = self.executor(mission, step, action_id)
            elif self._executor_accepts_fence(self.executor):
                if delegation_scope is not None:
                    result = self.executor(mission, step, action_id, execution_fence=dispatch_fence, delegation_scope=delegation_scope)
                else:
                    result = self.executor(mission, step, action_id, execution_fence=dispatch_fence)
            elif self.require_execution_fence:
                raise ExecutionFenceError("strict runtime executor does not accept execution fences")
            else:
                result = self.executor(mission, step, action_id)
        except ExecutionFenceError:
            raise
        except Exception as exc:
            from .intelligence_layer.skills import SkillAuthorizationError
            if isinstance(exc, SkillAuthorizationError):
                mission.checkpoint = {**dict(mission.checkpoint or {}), "status": "not_dispatched"}
                return self._block_on_skill_context(mission)
            # Keep the in-flight checkpoint durable. A new runtime can safely resume it.
            mission.error = type(exc).__name__
            mission.record_observation({"type": "execution_exception", "success": False, "error": str(exc), "action_id": action_id})
            return self._save(mission)

        observation = dict(result or {})
        observation.setdefault("type", "tool_observation")
        observation.setdefault("action_id", action_id)
        observation.setdefault("step_id", step.step_id)
        observation.setdefault("mission_id", mission.mission_id)
        effect_id = str(observation.get("effect_id", "") or "")
        effect_state = str(observation.get("effect_state", "") or "")
        if effect_id and effect_state:
            mission.error = "external effect requires reconciliation"
            mission.failures.append({
                "class": FailureClass.UNKNOWN.value,
                "reason": mission.error,
                "step_id": step.step_id,
                "action_id": action_id,
                "effect_id": effect_id,
                "effect_state": effect_state,
            })
            mission.emit(
                EventType.FAILURE_DETECTED,
                step_id=step.step_id,
                data={"class": FailureClass.UNKNOWN.value, "effect_id": effect_id, "effect_state": effect_state},
            )
            checkpoint = dict(mission.checkpoint or {})
            checkpoint.update({"status": "in_flight", "effect_id": effect_id, "effect_state": effect_state})
            mission.checkpoint = checkpoint
            mission.record_observation({
                "type": "external_effect_recovery_required",
                "success": False,
                "effect_id": effect_id,
                "effect_state": effect_state,
                "reason_code": observation.get("reason_code", "UNCLASSIFIED"),
                "action_id": action_id,
                "step_id": step.step_id,
            })
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return self._save(mission)
        typed_observation = Observation.from_result(step.action, action_id, observation, request_id=mission.request_id, scope=mission.scope_snapshot)
        observation["observation"] = typed_observation.to_dict()
        mission.transition(MissionStatus.OBSERVING, "action returned observation", action_id=action_id)
        mission.record_observation(observation)
        success = bool(observation.get("success", observation.get("ok", False)))
        mission.record_action(action_id, step.step_id, "completed" if success else "failed", observation)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "completed", "plan_version": mission.plan.version}
        if skill_context is not None:
            mission.checkpoint["skill_reference"] = skill_context.reference
        if self.task_graph_adapter is not None:
            if success:
                self.task_graph_adapter.complete_step(mission, step.step_id, observation, action_id)
            else:
                self.task_graph_adapter.fail_step(mission, step.step_id, str(observation.get("error", "mission step failed")))
        try:
            strategy_decision = self._interpret_observation(mission, step, observation, success=success)
        except (TypeError, ValueError, KeyError) as exc:
            mission.error = f"observation interpretation rejected: {type(exc).__name__}"
            mission.recovery_events.append({"event": "interpretation_rejected", "reason": str(exc), "action_id": action_id})
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            return self._save(mission)
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        scope_blocked = bool(observation.get("target") and isinstance(allowed_targets, (list, tuple, set)) and str(observation.get("target")) not in {str(item) for item in allowed_targets})
        if scope_blocked:
            mission.error = "observation proposed a target outside deterministic scope"
            mission.failures.append({"class": FailureClass.SCOPE.value, "reason": mission.error, "target": observation.get("target")})
            mission.transition(MissionStatus.SCOPE_BLOCKED, mission.error)
            return self._save(mission)
        if success:
            step_arguments = dict(step.retry_policy).get("arguments", {})
            tool_argument = step_arguments.get("query") if isinstance(step_arguments, dict) else None
            verified_evidence = self._successful_observation_evidence(
                mission,
                observation,
                tool_name=step.action,
                tool_argument=tool_argument,
            )
            if verified_evidence:
                criterion_id, verified_result = verified_evidence
                mission.evidence.append({"criterion_id": criterion_id, "passed": True, "source": step.action, "result": {"source": step.action, "result": verified_result}, "provenance": {"mission_id": mission.mission_id, "step_id": step.step_id, "action_id": action_id, "verification_authority": self._verification_authority(step.action)}})
                mission.emit(EventType.EVIDENCE_ADDED, step_id=step.step_id, data={"criterion_id": criterion_id})
            if strategy_decision is not None and strategy_decision.decision.value in {"REPLAN", "CHANGE_HYPOTHESIS", "ADD_EVIDENCE"}:
                mission.transition(MissionStatus.REPLANNING, strategy_decision.reason)
                mission.emit(EventType.REPLAN_TRIGGERED, step_id=step.step_id, data=strategy_decision.to_dict())
                new_plan = self.replanner(mission, {**observation, "interpretation": mission.interpretations[-1], "strategy_decision": strategy_decision.to_dict()})
                if new_plan.objective != mission.objective:
                    mission.error = "replanner attempted to change Owner objective"
                    mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                    return self._save(mission)
                mission.replan_history.append({"from_version": mission.plan.version, "to_version": new_plan.version, "reason": strategy_decision.reason, "trigger": strategy_decision.to_dict()})
                mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.plan = new_plan
                mission.current_step = 0
                mission.retry_count = 0
                mission.transition(MissionStatus.READY, "informative observation caused replan", plan_version=new_plan.version)
                return self._save(mission)
            mission.current_step += 1
            mission.retry_count = 0
            mission.transition(MissionStatus.READY, "observation accepted")
            return self._save(mission)

        failure = FailureClass(str(observation.get("failure_class", FailureClass.UNKNOWN.value))) if str(observation.get("failure_class", FailureClass.UNKNOWN.value)) in {item.value for item in FailureClass} else FailureClass.UNKNOWN
        mission.failures.append({"class": failure.value, "reason": observation.get("error", "action failed"), "step_id": step.step_id, "action_id": action_id})
        mission.emit(EventType.FAILURE_DETECTED, step_id=step.step_id, data={"class": failure.value, "reason": observation.get("error", "action failed")})
        mission.retry_count += 1
        action = self.recovery_policy.action_for(failure, mission.retry_count - 1)
        mission.emit(EventType.FAILURE_DIAGNOSED, step_id=step.step_id, data={"class": failure.value, "recovery": action.value})
        if action is RecoveryAction.OWNER_INPUT_REQUIRED:
            mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, "authorization requires owner input")
        elif action is RecoveryAction.SCOPE_BLOCKED:
            mission.transition(MissionStatus.SCOPE_BLOCKED, "scope blocked")
        elif action is RecoveryAction.RESOURCE_BLOCKED:
            mission.transition(MissionStatus.RESOURCE_BLOCKED, "resource blocked")
        elif action is RecoveryAction.REPLAN:
            mission.transition(MissionStatus.REPLANNING, "observation invalidated current plan")
            mission.emit(EventType.REPLAN_TRIGGERED, step_id=step.step_id, data={"reason": "failure observation"})
            new_plan = self.replanner(mission, observation)
            if new_plan.objective != mission.objective:
                mission.error = "replanner attempted to change Owner objective"
                mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                return self._save(mission)
            mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": "failure observation"})
            mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint})
            mission.plan = new_plan
            mission.current_step = 0
            mission.retry_count = 0
            mission.transition(MissionStatus.READY, "new plan persisted", plan_version=new_plan.version)
        elif action is RecoveryAction.RETRY:
            mission.transition(MissionStatus.READY, "bounded retry selected")
        else:
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, "recovery budget exhausted")
        return self._save(mission)

    def run_to_completion(self, mission_id: str, *, max_slices: int | None = None, heartbeat: Callable[[], None] | None = None) -> Mission:
        limit = max_slices or self._load(mission_id).max_iterations
        for _ in range(limit):
            if heartbeat is not None:
                heartbeat()
            mission = self.run_slice(mission_id)
            if mission.is_terminal:
                return mission
        return self._load(mission_id)


__all__ = ["MissionRuntime"]
