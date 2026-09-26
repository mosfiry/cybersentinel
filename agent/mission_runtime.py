from __future__ import annotations

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable
import copy
import hashlib
import json

from .mission import Mission, MissionStatus, MissionStore
from .planning import FailureClass, GoalVerification, Plan, PlanStep, RecoveryAction, RecoveryPolicy, VerificationCriterion, evidence_for
from .trajectory import EventType
from .observation import Observation
from .observation_intelligence import ObservationInterpreter, should_interpret_observation
from .hypotheses import HypothesisEngine, HypothesisState
from .strategy import StrategyState, decide as decide_strategy
from .model_protocol import ConversationTurn, NativeModel, ToolCallResult
from .provider_api import ProviderError
from .model_intelligence.context import ContextAssembler
from .model_intelligence.tool_calls import execute_bounded_parallel, validate_proposals
from .orchestration import DeterministicScheduler, ExecutionGraph, ExecutionNode, GraphValidationError, NodeState


class MissionRuntime:
    """Persistent autonomous mission loop. Every slice is restart-safe and bounded."""

    def __init__(self, store: MissionStore, *, executor: Callable[[Mission, PlanStep, str], dict[str, Any]], authorizer: Callable[[Mission, PlanStep], tuple[bool, str]] | None = None, replanner: Callable[[Mission, dict[str, Any]], Plan] | None = None, verifier: Callable[[Mission], GoalVerification] | None = None, recovery_policy: RecoveryPolicy | None = None, interpreter: ObservationInterpreter | None = None, require_authorization_snapshot: bool = True, authorization_snapshot_factory: Callable[[Mission], Any] | None = None, orchestration_retry_policies: dict[str, dict[str, Any]] | None = None, orchestration_resource_policies: dict[str, dict[str, Any]] | None = None):
        self.store = store
        self.executor = executor
        self.authorizer = authorizer or self._default_authorizer
        self.replanner = replanner or self._default_replanner
        self.verifier = verifier or self._default_verifier
        self.recovery_policy = recovery_policy or RecoveryPolicy()
        self.interpreter = interpreter or ObservationInterpreter()
        self.require_authorization_snapshot = require_authorization_snapshot
        self.authorization_snapshot_factory = authorization_snapshot_factory
        self.orchestration_retry_policies = {str(key): dict(value) for key, value in (orchestration_retry_policies or {}).items()}
        self.orchestration_resource_policies = {str(key): dict(value) for key, value in (orchestration_resource_policies or {}).items()}

    def _mission_authorization(self, mission: Mission, *, actions: set[str] | None = None) -> tuple[bool, str]:
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
            requested_actions = actions if actions is not None else {step.action for step in mission.plan.steps if step.action != "__planning_failure__"}
            if requested_actions - set(snapshot.allowed_actions) or requested_actions - set(snapshot.allowed_tools) or requested_actions.intersection(snapshot.forbidden_actions):
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

    def create(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> Mission:
        snapshot_factory = kwargs.pop("authorization_snapshot_factory", None) or self.authorization_snapshot_factory
        mission = Mission.create(owner_request, objective, plan, **kwargs)
        if mission.authorization_snapshot is None and snapshot_factory is not None:
            snapshot = snapshot_factory(mission)
            if snapshot is not None:
                mission.authorization_snapshot = snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot)
        if mission.authorization_snapshot:
            mission.provenance["authorization_snapshot_version"] = int(mission.authorization_snapshot.get("version", 1))
        mission.transition(MissionStatus.READY, "plan persisted")
        return self.store.save(mission)

    def create_graph(self, owner_request: str, objective: str, plan: Plan, *, max_parallel: int = 1, node_budget: int | None = None, max_runs: int | None = None, tool_budget: int | None = None, retry_budget: int | None = None, max_duration_seconds: int | None = 3600, **kwargs: Any) -> Mission:
        """Create a mission whose plan is executed as a validated dependency graph."""
        if max_parallel < 1 or max_parallel > 32 or (node_budget is not None and node_budget < 0):
            raise ValueError("invalid graph execution budget")
        criteria = kwargs.get("completion_criteria")
        if not isinstance(criteria, list) or not criteria or any(not isinstance(item, dict) or not str(item.get("criterion_id", "")).strip() for item in criteria):
            raise ValueError("DAG execution requires explicit deterministic completion criteria")
        if len({str(item["criterion_id"]) for item in criteria}) != len(criteria):
            raise ValueError("completion criterion identities must be unique")
        planned_step_ids = {str(step.step_id) for step in plan.steps}
        if {str(item["criterion_id"]) for item in criteria} - planned_step_ids:
            raise ValueError("completion criteria must bind to stable plan step identities")
        ExecutionGraph.from_plan("validation", "validation", plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        mission = self.create(owner_request, objective, plan, **kwargs)
        authorization_ok, reason = self._mission_authorization(mission, actions=set())
        if not authorization_ok:
            raise PermissionError("mission graph requires a valid authorization snapshot: " + reason)
        run_id = hashlib.sha256((mission.mission_id + "\0" + mission.request_id + "\0" + mission.plan.fingerprint).encode()).hexdigest()[:24]
        graph = ExecutionGraph.from_plan(mission.mission_id, run_id, mission.plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        default_runs = max(1, len(graph.nodes) + sum(node.retry_limit for node in graph.nodes))
        state = DeterministicScheduler.initial_state(graph, authorization_hash=self._graph_authorization_hash(mission), node_budget=node_budget, max_parallel=max_parallel, max_runs=default_runs if max_runs is None else max_runs, tool_budget=tool_budget, retry_budget=retry_budget, max_duration_seconds=max_duration_seconds)
        mission.progress["execution_mode"] = "dag"
        mission.progress["execution_run_id"] = run_id
        mission.checkpoint = {**mission.checkpoint, "status": "graph_initialized", "execution_run_id": run_id, "plan_hash": graph.plan_hash, "orchestration": state}
        return self.store.save(mission)

    def create_from_owner_instruction(self, instruction: str, plan: Plan, *, authorization_context: Any, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, owner_identity_ref: str = "", provenance: dict[str, Any] | None = None, authorization_snapshot_factory: Callable[[Mission], Any] | None = None) -> Mission:
        """Create a Mission without allowing model understanding to rewrite the Owner objective."""
        from security.authorization_context import AuthorizationContext
        if not isinstance(authorization_context, AuthorizationContext):
            raise TypeError("Owner Instruction requires typed AuthorizationContext")
        objective = str(instruction).strip()
        if not objective:
            raise ValueError("Owner Instruction cannot be empty")
        return self.create(
            objective,
            objective,
            plan,
            request_id=authorization_context.request_id,
            owner_identity_ref=owner_identity_ref or authorization_context.owner_evidence_fingerprint,
            owner_instruction=objective,
            authorization_context=authorization_context.to_dict(),
            scope_snapshot=scope_snapshot,
            policy_snapshot=authorization_context.policy_snapshot.to_dict(),
            completion_criteria=completion_criteria,
            provenance={"source": "owner_instruction", **(provenance or {})},
            authorization_snapshot_factory=authorization_snapshot_factory,
        )

    def provide_owner_decision(self, mission_id: str, *, allow: bool, authorization_context: dict[str, Any] | None = None) -> Mission:
        mission = self._load(mission_id)
        if mission.status is not MissionStatus.OWNER_INPUT_REQUIRED:
            raise ValueError("mission is not waiting for owner input")
        if not allow:
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": "owner denied action"})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, "owner denied")
        else:
            mission.authorization_context = authorization_context or {"owner_decision": "allow"}
            mission.transition(MissionStatus.READY, "owner allowed action")
        return self.store.save(mission)

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
        if proposal.new_evidence:
            for item in proposal.new_evidence:
                normalized = dict(item)
                normalized.setdefault("criterion_id", str(normalized.get("evidence_id") or proposal.observation_id))
                normalized.setdefault("passed", True)
                normalized.setdefault("source", "observation_interpreter")
                normalized.setdefault("result", dict(item))
                normalized.setdefault("provenance", {"mission_id": mission.mission_id, "observation_id": proposal.observation_id, "authority": None})
                mission.evidence.append(normalized)
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

    def reconcile_in_flight(self, mission_id: str, *, executed: bool, observation: dict[str, Any] | None = None) -> Mission:
        """Resolve an ambiguous external side effect without silently replaying it.

        ``executed=True`` records the external receipt as completed.  ``False``
        records that reconciliation found no side effect and permits one safe
        retry.  The runtime never infers either outcome from a process crash.
        """
        mission = self._load(mission_id)
        checkpoint = dict(mission.checkpoint or {})
        checkpoint_status = checkpoint.get("status")
        if checkpoint_status not in {"in_flight", "in_flight_parallel"}:
            raise ValueError("mission has no in-flight action requiring reconciliation")
        if checkpoint_status == "in_flight_parallel":
            ambiguous_ids = [str(item) for item in checkpoint.get("ambiguous_tool_call_ids", checkpoint.get("tool_call_ids", []))]
            if not ambiguous_ids:
                raise ValueError("parallel checkpoint has no ambiguous tool calls")
            if executed:
                base_observation = dict(observation or {"success": True, "source": "external_reconciliation"})
                base_observation.setdefault("success", True)
                for tool_call_id in ambiguous_ids:
                    result = {**base_observation, "tool_call_id": tool_call_id, "type": "reconciled_observation"}
                    mission.record_observation(result)
                    mission.record_action(tool_call_id, str(checkpoint.get("step_id", "")), "completed", result)
                    mission.evidence.append({"criterion_id": result.get("criterion_id", str(checkpoint.get("step_id", ""))), "passed": bool(result.get("success")), "source": result.get("source", "external_reconciliation"), "result": result, "provenance": {"mission_id": mission.mission_id, "tool_call_id": tool_call_id, "reconciled": True}})
                mission.checkpoint = {**checkpoint, "status": "completed", "reconciled": True}
                mission.current_step += 1
                mission.transition(MissionStatus.READY, "parallel in-flight actions reconciled as executed", tool_call_ids=ambiguous_ids)
            else:
                mission.checkpoint = {**checkpoint, "status": "reconciled_not_executed", "reconciled": True}
                mission.transition(MissionStatus.READY, "parallel in-flight actions reconciled as not executed", tool_call_ids=ambiguous_ids)
            return self.store.save(mission)
        action_id = str(checkpoint.get("action_id", ""))
        step_id = str(checkpoint.get("step_id", ""))
        if executed:
            result = dict(observation or {"success": True, "source": "external_reconciliation"})
            result.setdefault("success", True)
            result.update({"action_id": action_id, "step_id": step_id, "type": "reconciled_observation"})
            mission.record_observation(result)
            mission.record_action(action_id, step_id, "completed", result)
            mission.checkpoint = {**checkpoint, "status": "completed", "reconciled": True}
            mission.evidence.append({"criterion_id": result.get("criterion_id", step_id), "passed": bool(result.get("success")), "source": result.get("source", "external_reconciliation"), "result": result, "provenance": {"mission_id": mission.mission_id, "action_id": action_id, "reconciled": True}})
            mission.current_step += 1
            mission.transition(MissionStatus.READY, "in-flight action reconciled as executed", action_id=action_id)
        else:
            mission.checkpoint = {**checkpoint, "status": "reconciled_not_executed", "reconciled": True}
            mission.transition(MissionStatus.READY, "in-flight action reconciled as not executed", action_id=action_id)
        return self.store.save(mission)

    def run_model_loop(self, mission_id: str, model: NativeModel, *, tools: list[dict[str, Any]], run_id: str = "", max_turns: int = 20) -> Mission:
        """Run a real model/tool/observation loop for a durable mission."""
        from security.authorization import authorize_tool
        from security.authorization_context import AuthorizationContext
        from tools.registry import execute as execute_tool

        mission = self._load(mission_id)
        if mission.progress.get("execution_mode") == "dag":
            raise PermissionError("model tool proposals cannot bypass the authorized deterministic execution graph")
        if mission.is_terminal:
            return mission
        if (mission.checkpoint or {}).get("status") in {"in_flight", "in_flight_parallel"}:
            mission.error = "in-flight native tool outcome is unknown; reconciliation required"
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return self.store.save(mission)
        run_id = run_id or str(mission.progress.get("model_run_id") or hashlib.sha256((mission.mission_id + mission.request_id).encode()).hexdigest()[:20])
        mission.progress["model_run_id"] = run_id
        progress = mission.progress.setdefault("model_loop", {"turns": [], "tool_results": [], "seen_call_ids": []})
        seen = set(str(item) for item in progress.setdefault("seen_call_ids", []))
        auth_context = None
        if mission.authorization_context:
            try:
                auth_context = AuthorizationContext.from_dict(dict(mission.authorization_context))
            except (KeyError, TypeError, ValueError, PermissionError):
                auth_context = None

        for _ in range(max_turns):
            turn_id = f"{run_id}:turn:{len(progress['turns']) + 1}"
            current_step = mission.current_plan_step
            assembled = ContextAssembler().build(mission, tool_results=progress.get("tool_results", ()), tools=tools)
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
                turn = model.complete(messages, tools, mission_id=mission.mission_id, run_id=run_id, turn_id=turn_id, plan_version=mission.plan.version)
            except ProviderError as exc:
                kind = getattr(exc, "kind", "PROVIDER_FAILURE")
                failure = {"class": FailureClass.PROVIDER.value, "kind": str(kind), "reason": str(exc), "turn_id": turn_id, "run_id": run_id}
                mission.failures.append(failure)
                mission.progress.setdefault("model_failures", []).append(failure)
                mission.emit(EventType.FAILURE_DETECTED, data=failure)
                mission.error = f"model provider failure: {kind}"
                mission.retry_count += 1
                action = self.recovery_policy.action_for(FailureClass.PROVIDER, mission.retry_count - 1)
                mission.emit(EventType.FAILURE_DIAGNOSED, data={"class": FailureClass.PROVIDER.value, "kind": str(kind), "recovery": action.value})
                if action is RecoveryAction.RETRY:
                    mission.transition(MissionStatus.READY, "provider failure; bounded retry selected")
                elif action is RecoveryAction.REPLAN:
                    mission.transition(MissionStatus.REPLANNING, "provider failure; replan selected")
                else:
                    mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
                self.store.save(mission)
                if mission.is_terminal:
                    return mission
                continue
            if auth_context is not None and turn.tool_calls:
                from dataclasses import replace as replace_dataclass
                turn = replace_dataclass(turn, tool_calls=tuple(
                    replace_dataclass(
                        proposal,
                        request_id=mission.request_id,
                        authorization_context_id=auth_context.owner_evidence_fingerprint,
                        scope_snapshot_id=auth_context.scope_snapshot.snapshot_id if auth_context.scope_snapshot else "",
                    )
                    for proposal in turn.tool_calls
                ))
            progress["turns"].append(turn.to_dict())
            mission.emit(EventType.MODEL_TURN, data={"turn_id": turn.turn_id, "provider": turn.provider, "model": turn.model, "tool_call_count": len(turn.tool_calls), "finish_reason": turn.finish_reason})
            if not turn.tool_calls:
                progress["last_model_content"] = turn.content
                progress["last_model_finish_reason"] = turn.finish_reason
                verification = self.verifier(mission)
                mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
                if verification.verified:
                    mission.transition(MissionStatus.GOAL_COMPLETED, "model final accepted with deterministic evidence")
                    mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
                    mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state, "model_final": turn.content})
                else:
                    mission.error = "model final lacked deterministic goal evidence"
                    mission.transition(MissionStatus.READY, mission.error)
                return self.store.save(mission)
            if len(turn.tool_calls) > 1:
                self._run_parallel_model_calls(mission, turn.tool_calls, auth_context=auth_context, run_id=run_id, current_step=current_step, progress=progress, seen=seen)
                self.store.save(mission)
                if mission.is_terminal:
                    return mission
                continue
            for proposal in turn.tool_calls:
                if proposal.mission_id and proposal.mission_id != mission.mission_id:
                    result = ToolCallResult(proposal, False, error="tool call belongs to another mission")
                elif proposal.run_id and proposal.run_id != run_id:
                    result = ToolCallResult(proposal, False, error="tool call belongs to another run")
                elif proposal.tool_call_id in seen:
                    result = ToolCallResult(proposal, False, error="duplicate tool call rejected; prior result is authoritative")
                else:
                    seen.add(proposal.tool_call_id)
                    progress["seen_call_ids"].append(proposal.tool_call_id)
                    argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
                    decision = authorize_tool([proposal.name, argument], context=auth_context)
                    mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
                    mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
                    if not decision.allowed:
                        result = ToolCallResult(proposal, False, error=decision.reason)
                    else:
                        try:
                            mission.checkpoint = {"status": "in_flight", "tool_call_id": proposal.tool_call_id, "action_id": proposal.action_id, "step_id": proposal.step_id, "run_id": run_id}
                            self.store.save(mission)
                            raw = execute_tool(proposal.name, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id)
                            observation = dict(raw or {})
                            observation.update({"type": "tool_observation", "action_id": proposal.action_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
                            mission.record_observation(observation)
                            if current_step is not None:
                                self._interpret_observation(mission, current_step, observation, success=bool(observation.get("success", observation.get("ok", True))))
                            if bool(observation.get("success", observation.get("ok", True))):
                                criterion_id = observation.get("criterion_id") or (mission.completion_criteria[0].get("criterion_id") if mission.completion_criteria else None) or proposal.step_id or proposal.name
                                mission.evidence.append({"criterion_id": criterion_id, "passed": True, "source": observation.get("source", proposal.name), "result": observation, "provenance": {"mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id}})
                            mission.record_action(proposal.action_id or proposal.tool_call_id, proposal.step_id or proposal.name, "completed", observation)
                            mission.checkpoint = {"status": "completed", "tool_call_id": proposal.tool_call_id, "action_id": proposal.action_id, "step_id": proposal.step_id, "run_id": run_id}
                            result = ToolCallResult(proposal, True, result=observation)
                        except Exception as exc:
                            mission.error = f"native tool outcome is ambiguous: {type(exc).__name__}"
                            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
                            return self.store.save(mission)
                progress["tool_results"].append(result.to_dict())
            self.store.save(mission)
        mission.error = "model turn budget exhausted"
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        return self.store.save(mission)

    def _run_parallel_model_calls(self, mission: Mission, proposals: tuple[Any, ...], *, auth_context: Any, run_id: str, current_step: Any, progress: dict[str, Any], seen: set[str]) -> None:
        """Authorize and execute independent proposals concurrently, then fold results deterministically."""
        from security.authorization import authorize_tool
        from tools.registry import execute as execute_tool
        identity_errors = set(validate_proposals(proposals, mission_id=mission.mission_id, run_id=run_id, seen_call_ids=seen))
        authorized: list[tuple[Any, Any, Any]] = []
        results: list[ToolCallResult] = []
        for proposal in proposals:
            mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
            if any(proposal.tool_call_id == error.split(":", 1)[0] for error in identity_errors) or proposal.tool_call_id in seen:
                results.append(ToolCallResult(proposal, False, error="invalid, stale, or duplicate tool call"))
                continue
            seen.add(proposal.tool_call_id)
            progress["seen_call_ids"].append(proposal.tool_call_id)
            argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
            decision = authorize_tool([proposal.name, argument], context=auth_context)
            mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
            if decision.allowed:
                authorized.append((proposal, argument, decision))
            else:
                results.append(ToolCallResult(proposal, False, error=decision.reason))
        mission.checkpoint = {"status": "in_flight_parallel", "tool_call_ids": [item[0].tool_call_id for item in authorized], "run_id": run_id}
        self.store.save(mission)
        def execute_one(item: tuple[Any, Any, Any]) -> dict[str, Any]:
            proposal, argument, decision = item
            try:
                return dict(execute_tool(proposal.name, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id) or {})
            except Exception as exc:
                # An exception after dispatch cannot prove that the external side effect did not happen.
                # Preserve ambiguity so recovery cannot blindly replay this proposal.
                return {"_ambiguous": True, "error": str(exc), "failure_class": FailureClass.UNKNOWN.value, "exception": type(exc).__name__}
        raw_results = execute_bounded_parallel(authorized, execute_one, max_workers=min(4, max(1, len(authorized))))
        ambiguous: list[tuple[Any, dict[str, Any]]] = []
        for item, raw in zip(authorized, raw_results):
            if raw.get("_ambiguous"):
                ambiguous.append((item[0], raw))
                continue
            proposal = item[0]
            observation = dict(raw)
            observation.update({"type": "tool_observation", "action_id": proposal.action_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
            mission.record_observation(observation)
            success = bool(observation.get("success", observation.get("ok", True)))
            if current_step is not None:
                self._interpret_observation(mission, current_step, observation, success=success)
            if success:
                criterion_id = observation.get("criterion_id") or (mission.completion_criteria[0].get("criterion_id") if mission.completion_criteria else None) or proposal.step_id or proposal.name
                mission.evidence.append({"criterion_id": criterion_id, "passed": True, "source": observation.get("source", proposal.name), "result": observation, "provenance": {"mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id}})
            mission.record_action(proposal.action_id or proposal.tool_call_id, proposal.step_id or proposal.name, "completed" if success else "failed", observation)
            results.append(ToolCallResult(proposal, success, result=observation, error=str(observation.get("error", ""))))
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
                "run_id": run_id,
            }
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return
        mission.checkpoint = {"status": "completed", "tool_call_ids": [item[0].tool_call_id for item in authorized], "run_id": run_id}

    @staticmethod
    def _graph_authorization_hash(mission: Mission) -> str:
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        return snapshot.authorization_hash

    def _sync_graph_events(self, mission: Mission, state: dict[str, Any]) -> None:
        """Mirror durable scheduling decisions into the existing hash-chained trajectory."""
        start = int(state.get("trajectory_event_count", 0))
        events = list(state.get("events", []))
        for item in events[start:]:
            mission.emit(EventType.SCHEDULER_DECISION, step_id=str(item.get("step_id", "")), data=dict(item))
            if item.get("event") in {"NODE_REJECTED", "AUTHORIZATION_BLOCKED", "BUDGET_BLOCKED", "RECOVERY_RECONCILED", "NODE_CANCELLED"}:
                mission.evidence.append({
                    "criterion_id": f"scheduler:{item.get('event')}:{item.get('node_id', '')}:{len(mission.evidence)}",
                    "passed": False,
                    "source": "deterministic_scheduler",
                    "result": dict(item),
                    "provenance": {"mission_id": mission.mission_id, "execution_run_id": state.get("execution_run_id"), "plan_hash": state.get("plan_hash"), "authorization_hash": state.get("authorization_hash")},
                })
        state["trajectory_event_count"] = len(events)

    def _authorize_graph_node(self, mission: Mission, step: PlanStep) -> tuple[bool, str]:
        valid, reason = self._mission_authorization(mission, actions={step.action} if step.action != "__planning_failure__" else set())
        if not valid:
            return False, reason
        try:
            decision = self.authorizer(mission, step)
        except Exception as exc:
            return False, f"authorization check failed closed: {type(exc).__name__}"
        if not isinstance(decision, tuple) or len(decision) != 2 or not bool(decision[0]):
            return False, str(decision[1] if isinstance(decision, tuple) and len(decision) > 1 else "authorization denied")
        return True, str(decision[1])

    def run_graph(self, mission_id: str, *, execution_run_id: str = "", max_parallel: int | None = None, node_budget: int | None = None, max_batches: int = 1) -> Mission:
        """Run a deterministic, bounded DAG slice through the existing durable MissionStore.

        Authorization is checked again immediately before each node dispatch. A crash
        marks outstanding work UNKNOWN and requires reconciliation rather than replay.
        """
        if max_batches < 1:
            raise ValueError("max_batches must be at least one")
        if max_parallel is not None and not 1 <= max_parallel <= 32:
            raise ValueError("max_parallel must be between one and the hard runtime cap of 32")
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        auth_ok, auth_reason = self._mission_authorization(mission, actions=set())
        if not auth_ok:
            mission.error = auth_reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": auth_reason})
            if not mission.is_terminal:
                mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, auth_reason)
            return self.store.save(mission)
        authorization_hash = self._graph_authorization_hash(mission)
        run_id = execution_run_id or str(mission.progress.get("execution_run_id") or hashlib.sha256((mission.mission_id + "\0" + mission.request_id + "\0" + mission.plan.fingerprint).encode()).hexdigest()[:24])
        graph = ExecutionGraph.from_plan(mission.mission_id, run_id, mission.plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        state = dict(mission.checkpoint.get("orchestration", {})) if isinstance(mission.checkpoint, dict) else {}
        if not state:
            state = DeterministicScheduler.initial_state(graph, authorization_hash=authorization_hash, node_budget=node_budget, max_parallel=max_parallel or 1)
        DeterministicScheduler.check_identity(state, graph, authorization_hash)
        if state.get("running_nodes") and not state.get("recovery_required"):
            DeterministicScheduler.recover(state)
        mission.progress["execution_run_id"] = run_id
        if state.get("recovery_required"):
            if mission.status is not MissionStatus.RECOVERY_REQUIRED:
                mission.error = "unknown node outcome requires reconciliation before graph continuation"
                if not mission.is_terminal:
                    mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            mission.checkpoint = {**mission.checkpoint, "orchestration": state}
            self._sync_graph_events(mission, state)
            return self.store.save(mission)
        if state.get("paused") or state.get("cancel_requested"):
            if state.get("cancel_requested") and not mission.is_terminal:
                mission.transition(MissionStatus.CANCELLED, "Owner cancellation prevents future node starts")
            elif state.get("paused") and mission.status is not MissionStatus.PAUSED:
                mission.transition(MissionStatus.PAUSED, "Owner pause prevents future node starts")
            mission.checkpoint = {**mission.checkpoint, "orchestration": state}
            self._sync_graph_events(mission, state)
            return self.store.save(mission)
        if len(state.get("completed_nodes", [])) == len(graph.nodes):
            mission.progress["graph_completed"] = True
            if mission.status is not MissionStatus.READY:
                mission.transition(MissionStatus.READY, "all execution graph nodes were already completed")
            self._sync_graph_events(mission, state)
            mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_checkpointed", "execution_run_id": run_id, "plan_hash": graph.plan_hash}
            return self.store.save(mission)
        if not DeterministicScheduler.start_run(state):
            mission.error = "execution run budget exhausted"
            mission.checkpoint = {**mission.checkpoint, "orchestration": state}
            self._sync_graph_events(mission, state)
            if not mission.is_terminal:
                mission.transition(MissionStatus.BUDGET_BLOCKED, mission.error)
            return self.store.save(mission)

        steps = {str(step.step_id): step for step in mission.plan.steps}
        for _ in range(max_batches):
            effective_parallelism = min(int(max_parallel or state["budget_state"]["max_parallel"]), int(state["budget_state"]["max_parallel"]))
            batch = DeterministicScheduler.reserve_batch(graph, state, limit=effective_parallelism)
            if not batch:
                break
            mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_batch_in_flight", "execution_run_id": run_id, "plan_hash": graph.plan_hash}
            self._sync_graph_events(mission, state)
            self.store.save(mission)

            def execute_one(node: ExecutionNode) -> tuple[str, dict[str, Any], str]:
                step = copy.deepcopy(steps[node.step_id])
                worker_mission = copy.deepcopy(mission)
                allowed, reason = self._authorize_graph_node(worker_mission, step)
                if not allowed:
                    return "AUTHORIZATION", {}, reason
                action_id = hashlib.sha256(f"{mission.mission_id}\0{run_id}\0{graph.plan_hash}\0{node.node_id}".encode()).hexdigest()
                try:
                    result = copy.deepcopy(dict(self.executor(worker_mission, step, action_id) or {}))
                except Exception as exc:
                    return "UNKNOWN_OUTCOME", {}, f"{type(exc).__name__}: execution outcome is unknown"
                return "RESULT", result, ""

            futures: dict[str, Any] = {}
            with ThreadPoolExecutor(max_workers=min(effective_parallelism, len(batch)), thread_name_prefix="mission-dag") as pool:
                for node in batch:
                    futures[node.node_id] = pool.submit(execute_one, node)
                for node in batch:
                    future = futures[node.node_id]
                    try:
                        result_kind, observation, detail = future.result()
                    except Exception as exc:
                        result_kind, observation, detail = "UNKNOWN_OUTCOME", {}, f"{type(exc).__name__}: worker outcome is unknown"
                    latest = self._load(mission_id)
                    latest_state = dict(latest.checkpoint.get("orchestration", {})) if isinstance(latest.checkpoint, dict) else {}
                    if latest_state.get("plan_hash") != graph.plan_hash or latest_state.get("execution_run_id") != run_id:
                        raise GraphValidationError("execution checkpoint changed identity while node was running")
                    mission = latest
                    state = latest_state
                    if result_kind == "AUTHORIZATION":
                        DeterministicScheduler.finish(state, node, success=False, error=detail, failure_class="AUTHORIZATION")
                    elif result_kind == "UNKNOWN_OUTCOME":
                        DeterministicScheduler.finish(state, node, success=False, error=detail, failure_class="UNKNOWN_OUTCOME")
                    else:
                        success = observation.get("success", observation.get("ok", False)) is True
                        failure_class = str(observation.get("failure_class", FailureClass.UNKNOWN.value))
                        DeterministicScheduler.finish(state, node, success=success, result=observation, error=str(observation.get("error", "")), failure_class=failure_class)
                        enriched = {**observation, "mission_id": mission.mission_id, "execution_run_id": run_id, "node_id": node.node_id, "step_id": node.step_id, "plan_hash": graph.plan_hash}
                        if success:
                            mission.evidence.append({"criterion_id": node.step_id, "passed": True, "source": steps[node.step_id].action, "result": enriched, "provenance": {"mission_id": mission.mission_id, "execution_run_id": run_id, "node_id": node.node_id, "plan_hash": graph.plan_hash, "authorization_hash": authorization_hash}})
                            action_id = hashlib.sha256(f"{mission.mission_id}\0{run_id}\0{graph.plan_hash}\0{node.node_id}".encode()).hexdigest()
                            mission.record_action(action_id, node.step_id, "completed", enriched)
                    self._sync_graph_events(mission, state)
                    mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_batch_in_flight" if state.get("running_nodes") else "graph_checkpointed", "execution_run_id": run_id, "plan_hash": graph.plan_hash}
                    self.store.save(mission)
            if state.get("recovery_required"):
                mission.error = "unknown node outcome requires reconciliation; no blind retry was attempted"
                mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": mission.error, "execution_run_id": run_id})
                mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
                self._sync_graph_events(mission, state)
                return self.store.save(mission)
            if state.get("cancel_requested"):
                if mission.status is not MissionStatus.CANCELLED:
                    mission.transition(MissionStatus.CANCELLED, "Owner cancellation prevents future node starts")
                self._sync_graph_events(mission, state)
                return self.store.save(mission)
            if state.get("paused"):
                if mission.status is not MissionStatus.PAUSED:
                    mission.transition(MissionStatus.PAUSED, "Owner pause took effect after in-flight nodes settled")
                self._sync_graph_events(mission, state)
                mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_paused", "execution_run_id": run_id, "plan_hash": graph.plan_hash}
                return self.store.save(mission)
        self._sync_graph_events(mission, state)
        mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_checkpointed", "execution_run_id": run_id, "plan_hash": graph.plan_hash}
        rejected = [item for item in state.get("nodes", {}).values() if item.get("state") == NodeState.REJECTED.value]
        if rejected:
            mission.error = "execution graph contains a node rejected by authorization or validation"
            failure_classes = {str(item.get("failure_class", "")) for item in rejected}
            target = MissionStatus.SCOPE_BLOCKED if "SCOPE" in failure_classes else MissionStatus.AUTHORIZATION_BLOCKED if "AUTHORIZATION" in failure_classes else MissionStatus.SAFETY_BLOCKED
            if not mission.is_terminal:
                mission.transition(target, mission.error)
        elif state.get("failed_nodes") or state.get("blocked_nodes"):
            mission.error = "execution graph contains failed or dependency-blocked nodes"
            if not mission.is_terminal:
                mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        elif len(state.get("completed_nodes", [])) == len(graph.nodes):
            mission.progress["graph_completed"] = True
            if not mission.is_terminal:
                mission.transition(MissionStatus.READY, "all execution graph nodes completed")
        else:
            budget = state.get("budget_state", {})
            tool_limit = budget.get("tool_budget", {}).get("dispatch_limit")
            node_limit = budget.get("node_budget")
            budget_exhausted = bool(state.get("budget_expired") or state.get("run_budget_exhausted"))
            budget_exhausted = budget_exhausted or (tool_limit is not None and int(budget["tool_budget"]["dispatches_started"]) >= int(tool_limit))
            budget_exhausted = budget_exhausted or (node_limit is not None and int(budget["nodes_started"]) >= int(node_limit))
            if budget_exhausted:
                mission.error = "execution graph budget exhausted with nodes remaining"
                if not mission.is_terminal:
                    mission.transition(MissionStatus.BUDGET_BLOCKED, mission.error)
            elif not mission.is_terminal:
                mission.transition(MissionStatus.READY, "graph slice checkpointed for durable continuation")
        return self.store.save(mission)

    def _require_owner_graph_control(self, mission: Mission, authorization_context: Any) -> None:
        from security.authorization_context import AuthorizationContext
        from security.owner_policy import policy_fingerprint
        if not isinstance(authorization_context, AuthorizationContext):
            raise TypeError("graph controls require typed Owner AuthorizationContext")
        if not authorization_context.owner_evidence.is_valid(authorization_context.request_id, authorization_context.session_id):
            raise PermissionError("Owner control evidence expired or is invalid")
        if authorization_context.policy_fingerprint != policy_fingerprint():
            raise PermissionError("Owner control policy is stale")
        if authorization_context.request_id != mission.request_id:
            raise PermissionError("Owner control context belongs to another request")
        if authorization_context.owner_evidence_fingerprint != mission.owner_identity_ref:
            raise PermissionError("Owner control context does not match mission identity")
        expected_policy = str((mission.policy_snapshot or {}).get("owner_policy_fingerprint", ""))
        if expected_policy and authorization_context.policy_fingerprint != expected_policy:
            raise PermissionError("Owner control context has stale policy")
        expected_instruction = str((mission.policy_snapshot or {}).get("owner_instruction_fingerprint", ""))
        if expected_instruction and authorization_context.instruction_fingerprint != expected_instruction:
            raise PermissionError("Owner control instruction does not match the mission")

    def replan_graph(self, mission_id: str, new_plan: Plan, *, authorization_context: Any, completion_criteria: list[dict[str, Any]] | None = None) -> Mission:
        """Accept an Owner-authorized graph revision only before any dispatch.

        A plan revision receives a new run identity/hash, revalidates every action
        against the unchanged authorization snapshot, and inherits all remaining
        durable budgets. Mid-run replanning is deliberately refused until side
        effects have been explicitly reconciled by a separate safe workflow.
        """
        mission = self._load(mission_id)
        self._require_owner_graph_control(mission, authorization_context)
        if mission.is_terminal:
            raise ValueError("terminal mission cannot be replanned")
        if new_plan.objective != mission.objective:
            raise PermissionError("replanning cannot change the Owner objective")
        if new_plan.version <= mission.plan.version:
            raise ValueError("replanned plan version must increase monotonically")
        prior_state = dict(mission.checkpoint.get("orchestration", {}))
        if not prior_state or prior_state.get("running_nodes") or prior_state.get("recovery_required"):
            raise ValueError("graph can only be replanned from a quiescent initialized checkpoint")
        if prior_state.get("paused") or prior_state.get("cancel_requested"):
            raise ValueError("resume a paused graph before replanning; cancelled graphs cannot be replanned")
        budget = prior_state.get("budget_state", {})
        if int(budget.get("nodes_started", 0)) or any(int(item.get("attempts", 0)) for item in prior_state.get("nodes", {}).values()):
            raise ValueError("replan refused after dispatch; reconcile side effects before creating a new run")
        criteria = completion_criteria if completion_criteria is not None else list(mission.completion_criteria)
        new_step_ids = {str(step.step_id) for step in new_plan.steps}
        if not criteria or any(not isinstance(item, dict) or not str(item.get("criterion_id", "")).strip() for item in criteria):
            raise ValueError("replanned graph requires explicit deterministic completion criteria")
        if len({str(item["criterion_id"]) for item in criteria}) != len(criteria) or {str(item["criterion_id"]) for item in criteria} - new_step_ids:
            raise ValueError("replanned completion criteria must uniquely bind to new step identities")
        ExecutionGraph.from_plan("validation", "validation", new_plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        mission.plan = new_plan
        mission.completion_criteria = [dict(item) for item in criteria]
        mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": "Owner-authorized DAG replan"})
        run_id = hashlib.sha256(f"{mission.mission_id}\0{mission.request_id}\0{prior_state['execution_run_id']}\0{new_plan.fingerprint}\0{len(mission.plan_history)}".encode()).hexdigest()[:24]
        graph = ExecutionGraph.from_plan(mission.mission_id, run_id, new_plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        new_state = DeterministicScheduler.initial_state(graph, authorization_hash=self._graph_authorization_hash(mission), node_budget=budget.get("node_budget"), max_parallel=int(budget.get("max_parallel", 1)), max_runs=int(budget.get("run_budget", {}).get("run_limit", mission.max_iterations)), tool_budget=budget.get("tool_budget", {}).get("dispatch_limit"), retry_budget=budget.get("retry_budget", {}).get("retry_limit"), max_duration_seconds=None)
        new_state["budget_state"] = budget
        allowed, reason = self._mission_authorization(mission, actions={step.action for step in new_plan.steps if step.action != "__planning_failure__"})
        if not allowed:
            raise PermissionError("replanned actions exceed current authorization: " + reason)
        mission.progress["execution_run_id"] = run_id
        mission.checkpoint = {**mission.checkpoint, "status": "graph_initialized", "execution_run_id": run_id, "plan_hash": graph.plan_hash, "orchestration": new_state}
        mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint, "execution_run_id": run_id, "authorization_hash": new_state["authorization_hash"]})
        return self.store.save(mission)

    def control_graph(self, mission_id: str, command: str, *, authorization_context: Any) -> Mission:
        mission = self._load(mission_id)
        self._require_owner_graph_control(mission, authorization_context)
        if mission.is_terminal:
            raise ValueError("terminal mission cannot be controlled")
        state = dict(mission.checkpoint.get("orchestration", {})) if isinstance(mission.checkpoint, dict) else {}
        if not state:
            raise ValueError("mission has no initialized execution graph")
        if command == "resume" and state.get("running_nodes"):
            raise ValueError("cannot resume until in-flight nodes settle")
        DeterministicScheduler.set_control(state, command)
        if command == "cancel" and not state.get("running_nodes"):
            mission.transition(MissionStatus.CANCELLED, "Owner cancelled execution graph")
        elif command == "cancel":
            mission.transition(MissionStatus.CANCELLING, "Owner cancellation requested; in-flight nodes will settle")
        elif command == "pause" and not state.get("running_nodes"):
            mission.transition(MissionStatus.PAUSED, "Owner paused execution graph")
        elif command == "pause":
            mission.transition(MissionStatus.PAUSED, "Owner pause requested; in-flight nodes will settle")
        elif command == "resume" and mission.status is MissionStatus.PAUSED:
            mission.transition(MissionStatus.READY, "Owner resumed execution graph")
        self._sync_graph_events(mission, state)
        mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_checkpointed"}
        return self.store.save(mission)

    def reconcile_graph_node(self, mission_id: str, node_id: str, *, executed: bool, result: Any = None, authorization_context: Any) -> Mission:
        mission = self._load(mission_id)
        self._require_owner_graph_control(mission, authorization_context)
        authorization_hash = self._graph_authorization_hash(mission)
        run_id = str(mission.progress.get("execution_run_id", ""))
        graph = ExecutionGraph.from_plan(mission.mission_id, run_id, mission.plan, retry_policy_by_step=self.orchestration_retry_policies, resource_policy_by_step=self.orchestration_resource_policies)
        state = dict(mission.checkpoint.get("orchestration", {}))
        DeterministicScheduler.check_identity(state, graph, authorization_hash)
        DeterministicScheduler.reconcile(state, graph, node_id, executed=executed, result=result)
        if executed:
            node = graph.by_id[node_id]
            receipt = {**dict(result or {}), "mission_id": mission.mission_id, "execution_run_id": run_id, "node_id": node.node_id, "step_id": node.step_id, "plan_hash": graph.plan_hash, "reconciled_by_owner": True}
            mission.evidence.append({"criterion_id": node.step_id, "passed": True, "source": "owner_reconciliation", "result": receipt, "provenance": {"mission_id": mission.mission_id, "execution_run_id": run_id, "node_id": node.node_id, "plan_hash": graph.plan_hash, "authorization_hash": authorization_hash, "owner_evidence_fingerprint": authorization_context.owner_evidence_fingerprint}})
            action_id = hashlib.sha256(f"{mission.mission_id}\0{run_id}\0{graph.plan_hash}\0{node.node_id}".encode()).hexdigest()
            mission.record_action(action_id, node.step_id, "reconciled", receipt)
        if not state.get("recovery_required") and mission.status is MissionStatus.RECOVERY_REQUIRED:
            if state.get("cancel_requested"):
                mission.transition(MissionStatus.READY, "Owner reconciled unknown outcome; cancellation remains in effect")
                mission.transition(MissionStatus.CANCELLED, "Owner cancellation remains in effect after reconciliation")
            elif state.get("paused"):
                mission.transition(MissionStatus.READY, "Owner reconciled unknown outcome; pause remains in effect")
                mission.transition(MissionStatus.PAUSED, "Owner pause remains in effect after reconciliation")
            else:
                mission.transition(MissionStatus.READY, "Owner reconciled unknown graph outcome")
        self._sync_graph_events(mission, state)
        mission.checkpoint = {**mission.checkpoint, "orchestration": state, "status": "graph_checkpointed"}
        return self.store.save(mission)

    def run_slice(self, mission_id: str) -> Mission:
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        if mission.progress.get("execution_mode") == "dag":
            return self.run_graph(mission_id)
        authorization_ok, authorization_reason = self._mission_authorization(mission)
        if not authorization_ok:
            mission.error = authorization_reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": authorization_reason})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, authorization_reason)
            return self.store.save(mission)
        if (mission.checkpoint or {}).get("status") == "in_flight":
            action_id = str(mission.checkpoint.get("action_id", ""))
            mission.error = "in-flight action outcome is unknown; reconciliation required"
            mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": mission.error, "action_id": action_id})
            mission.emit(EventType.FAILURE_DIAGNOSED, step_id=str(mission.checkpoint.get("step_id", "")), data={"class": FailureClass.UNKNOWN.value, "reason": mission.error, "recovery": "reconciliation_required", "action_id": action_id})
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error, action_id=action_id)
            return self.store.save(mission)
        if mission.iteration_count >= mission.max_iterations:
            mission.error = "iteration budget exhausted"
            mission.emit(EventType.FAILURE_DETECTED, data={"class": FailureClass.RESOURCE.value, "reason": mission.error})
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
            return self.store.save(mission)
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
            return self.store.save(mission)

        step = mission.current_plan_step
        action_id = f"{mission.mission_id}:{mission.plan.version}:{step.step_id}:{mission.current_step}"
        mission.emit(EventType.STEP_SELECTED, step_id=step.step_id, data={"action_id": action_id, "plan_version": mission.plan.version})
        signatures = mission.progress.setdefault("loop_signatures", {})
        signature = hashlib.sha256(json.dumps({"plan": mission.plan.fingerprint, "step": step.step_id, "action": step.action}, sort_keys=True).encode()).hexdigest()
        signatures[signature] = int(signatures.get(signature, 0)) + 1
        if signatures[signature] > 3:
            mission.error = "dead loop detected: repeated plan and action"
            mission.emit(EventType.FAILURE_DIAGNOSED, step_id=step.step_id, data={"class": FailureClass.LOGIC.value, "reason": mission.error})
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
            return self.store.save(mission)
        if any(item.get("action_id") == action_id and item.get("status") == "completed" for item in mission.action_history):
            mission.current_step += 1
            mission.transition(MissionStatus.READY, "idempotent action already completed")
            return self.store.save(mission)

        allowed, reason = self.authorizer(mission, step)
        mission.emit(EventType.AUTHORIZATION_CHECKED, step_id=step.step_id, data={"allowed": allowed, "reason": reason})
        if not allowed:
            mission.error = reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value if "authorization" in reason else FailureClass.SCOPE.value, "reason": reason, "step_id": step.step_id})
            mission.emit(EventType.OWNER_INPUT_REQUIRED if "authorization" in reason else EventType.FAILURE_DETECTED, step_id=step.step_id, data={"reason": reason})
            mission.transition(MissionStatus.OWNER_INPUT_REQUIRED if "authorization" in reason else MissionStatus.SCOPE_BLOCKED, reason)
            return self.store.save(mission)

        mission.transition(MissionStatus.RUNNING, "step started", step_id=step.step_id)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "in_flight", "plan_version": mission.plan.version}
        self.store.save(mission)
        try:
            result = self.executor(mission, step, action_id)
        except Exception as exc:
            # Keep the in-flight checkpoint durable. A new runtime can safely resume it.
            mission.error = type(exc).__name__
            mission.record_observation({"type": "execution_exception", "success": False, "error": str(exc), "action_id": action_id})
            return self.store.save(mission)

        observation = dict(result or {})
        observation.setdefault("type", "tool_observation")
        observation.setdefault("action_id", action_id)
        observation.setdefault("step_id", step.step_id)
        observation.setdefault("mission_id", mission.mission_id)
        typed_observation = Observation.from_result(step.action, action_id, observation, request_id=mission.request_id, scope=mission.scope_snapshot)
        observation["observation"] = typed_observation.to_dict()
        mission.transition(MissionStatus.OBSERVING, "action returned observation", action_id=action_id)
        mission.record_observation(observation)
        success = bool(observation.get("success", observation.get("ok", False)))
        mission.record_action(action_id, step.step_id, "completed" if success else "failed", observation)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "completed", "plan_version": mission.plan.version}
        try:
            strategy_decision = self._interpret_observation(mission, step, observation, success=success)
        except (TypeError, ValueError, KeyError) as exc:
            mission.error = f"observation interpretation rejected: {type(exc).__name__}"
            mission.recovery_events.append({"event": "interpretation_rejected", "reason": str(exc), "action_id": action_id})
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            return self.store.save(mission)
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        scope_blocked = bool(observation.get("target") and isinstance(allowed_targets, (list, tuple, set)) and str(observation.get("target")) not in {str(item) for item in allowed_targets})
        if scope_blocked:
            mission.error = "observation proposed a target outside deterministic scope"
            mission.failures.append({"class": FailureClass.SCOPE.value, "reason": mission.error, "target": observation.get("target")})
            mission.transition(MissionStatus.SCOPE_BLOCKED, mission.error)
            return self.store.save(mission)
        if success:
            mission.evidence.append({"criterion_id": observation.get("criterion_id", step.step_id), "passed": True, "source": observation.get("source", step.action), "result": observation, "provenance": {"mission_id": mission.mission_id, "step_id": step.step_id, "action_id": action_id}})
            mission.emit(EventType.EVIDENCE_ADDED, step_id=step.step_id, data={"criterion_id": observation.get("criterion_id", step.step_id)})
            if strategy_decision is not None and strategy_decision.decision.value in {"REPLAN", "CHANGE_HYPOTHESIS", "ADD_EVIDENCE"}:
                mission.transition(MissionStatus.REPLANNING, strategy_decision.reason)
                mission.emit(EventType.REPLAN_TRIGGERED, step_id=step.step_id, data=strategy_decision.to_dict())
                new_plan = self.replanner(mission, {**observation, "interpretation": mission.interpretations[-1], "strategy_decision": strategy_decision.to_dict()})
                if new_plan.objective != mission.objective:
                    mission.error = "replanner attempted to change Owner objective"
                    mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                    return self.store.save(mission)
                mission.replan_history.append({"from_version": mission.plan.version, "to_version": new_plan.version, "reason": strategy_decision.reason, "trigger": strategy_decision.to_dict()})
                mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.plan = new_plan
                mission.current_step = 0
                mission.retry_count = 0
                mission.transition(MissionStatus.READY, "informative observation caused replan", plan_version=new_plan.version)
                return self.store.save(mission)
            mission.current_step += 1
            mission.retry_count = 0
            mission.transition(MissionStatus.READY, "observation accepted")
            return self.store.save(mission)

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
                return self.store.save(mission)
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
        return self.store.save(mission)

    def run_to_completion(self, mission_id: str, *, max_slices: int | None = None, heartbeat: Callable[[], None] | None = None) -> Mission:
        initial = self._load(mission_id)
        limit = max_slices or initial.max_iterations
        if initial.progress.get("execution_mode") == "dag":
            for _ in range(limit):
                if heartbeat is not None:
                    heartbeat()
                mission = self.run_graph(mission_id, max_batches=1)
                state = dict(mission.checkpoint.get("orchestration", {}))
                if mission.is_terminal or state.get("paused") or state.get("cancel_requested") or state.get("recovery_required"):
                    return mission
                if len(state.get("completed_nodes", [])) == len(state.get("nodes", {})):
                    verification = self.verifier(mission)
                    mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
                    if verification.verified:
                        mission.transition(MissionStatus.GOAL_COMPLETED, "execution DAG completed with deterministic evidence")
                        mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
                        mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state, "execution_run_id": state.get("execution_run_id")})
                    else:
                        mission.error = "execution graph completed without all required evidence"
                        mission.transition(MissionStatus.VERIFICATION_BLOCKED, mission.error)
                    return self.store.save(mission)
                budget = state.get("budget_state", {})
                node_limit = budget.get("node_budget")
                tool_limit = budget.get("tool_budget", {}).get("dispatch_limit")
                tool_exhausted = tool_limit is not None and int(budget.get("tool_budget", {}).get("dispatches_started", 0)) >= int(tool_limit) and bool(state.get("ready_nodes"))
                node_exhausted = node_limit is not None and int(budget.get("nodes_started", 0)) >= int(node_limit) and bool(state.get("ready_nodes"))
                if tool_exhausted or node_exhausted or state.get("budget_expired") or state.get("run_budget_exhausted"):
                    return mission
                # No ready/running work means budget exhaustion or a blocked graph;
                # retain the durable checkpoint and stop instead of spinning.
                if not state.get("ready_nodes") and not state.get("running_nodes"):
                    return mission
            return self._load(mission_id)
        for _ in range(limit):
            if heartbeat is not None:
                heartbeat()
            mission = self.run_slice(mission_id)
            if mission.is_terminal:
                return mission
        return self._load(mission_id)


__all__ = ["MissionRuntime"]
