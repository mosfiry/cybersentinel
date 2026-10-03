from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
import hashlib
import inspect
import json

from .mission import Mission, MissionClaimBinding, MissionStatus, MissionStore
from .execution_fence import ExecutionFence, ExecutionFenceError
from .planning import FailureClass, GoalVerification, Plan, PlanStep, RecoveryAction, RecoveryPolicy, VerificationCriterion, evidence_for
from .trajectory import EventType
from .observation import Observation
from .observation_intelligence import ObservationInterpreter, should_interpret_observation
from .hypotheses import HypothesisEngine, HypothesisState
from .strategy import StrategyState, decide as decide_strategy
from .model_protocol import ConversationTurn, NativeModel, ToolCallResult, validate_model_turn
from .provider_api import ProviderError
from .model_intelligence.context import ContextAssembler
from .model_intelligence.tool_calls import execute_bounded_parallel, validate_proposals

class MissionRuntime:
    """Persistent autonomous mission loop. Every slice is restart-safe and bounded."""

    def __init__(self, store: MissionStore, *, executor: Callable[[Mission, PlanStep, str], dict[str, Any]], authorizer: Callable[[Mission, PlanStep], tuple[bool, str]] | None = None, replanner: Callable[[Mission, dict[str, Any]], Plan] | None = None, verifier: Callable[[Mission], GoalVerification] | None = None, recovery_policy: RecoveryPolicy | None = None, interpreter: ObservationInterpreter | None = None, require_authorization_snapshot: bool = True, authorization_snapshot_factory: Callable[[Mission], Any] | None = None, execution_fence: ExecutionFence | None = None, require_execution_fence: bool = False):
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
            return self.store.save(mission)
        return self.store.save(mission, execution_fence=fence)

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

    def create_from_owner_instruction(self, instruction: str, plan: Plan, *, authorization_context: Any, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, owner_identity_ref: str = "", provenance: dict[str, Any] | None = None, authorization_snapshot_factory: Callable[[Mission], Any] | None = None) -> Mission:
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
            provenance={"source": "owner_instruction", **(provenance or {})},
            authorization_snapshot_factory=authorization_snapshot_factory,
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
    ) -> Any:
        """Dispatch native-model tools with the same strict workspace/evidence boundary."""
        from tools.registry import execute as execute_tool

        workspace = None
        evidence_store = None
        target_identity = None
        mission_authorization = mission.authorization_snapshot
        if name == "run_project_tests":
            if execution_fence is None:
                raise ExecutionFenceError("native workspace dispatch requires an execution fence")
            if (
                not execution_fence.queue.require_execution_fence
                or execution_fence.queue.mission_store is not self.store
            ):
                raise ExecutionFenceError("native workspace dispatch requires its strict queue and MissionStore")
            execution_fence.assert_active_execution(mission)
            from security.mission_authorization import MissionAuthorizationSnapshot
            from workspace import Workspace
            from .evidence import EvidenceChainStore

            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            mission_authorization = snapshot
            workspace_root = str(snapshot.workspace_boundary.get("root", "")).strip()
            if not workspace_root:
                raise ExecutionFenceError("native workspace dispatch requires the Owner-authorized workspace root")
            workspace = Workspace(workspace_root)
            evidence_store = EvidenceChainStore(
                Path(self.store.db_path).with_name("evidence_chain.db"),
                execution_fence=execution_fence,
                mission_store=self.store,
                mission=mission,
                require_execution_fence=True,
            )
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
            workspace=workspace,
            evidence_store=evidence_store,
            mission_id=mission.mission_id,
            target_identity=target_identity,
            execution_fence=execution_fence,
            execution_id=execution_id,
        )

    def run_model_loop(self, mission_id: str, model: NativeModel, *, tools: list[dict[str, Any]], run_id: str = "", max_turns: int = 20, heartbeat: Callable[[], None] | None = None) -> Mission:
        """Run a real model/tool/observation loop for a durable mission."""
        from security.authorization import authorize_tool
        from security.authorization_context import AuthorizationContext

        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        if (mission.checkpoint or {}).get("status") in {"in_flight", "in_flight_parallel"}:
            mission.error = "in-flight native tool outcome is unknown; reconciliation required"
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return self._save(mission)
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
            if heartbeat is not None:
                heartbeat()
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
                turn = validate_model_turn(model.complete(messages, tools, mission_id=mission.mission_id, run_id=run_id, turn_id=turn_id, plan_version=mission.plan.version))
            except ProviderError as exc:
                kind = getattr(exc, "kind", "PROVIDER_FAILURE")
                attempts = [
                    {key: str(item.get(key, "")) for key in ("provider", "model", "kind")}
                    for item in getattr(exc, "attempts", ())
                    if isinstance(item, dict)
                ]
                failure = {
                    "class": FailureClass.PROVIDER.value,
                    "kind": str(kind),
                    "provider": str(getattr(exc, "provider", "") or ""),
                    "model": str(getattr(exc, "model", "") or ""),
                    "attempts": attempts,
                    "reason": "provider/model call failed",
                    "turn_id": turn_id,
                    "run_id": run_id,
                }
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
                self._save(mission)
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
                return self._save(mission)
            if len(turn.tool_calls) > 1:
                self._run_parallel_model_calls(mission, turn.tool_calls, auth_context=auth_context, run_id=run_id, current_step=current_step, progress=progress, seen=seen)
                self._save(mission)
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
                            task_id = proposal.step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                            execution_id = proposal.action_id or proposal.tool_call_id
                            mission.checkpoint = {"status": "in_flight", "tool_call_id": proposal.tool_call_id, "action_id": execution_id, "step_id": task_id, "run_id": run_id, "plan_version": mission.plan.version}
                            dispatch_fence = self._fence_for(mission, task_id=task_id, execution_id=execution_id)
                            if dispatch_fence is not None:
                                dispatch_fence.assert_active_execution(mission)
                            self._save(mission)
                            if heartbeat is not None:
                                heartbeat()
                            if dispatch_fence is not None:
                                dispatch_fence.assert_active_execution(mission)
                            raw = self._execute_native_tool(
                                proposal.name,
                                argument,
                                decision.decision,
                                mission,
                                dispatch_fence,
                                execution_id,
                            )
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
                            return self._save(mission)
                progress["tool_results"].append(result.to_dict())
            self._save(mission)
        mission.error = "model turn budget exhausted"
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        return self._save(mission)

    def _run_parallel_model_calls(self, mission: Mission, proposals: tuple[Any, ...], *, auth_context: Any, run_id: str, current_step: Any, progress: dict[str, Any], seen: set[str]) -> None:
        """Authorize and execute independent proposals concurrently, then fold results deterministically."""
        from security.authorization import authorize_tool
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
        self._save(mission)
        def execute_one(item: tuple[Any, Any, Any]) -> dict[str, Any]:
            proposal, argument, decision = item
            try:
                task_id = proposal.step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                execution_id = proposal.action_id or proposal.tool_call_id
                dispatch_fence = self._fence_for(mission, task_id=task_id, execution_id=execution_id)
                if dispatch_fence is not None:
                    dispatch_fence.assert_active_execution(mission)
                return dict(self._execute_native_tool(
                    proposal.name,
                    argument,
                    decision.decision,
                    mission,
                    dispatch_fence,
                    execution_id,
                ) or {})
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
                "execution_ids": [item[0].action_id or item[0].tool_call_id for item in authorized],
                "task_ids": [
                    item[0].step_id or str(getattr(current_step, "step_id", "") or "__mission__")
                    for item in authorized
                ],
                "plan_version": mission.plan.version,
                "run_id": run_id,
            }
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return
        mission.checkpoint = {"status": "completed", "tool_call_ids": [item[0].tool_call_id for item in authorized], "run_id": run_id}

    def run_slice(self, mission_id: str) -> Mission:
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        authorization_ok, authorization_reason = self._mission_authorization(mission)
        if not authorization_ok:
            mission.error = authorization_reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": authorization_reason})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, authorization_reason)
            return self._save(mission)
        checkpoint = dict(mission.checkpoint or {})
        checkpoint_status = checkpoint.get("status")
        if checkpoint_status in {"in_flight", "in_flight_parallel"}:
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

        mission.transition(MissionStatus.RUNNING, "step started", step_id=step.step_id)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "in_flight", "plan_version": mission.plan.version}
        self._save(mission)
        dispatch_fence = self._fence_for(mission, task_id=step.step_id, execution_id=action_id)
        if dispatch_fence is not None:
            dispatch_fence.assert_active_execution(mission)
        try:
            if dispatch_fence is None:
                result = self.executor(mission, step, action_id)
            elif self._executor_accepts_fence(self.executor):
                result = self.executor(mission, step, action_id, execution_fence=dispatch_fence)
            elif self.require_execution_fence:
                raise ExecutionFenceError("strict runtime executor does not accept execution fences")
            else:
                result = self.executor(mission, step, action_id)
        except ExecutionFenceError:
            raise
        except Exception as exc:
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
            mission.evidence.append({"criterion_id": observation.get("criterion_id", step.step_id), "passed": True, "source": observation.get("source", step.action), "result": observation, "provenance": {"mission_id": mission.mission_id, "step_id": step.step_id, "action_id": action_id}})
            mission.emit(EventType.EVIDENCE_ADDED, step_id=step.step_id, data={"criterion_id": observation.get("criterion_id", step.step_id)})
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
