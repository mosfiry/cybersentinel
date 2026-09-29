from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
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


class MissionRuntime:
    """Persistent autonomous mission loop. Every slice is restart-safe and bounded."""

    def __init__(self, store: MissionStore, *, executor: Callable[[Mission, PlanStep, str], dict[str, Any]], authorizer: Callable[[Mission, PlanStep], tuple[bool, str]] | None = None, replanner: Callable[[Mission, dict[str, Any]], Plan] | None = None, verifier: Callable[[Mission], GoalVerification] | None = None, recovery_policy: RecoveryPolicy | None = None, interpreter: ObservationInterpreter | None = None, require_authorization_snapshot: bool = True, authorization_snapshot_factory: Callable[[Mission], Any] | None = None):
        self.store = store
        self.executor = executor
        self.authorizer = authorizer or self._default_authorizer
        self.replanner = replanner or self._default_replanner
        self.verifier = verifier or self._default_verifier
        self.recovery_policy = recovery_policy or RecoveryPolicy()
        self.interpreter = interpreter or ObservationInterpreter()
        self.require_authorization_snapshot = require_authorization_snapshot
        self.authorization_snapshot_factory = authorization_snapshot_factory

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
    def _proposal_snapshot_gate(mission: Mission, tool_name: str) -> tuple[bool, str, str]:
        from security.execution_proof import RejectionCode
        from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
        if not mission.authorization_snapshot:
            return False, RejectionCode.SNAPSHOT_MISSING.value, "mission authorization snapshot missing"
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
        except (MissionAuthorizationError, KeyError, TypeError, ValueError, PermissionError):
            return False, RejectionCode.SNAPSHOT_INVALID.value, "mission authorization snapshot invalid"
        if not snapshot.is_active():
            return False, RejectionCode.SNAPSHOT_EXPIRED.value, "mission authorization snapshot expired or not active"
        if tool_name in snapshot.forbidden_actions:
            return False, RejectionCode.FORBIDDEN_ACTION.value, "tool is forbidden by mission authorization snapshot"
        if tool_name not in snapshot.allowed_tools or tool_name not in snapshot.allowed_actions:
            return False, RejectionCode.TOOL_NOT_ALLOWED.value, "tool is outside mission authorization snapshot allowlist"
        return True, "", "authorized"

    @staticmethod
    def _derive_execution_proof(mission: Mission, proposal: Any, argument: Any, decision: Any) -> Any:
        from security.execution_boundary import MissionExecutionBoundary
        return MissionExecutionBoundary.derive(
            mission,
            tool=proposal.name,
            argument=argument,
            decision=decision.decision if decision is not None and decision.allowed else None,
            tool_call_id=proposal.tool_call_id,
        )

    def _registry_context(self, mission: Mission, tool_name: str) -> dict[str, Any]:
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        scope = mission.scope_snapshot if isinstance(mission.scope_snapshot, dict) else {}
        result: dict[str, Any] = {
            "mission_id": mission.mission_id,
            "mission_authorization": snapshot,
            "target_identity": str(scope.get("target_id") or snapshot.target_identity),
        }
        if tool_name == "run_project_tests":
            from agent.evidence import EvidenceChainStore
            from workspace import Workspace
            root = str(snapshot.workspace_boundary.get("root", ""))
            if not root:
                raise PermissionError("mission workspace boundary required")
            result["workspace"] = Workspace(root)
            result["evidence_store"] = EvidenceChainStore(Path(self.store.db_path).with_name("evidence_chain.db"))
        return result

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
        evidence = tuple(evidence_for(item["criterion_id"], True, item.get("source", "system"), item.get("result", {}), provenance=item.get("provenance", {})) for item in mission._verified_system_evidence())
        return GoalVerification.evaluate(mission.objective, criteria, evidence)

    @staticmethod
    def _completed_plan_steps(mission: Mission) -> set[str]:
        fingerprint = mission.plan.fingerprint
        return {
            str(item.get("step_id", ""))
            for item in mission.action_history
            if item.get("status") == "completed"
            and item.get("plan_fingerprint") == fingerprint
            and item.get("step_id")
        }

    @classmethod
    def _ready_plan_steps(cls, mission: Mission) -> list[tuple[int, PlanStep]]:
        completed = cls._completed_plan_steps(mission)
        return [
            (index, step)
            for index, step in enumerate(mission.plan.steps)
            if step.step_id not in completed and set(step.prerequisites).issubset(completed)
        ]

    @staticmethod
    def _is_repeatable_observation(tool_name: str) -> bool:
        from tools.registry import get_tool
        spec = get_tool(tool_name)
        return bool(spec and spec.risk_class in {"read", "analysis"})

    @classmethod
    def _bind_proposal_to_ready_step(cls, mission: Mission, proposal: Any) -> tuple[Any, PlanStep | None, str]:
        if proposal.plan_version != mission.plan.version:
            return proposal, None, "tool call belongs to a stale plan version"
        completed = cls._completed_plan_steps(mission)
        by_id = {step.step_id: step for step in mission.plan.steps}
        if proposal.step_id:
            step = by_id.get(proposal.step_id)
            if step is None:
                return proposal, None, "tool call references an unknown plan step"
            if step.action != proposal.name:
                return proposal, None, "tool name does not match the referenced plan step"
            if proposal.step_id in completed:
                if cls._is_repeatable_observation(proposal.name):
                    from dataclasses import replace
                    return replace(proposal, step_id=""), step, ""
                return proposal, None, "plan step is already completed"
            missing = sorted(set(step.prerequisites) - completed)
            if missing:
                return proposal, None, f"plan step prerequisite not completed: {', '.join(missing)}"
            return proposal, step, ""

        matching = [step for step in mission.plan.steps if step.action == proposal.name]
        if not matching:
            # Mission-authorized auxiliary observations need not be plan steps,
            # but they can never satisfy a plan prerequisite.
            return proposal, None, ""
        ready = [step for _, step in cls._ready_plan_steps(mission) if step.action == proposal.name]
        if len(ready) == 1:
            from dataclasses import replace
            bound = replace(proposal, step_id=ready[0].step_id)
            return bound, ready[0], ""
        if not ready:
            unfinished = [step for step in matching if step.step_id not in completed]
            if not unfinished and cls._is_repeatable_observation(proposal.name):
                return proposal, None, ""
            return proposal, None, "no matching plan step is ready; prerequisite or completion gate blocked the tool call"
        return proposal, None, "tool call ambiguously matches multiple ready plan steps"

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
        return self.create(
            objective,
            objective,
            plan,
            request_id=authorization_context.request_id,
            owner_identity_ref=owner_identity_ref or str(getattr(authorization_context.owner_evidence, "owner_id", "") or authorization_context.owner_evidence_fingerprint),
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

    def _record_verified_criterion_evidence(self, mission: Mission, action_id: str) -> None:
        for criterion in mission.completion_criteria:
            criterion_id = str(criterion.get("criterion_id", ""))
            if not criterion_id:
                continue
            record = self.store.issue_criterion_evidence(mission, criterion_id, action_id)
            if record is None:
                continue
            system_evidence = record.get("system_evidence")
            evidence_id = str(system_evidence.get("provenance_token", "")) if isinstance(system_evidence, dict) else ""
            if evidence_id:
                record["evidence_id"] = evidence_id
            mission.evidence.append(record)
            mission.emit(EventType.EVIDENCE_ADDED, data={"criterion_id": criterion_id, "provenance": "system-signed"})

    @staticmethod
    def _persisted_verified_evidence_ids(mission: Mission) -> set[str]:
        """Resolve references only to persisted evidence with verified system provenance."""
        if not mission.evidence:
            return set()
        eligible: set[str] = set()
        for item in mission._verified_system_evidence():
            verified = item.get("verified_provenance", {})
            evidence_id = str(verified.get("provenance_token", "")) if isinstance(verified, dict) else ""
            if evidence_id and str(item.get("evidence_id", evidence_id)) == evidence_id:
                eligible.add(evidence_id)
        return eligible

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
        hypothesis_updates = engine.apply(
            proposal,
            goal_verified=False,
            deterministic_validation=False,
            eligible_evidence_ids=self._persisted_verified_evidence_ids(mission),
        )
        mission.hypotheses = engine.snapshot()
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
        if proposal.provenance.get("source") != "model_proposal":
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
                bindings = checkpoint.get("call_bindings", {}) if isinstance(checkpoint.get("call_bindings"), dict) else {}
                for tool_call_id in ambiguous_ids:
                    binding = bindings.get(tool_call_id, {}) if isinstance(bindings.get(tool_call_id), dict) else {}
                    action_id = str(binding.get("action_id") or tool_call_id)
                    step_id = str(binding.get("step_id", ""))
                    result = {**base_observation, "tool_call_id": tool_call_id, "action_id": action_id, "step_id": step_id, "type": "reconciled_observation"}
                    mission.record_observation(result)
                    mission.record_action(action_id, step_id, "completed", result, plan_fingerprint=str(checkpoint.get("plan_fingerprint", "")))
                mission.checkpoint = {**checkpoint, "status": "completed", "reconciled": True}
                ready = self._ready_plan_steps(mission)
                mission.current_step = ready[0][0] if ready else len(mission.plan.steps)
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
            mission.record_action(action_id, step_id, "completed", result, plan_fingerprint=str(checkpoint.get("plan_fingerprint", "")))
            mission.checkpoint = {**checkpoint, "status": "completed", "reconciled": True}
            ready = self._ready_plan_steps(mission)
            mission.current_step = ready[0][0] if ready else len(mission.plan.steps)
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
        if mission.is_terminal:
            return mission
        try:
            mission.plan.validate_dependency_graph()
        except ValueError as exc:
            mission.error = f"invalid plan dependency graph: {type(exc).__name__}"
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            return self.store.save(mission)
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
                    mission.verification_state = self.store.issue_completion_proof(mission)
                    mission.transition(MissionStatus.GOAL_COMPLETED, "model final accepted with deterministic evidence", verification=mission.verification_state)
                    mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
                    mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state, "model_final": turn.content})
                else:
                    mission.error = "model final lacked deterministic goal evidence"
                    mission.transition(MissionStatus.READY, mission.error)
                return self.store.save(mission)
            if len(turn.tool_calls) > 1:
                self._run_parallel_model_calls(mission, turn.tool_calls, auth_context=auth_context, run_id=run_id, progress=progress, seen=seen)
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
                    proposal, planned_step, binding_error = self._bind_proposal_to_ready_step(mission, proposal)
                    if binding_error:
                        mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "PLAN_STEP_BLOCKED", "reason": binding_error})
                        result = ToolCallResult(proposal, False, error=binding_error)
                        progress["tool_results"].append(result.to_dict())
                        continue
                    argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
                    snapshot_ok, snapshot_code, snapshot_reason = self._proposal_snapshot_gate(mission, proposal.name)
                    if not snapshot_ok:
                        mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": snapshot_code, "reason": snapshot_reason})
                        result = ToolCallResult(proposal, False, error=f"{snapshot_code}: {snapshot_reason}")
                        progress["tool_results"].append(result.to_dict())
                        continue
                    decision = authorize_tool([proposal.name, argument], context=auth_context)
                    mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
                    mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
                    if not decision.allowed:
                        result = ToolCallResult(proposal, False, error=decision.reason)
                    else:
                        proof = None
                        try:
                            proof = self._derive_execution_proof(mission, proposal, argument, decision)
                            mission.emit(EventType.PROOF_CREATED, data={"tool_call_id": proposal.tool_call_id, "proof_fingerprint": proof.proof_fingerprint, "snapshot_hash": proof.snapshot_hash, "plan_hash": proof.plan_hash})
                            from security.execution_boundary import MissionExecutionBoundary
                            proof_ok, proof_reason, proof_code = MissionExecutionBoundary.validate(proof, mission)
                            mission.emit(EventType.PROOF_VERIFIED, data={"tool_call_id": proposal.tool_call_id, "allowed": proof_ok, "reason": proof_reason})
                            if not proof_ok:
                                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": proof_code, "reason": proof_reason})
                                result = ToolCallResult(proposal, False, error=f"{proof_code}: {proof_reason}")
                                progress["tool_results"].append(result.to_dict())
                                continue
                            registry_context = self._registry_context(mission, proposal.name)
                        except Exception as exc:
                            mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "PROOF_INVALID", "reason": f"execution authorization rejected: {type(exc).__name__}"})
                            result = ToolCallResult(proposal, False, error=f"PROOF_INVALID: execution authorization rejected: {type(exc).__name__}")
                            progress["tool_results"].append(result.to_dict())
                            continue
                        try:
                            mission.checkpoint = {"status": "in_flight", "tool_call_id": proposal.tool_call_id, "action_id": proposal.action_id or proposal.tool_call_id, "step_id": proposal.step_id, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
                            self.store.save(mission)
                            raw = execute_tool(proposal.name, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id, tool_call_id=proposal.tool_call_id, execution_proof=proof, execution_class="MISSION_BOUND", **registry_context)
                            observation = dict(raw or {})
                            observation.update({"type": "tool_observation", "source": proposal.name, "action_id": proposal.action_id or proposal.tool_call_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
                            mission.record_observation(observation)
                            success = bool(observation.get("success", observation.get("ok", False)))
                            if planned_step is not None:
                                self._interpret_observation(mission, planned_step, observation, success=success)
                            action_id = proposal.action_id or proposal.tool_call_id
                            mission.record_action(action_id, proposal.step_id, "completed" if success else "failed", observation, plan_fingerprint=mission.plan.fingerprint)
                            if success:
                                self._record_verified_criterion_evidence(mission, action_id)
                                ready_after = self._ready_plan_steps(mission)
                                mission.current_step = ready_after[0][0] if ready_after else len(mission.plan.steps)
                            mission.checkpoint = {"status": "completed", "tool_call_id": proposal.tool_call_id, "action_id": action_id, "step_id": proposal.step_id, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
                            result = ToolCallResult(proposal, success, result=observation, error=str(observation.get("error", "")))
                        except Exception as exc:
                            mission.error = f"native tool outcome is ambiguous: {type(exc).__name__}"
                            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
                            return self.store.save(mission)
                progress["tool_results"].append(result.to_dict())
            self.store.save(mission)
        mission.error = "model turn budget exhausted"
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        return self.store.save(mission)

    def _run_parallel_model_calls(self, mission: Mission, proposals: tuple[Any, ...], *, auth_context: Any, run_id: str, progress: dict[str, Any], seen: set[str]) -> None:
        """Authorize, proof-bind, and execute independent proposals in parallel."""
        from security.authorization import authorize_tool
        from security.execution_boundary import MissionExecutionBoundary
        from tools.registry import execute as execute_tool

        identity_errors = set(validate_proposals(proposals, mission_id=mission.mission_id, run_id=run_id, seen_call_ids=seen))
        authorized: list[tuple[Any, Any, Any, Any, dict[str, Any]]] = []
        results: list[ToolCallResult] = []
        claimed_step_ids: set[str] = set()
        for proposal in proposals:
            mission.emit(EventType.TOOL_PROPOSED, data=proposal.to_dict())
            invalid_id = any(proposal.tool_call_id == error.split(":", 1)[0] for error in identity_errors)
            if invalid_id or proposal.tool_call_id in seen:
                results.append(ToolCallResult(proposal, False, error="invalid, stale, or duplicate tool call"))
                continue
            seen.add(proposal.tool_call_id)
            progress["seen_call_ids"].append(proposal.tool_call_id)
            proposal, planned_step, binding_error = self._bind_proposal_to_ready_step(mission, proposal)
            if binding_error:
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "PLAN_STEP_BLOCKED", "reason": binding_error})
                results.append(ToolCallResult(proposal, False, error=binding_error))
                continue
            if planned_step is not None and planned_step.step_id in claimed_step_ids:
                if self._is_repeatable_observation(proposal.name):
                    from dataclasses import replace
                    proposal = replace(proposal, step_id="")
                else:
                    results.append(ToolCallResult(proposal, False, error="plan step cannot be executed twice in one parallel batch"))
                    continue
            if planned_step is not None:
                claimed_step_ids.add(planned_step.step_id)
            argument = proposal.arguments.get("query") if isinstance(proposal.arguments, dict) else None
            snapshot_ok, snapshot_code, snapshot_reason = self._proposal_snapshot_gate(mission, proposal.name)
            if not snapshot_ok:
                mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": False, "reason": snapshot_reason})
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": snapshot_code, "reason": snapshot_reason})
                results.append(ToolCallResult(proposal, False, error=f"{snapshot_code}: {snapshot_reason}"))
                continue
            decision = authorize_tool([proposal.name, argument], context=auth_context)
            mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": decision.allowed, "reason": decision.reason})
            if not decision.allowed:
                results.append(ToolCallResult(proposal, False, error=decision.reason))
                continue
            try:
                proof = self._derive_execution_proof(mission, proposal, argument, decision)
                mission.emit(EventType.PROOF_CREATED, data={"tool_call_id": proposal.tool_call_id, "proof_fingerprint": proof.proof_fingerprint, "snapshot_hash": proof.snapshot_hash, "plan_hash": proof.plan_hash})
                proof_ok, proof_reason, proof_code = MissionExecutionBoundary.validate(proof, mission)
                mission.emit(EventType.PROOF_VERIFIED, data={"tool_call_id": proposal.tool_call_id, "allowed": proof_ok, "reason": proof_reason})
                if not proof_ok:
                    mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": proof_code, "reason": proof_reason})
                    results.append(ToolCallResult(proposal, False, error=f"{proof_code}: {proof_reason}"))
                    continue
                registry_context = self._registry_context(mission, proposal.name)
                authorized.append((proposal, argument, decision, proof, registry_context))
            except Exception as exc:
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "PROOF_INVALID", "reason": f"execution authorization rejected: {type(exc).__name__}"})
                results.append(ToolCallResult(proposal, False, error=f"PROOF_INVALID: execution authorization rejected: {type(exc).__name__}"))

        all_ids = [item[0].tool_call_id for item in authorized]
        call_bindings = {item[0].tool_call_id: {"action_id": item[0].action_id or item[0].tool_call_id, "step_id": item[0].step_id} for item in authorized}
        mission.checkpoint = {"status": "in_flight_parallel", "tool_call_ids": all_ids, "call_bindings": call_bindings, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
        self.store.save(mission)

        def execute_one(item: tuple[Any, Any, Any, Any, dict[str, Any]]) -> dict[str, Any]:
            proposal, argument, decision, proof, registry_context = item
            proof_ok, proof_reason, proof_code = MissionExecutionBoundary.validate(proof, mission)
            if not proof_ok:
                return {"_proof_rejected": True, "proof_code": proof_code, "proof_reason": proof_reason}
            try:
                raw = execute_tool(
                    proposal.name, argument,
                    authorization_decision=decision.decision,
                    scope_context=mission.scope_snapshot,
                    request_id=mission.request_id,
                    tool_call_id=proposal.tool_call_id,
                    execution_proof=proof,
                    execution_class="MISSION_BOUND",
                    **registry_context,
                )
                return {"raw": dict(raw or {})}
            except Exception as exc:
                return {"_ambiguous": True, "error": str(exc), "failure_class": FailureClass.UNKNOWN.value, "exception": type(exc).__name__}

        raw_results = execute_bounded_parallel(authorized, execute_one, max_workers=min(4, max(1, len(authorized))))
        ambiguous: list[tuple[Any, dict[str, Any]]] = []
        for item, wrapped in zip(authorized, raw_results):
            proposal = item[0]
            if wrapped.get("_proof_rejected"):
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": wrapped.get("proof_code"), "reason": wrapped.get("proof_reason")})
                results.append(ToolCallResult(proposal, False, error=f"{wrapped.get('proof_code')}: {wrapped.get('proof_reason')}"))
                continue
            if wrapped.get("_ambiguous"):
                ambiguous.append((proposal, wrapped))
                continue
            observation = dict(wrapped.get("raw") or {})
            observation.update({"type": "tool_observation", "source": proposal.name, "action_id": proposal.action_id or proposal.tool_call_id, "step_id": proposal.step_id, "mission_id": mission.mission_id, "tool_call_id": proposal.tool_call_id})
            mission.record_observation(observation)
            success = bool(observation.get("success", observation.get("ok", False)))
            planned_step = next((step for step in mission.plan.steps if step.step_id == proposal.step_id), None)
            if planned_step is not None:
                self._interpret_observation(mission, planned_step, observation, success=success)
            action_id = proposal.action_id or proposal.tool_call_id
            mission.record_action(action_id, proposal.step_id, "completed" if success else "failed", observation, plan_fingerprint=mission.plan.fingerprint)
            if success:
                self._record_verified_criterion_evidence(mission, action_id)
                ready_after = self._ready_plan_steps(mission)
                mission.current_step = ready_after[0][0] if ready_after else len(mission.plan.steps)
            results.append(ToolCallResult(proposal, success, result=observation, error=str(observation.get("error", ""))))

        proposal_order = {proposal.tool_call_id: index for index, proposal in enumerate(proposals)}
        results.sort(key=lambda result: proposal_order.get(result.proposal.tool_call_id, len(proposal_order)))
        progress["tool_results"].extend(result.to_dict() for result in results)
        if ambiguous:
            ambiguous_ids = [proposal.tool_call_id for proposal, _ in ambiguous]
            mission.error = "parallel tool outcome is ambiguous; reconciliation required"
            mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": mission.error, "tool_call_ids": ambiguous_ids})
            mission.emit(EventType.FAILURE_DIAGNOSED, data={"class": FailureClass.UNKNOWN.value, "reason": mission.error, "recovery": "reconciliation_required", "tool_call_ids": ambiguous_ids})
            mission.checkpoint = {"status": "in_flight_parallel", "tool_call_ids": all_ids, "ambiguous_tool_call_ids": ambiguous_ids, "call_bindings": call_bindings, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
            return
        mission.checkpoint = {"status": "completed", "tool_call_ids": all_ids, "call_bindings": call_bindings, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}

    def run_slice(self, mission_id: str) -> Mission:
        mission = self._load(mission_id)
        if mission.is_terminal:
            return mission
        authorization_ok, authorization_reason = self._mission_authorization(mission)
        if not authorization_ok:
            mission.error = authorization_reason
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": authorization_reason})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, authorization_reason)
            return self.store.save(mission)
        checkpoint_status = str((mission.checkpoint or {}).get("status", ""))
        if checkpoint_status in {"in_flight", "in_flight_parallel"}:
            action_id = str(mission.checkpoint.get("action_id", ""))
            tool_call_ids = list(mission.checkpoint.get("ambiguous_tool_call_ids", ())) if checkpoint_status == "in_flight_parallel" else []
            mission.error = "in-flight parallel tool outcomes are unknown; reconciliation required" if checkpoint_status == "in_flight_parallel" else "in-flight action outcome is unknown; reconciliation required"
            mission.failures.append({"class": FailureClass.UNKNOWN.value, "reason": mission.error, "action_id": action_id, "tool_call_ids": tool_call_ids})
            mission.emit(EventType.FAILURE_DIAGNOSED, step_id=str(mission.checkpoint.get("step_id", "")), data={"class": FailureClass.UNKNOWN.value, "reason": mission.error, "recovery": "reconciliation_required", "action_id": action_id, "tool_call_ids": tool_call_ids})
            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error, action_id=action_id)
            return self.store.save(mission)
        if mission.progress.get("cancel_requested"):
            mission.progress.pop("cancel_requested", None)
            mission.transition(MissionStatus.CANCELLED, "Owner cancellation request accepted at a safe execution boundary")
            mission.checkpoint = {**mission.checkpoint, "status": "cancelled"}
            return self.store.save(mission)
        if mission.progress.get("pause_requested") or mission.status is MissionStatus.PAUSED:
            mission.transition(MissionStatus.PAUSED, "Owner pause request accepted at a safe execution boundary")
            mission.checkpoint = {**mission.checkpoint, "status": "paused"}
            return self.store.save(mission)
        if mission.iteration_count >= mission.max_iterations:
            mission.error = "iteration budget exhausted"
            mission.emit(EventType.FAILURE_DETECTED, data={"class": FailureClass.RESOURCE.value, "reason": mission.error})
            mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
            return self.store.save(mission)
        mission.iteration_count += 1
        ready_steps = self._ready_plan_steps(mission)
        completed_steps = self._completed_plan_steps(mission)
        pending_steps = [step for step in mission.plan.steps if step.step_id not in completed_steps]
        if not pending_steps:
            mission.transition(MissionStatus.VERIFYING, "all plan steps observed")
            mission.emit(EventType.GOAL_VERIFICATION_STARTED)
            verification = self.verifier(mission)
            mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
            if verification.verified:
                mission.emit(EventType.GOAL_VERIFIED, data={"evidence_count": len(verification.evidence)})
                mission.verification_state = self.store.issue_completion_proof(mission)
                mission.transition(MissionStatus.GOAL_COMPLETED, "required verification evidence present", verification=mission.verification_state)
                mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state})
            else:
                missing = list(verification.missing_criteria)
                mission.error = "required verification evidence missing: " + ", ".join(missing)
                mission.emit(EventType.OWNER_INPUT_REQUIRED, data={"reason": mission.error, "missing_criteria": missing})
                mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, mission.error)
            return self.store.save(mission)

        if not ready_steps:
            mission.error = "plan dependency graph has no executable step"
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            return self.store.save(mission)

        step_index, step = ready_steps[0]
        mission.current_step = step_index
        action_id = f"{mission.mission_id}:{mission.plan.version}:{step.step_id}:{step_index}"
        prior_action = next((item for item in mission.action_history if item.get("action_id") == action_id and item.get("status") == "completed"), None)
        if prior_action and prior_action.get("plan_fingerprint") not in {None, "", mission.plan.fingerprint}:
            action_id = f"{action_id}:plan:{mission.plan.fingerprint[:12]}"
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
            mission.record_action(action_id, step.step_id, "completed", prior_action.get("observation", {}) if prior_action else {}, plan_fingerprint=mission.plan.fingerprint)
            next_steps = self._ready_plan_steps(mission)
            mission.current_step = next_steps[0][0] if next_steps else len(mission.plan.steps)
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
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "in_flight", "plan_version": mission.plan.version, "plan_fingerprint": mission.plan.fingerprint}
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
        observation.setdefault("source", step.action)
        observation.setdefault("action_id", action_id)
        observation.setdefault("step_id", step.step_id)
        observation.setdefault("mission_id", mission.mission_id)
        typed_observation = Observation.from_result(step.action, action_id, observation, request_id=mission.request_id, scope=mission.scope_snapshot)
        observation["observation"] = typed_observation.to_dict()
        mission.transition(MissionStatus.OBSERVING, "action returned observation", action_id=action_id)
        mission.record_observation(observation)
        success = bool(observation.get("success", observation.get("ok", False)))
        mission.record_action(action_id, step.step_id, "completed" if success else "failed", observation, plan_fingerprint=mission.plan.fingerprint)
        mission.checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "completed", "plan_version": mission.plan.version, "plan_fingerprint": mission.plan.fingerprint}
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
            self._record_verified_criterion_evidence(mission, action_id)
            if strategy_decision is not None and strategy_decision.decision.value in {"REPLAN", "CHANGE_HYPOTHESIS", "ADD_EVIDENCE"}:
                mission.transition(MissionStatus.REPLANNING, strategy_decision.reason)
                mission.emit(EventType.REPLAN_TRIGGERED, step_id=step.step_id, data=strategy_decision.to_dict())
                new_plan = self.replanner(mission, {**observation, "interpretation": mission.interpretations[-1], "strategy_decision": strategy_decision.to_dict()})
                if new_plan.objective != mission.objective:
                    mission.error = "replanner attempted to change Owner objective"
                    mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                    return self.store.save(mission)
                try:
                    new_plan.validate_dependency_graph()
                except ValueError:
                    mission.error = "replanner returned an invalid dependency graph"
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
            next_steps = self._ready_plan_steps(mission)
            mission.current_step = next_steps[0][0] if next_steps else len(mission.plan.steps)
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
            try:
                new_plan.validate_dependency_graph()
            except ValueError:
                mission.error = "replanner returned an invalid dependency graph"
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
        limit = max_slices or self._load(mission_id).max_iterations
        for _ in range(limit):
            if heartbeat is not None:
                heartbeat()
            mission = self.run_slice(mission_id)
            if mission.is_terminal or mission.status is MissionStatus.PAUSED:
                return mission
        return self._load(mission_id)


__all__ = ["MissionRuntime"]
