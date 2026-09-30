from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
import hashlib
import json

from .mission import Mission, MissionStatus, MissionStore, MissionWriteConflictError
from .planning import FailureClass, GoalVerification, Plan, PlanStep, RecoveryAction, RecoveryPolicy, VerificationCriterion, evidence_for
from .trajectory import EventType
from .observation import Observation
from .observation_intelligence import ObservationInterpreter, should_interpret_observation
from .strategy import StrategyState, decide as decide_strategy
from .model_protocol import ConversationTurn, NativeModel, ToolCallResult
from .provider_api import ProviderError
from .model_intelligence.context import ContextAssembler
from .model_intelligence.tool_calls import execute_bounded_parallel, validate_proposals
from .context import sanitize_model_data, sanitize_model_text


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
        self._live_missions: dict[str, Mission] = {}

    def activate_live_mission(self, mission: Mission) -> None:
        """Use this request's authenticated mission object without persisting its proof."""
        if not isinstance(mission, Mission):
            raise TypeError("live mission must be a Mission")
        self._live_missions[mission.mission_id] = mission

    def release_live_mission(self, mission_id: str) -> None:
        """Discard transient authorization evidence when the request execution ends."""
        self._live_missions.pop(str(mission_id), None)

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
            scope_snapshot_id = scope.get("scope_snapshot_id")
            authorization_scope_id = (
                (mission.authorization_context or {}).get("scope_snapshot_id")
                if isinstance(mission.authorization_context, dict)
                else None
            )
            if scope_snapshot_id or authorization_scope_id:
                from security.authorization_context import AuthorizationContext
                from security.scope_store import get_snapshot_for_owner_session

                context = AuthorizationContext.from_dict(dict(mission.authorization_context or {}))
                if (
                    not scope_snapshot_id
                    or not authorization_scope_id
                    or str(scope_snapshot_id) != str(authorization_scope_id)
                ):
                    return False, "mission scope binding identifier is missing or mismatched"
                persisted_scope = get_snapshot_for_owner_session(
                    str(scope_snapshot_id),
                    scope.get("target_id"),
                    owner_session_token=context.session_id,
                )
                bound_fingerprint = str(scope.get("scope_snapshot_fingerprint") or "")
                if (
                    context.scope_snapshot is None
                    or context.session_id != persisted_scope.authorization.owner_session_id
                    or context.scope_snapshot.snapshot_id != str(scope_snapshot_id)
                    or context.scope_snapshot.to_dict() != persisted_scope.to_dict()
                    or str(scope.get("program_id") or "") != persisted_scope.authorization.program_id
                    or not bound_fingerprint
                    or context.scope_fingerprint != bound_fingerprint
                ):
                    return False, "mission scope binding differs from the persisted Owner snapshot"
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

    @staticmethod
    def _live_owner_session_failure(mission: Mission, auth_context: Any) -> str | None:
        """Revalidate the session-bound Owner identity at the dispatch boundary."""
        owner_evidence = getattr(auth_context, "owner_evidence", None)
        context_session_id = getattr(auth_context, "session_id", None)
        evidence_session_id = getattr(owner_evidence, "session_id", None)
        if context_session_id and evidence_session_id and context_session_id != evidence_session_id:
            return "Owner session binding mismatch"
        session_id = context_session_id or evidence_session_id
        if not session_id:
            return None
        if not isinstance(session_id, str):
            return "live Owner session could not be verified"
        try:
            from security.owner_password import resolve_session

            live_owner = resolve_session(session_id)
        except Exception:
            return "live Owner session could not be verified"
        if not isinstance(live_owner, dict) or live_owner.get("session_id") != session_id:
            return "live Owner session expired or was revoked"
        evidence_owner_id = str(getattr(owner_evidence, "owner_id", "") or "")
        live_owner_id = str(live_owner.get("owner_id", "") or "")
        mission_owner_id = str(getattr(mission, "owner_identity_ref", "") or "")
        if evidence_owner_id and (live_owner_id != evidence_owner_id or (mission_owner_id and mission_owner_id != evidence_owner_id)):
            return "live Owner session identity mismatch"
        return None

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

    @staticmethod
    def _normalize_native_tool_result(raw: Any, *, tool_name: str, action_id: str, step_id: str, mission_id: str, tool_call_id: str) -> tuple[dict[str, Any], bool]:
        """Normalize returned JSON data into an observation and execution status.

        Explicit ``success`` (preferred) or ``ok`` booleans determine status.
        Without either flag, ordinary returned data is a successful execution;
        an error-only envelope is not. Useful data alongside provider errors is
        retained as a visible partial success, not discarded as a failure.

        Execution status is bookkeeping only and never supplies criterion
        evidence or completion proof.
        """
        payload = dict(raw) if isinstance(raw, dict) else {"result": raw}
        partial_success = False
        if isinstance(raw, dict):
            explicit_flag = "success" if "success" in raw else "ok" if "ok" in raw else None
            has_error = any(bool(raw.get(key)) for key in ("error", "errors", "error_type", "failure_class"))
            envelope_fields = {
                "success", "ok", "error", "errors", "error_type", "failure_class", "exception",
                "message", "reason", "detail", "details", "code", "status_code",
                "query", "scope", "source", "type", "action_id", "step_id", "mission_id", "tool_call_id",
            }

            def carries_payload(key: str, value: Any) -> bool:
                if key in envelope_fields or value is None or value == "" or value == [] or value == {}:
                    return False
                if key in {"results", "items", "data", "records", "entries"} and not value:
                    return False
                if key in {"total_results", "result_count"} and value == 0:
                    return False
                return True

            has_data = any(carries_payload(key, value) for key, value in raw.items())
            if explicit_flag is not None:
                success = raw[explicit_flag] is True
            else:
                success = not (has_error and not has_data)
            partial_success = success and has_error and has_data
        else:
            success = True

        observation = {
            **payload,
            "success": success,
            **({"partial_success": True} if partial_success else {}),
            "type": "tool_observation",
            "source": tool_name,
            "action_id": action_id,
            "step_id": step_id,
            "mission_id": mission_id,
            "tool_call_id": tool_call_id,
        }
        return observation, success

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
        saved = self.store.save(mission)
        if isinstance(mission.authorization_context, dict):
            try:
                from security.authorization_context import AuthorizationContext
                AuthorizationContext.from_dict(dict(mission.authorization_context))
            except (KeyError, TypeError, ValueError, PermissionError):
                pass
            else:
                self.activate_live_mission(mission)
        return saved

    def create_from_owner_instruction(self, instruction: str, plan: Plan, *, authorization_context: Any, scope_snapshot: dict[str, Any] | None = None, completion_criteria: list[dict[str, Any]] | None = None, owner_identity_ref: str = "", provenance: dict[str, Any] | None = None, authorization_snapshot_factory: Callable[[Mission], Any] | None = None, mission_id: str | None = None) -> Mission:
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
            mission_id=mission_id,
        )

    def provide_owner_decision(self, mission_id: str, *, allow: bool, authorization_context: dict[str, Any] | None = None) -> Mission:
        mission = self._load(mission_id)
        if mission.status is not MissionStatus.OWNER_INPUT_REQUIRED:
            raise ValueError("mission is not waiting for owner input")
        if not allow:
            mission.failures.append({"class": FailureClass.AUTHORIZATION.value, "reason": "owner denied action"})
            mission.transition(MissionStatus.AUTHORIZATION_BLOCKED, "owner denied")
            live_authorization = None
        else:
            if authorization_context:
                from security.authorization_context import AuthorizationContext
                live_authorization = AuthorizationContext.from_dict(dict(authorization_context))
                mission.authorization_context = live_authorization.to_dict()
            else:
                live_authorization = None
                mission.authorization_context = {"owner_decision": "allow"}
            mission.transition(MissionStatus.READY, "owner allowed action")
        saved = self.store.save(mission)
        if live_authorization is not None:
            self.activate_live_mission(saved)
        return saved

    def _load(self, mission_id: str) -> Mission:
        live = self._live_missions.get(str(mission_id))
        if live is not None:
            return live
        mission = self.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission

    def _accept_pending_control(self, mission: Mission) -> Mission | None:
        """Commit pause/cancel only at a boundary with no claimed tool effect."""
        current = mission
        for _ in range(8):
            if current.is_terminal:
                return current
            cancel = bool(current.progress.get("cancel_requested"))
            pause = bool(current.progress.get("pause_requested"))
            if not cancel and not pause:
                return None
            if str((current.checkpoint or {}).get("status", "")) in {"in_flight", "in_flight_parallel"}:
                return None
            if cancel:
                current.progress.pop("cancel_requested", None)
                current.progress.pop("pause_requested", None)
                current.transition(MissionStatus.CANCELLED, "Owner cancellation request accepted at a safe execution boundary")
                current.checkpoint = {**current.checkpoint, "status": "cancelled"}
            else:
                current.progress.pop("pause_requested", None)
                current.transition(MissionStatus.PAUSED, "Owner pause request accepted at a safe execution boundary")
                current.checkpoint = {**current.checkpoint, "status": "paused"}
            try:
                return self.store.save(current)
            except MissionWriteConflictError:
                current = self._load(current.mission_id)
        return current

    def _claim_callback(self, mission: Mission, checkpoint: dict[str, Any]) -> tuple[Mission, bool]:
        """Use MissionStore's optimistic write as the callback/control linearization point."""
        if mission.is_terminal:
            return mission, False
        if mission.progress.get("cancel_requested") or mission.progress.get("pause_requested"):
            return self._accept_pending_control(mission) or mission, False
        mission.checkpoint = checkpoint
        try:
            return self.store.save(mission), True
        except MissionWriteConflictError:
            latest = self._load(mission.mission_id)
            controlled = self._accept_pending_control(latest)
            return controlled or latest, False

    def _claim_followup_callback(self, mission: Mission, stage: str) -> tuple[Mission, bool]:
        """Claim model-backed postprocessing without dropping the tool-effect checkpoint."""
        expected = dict(mission.checkpoint or {})
        expected_status = str(expected.get("status", ""))
        expected_call_id = str(expected.get("tool_call_id", ""))
        expected_parallel_ids = tuple(str(item) for item in expected.get("tool_call_ids", ()))
        for _ in range(8):
            current = self._load(mission.mission_id)
            checkpoint = dict(current.checkpoint or {})
            if current.is_terminal:
                return current, False
            if (
                str(checkpoint.get("status", "")) != expected_status
                or expected_status not in {"in_flight", "in_flight_parallel"}
                or str(checkpoint.get("tool_call_id", "")) != expected_call_id
                or tuple(str(item) for item in checkpoint.get("tool_call_ids", ())) != expected_parallel_ids
            ):
                return current, False
            if current.progress.get("cancel_requested") or current.progress.get("pause_requested"):
                return self._require_reconciliation(
                    current.mission_id,
                    expected_status,
                    f"control arrived before claimed {stage} callback; tool outcome requires reconciliation",
                ), False
            current.checkpoint = {**checkpoint, "followup_claim": stage}
            try:
                saved = self.store.save(current)
            except MissionWriteConflictError:
                continue
            # The caller holds the tool result in memory; advance only its CAS
            # token/checkpoint so the eventual durable result write is based on
            # this exact follow-up claim.
            mission.integrity_hash = saved.integrity_hash
            mission.checkpoint = dict(saved.checkpoint)
            return mission, True
        return self._load(mission.mission_id), False

    def _require_reconciliation(self, mission_id: str, checkpoint_status: str, reason: str) -> Mission:
        """Retain an in-flight claim when a callback result could not be committed."""
        current = self._load(mission_id)
        for _ in range(8):
            if str((current.checkpoint or {}).get("status", "")) != checkpoint_status:
                return current
            if current.status is MissionStatus.RECOVERY_REQUIRED or current.is_terminal:
                return current
            current.error = reason
            current.transition(MissionStatus.RECOVERY_REQUIRED, reason)
            try:
                return self.store.save(current)
            except MissionWriteConflictError:
                current = self._load(mission_id)
        return current

    def _record_verified_criterion_evidence(self, mission: Mission, action_id: str) -> None:
        action = next((item for item in mission.action_history if item.get("action_id") == action_id), None)
        observation = action.get("observation") if isinstance(action, dict) else None
        if isinstance(observation, dict) and observation.get("source") == "scoped_http_probe":
            # A remote HTTP response is never a system verifier, even when the
            # transport completed successfully; preserve it only as observation.
            return
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
    def _reasoning_case_for_observation(mission: Mission, observation: dict[str, Any], proposal: Any) -> dict[str, Any]:
        """Build a durable, non-authoritative case from one canonical interpretation."""
        import math
        from evaluation.critic import critique
        from reasoning.cases import make_case

        def text_items(values: Any, *, limit: int = 8, width: int = 400) -> tuple[str, ...]:
            if not isinstance(values, (tuple, list)):
                return ()
            return tuple(str(item).strip()[:width] for item in values[:limit] if str(item).strip())

        def evidence_ids(values: Any) -> tuple[str, ...]:
            if not isinstance(values, (tuple, list, set, frozenset)):
                return ()
            return tuple(dict.fromkeys(str(item).strip()[:128] for item in values if str(item).strip()))[:32]

        def item_evidence_ids(values: Any) -> tuple[str, ...]:
            if not isinstance(values, (tuple, list)):
                return ()
            return evidence_ids([item.get("evidence_id", "") for item in values if isinstance(item, dict)])

        verified_records = mission._verified_system_evidence()
        verified_ids = {
            str(item.get("evidence_id") or (item.get("system_evidence") or {}).get("provenance_token", ""))
            for item in verified_records
        }
        verified_ids.discard("")
        claimed_support = set(evidence_ids(getattr(proposal, "supporting_evidence_ids", ())))
        claimed_support.update(evidence_ids(observation.get("supporting_evidence_ids", ())))
        claimed_support.update(item_evidence_ids(observation.get("evidence", ())))
        claimed_counter = set(evidence_ids(getattr(proposal, "counter_evidence_ids", ())))
        claimed_counter.update(evidence_ids(observation.get("counter_evidence_ids", ())))
        claimed_counter.update(item_evidence_ids(observation.get("counter_evidence", observation.get("contradictions", ()))))
        claimed_support.update(item_evidence_ids(getattr(proposal, "new_evidence", ())))
        claimed_counter.update(item_evidence_ids(getattr(proposal, "contradictions", ())))
        supporting = tuple(sorted(claimed_support & verified_ids))
        contradicting = tuple(sorted(claimed_counter & verified_ids))
        all_claimed_ids = claimed_support | claimed_counter
        for updates in (getattr(proposal, "hypothesis_updates", ()), observation.get("hypothesis_updates", ())):
            if isinstance(updates, (tuple, list)):
                for update in updates[:8]:
                    if isinstance(update, dict):
                        all_claimed_ids.update(evidence_ids(update.get("supporting_evidence_ids", ())))
                        all_claimed_ids.update(evidence_ids(update.get("counter_evidence_ids", ())))
        proposal_changes = getattr(proposal, "confidence_changes", ())
        observation_changes = observation.get("confidence_changes", ())
        raw_changes = proposal_changes or observation_changes
        for changes in (proposal_changes, observation_changes):
            if not isinstance(changes, (tuple, list)):
                continue
            for change in changes[:8]:
                if hasattr(change, "to_dict"):
                    proposed = change.to_dict()
                elif isinstance(change, dict):
                    proposed = change
                else:
                    continue
                all_claimed_ids.update(evidence_ids(proposed.get("supporting_evidence_ids", ())))
                all_claimed_ids.update(evidence_ids(proposed.get("counter_evidence_ids", ())))
        rejected_ids = tuple(sorted(all_claimed_ids - verified_ids))

        candidates: list[dict[str, Any]] = []
        for item in getattr(proposal, "hypothesis_updates", ())[:8]:
            if not isinstance(item, dict):
                continue
            statement = str(item.get("statement") or item.get("hypothesis") or item.get("description") or "").strip()[:500]
            candidates.append({
                "record_type": "HYPOTHESIS_CANDIDATE",
                "hypothesis_id": str(item.get("hypothesis_id", ""))[:120],
                "statement": statement,
                "status": "UNVALIDATED",
                "model_claimed_status": str(item.get("status", ""))[:80],
                "rationale": str(item.get("rationale") or item.get("reason") or "")[:300],
                "assumptions": list(text_items(item.get("assumptions", ()), limit=4, width=250)),
                "provenance": {"source": "model_proposal", "trust": "untrusted_claim"},
            })

        raw_confidence = observation.get("model_confidence", observation.get("confidence"))
        try:
            parsed_confidence = float(raw_confidence) if not isinstance(raw_confidence, bool) and raw_confidence is not None else None
        except (TypeError, ValueError, OverflowError):
            parsed_confidence = None
        if parsed_confidence is not None and math.isfinite(parsed_confidence) and 0.0 <= parsed_confidence <= 1.0:
            model_confidence = {
                "claimed_value": parsed_confidence,
                "source": "model_proposal" if "model_confidence" in observation else "raw_observation",
                "trust": "untrusted_claim",
            }
        else:
            model_confidence = {
                "claimed_value": None,
                "source": "untrusted_observation" if "confidence" in observation or "model_confidence" in observation else "not_provided",
                "trust": "untrusted_claim",
            }

        model_confidence_changes: list[dict[str, Any]] = []
        for change in raw_changes[:8] if isinstance(raw_changes, (tuple, list)) else ():
            if hasattr(change, "to_dict"):
                proposed = change.to_dict()
            elif isinstance(change, dict):
                proposed = change
            else:
                continue
            proposed_support = evidence_ids(proposed.get("supporting_evidence_ids", ()))
            proposed_counter = evidence_ids(proposed.get("counter_evidence_ids", ()))
            model_confidence_changes.append({
                "hypothesis_id": str(proposed.get("hypothesis_id", ""))[:120],
                "delta": proposed.get("delta", 0.0),
                "reason": str(proposed.get("reason", ""))[:300],
                "verified_supporting_evidence_ids": [item for item in proposed_support if item in verified_ids],
                "verified_counter_evidence_ids": [item for item in proposed_counter if item in verified_ids],
                "claimed_unverified_evidence_ids": [item for item in (*proposed_support, *proposed_counter) if item not in verified_ids][:16],
                "provenance": {"source": "model_proposal", "trust": "untrusted_claim"},
            })

        alternatives = text_items(observation.get("alternative_explanations", ()), limit=4, width=250)
        if not alternatives:
            alternatives = ("insufficient evidence for a determination", "tool or observation artifact", "benign or routine explanation")
        required = text_items(getattr(proposal, "required_next_evidence", ()), limit=8, width=250)
        if not required:
            required = ("independent system evidence relevant to the observation",)
        confidence_rationale = (
            "NOT_ASSESSED: model/raw confidence is retained separately as an untrusted claim; "
            "no evidence-derived confidence score was computed."
        )

        knowledge_sources: list[dict[str, Any]] = []
        for item in mission.knowledge_context[-8:]:
            if not isinstance(item, dict):
                continue
            source_provenance = item.get("provenance", {}) if isinstance(item.get("provenance"), dict) else {}
            linked_ids = evidence_ids(item.get("evidence_ids", ()))
            knowledge_sources.append({
                "record_type": str(item.get("record_type", item.get("type", "knowledge")))[:80],
                "source": str(item.get("source") or source_provenance.get("source") or "")[:160],
                "trust": str(item.get("trust") or source_provenance.get("trust") or "unspecified")[:80],
                "validation_state": str(item.get("validation_state") or item.get("status") or "unknown")[:80],
                "verified_evidence_ids": [item_id for item_id in linked_ids if item_id in verified_ids],
            })

        case = make_case(
            observation=str(getattr(proposal, "summary", "") or observation.get("summary") or "observation recorded")[:1000],
            hypotheses=tuple(candidates),
            supporting=supporting,
            contradicting=contradicting,
            alternatives=alternatives,
            required=required,
            techniques=text_items(observation.get("technique_mappings", ()), limit=8, width=120),
            confidence=0.0,
            confidence_rationale=confidence_rationale,
            limitations=(
                "Raw observation and model-authored claims are untrusted and not semantically validated.",
                "Critic output is structural diagnosis/evidence request only; it cannot change confidence, validation, authorization, scope, or completion.",
            ),
            provenance={
                "source": "mission_runtime_observation_interpretation",
                "trust": str(getattr(proposal, "provenance", {}).get("trust", "untrusted_observation_data")),
                "mission_id": mission.mission_id,
                "observation_id": str(getattr(proposal, "observation_id", "")),
                "action_id": str(observation.get("action_id", "")),
                "tool": str(observation.get("source", "")),
                "knowledge_sources": knowledge_sources,
            },
        )
        case_record = case.to_dict()
        audit = {
            "verified_ids": sorted(verified_ids),
            "claimed_ids": sorted(all_claimed_ids),
            "rejected_ids": list(rejected_ids),
        }
        untrusted_claims = {
            "facts": list(text_items(getattr(proposal, "facts", ()), limit=8, width=300)),
            "candidate_hypothesis_count": len(candidates),
            "new_evidence_claim_count": len(getattr(proposal, "new_evidence", ())),
            "contradiction_claim_count": len(getattr(proposal, "contradictions", ())),
            "confidence_changes": model_confidence_changes,
            "model_rationale": str(getattr(proposal, "replan_reason", "") or getattr(proposal, "recommended_strategy_change", ""))[:500],
            "provenance": dict(getattr(proposal, "provenance", {})),
        }
        diagnostics = critique({
            "observations": list(case.observations),
            "candidate_hypotheses": list(case.candidate_hypotheses),
            "claims": untrusted_claims["facts"],
            "untrusted_claims": untrusted_claims,
            "tool_result_present": bool(observation.get("source") or observation.get("observation")),
            "tool_interpretation_claims": [*case.observations, *untrusted_claims["facts"]],
            "reasoning_rationale": untrusted_claims["model_rationale"],
            "supporting_evidence": list(case.supporting_evidence),
            "contradicting_evidence": list(case.contradicting_evidence),
            "verified_evidence_ids": sorted(verified_ids),
            "unverified_evidence_ids": list(rejected_ids),
            "required_next_evidence": list(case.required_next_evidence),
            "alternative_explanations": list(case.alternative_explanations),
            "confidence": case.confidence,
            "model_confidence": model_confidence,
            "model_confidence_changes": model_confidence_changes,
            "confidence_rationale": case.confidence_rationale,
            "technique_mappings": list(case.technique_mappings),
        }).to_dict()
        return {
            "record_type": "REASONING_CASE",
            **case_record,
            "model_confidence": model_confidence,
            "evidence_confidence": {
                "value": None,
                "state": "NOT_ASSESSED",
                "rationale": "This slice does not derive confidence from evidence quality; see system_validation separately.",
            },
            "system_validation": {
                "state": "UNVALIDATED",
                "verified_evidence_ids": list(supporting + contradicting),
                "changed_by_critic": False,
            },
            "evidence_reference_audit": audit,
            "untrusted_claims": untrusted_claims,
            "critic": diagnostics,
        }

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
        mission.knowledge_context = list(mission.knowledge_context)
        interpreted_record = {
            **proposal.to_dict(),
            "record_type": "INTERPRETED_OBSERVATION",
            "proposal_trust": str(proposal.provenance.get("trust", "untrusted_observation_data")),
            "untrusted_claim_fields": ["facts", "new_evidence", "contradictions", "supporting_evidence_ids", "counter_evidence_ids", "hypothesis_updates", "confidence_changes"],
            "reasoning_case": self._reasoning_case_for_observation(mission, observation, proposal),
        }
        mission.interpretations.append(interpreted_record)
        mission.emit(EventType.OBSERVATION_INTERPRETED, step_id=step.step_id, data=interpreted_record)
        scope_blocked = False
        target = observation.get("target")
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        if target and isinstance(allowed_targets, (list, tuple, set)) and str(target) not in {str(item) for item in allowed_targets}:
            scope_blocked = True
        decision_proposal = replace(
            proposal,
            facts=(),
            hypothesis_updates=(),
            confidence_changes=(),
            recommended_strategy_change="",
        )
        decision = decide_strategy(decision_proposal, action_success=success, scope_blocked=scope_blocked)
        if decision.decision.value in {"REPLAN", "ADD_EVIDENCE"}:
            decision = replace(
                decision,
                reason="untrusted observation claims require independent evidence",
                required_evidence=decision.required_evidence or ("independent corroboration of the observation claims",),
                next_strategy="",
                provenance={
                    **decision.provenance,
                    "input_trust": proposal.provenance.get("trust", "untrusted_observation_data"),
                    "purpose": "evidence_seeking",
                },
            )
        mission.strategy_decisions.append(decision.to_dict())
        strategy = StrategyState.from_dict(mission.strategy_state, objective=mission.objective)
        if decision.next_strategy:
            strategy.current_strategy = decision.next_strategy
            strategy.version += 1
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

    @staticmethod
    def _tool_definition_names(tools: list[dict[str, Any]]) -> frozenset[str]:
        names = set()
        for item in tools:
            if not isinstance(item, dict):
                continue
            function = item.get("function") if isinstance(item.get("function"), dict) else {}
            name = function.get("name", item.get("name", ""))
            if isinstance(name, str) and name:
                names.add(name)
        return frozenset(names)

    @staticmethod
    def _specialist_evidence_references(mission: Mission, tool_results: list[dict[str, Any]]) -> set[str]:
        references: set[str] = set()
        for item in mission.evidence:
            if not isinstance(item, dict):
                continue
            for key in ("evidence_id", "id"):
                if item.get(key):
                    references.add(str(item[key]))
            system_evidence = item.get("system_evidence")
            if isinstance(system_evidence, dict) and system_evidence.get("provenance_token"):
                references.add(str(system_evidence["provenance_token"]))
        for item in [*mission.observations, *tool_results]:
            if not isinstance(item, dict):
                continue
            for key in ("tool_call_id", "action_id", "observation_id"):
                if item.get(key):
                    references.add(str(item[key]))
            nested = item.get("result", item.get("observation", {}))
            if isinstance(nested, dict):
                results = nested.get("results", ())
                for entry in results if isinstance(results, list) else ():
                    if isinstance(entry, dict):
                        for key in ("id", "result_id", "source_id", "evidence_id"):
                            if entry.get(key):
                                references.add(str(entry[key]))
        return references

    def run_specialist(self, mission_id: str, *, router: Any, profile_id: str, task_id: str, question: str, max_turns: int = 20, mind: Any = None, preference: str = "balanced") -> Mission:
        """Run one profile-bound proposal through this durable MissionRuntime and its existing model/tool gates."""
        from security.mission_authorization import MissionAuthorizationSnapshot
        from tools.registry import REGISTRY, provider_tool_schemas
        from .model_router import ModelRouter
        from .model_protocol import RouterNativeModel
        from .specialists import SpecialistContractError, SpecialistInput, SpecialistInvocation, get_specialist_profile

        mission = self._load(mission_id)
        if mission.is_terminal:
            raise ValueError("specialists cannot run for a terminal mission")
        if mission.status is MissionStatus.PAUSED:
            raise ValueError("paused missions must be resumed before specialist execution")
        profile = get_specialist_profile(profile_id)
        authorized, reason = self._mission_authorization(mission)
        if not authorized:
            raise PermissionError("mission authorization blocked specialist: " + reason)
        step = next((item for item in mission.plan.steps if item.step_id == str(task_id)), None)
        if step is None or step.action not in profile.allowed_tools:
            raise SpecialistContractError("task_outside_specialist_profile")
        specialist_input = SpecialistInput(mission.mission_id, step.step_id, mission.plan.version, question)
        specialist_input.validate()
        budget = mission.provenance.get("owner_budget") if isinstance(mission.provenance, dict) else None
        if not isinstance(budget, dict) or not isinstance(budget.get("tools"), (list, tuple)):
            raise PermissionError("persisted Owner tool allowlist is unavailable")
        owner_tools = {str(item) for item in budget["tools"]}
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            raise PermissionError("mission authorization snapshot is invalid") from exc
        snapshot_tools = set(snapshot.allowed_tools).intersection(snapshot.allowed_actions).difference(snapshot.forbidden_actions)
        authorization = mission.authorization_context if isinstance(mission.authorization_context, dict) else {}
        scope_available = bool(authorization.get("scope_snapshot_id"))
        task_tools = {step.action}
        allowed_tools = tuple(
            name for name in profile.allowed_tools
            if name in owner_tools and name in snapshot_tools and name in task_tools
            and name in REGISTRY and REGISTRY[name].available and callable(REGISTRY[name].handler)
            and (not REGISTRY[name].scope_required or scope_available)
        )
        if not allowed_tools:
            raise PermissionError("specialist has no tools within the Owner, mission, scope, and task intersections")
        for key, value in (
            ("owner_instruction", mission.owner_instruction or mission.owner_request),
            ("mission_objective", mission.objective),
            ("plan", mission.plan),
            ("authorization_snapshot", mission.authorization_snapshot),
            ("task_step", step),
        ):
            if value is None or value == "":
                if key in profile.required_context:
                    raise SpecialistContractError("required_context_missing")

        selection = dict(mission.model_selection) if isinstance(mission.model_selection, dict) else {}
        selection_mode = str(selection.get("mode") or "auto")
        pinned_profile = str(selection.get("profile_id") or "auto")
        if selection_mode not in {"auto", "explicit"} or (selection_mode == "explicit" and not selection.get("profile_fingerprint")):
            raise PermissionError("persisted Owner model selection is invalid")
        if not isinstance(router, ModelRouter):
            raise TypeError("specialist routing requires the configured ModelRouter")
        selected_router, resolved_selection = router.with_model_selection(
            pinned_profile,
            expected_fingerprint=str(selection["profile_fingerprint"]) if selection_mode == "explicit" else None,
        )
        if resolved_selection.get("mode") != selection_mode or resolved_selection.get("profile_id") != pinned_profile:
            raise PermissionError("specialist model selection differs from the persisted Owner policy")
        if not selection:
            mission.model_selection = dict(resolved_selection)
            mission = self.store.save(mission)

        schemas = provider_tool_schemas(allowed_tools, scope_available=scope_available)
        if self._tool_definition_names(schemas) != frozenset(allowed_tools):
            raise PermissionError("specialist tool schemas do not match the authorized role intersection")
        invocation = SpecialistInvocation(profile, specialist_input, allowed_tools)
        specialist_context = invocation.context(resolved_selection)
        specialist_context.update({
            "owner_instruction": mission.owner_instruction or mission.owner_request,
            "mission_objective": mission.objective,
            "task_step": step.to_dict(),
            "scope_snapshot": mission.scope_snapshot,
            "effective_tool_intersection": list(allowed_tools),
            "authorization_snapshot": {
                "authorization_hash": snapshot.authorization_hash,
                "target_identity": snapshot.target_identity,
                "allowed_tools": list(allowed_tools),
                "scope": list(snapshot.scope),
            },
        })
        run_id = "specialist-" + hashlib.sha256(f"{mission_id}:{profile.profile_id}:{task_id}:{mission.plan.version}".encode()).hexdigest()[:20]
        if mind is None:
            specialist_model = RouterNativeModel(selected_router)
        else:
            from .model_protocol import MindNativeModel
            specialist_model = MindNativeModel(selected_router, mind, self.store, preference=preference)
        return self.run_model_loop(
            mission_id,
            specialist_model,
            tools=schemas,
            run_id=run_id,
            max_turns=max_turns,
            specialist=invocation,
            specialist_context=specialist_context,
        )

    def _record_specialist_proposal(self, mission: Mission, invocation: Any, turn: Any, *, previous_checkpoint: dict[str, Any]) -> Mission:
        from .specialists import SpecialistContractError, parse_specialist_output

        progress = mission.progress.setdefault("model_loop", {"turns": [], "tool_results": [], "seen_call_ids": []})
        references = self._specialist_evidence_references(mission, progress.get("tool_results", []))
        current_task = next((item for item in mission.plan.steps if item.step_id == invocation.specialist_input.task_id), None)
        if mission.plan.version != invocation.specialist_input.plan_version or current_task is None or current_task.action not in invocation.allowed_tools:
            proposal = None
            rejection_reason = "task_boundary_changed"
            accepted = False
        else:
            try:
                output = parse_specialist_output(turn.content, evidence_refs=references)
                proposal = output.to_dict()
                rejection_reason = ""
                accepted = True
            except SpecialistContractError as exc:
                proposal = None
                rejection_reason = exc.code
                accepted = False
        record = {
            "profile_id": invocation.profile.profile_id,
            "role": invocation.profile.role,
            "mission_id": mission.mission_id,
            "task_id": invocation.specialist_input.task_id,
            "plan_version": invocation.specialist_input.plan_version,
            "accepted": accepted,
            "authority": "proposal_only",
            "model_selection_policy": invocation.profile.model_selection_policy,
            "owner_model_selection": dict(mission.model_selection),
            "provider": str(getattr(turn, "provider", "")),
            "model": str(getattr(turn, "model", "")),
            "proposal": proposal,
            "rejection_reason": rejection_reason,
        }
        mission.progress.setdefault("specialist_proposals", []).append(record)
        mission.progress["last_specialist_proposal"] = record
        mission.checkpoint = previous_checkpoint
        try:
            return self.store.save(mission)
        except MissionWriteConflictError:
            latest = self._load(mission.mission_id)
            return self._accept_pending_control(latest) or latest

    def run_model_loop(self, mission_id: str, model: NativeModel, *, tools: list[dict[str, Any]], run_id: str = "", max_turns: int = 20, specialist: Any = None, specialist_context: dict[str, Any] | None = None) -> Mission:
        """Run a real model/tool/observation loop for a durable mission."""
        from security.authorization import authorize_tool
        from security.authorization_context import AuthorizationContext
        from tools.registry import execute as execute_tool

        allowed_tool_names = self._tool_definition_names(tools)
        if specialist is not None and (specialist_context is None or allowed_tool_names != frozenset(specialist.allowed_tools)):
            raise PermissionError("specialist context and tool schemas do not match the role intersection")

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
            mission = self._load(mission_id)
            if mission.is_terminal:
                return mission
            if specialist is not None:
                task = next((item for item in mission.plan.steps if item.step_id == specialist.specialist_input.task_id), None)
                if mission.plan.version != specialist.specialist_input.plan_version or task is None or task.action not in specialist.allowed_tools:
                    raise PermissionError("specialist mission/task boundary changed during execution")
            checkpoint_status = str((mission.checkpoint or {}).get("status", ""))
            if checkpoint_status in {"model_in_flight", "verification_in_flight"}:
                return self._require_reconciliation(
                    mission_id,
                    checkpoint_status,
                    "in-flight model/verifier callback outcome is unknown; reconciliation required",
                )
            if str((mission.checkpoint or {}).get("status", "")) in {"in_flight", "in_flight_parallel"}:
                mission.error = "in-flight native tool outcome is unknown; reconciliation required"
                mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
                return self.store.save(mission)
            controlled = self._accept_pending_control(mission)
            if controlled is not None:
                return controlled
            mission.progress["model_run_id"] = run_id
            progress = mission.progress.setdefault("model_loop", {"turns": [], "tool_results": [], "seen_call_ids": []})
            seen = set(str(item) for item in progress.setdefault("seen_call_ids", []))
            turn_id = f"{run_id}:turn:{len(progress['turns']) + 1}"
            assembled = ContextAssembler().build(mission, tool_results=progress.get("tool_results", ()), tools=tools, specialist_context=specialist_context)
            progress["last_context_hash"] = assembled.context_hash
            mission.progress["model_context_provenance"] = [dict(item) for item in assembled.provenance if isinstance(item, dict)]
            mission.progress["memory_retrieval"] = [
                {
                    "memory_id": str(item.get("memory_id", "")),
                    "source_mission_id": str(item.get("source_mission_id", "")),
                    "content_hash": str(item.get("content_hash", "")),
                    "system_evidence_refs": [dict(ref) if isinstance(ref, dict) else str(ref) for ref in item.get("system_evidence_refs", ())],
                    "validation_state": str(item.get("validation_state", "unverified_memory")),
                }
                for item in assembled.provenance if isinstance(item, dict) and item.get("source") == "memory"
            ]
            progress["context_compaction"] = {
                "compacted": assembled.compacted,
                "compacted_items": assembled.compacted_items,
                "owner_objective": sanitize_model_text(mission.objective),
                "mission_id": mission.mission_id,
                "scope_bounds": sanitize_model_data({
                    key: mission.scope_snapshot[key]
                    for key in ("scope_snapshot_id", "target_id", "scope", "authorized_assets", "allowed_networks", "forbidden_actions")
                    if isinstance(mission.scope_snapshot, dict) and key in mission.scope_snapshot
                }),
                "policy_fingerprint": str((mission.policy_snapshot or {}).get("owner_policy_fingerprint", "")) if isinstance(mission.policy_snapshot, dict) else "",
                "evidence_provenance": [item.get("provenance", {}) for item in mission.evidence],
                "tool_call_ids": [item.get("tool_call_id", "") for item in progress.get("tool_results", ())],
            }
            messages = assembled.messages
            previous_checkpoint = dict(mission.checkpoint or {})
            mission, claimed = self._claim_callback(
                mission,
                {"status": "model_in_flight", "kind": "native_model", "run_id": run_id, "turn_id": turn_id, "plan_version": mission.plan.version},
            )
            if not claimed:
                return mission
            progress = mission.progress["model_loop"]
            try:
                turn = model.complete(messages, tools, mission_id=mission.mission_id, run_id=run_id, turn_id=turn_id, plan_version=mission.plan.version)
            except ProviderError as exc:
                latest = self._load(mission_id)
                controlled = self._accept_pending_control(latest)
                if controlled is not None:
                    return controlled
                if latest.is_terminal:
                    return latest
                mission = latest
                progress = mission.progress.setdefault("model_loop", {"turns": [], "tool_results": [], "seen_call_ids": []})
                kind = getattr(exc, "kind", "PROVIDER_FAILURE")
                if specialist is not None:
                    checkpoint = mission.checkpoint if isinstance(mission.checkpoint, dict) else {}
                    if checkpoint.get("status") != "model_in_flight" or checkpoint.get("turn_id") != turn_id:
                        return mission
                    mission.checkpoint = previous_checkpoint
                    failure = {
                        "profile_id": specialist.profile.profile_id,
                        "task_id": specialist.specialist_input.task_id,
                        "kind": str(kind),
                        "run_id": run_id,
                        "turn_id": turn_id,
                    }
                    mission.progress.setdefault("specialist_failures", []).append(failure)
                    try:
                        return self.store.save(mission)
                    except MissionWriteConflictError:
                        latest = self._load(mission_id)
                        return self._accept_pending_control(latest) or latest
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
                mission.checkpoint = {"status": "model_call_failed", "run_id": run_id, "turn_id": turn_id}
                try:
                    self.store.save(mission)
                except MissionWriteConflictError:
                    latest = self._load(mission_id)
                    return self._accept_pending_control(latest) or latest
                if mission.is_terminal:
                    return mission
                continue
            except Exception:
                latest = self._load(mission_id)
                controlled = self._accept_pending_control(latest)
                if controlled is not None:
                    return controlled
                if (
                    (latest.checkpoint or {}).get("status") == "model_in_flight"
                    and (latest.checkpoint or {}).get("turn_id") == turn_id
                ):
                    latest.checkpoint = previous_checkpoint
                    try:
                        self.store.save(latest)
                    except MissionWriteConflictError:
                        latest = self._load(mission_id)
                        controlled = self._accept_pending_control(latest)
                        if controlled is not None:
                            return controlled
                raise
            latest = self._load(mission_id)
            controlled = self._accept_pending_control(latest)
            if controlled is not None:
                return controlled
            if latest.is_terminal:
                return latest
            if (
                (latest.checkpoint or {}).get("status") != "model_in_flight"
                or (latest.checkpoint or {}).get("turn_id") != turn_id
            ):
                return latest
            mission = latest
            progress = mission.progress["model_loop"]
            seen = set(str(item) for item in progress.setdefault("seen_call_ids", []))
            if previous_checkpoint.get("status") == "model_in_flight":
                previous_checkpoint = {"status": "model_turn_completed", "run_id": run_id, "turn_id": turn_id}
            mission.checkpoint = previous_checkpoint
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
            orchestration = turn.orchestration if isinstance(turn.orchestration, dict) else {}
            for invocation in orchestration.get("invocations", ()):
                if isinstance(invocation, dict):
                    mission.emit(EventType.MODEL_INVOCATION, step_id=str(orchestration.get("task_id", "")), data={**invocation, "request_id": mission.request_id, "mission_id": mission.mission_id, "model_outputs_are_evidence": False})
            if orchestration:
                mission.emit(EventType.MODEL_ORCHESTRATION, step_id=str(orchestration.get("task_id", "")), data={
                    "record_type": "MODEL_ORCHESTRATION",
                    "status": orchestration.get("status", "unknown"),
                    "request_id": mission.request_id,
                    "mission_id": mission.mission_id,
                    "task_id": orchestration.get("task_id", ""),
                    "context_hash": orchestration.get("context_hash", ""),
                    "preference": orchestration.get("preference", ""),
                    "critic_status": orchestration.get("critic_status", "not_run"),
                    "critic_report": orchestration.get("critic_report"),
                    "budget": orchestration.get("budget", {}),
                    "model_outputs_are_evidence": False,
                    "can_change_authorization_or_completion": False,
                })
            mission.emit(EventType.MODEL_TURN, data={"turn_id": turn.turn_id, "provider": turn.provider, "model": turn.model, "tool_call_count": len(turn.tool_calls), "finish_reason": turn.finish_reason, "orchestration_status": orchestration.get("status", "not_available"), "context_hash": orchestration.get("context_hash", "")})
            mission.checkpoint = previous_checkpoint
            try:
                mission = self.store.save(mission)
            except MissionWriteConflictError:
                latest = self._load(mission_id)
                return self._accept_pending_control(latest) or latest
            latest = self._load(mission_id)
            controlled = self._accept_pending_control(latest)
            if controlled is not None:
                return controlled
            if latest.is_terminal:
                return latest
            mission = latest
            progress = mission.progress["model_loop"]
            seen = set(str(item) for item in progress.setdefault("seen_call_ids", []))
            if not turn.tool_calls:
                progress["last_model_content"] = turn.content
                progress["last_model_finish_reason"] = turn.finish_reason
                latest = self._load(mission_id)
                controlled = self._accept_pending_control(latest)
                if controlled is not None:
                    return controlled
                if latest.is_terminal:
                    return latest
                mission = latest
                progress = mission.progress["model_loop"]
                if specialist is not None:
                    return self._record_specialist_proposal(mission, specialist, turn, previous_checkpoint=previous_checkpoint)
                mission, claimed = self._claim_callback(
                    mission,
                    {"status": "verification_in_flight", "kind": "mission_verifier", "run_id": run_id, "turn_id": turn_id},
                )
                if not claimed:
                    return mission
                verification = self.verifier(mission)
                latest = self._load(mission_id)
                controlled = self._accept_pending_control(latest)
                if controlled is not None:
                    return controlled
                if latest.is_terminal:
                    return latest
                mission = latest
                progress = mission.progress["model_loop"]
                mission.checkpoint = previous_checkpoint
                mission.verification_state = {"verified": verification.verified, "missing_criteria": list(verification.missing_criteria), "evidence_count": len(verification.evidence)}
                if verification.verified:
                    mission.verification_state = self.store.issue_completion_proof(mission)
                    mission.transition(MissionStatus.GOAL_COMPLETED, "model final accepted with deterministic evidence", verification=mission.verification_state)
                    mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
                    mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state, "model_final": turn.content})
                else:
                    mission.error = "model final lacked deterministic goal evidence"
                    mission.transition(MissionStatus.READY, mission.error)
                try:
                    return self.store.save(mission)
                except MissionWriteConflictError:
                    latest = self._load(mission_id)
                    return self._accept_pending_control(latest) or latest
            if len(turn.tool_calls) > 1:
                if specialist is not None:
                    for proposal in turn.tool_calls:
                        progress["tool_results"].append(ToolCallResult(proposal, False, error="specialist task permits one tool proposal per model turn").to_dict())
                    try:
                        self.store.save(mission)
                    except MissionWriteConflictError:
                        latest = self._load(mission_id)
                        return self._accept_pending_control(latest) or latest
                    continue
                if not self._run_parallel_model_calls(mission, turn.tool_calls, auth_context=auth_context, run_id=run_id, progress=progress, seen=seen, allowed_tool_names=allowed_tool_names):
                    return self._load(mission_id)
                try:
                    self.store.save(mission)
                except MissionWriteConflictError:
                    return self._require_reconciliation(mission_id, "in_flight_parallel", "parallel native tool results were not durably committed")
                if mission.is_terminal:
                    return mission
                continue
            for proposal in turn.tool_calls:
                latest = self._load(mission_id)
                controlled = self._accept_pending_control(latest)
                if controlled is not None:
                    return controlled
                if latest.is_terminal:
                    return latest
                mission = latest
                progress = mission.progress["model_loop"]
                seen = set(str(item) for item in progress.setdefault("seen_call_ids", []))
                if proposal.mission_id and proposal.mission_id != mission.mission_id:
                    result = ToolCallResult(proposal, False, error="tool call belongs to another mission")
                elif proposal.run_id and proposal.run_id != run_id:
                    result = ToolCallResult(proposal, False, error="tool call belongs to another run")
                elif proposal.tool_call_id in seen:
                    result = ToolCallResult(proposal, False, error="duplicate tool call rejected; prior result is authoritative")
                else:
                    seen.add(proposal.tool_call_id)
                    progress["seen_call_ids"].append(proposal.tool_call_id)
                    if specialist is not None:
                        if proposal.name not in specialist.allowed_tools or proposal.name not in allowed_tool_names or (proposal.step_id and proposal.step_id != specialist.specialist_input.task_id):
                            result = ToolCallResult(proposal, False, error="tool is outside the specialist task boundary")
                            progress["tool_results"].append(result.to_dict())
                            continue
                        if not proposal.step_id:
                            proposal = replace(proposal, step_id=specialist.specialist_input.task_id)
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
                        if proposal.name not in allowed_tool_names:
                            result = ToolCallResult(proposal, False, error="tool is outside the supplied model tool schema allowlist")
                            progress["tool_results"].append(result.to_dict())
                            continue
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
                        mission.checkpoint = {"status": "in_flight", "tool_call_id": proposal.tool_call_id, "action_id": proposal.action_id or proposal.tool_call_id, "step_id": proposal.step_id, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
                        try:
                            mission = self.store.save(mission)
                        except MissionWriteConflictError:
                            latest = self._load(mission_id)
                            return self._accept_pending_control(latest) or latest
                        session_failure = self._live_owner_session_failure(mission, auth_context)
                        if session_failure:
                            mission.checkpoint = previous_checkpoint
                            mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": False, "reason": session_failure})
                            mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "OWNER_SESSION_INVALID", "reason": session_failure})
                            result = ToolCallResult(proposal, False, error=session_failure)
                            progress["tool_results"].append(result.to_dict())
                            continue
                        try:
                            raw = execute_tool(proposal.name, argument, authorization_decision=decision.decision, scope_context=mission.scope_snapshot, request_id=mission.request_id, tool_call_id=proposal.tool_call_id, execution_proof=proof, execution_class="MISSION_BOUND", **registry_context)
                            action_id = proposal.action_id or proposal.tool_call_id
                            observation, success = self._normalize_native_tool_result(
                                raw,
                                tool_name=proposal.name,
                                action_id=action_id,
                                step_id=proposal.step_id,
                                mission_id=mission.mission_id,
                                tool_call_id=proposal.tool_call_id,
                            )
                            if specialist is not None:
                                observation["authority"] = "untrusted_observation"
                                observation["specialist_profile_id"] = specialist.profile.profile_id
                            mission.record_observation(observation)
                            if planned_step is not None and specialist is None:
                                mission, followup_claimed = self._claim_followup_callback(mission, f"observation_interpretation:{proposal.tool_call_id}")
                                if not followup_claimed:
                                    return mission
                                self._interpret_observation(mission, planned_step, observation, success=success)
                            if specialist is None:
                                mission.record_action(action_id, proposal.step_id, "completed" if success else "failed", observation, plan_fingerprint=mission.plan.fingerprint)
                            if success and specialist is None:
                                self._record_verified_criterion_evidence(mission, action_id)
                                ready_after = self._ready_plan_steps(mission)
                                mission.current_step = ready_after[0][0] if ready_after else len(mission.plan.steps)
                            mission.checkpoint = {"status": "completed", "tool_call_id": proposal.tool_call_id, "action_id": action_id, "step_id": proposal.step_id, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
                            result = ToolCallResult(proposal, success, result=observation, error=str(observation.get("error", "")))
                        except Exception as exc:
                            mission.error = f"native tool outcome is ambiguous: {type(exc).__name__}"
                            mission.transition(MissionStatus.RECOVERY_REQUIRED, mission.error)
                            try:
                                return self.store.save(mission)
                            except MissionWriteConflictError:
                                return self._require_reconciliation(mission_id, "in_flight", "native tool result was not durably committed")
                progress["tool_results"].append(result.to_dict())
            try:
                self.store.save(mission)
            except MissionWriteConflictError:
                latest = self._load(mission_id)
                if str((latest.checkpoint or {}).get("status", "")) == "in_flight":
                    return self._require_reconciliation(mission_id, "in_flight", "native tool result was not durably committed")
                return self._accept_pending_control(latest) or latest
        mission = self._load(mission_id)
        controlled = self._accept_pending_control(mission)
        if controlled is not None:
            return controlled
        if specialist is not None:
            mission.progress.setdefault("specialist_failures", []).append({
                "profile_id": specialist.profile.profile_id,
                "task_id": specialist.specialist_input.task_id,
                "reason": "turn_budget_exhausted",
                "run_id": run_id,
            })
            return self.store.save(mission)
        mission.error = "model turn budget exhausted"
        mission.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, mission.error)
        return self.store.save(mission)

    def _run_parallel_model_calls(self, mission: Mission, proposals: tuple[Any, ...], *, auth_context: Any, run_id: str, progress: dict[str, Any], seen: set[str], allowed_tool_names: frozenset[str]) -> bool:
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
            if proposal.name not in allowed_tool_names:
                results.append(ToolCallResult(proposal, False, error="tool is outside the supplied model tool schema allowlist"))
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
        try:
            self.store.save(mission)
        except MissionWriteConflictError:
            latest = self._load(mission.mission_id)
            self._accept_pending_control(latest)
            return False

        def execute_one(item: tuple[Any, Any, Any, Any, dict[str, Any]]) -> dict[str, Any]:
            proposal, argument, decision, proof, registry_context = item
            proof_ok, proof_reason, proof_code = MissionExecutionBoundary.validate(proof, mission)
            if not proof_ok:
                return {"_proof_rejected": True, "proof_code": proof_code, "proof_reason": proof_reason}
            session_failure = self._live_owner_session_failure(mission, auth_context)
            if session_failure:
                return {"_owner_session_rejected": True, "reason": session_failure}
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
                return {"raw": raw}
            except Exception as exc:
                return {"_ambiguous": True, "error": str(exc), "failure_class": FailureClass.UNKNOWN.value, "exception": type(exc).__name__}

        raw_results = execute_bounded_parallel(authorized, execute_one, max_workers=min(4, max(1, len(authorized))))
        ambiguous: list[tuple[Any, dict[str, Any]]] = []
        for item, wrapped in zip(authorized, raw_results):
            proposal = item[0]
            if wrapped.get("_owner_session_rejected"):
                reason = str(wrapped.get("reason") or "live Owner session could not be verified")
                mission.emit(EventType.AUTHORIZATION_CHECKED, data={"tool_call_id": proposal.tool_call_id, "allowed": False, "reason": reason})
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": "OWNER_SESSION_INVALID", "reason": reason})
                results.append(ToolCallResult(proposal, False, error=reason))
                continue
            if wrapped.get("_proof_rejected"):
                mission.emit(EventType.EXECUTION_REJECTED, data={"tool_call_id": proposal.tool_call_id, "code": wrapped.get("proof_code"), "reason": wrapped.get("proof_reason")})
                results.append(ToolCallResult(proposal, False, error=f"{wrapped.get('proof_code')}: {wrapped.get('proof_reason')}"))
                continue
            if wrapped.get("_ambiguous"):
                ambiguous.append((proposal, wrapped))
                continue
            action_id = proposal.action_id or proposal.tool_call_id
            observation, success = self._normalize_native_tool_result(
                wrapped.get("raw"),
                tool_name=proposal.name,
                action_id=action_id,
                step_id=proposal.step_id,
                mission_id=mission.mission_id,
                tool_call_id=proposal.tool_call_id,
            )
            mission.record_observation(observation)
            planned_step = next((step for step in mission.plan.steps if step.step_id == proposal.step_id), None)
            if planned_step is not None:
                mission, followup_claimed = self._claim_followup_callback(mission, f"parallel_observation_interpretation:{proposal.tool_call_id}")
                if not followup_claimed:
                    return True
                self._interpret_observation(mission, planned_step, observation, success=success)
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
            return True
        mission.checkpoint = {"status": "completed", "tool_call_ids": all_ids, "call_bindings": call_bindings, "run_id": run_id, "plan_fingerprint": mission.plan.fingerprint}
        return True

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
        if checkpoint_status in {"model_in_flight", "verification_in_flight"}:
            return self._require_reconciliation(
                mission_id,
                checkpoint_status,
                "in-flight model/verifier callback outcome is unknown; reconciliation required",
            )
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
            previous_checkpoint = dict(mission.checkpoint or {})
            mission, claimed = self._claim_callback(
                mission,
                {"status": "verification_in_flight", "kind": "mission_verifier", "plan_version": mission.plan.version},
            )
            if not claimed:
                return mission
            verification = self.verifier(mission)
            latest = self._load(mission_id)
            controlled = self._accept_pending_control(latest)
            if controlled is not None:
                return controlled
            if latest.is_terminal:
                return latest
            mission = latest
            mission.checkpoint = previous_checkpoint
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
        completed_checkpoint = {"step_id": step.step_id, "action_id": action_id, "status": "completed", "plan_version": mission.plan.version, "plan_fingerprint": mission.plan.fingerprint}
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
        try:
            mission = self.store.save(mission)
        except MissionWriteConflictError:
            latest = self._load(mission_id)
            return self._accept_pending_control(latest) or latest
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
        mission, followup_claimed = self._claim_followup_callback(mission, f"observation_interpretation:{action_id}")
        if not followup_claimed:
            return mission
        try:
            strategy_decision = self._interpret_observation(mission, step, observation, success=success)
        except (TypeError, ValueError, KeyError) as exc:
            mission.error = f"observation interpretation rejected: {type(exc).__name__}"
            mission.recovery_events.append({"event": "interpretation_rejected", "reason": str(exc), "action_id": action_id})
            mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
            mission.checkpoint = completed_checkpoint
            return self.store.save(mission)
        allowed_targets = (mission.scope_snapshot or {}).get("allowed_targets") if isinstance(mission.scope_snapshot, dict) else None
        scope_blocked = bool(observation.get("target") and isinstance(allowed_targets, (list, tuple, set)) and str(observation.get("target")) not in {str(item) for item in allowed_targets})
        if scope_blocked:
            mission.error = "observation proposed a target outside deterministic scope"
            mission.failures.append({"class": FailureClass.SCOPE.value, "reason": mission.error, "target": observation.get("target")})
            mission.transition(MissionStatus.SCOPE_BLOCKED, mission.error)
            mission.checkpoint = completed_checkpoint
            return self.store.save(mission)
        if success:
            self._record_verified_criterion_evidence(mission, action_id)
            if strategy_decision is not None and strategy_decision.decision.value in {"REPLAN", "CHANGE_HYPOTHESIS", "ADD_EVIDENCE"}:
                mission.transition(MissionStatus.REPLANNING, strategy_decision.reason)
                mission.emit(EventType.REPLAN_TRIGGERED, step_id=step.step_id, data=strategy_decision.to_dict())
                mission, followup_claimed = self._claim_followup_callback(mission, f"replanner:{action_id}")
                if not followup_claimed:
                    return mission
                new_plan = self.replanner(mission, {**observation, "interpretation": mission.interpretations[-1], "strategy_decision": strategy_decision.to_dict()})
                if new_plan.objective != mission.objective:
                    mission.error = "replanner attempted to change Owner objective"
                    mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                    mission.checkpoint = completed_checkpoint
                    return self.store.save(mission)
                try:
                    new_plan.validate_dependency_graph()
                except ValueError:
                    mission.error = "replanner returned an invalid dependency graph"
                    mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                    mission.checkpoint = completed_checkpoint
                    return self.store.save(mission)
                mission.replan_history.append({"from_version": mission.plan.version, "to_version": new_plan.version, "reason": strategy_decision.reason, "trigger": strategy_decision.to_dict()})
                mission.plan_history.append({"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.emit(EventType.PLAN_REVISED, data={"version": new_plan.version, "fingerprint": new_plan.fingerprint, "reason": strategy_decision.reason})
                mission.plan = new_plan
                mission.current_step = 0
                mission.retry_count = 0
                mission.transition(MissionStatus.READY, "informative observation caused replan", plan_version=new_plan.version)
                mission.checkpoint = completed_checkpoint
                return self.store.save(mission)
            next_steps = self._ready_plan_steps(mission)
            mission.current_step = next_steps[0][0] if next_steps else len(mission.plan.steps)
            mission.retry_count = 0
            mission.transition(MissionStatus.READY, "observation accepted")
            mission.checkpoint = completed_checkpoint
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
            mission, followup_claimed = self._claim_followup_callback(mission, f"replanner:{action_id}")
            if not followup_claimed:
                return mission
            new_plan = self.replanner(mission, observation)
            if new_plan.objective != mission.objective:
                mission.error = "replanner attempted to change Owner objective"
                mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                mission.checkpoint = completed_checkpoint
                return self.store.save(mission)
            try:
                new_plan.validate_dependency_graph()
            except ValueError:
                mission.error = "replanner returned an invalid dependency graph"
                mission.transition(MissionStatus.SAFETY_BLOCKED, mission.error)
                mission.checkpoint = completed_checkpoint
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
        mission.checkpoint = completed_checkpoint
        return self.store.save(mission)

    def run_to_completion(self, mission_id: str, *, max_slices: int | None = None, heartbeat: Callable[[], None] | None = None) -> Mission:
        try:
            limit = max_slices or self._load(mission_id).max_iterations
            for _ in range(limit):
                if heartbeat is not None:
                    heartbeat()
                mission = self.run_slice(mission_id)
                if mission.is_terminal or mission.status is MissionStatus.PAUSED:
                    return mission
            return self._load(mission_id)
        finally:
            self.release_live_mission(mission_id)


__all__ = ["MissionRuntime"]
