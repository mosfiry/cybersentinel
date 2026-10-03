from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Any, Callable

from agent.effect_reconciliation import (
    EffectReconciliationAction,
    EffectReconciliationEngine,
)
from agent.external_effects import EffectState, ExternalEffectLedger
from agent.mission import Mission, MissionStatus
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionScheduler, WorkerMissionState
from agent.planning import Plan
from security.owner_policy import OwnerAuthenticationEvidence


class MissionService:
    """Owner-scoped mission control plane; execution remains MissionRuntime-owned."""

    def __init__(
        self,
        runtime: MissionRuntime,
        queue: MissionQueue,
        scheduler: MissionScheduler | None = None,
        *,
        owner_revalidator: Callable[[str, str], OwnerAuthenticationEvidence] | None = None,
        reconciliation_engine: EffectReconciliationEngine | None = None,
    ):
        self.runtime = runtime
        self.queue = queue
        self.scheduler = scheduler
        self.owner_revalidator = owner_revalidator
        self.reconciliation_engine = reconciliation_engine

    def create_mission(self, owner_request: str, objective: str, plan: Plan, **kwargs: Any) -> dict[str, Any]:
        if not str(kwargs.get("request_id") or "").strip():
            context_request_id = getattr(kwargs.get("authorization_context"), "request_id", "")
            kwargs["request_id"] = str(context_request_id or uuid.uuid4().hex)
        mission = self.runtime.create(owner_request, objective, plan, **kwargs)
        return mission.to_dict()

    @staticmethod
    def _owner_identity_ref(owner_session_token: str | None) -> str:
        from security.owner_password import authenticated_owner

        if not isinstance(owner_session_token, str) or not owner_session_token.strip():
            raise PermissionError("owner authentication required")
        owner = authenticated_owner(owner_session_token)
        if not isinstance(owner, dict) or owner.get("owner_id") is None:
            raise PermissionError("owner authentication required")
        return f"owner:{int(owner['owner_id'])}"

    def _authorized_mission(
        self,
        mission_id: str,
        owner_session_token: str | None,
        *,
        allow_unbound_read: bool = False,
    ) -> tuple[Mission, str]:
        owner_ref = self._owner_identity_ref(owner_session_token)
        mission = self._load(mission_id)
        if mission.owner_identity_ref != owner_ref:
            if not (allow_unbound_read and not mission.owner_identity_ref):
                raise PermissionError("mission access denied")
        return mission, owner_ref

    def _assert_unleased(self, mission_id: str) -> None:
        try:
            item = self.queue.get(mission_id)
        except KeyError:
            return
        if item.lease_owner is not None:
            raise PermissionError("active worker lease blocks Owner control")

    def _prepare_reconciled_resume(self, mission: Mission, owner_session_token: str) -> Mission:
        """Consume only exact terminal V7 outcomes, then require a separate Owner reauthorization."""
        if mission.status is not MissionStatus.RECOVERY_REQUIRED:
            return mission
        if mission.progress.get("owner_cancel_requested"):
            raise ValueError("cancelled recovery mission cannot be resumed")
        checkpoint = dict(mission.checkpoint or {})
        checkpoint_status = checkpoint.get("status")
        if checkpoint_status not in {"in_flight", "in_flight_parallel"}:
            raise ValueError("in-flight mission requires reconciliation before resume")
        try:
            checkpoint_version = int(checkpoint.get("plan_version"))
        except (TypeError, ValueError) as exc:
            raise ValueError("recovery checkpoint has no valid plan version") from exc
        if checkpoint_version != mission.plan.version:
            raise ValueError("recovery checkpoint is stale for the current plan")

        pairs: list[tuple[str, str, str]] = []
        if checkpoint_status == "in_flight":
            task_id = str(checkpoint.get("step_id") or "")
            execution_id = str(checkpoint.get("action_id") or checkpoint.get("tool_call_id") or "")
            if not task_id or not execution_id:
                raise ValueError("recovery checkpoint lacks an exact execution identity")
            pairs.append((task_id, execution_id, str(checkpoint.get("tool_call_id") or "")))
        elif checkpoint_status == "in_flight_parallel":
            tool_call_ids = [str(item) for item in checkpoint.get("tool_call_ids", ())]
            execution_ids = [str(item) for item in checkpoint.get("execution_ids", ())]
            task_ids = [str(item) for item in checkpoint.get("task_ids", ())]
            ambiguous_ids = [
                str(item)
                for item in checkpoint.get("ambiguous_tool_call_ids", tool_call_ids)
            ]
            if (
                not tool_call_ids
                or len(tool_call_ids) != len(execution_ids)
                or len(tool_call_ids) != len(task_ids)
                or len(set(tool_call_ids)) != len(tool_call_ids)
                or not ambiguous_ids
                or any(item not in tool_call_ids for item in ambiguous_ids)
            ):
                raise ValueError("parallel recovery checkpoint identities are invalid")
            wanted = set(ambiguous_ids)
            pairs = [
                (task_ids[index], execution_ids[index], call_id)
                for index, call_id in enumerate(tool_call_ids)
                if call_id in wanted
            ]
            if len(pairs) != len(wanted) or any(not task_id or not execution_id for task_id, execution_id, _ in pairs):
                raise ValueError("parallel recovery checkpoint does not bind every ambiguous call")
            current_step = mission.current_plan_step
            if current_step is None or any(task_id != current_step.step_id for task_id, _, _ in pairs):
                raise ValueError("parallel recovery checkpoint cannot be mapped to the current plan step")
        else:
            raise ValueError("recovery checkpoint is not an in-flight V7 execution")

        engine = self._reconciliation_engine()
        context = self._owner_context(owner_session_token)
        effects = engine.ledger.list_effects(mission_id=mission.mission_id, limit=1000)
        if len(effects) >= 1000:
            raise ValueError("effect history exceeds the safe reconciliation inspection bound")
        if not effects:
            raise ValueError("recovery checkpoint has no matching durable effect")

        exact: list[tuple[str, str, str, Any]] = []
        for task_id, execution_id, tool_call_id in pairs:
            matches = [
                item
                for item in effects
                if item.task_id == task_id
                and item.task_version == checkpoint_version
                and item.execution_id == execution_id
            ]
            if len(matches) != 1:
                raise ValueError("recovery checkpoint is missing or ambiguously bound to a durable effect")
            effect = matches[0]
            if checkpoint.get("effect_id") and len(pairs) == 1 and str(checkpoint["effect_id"]) != effect.effect_id:
                raise ValueError("recovery checkpoint effect identity does not match the ledger")
            inspection = engine.inspect(effect.effect_id, context=context)
            if inspection.owner_binding_status != "BOUND":
                raise ValueError("unbound or rebound effect cannot authorize mission resume")
            try:
                state = EffectState(effect.state)
            except ValueError as exc:
                raise ValueError("effect state is unknown and cannot authorize mission resume") from exc
            if state not in {EffectState.SUCCEEDED, EffectState.FAILED}:
                raise ValueError("unresolved external effects block mission resume")
            terminal_events = {
                EffectState.SUCCEEDED: {
                    "SUCCEEDED",
                    "LATE_RESULT_OBSERVED",
                    "OWNER_CONFIRMED_APPLIED",
                    "PROVIDER_CONFIRMED_APPLIED",
                },
                EffectState.FAILED: {
                    "RECONCILED_NOT_DISPATCHED",
                    "OWNER_CONFIRMED_NO_EFFECT",
                    "PROVIDER_CONFIRMED_NO_EFFECT",
                },
            }
            history = engine.ledger.history(effect.effect_id, limit=1000)
            terminal_event = history[-1] if history else None
            if (
                terminal_event is None
                or terminal_event.get("to_state") != state.value
                or terminal_event.get("event_type") not in terminal_events[state]
            ):
                raise ValueError("terminal effect lacks durable applied/no-effect evidence")
            exact.append((task_id, execution_id, tool_call_id, effect))

        expected_ids = {item[3].effect_id for item in exact}
        for item in effects:
            try:
                state = EffectState(item.state)
            except ValueError as exc:
                raise ValueError("unknown effect state blocks mission resume") from exc
            if state not in {EffectState.SUCCEEDED, EffectState.FAILED} and item.effect_id not in expected_ids:
                raise ValueError("another unresolved effect blocks mission resume")

        outcomes = {EffectState(item[3].state) for item in exact}
        if len(outcomes) != 1:
            raise ValueError("mixed parallel effect outcomes require separate recovery")
        applied = outcomes == {EffectState.SUCCEEDED}
        effect_ids = [item[3].effect_id for item in exact]

        try:
            queued = self.queue.get(mission.mission_id)
        except KeyError:
            queued = None
        if queued is not None:
            if queued.lease_owner is not None or queued.state is WorkerMissionState.EXECUTING:
                raise PermissionError("active worker lease blocks Owner recovery")
            if queued.state is WorkerMissionState.CANCELLED:
                raise ValueError("cancelled queue item cannot be resumed")
        # Make the queue non-claimable before changing mission state. If the
        # process dies between these writes, restart can only leave the mission
        # quarantined; no worker can dispatch the old action.
        quarantined = self.queue.enqueue(mission.mission_id, state=WorkerMissionState.NEEDS_INPUT)
        if quarantined.state is WorkerMissionState.EXECUTING:
            raise PermissionError("active worker lease blocks Owner recovery")

        if applied:
            for task_id, execution_id, tool_call_id, effect in exact:
                observation = {
                    "type": "external_effect_reconciled",
                    "success": True,
                    "mission_id": mission.mission_id,
                    "step_id": task_id,
                    "action_id": execution_id,
                    "effect_id": effect.effect_id,
                    "effect_state": EffectState.SUCCEEDED.value,
                    "source": "owner_reconciliation",
                }
                mission.record_observation(observation)
                mission.record_action(execution_id, task_id, "completed", observation)
                self._append_reconciled_model_result(
                    mission, effect, tool_call_id, success=True
                )
            current_step = mission.current_plan_step
            if current_step is not None and all(item[0] == current_step.step_id for item in exact):
                step_action_id = f"{mission.mission_id}:{mission.plan.version}:{current_step.step_id}:{mission.current_step}"
                mission.record_action(
                    step_action_id,
                    current_step.step_id,
                    "completed",
                    {
                        "type": "parallel_external_effects_reconciled",
                        "success": True,
                        "effect_ids": effect_ids,
                    },
                )
            mission.checkpoint = {
                "status": "reconciled_applied",
                "effect_ids": effect_ids,
                "plan_version": mission.plan.version,
                "task_ids": [item[0] for item in exact],
                "execution_ids": [item[1] for item in exact],
            }
            resolution = "OWNER_CONFIRMED_APPLIED"
        else:
            old_version = mission.plan.version
            reason = "Owner-confirmed no effect; create a new execution identity"
            mission.plan = mission.plan.replan(
                steps=mission.plan.steps,
                assumptions=(*mission.plan.assumptions, reason),
                reason=reason,
            )
            mission.plan_history.append(
                {
                    "version": mission.plan.version,
                    "fingerprint": mission.plan.fingerprint,
                    "reason": reason,
                }
            )
            mission.replan_history.append(
                {
                    "from_version": old_version,
                    "to_version": mission.plan.version,
                    "reason": reason,
                    "effect_ids": effect_ids,
                }
            )
            for task_id, execution_id, tool_call_id, effect in exact:
                self._append_reconciled_model_result(
                    mission, effect, tool_call_id, success=False
                )
            mission.checkpoint = {
                "status": "reconciled_no_effect",
                "effect_ids": effect_ids,
                "prior_plan_version": old_version,
                "plan_version": mission.plan.version,
                "task_ids": [item[0] for item in exact],
                "prior_execution_ids": [item[1] for item in exact],
            }
            resolution = "OWNER_CONFIRMED_NO_EFFECT"

        mission.error = "Owner reauthorization required after effect reconciliation"
        mission.progress["reconciliation_complete"] = True
        mission.recovery_events.append(
            {"event": "effects_reconciled_for_resume", "resolution": resolution, "effect_ids": effect_ids}
        )
        mission.transition(
            MissionStatus.OWNER_REAUTH_REQUIRED,
            "terminal effect outcomes recorded; fresh Owner authorization required",
            effect_ids=effect_ids,
            resolution=resolution,
        )
        return self.runtime.store.save(mission)

    @staticmethod
    def _append_reconciled_model_result(
        mission: Mission, effect: Any, tool_call_id: str, *, success: bool
    ) -> None:
        model_loop = mission.progress.get("model_loop")
        if not isinstance(model_loop, dict) or not tool_call_id:
            return
        results = model_loop.setdefault("tool_results", [])
        if any(item.get("tool_call_id") == tool_call_id for item in results if isinstance(item, dict)):
            return
        results.append(
            {
                "tool_call_id": tool_call_id,
                "name": effect.operation,
                "arguments": {},
                "ok": success,
                "result": {
                    "type": "external_effect_reconciled",
                    "effect_id": effect.effect_id,
                    "effect_state": EffectState.SUCCEEDED.value if success else EffectState.FAILED.value,
                },
                "error": "" if success else "OWNER_CONFIRMED_NO_EFFECT",
                "mission_id": mission.mission_id,
                "request_id": mission.request_id,
                "plan_version": mission.plan.version,
                "step_id": effect.task_id,
            }
        )

    def _reauthorize_before_enqueue(self, mission_id: str, owner_session_token: str | None) -> Mission:
        if not isinstance(owner_session_token, str) or not owner_session_token.strip():
            raise PermissionError("owner revalidation required before queueing")
        if self.owner_revalidator is None:
            raise PermissionError("owner revalidation is unavailable")
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if mission.progress.get("owner_cancel_requested"):
            raise ValueError("cancelled recovery mission cannot be resumed")
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            mission = self._prepare_reconciled_resume(mission, owner_session_token)
        if mission.is_terminal and mission.status not in {
            MissionStatus.OWNER_INPUT_REQUIRED,
            MissionStatus.OWNER_REAUTH_REQUIRED,
        }:
            raise ValueError("terminal mission cannot be queued")
        self._assert_unleased(mission_id)

        evidence = self.owner_revalidator(mission_id, owner_session_token)
        mission, owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if not isinstance(evidence, OwnerAuthenticationEvidence) or not evidence.is_valid(
            mission.request_id,
            session_id=owner_session_token,
        ):
            raise PermissionError("owner revalidation evidence is invalid")
        if mission.owner_identity_ref != owner_ref:
            raise PermissionError("mission Owner identity changed during revalidation")
        authorization = mission.authorization_snapshot
        if not isinstance(authorization, dict):
            raise PermissionError("mission authorization snapshot is unavailable")
        if (
            authorization.get("owner_identity") != owner_ref
            or authorization.get("mission_id") != mission.mission_id
            or authorization.get("owner_approval") != evidence.proof_fingerprint
        ):
            raise PermissionError("owner authorization is not bound to the queued mission")
        authentication = (mission.policy_snapshot or {}).get("authentication", {})
        if not isinstance(authentication, dict) or authentication.get("proof_fingerprint") != evidence.proof_fingerprint:
            raise PermissionError("owner policy snapshot is not bound to the current session")
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("in-flight mission requires reconciliation before resume")
        if mission.is_terminal and mission.status not in {
            MissionStatus.OWNER_INPUT_REQUIRED,
            MissionStatus.OWNER_REAUTH_REQUIRED,
        }:
            raise ValueError("mission cannot be queued in its current terminal state")
        return mission

    def start_mission(self, mission_id: str, *, owner_session_token: str | None = None) -> dict[str, Any]:
        self._reauthorize_before_enqueue(mission_id, owner_session_token)
        return self.queue.enqueue(mission_id).__dict__.copy()

    def pause_mission(
        self, mission_id: str, *, owner_session_token: str | None = None
    ) -> dict[str, Any]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if mission.is_terminal:
            return mission.to_dict()
        queued = self.queue.enqueue(mission_id, state=WorkerMissionState.PAUSED)
        if queued.state is WorkerMissionState.EXECUTING:
            raise PermissionError("active worker lease blocks Owner control")
        mission.progress["pause_requested"] = True
        mission.checkpoint = {**mission.checkpoint, "status": "paused"}
        return self.runtime.store.save(mission).to_dict()

    def resume_mission(self, mission_id: str, *, owner_session_token: str | None = None) -> dict[str, Any]:
        mission = self._reauthorize_before_enqueue(mission_id, owner_session_token)
        mission.progress.pop("pause_requested", None)
        mission = self.runtime.store.save(mission)
        self.queue.enqueue(mission_id)
        return mission.to_dict()

    def cancel_mission(
        self, mission_id: str, *, owner_session_token: str | None = None
    ) -> dict[str, Any]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if mission.is_terminal and mission.status not in {
            MissionStatus.OWNER_INPUT_REQUIRED,
            MissionStatus.OWNER_REAUTH_REQUIRED,
            MissionStatus.RECOVERY_REQUIRED,
        }:
            return mission.to_dict()
        queued = self.queue.enqueue(mission_id, state=WorkerMissionState.CANCELLED)
        if queued.state is WorkerMissionState.EXECUTING:
            raise PermissionError("active worker lease blocks Owner control")
        if mission.status is MissionStatus.RECOVERY_REQUIRED:
            # Keep the recovery status and checkpoint available to V7 reconciliation.
            # Cancellation prevents dispatch; it does not assert an effect outcome.
            mission.progress["owner_cancel_requested"] = True
            mission.recovery_events.append({"event": "owner_cancel_requested", "reason": "ambiguous effect remains auditable"})
        elif not mission.is_terminal:
            mission.transition(MissionStatus.CANCELLED, "Owner requested mission cancellation")
            mission.checkpoint = {**mission.checkpoint, "status": "cancelled"}
        elif mission.status in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.OWNER_REAUTH_REQUIRED}:
            mission.transition(MissionStatus.CANCELLED, "Owner requested mission cancellation")
            mission.checkpoint = {**mission.checkpoint, "status": "cancelled"}
        return self.runtime.store.save(mission).to_dict()

    def schedule_mission(
        self,
        mission_id: str,
        *,
        owner_session_token: str | None = None,
        run_at: str,
        interval_seconds: int | None = None,
        retry_limit: int = 0,
        schedule_id: str | None = None,
    ) -> dict[str, Any]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if self.scheduler is None:
            raise RuntimeError("scheduler is not configured")
        if mission.is_terminal or mission.status is MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("mission cannot be scheduled in its current state")
        self._assert_unleased(mission_id)
        return self.scheduler.schedule(
            mission_id,
            run_at=run_at,
            interval_seconds=interval_seconds,
            retry_limit=retry_limit,
            schedule_id=schedule_id,
        ).__dict__.copy()

    def _owner_context(self, owner_session_token: str):
        from security.authorization_context import AuthorizationContext
        from security.owner_policy import authenticate_owner, capture_policy_snapshot

        request_id = uuid.uuid4().hex
        evidence = authenticate_owner(owner_session_token, request_id)
        snapshot = capture_policy_snapshot(request_id, evidence)
        return AuthorizationContext(
            request_id=request_id,
            owner_evidence=evidence,
            policy_snapshot=snapshot,
            session_id=evidence.session_id,
        )

    def _reconciliation_engine(self) -> EffectReconciliationEngine:
        if self.reconciliation_engine is None:
            self.reconciliation_engine = EffectReconciliationEngine(
                ledger=ExternalEffectLedger(self.queue.db_path),
                mission_store=self.runtime.store,
            )
        return self.reconciliation_engine

    def effects(
        self,
        mission_id: str,
        *,
        owner_session_token: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if not mission.owner_identity_ref:
            raise PermissionError("legacy unbound mission has no effect inspection authority")
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("effect listing limit must be between 1 and 1000")
        engine = self._reconciliation_engine()
        context = self._owner_context(str(owner_session_token))
        records = engine.ledger.list_effects(mission_id=mission_id, limit=limit)
        return [asdict(engine.inspect(item.effect_id, context=context)) for item in records]

    def inspect_effect(
        self,
        mission_id: str,
        effect_id: str,
        *,
        owner_session_token: str | None = None,
    ) -> dict[str, Any]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if not mission.owner_identity_ref:
            raise PermissionError("legacy unbound mission has no effect inspection authority")
        engine = self._reconciliation_engine()
        context = self._owner_context(str(owner_session_token))
        effect = engine.ledger.get(effect_id)
        if effect is None:
            raise KeyError("unknown_effect")
        if effect.mission_id != mission_id:
            raise PermissionError("effect does not belong to this mission")
        return asdict(engine.inspect(effect_id, context=context))

    def reconcile_effect(
        self,
        mission_id: str,
        effect_id: str,
        *,
        owner_session_token: str | None = None,
        outcome: str,
        evidence_reference: str,
    ) -> dict[str, Any]:
        mission, _owner_ref = self._authorized_mission(mission_id, owner_session_token)
        if mission.status is not MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("mission is not quarantined for effect reconciliation")
        try:
            action = EffectReconciliationAction(outcome)
        except (TypeError, ValueError) as exc:
            raise ValueError("unsupported Owner reconciliation outcome") from exc
        if action not in {
            EffectReconciliationAction.OWNER_CONFIRM_APPLIED,
            EffectReconciliationAction.OWNER_CONFIRM_NO_EFFECT,
        }:
            raise ValueError("only explicit Owner outcomes are available through this control plane")
        engine = self._reconciliation_engine()
        effect = engine.ledger.get(effect_id)
        if effect is None:
            raise KeyError("unknown_effect")
        if effect.mission_id != mission_id:
            raise PermissionError("effect does not belong to this mission")
        context = self._owner_context(str(owner_session_token))
        authorization = engine.authorize(
            effect_id,
            context=context,
            action=action,
            evidence_reference=evidence_reference,
        )
        result = engine.apply_owner_decision(effect_id, authorization=authorization)
        return asdict(result)

    def status(self, mission_id: str, *, owner_session_token: str | None = None) -> dict[str, Any]:
        return self._authorized_mission(mission_id, owner_session_token, allow_unbound_read=True)[0].to_dict()

    def timeline(self, mission_id: str, *, owner_session_token: str | None = None) -> list[dict[str, Any]]:
        return list(self._authorized_mission(mission_id, owner_session_token, allow_unbound_read=True)[0].trajectory)

    def evidence(self, mission_id: str, *, owner_session_token: str | None = None) -> list[dict[str, Any]]:
        return list(self._authorized_mission(mission_id, owner_session_token, allow_unbound_read=True)[0].evidence)

    def artifacts(self, mission_id: str, *, owner_session_token: str | None = None) -> list[dict[str, Any]]:
        return list(self._authorized_mission(mission_id, owner_session_token, allow_unbound_read=True)[0].artifacts)

    def logs(self, mission_id: str, *, owner_session_token: str | None = None) -> list[dict[str, Any]]:
        mission = self._authorized_mission(mission_id, owner_session_token, allow_unbound_read=True)[0]
        return list(mission.progress.get("logs", ()))

    def _load(self, mission_id: str) -> Mission:
        mission = self.runtime.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        return mission


__all__ = ["MissionService"]
