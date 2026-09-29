from __future__ import annotations

"""CyberSentinel's orchestration layer; authority remains in AgentCore/runtime."""

from typing import Any

from .model_orchestrator import ModelOrchestrator, PREFERENCES


class CyberSentinelMind:
    """Coordinates chat-to-Mission flow and capability-routed inference only.

    This class does not authenticate, authorize, execute tools, mint evidence, or
    validate mission completion. The caller authenticates the Owner and AgentCore
    remains the only path to the existing deterministic MissionRuntime controls.
    """

    def __init__(self, router: Any, *, preference: str = "balanced", policy_max_models: int | None = None):
        if preference not in PREFERENCES:
            raise ValueError("invalid_model_preference")
        self.router = router
        self.preference = preference
        self.policy_max_models = policy_max_models

    def orchestrate(
        self,
        *,
        router: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        objective: str,
        request_id: str,
        mission_id: str,
        task_id: str,
        context_hash: str,
        context_provenance: list[dict[str, Any]],
        preference: str | None = None,
        verified_evidence_ids: tuple[str, ...] = (),
        require_tool_calling: bool = False,
    ) -> dict[str, Any]:
        selected_preference = preference or self.preference
        if selected_preference not in PREFERENCES:
            raise ValueError("invalid_model_preference")
        return ModelOrchestrator(
            router,
            policy_max_models=self.policy_max_models,
        ).orchestrate(
            messages,
            tools,
            objective=objective,
            request_id=request_id,
            mission_id=mission_id,
            task_id=task_id,
            context_hash=context_hash,
            context_provenance=context_provenance,
            preference=selected_preference,
            verified_evidence_ids=verified_evidence_ids,
            require_tool_calling=require_tool_calling,
        )

    def chat(
        self,
        *,
        core: Any,
        payload: dict[str, Any],
        text: str,
        owner_session_token: str,
        owner_id: str,
        conversation_id: str,
        run_mission: bool = True,
    ) -> Any:
        """Route one authenticated chat turn to a new or resumed durable Mission."""
        from api.models import requested_model_id, requested_model_preference

        profile_id = requested_model_id(payload, default=None)
        mission_id = str(payload.get("mission_id") or "").strip()
        preference_default = "balanced"
        if mission_id:
            existing = core.store.load_for_owner(mission_id, owner_id)
            if existing is None:
                raise KeyError("unknown_mission")
            preference_default = str((existing.model_selection or {}).get("preference") or "balanced")
        preference = requested_model_preference(payload, default=preference_default)
        if profile_id is not None and "model_preference" in payload:
            raise ValueError("model_id_and_preference_are_mutually_exclusive")
        self.preference = preference or preference_default
        core.mind = self
        core.model_preference = self.preference
        if mission_id:
            return core.resume_mission(
                mission_id,
                owner_session_token=owner_session_token,
                model_id=profile_id,
                model_preference=preference if "model_preference" in payload else None,
                run=run_mission,
            )
        return core.run_owner_mission(
            text,
            owner_session_token=owner_session_token,
            request_id=str(payload.get("request_id") or "") or None,
            scope_context=payload.get("scope_context"),
            completion_criteria=payload.get("completion_criteria"),
            model_id=profile_id if profile_id is not None else "auto",
            model_preference=self.preference,
            conversation_id=conversation_id,
            run=run_mission,
        )


__all__ = ["CyberSentinelMind"]
