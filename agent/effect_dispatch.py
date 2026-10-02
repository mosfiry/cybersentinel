from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, NoReturn

from .effect_intent import ExternalEffectIntent
from .mission import Mission


@dataclass(frozen=True)
class EffectDispatchReceipt:
    """A handler result whose intent and mission evidence were durably confirmed."""

    intent: ExternalEffectIntent
    observation: dict[str, Any]


class EffectOutcomeUnknownError(RuntimeError):
    """The handler may have started, but a trusted result could not be committed."""


class MissionEffectDispatcher:
    """Enforce the M2.d effect-intent protocol around a real local tool handler.

    This gate is attached only to a MissionRuntime running under MissionWorker's
    claim-bound MissionStore facade. The PREPARED and DISPATCHING writes are
    committed before ``handler`` is invoked; all outcomes after entering the
    handler are either atomically confirmed or conservatively marked UNKNOWN.
    """

    def __init__(self, store: Any):
        self.store = store

    def dispatch(
        self,
        mission: Mission,
        *,
        logical_action_id: str,
        tool_id: str,
        payload: Any,
        handler: Callable[[], Any],
        action_id: str | None = None,
        step_id: str | None = None,
        result_factory: Callable[[Any], dict[str, Any]] | None = None,
    ) -> EffectDispatchReceipt:
        intents = self.store.effect_intents
        intent = intents.prepare(
            mission,
            logical_action_id=logical_action_id,
            tool_id=tool_id,
            payload=payload,
        )
        # If this fenced commit fails, handler is never entered.
        intents.mark_dispatching(mission, intent.effect_id)

        try:
            raw_result = handler()
            observation = result_factory(raw_result) if result_factory else dict(raw_result or {})
            if not isinstance(observation, dict):
                raise TypeError("effect handler must return a JSON object")
        except Exception as exc:
            self._mark_unknown_or_raise(mission, intent.effect_id, exc)
            raise AssertionError("unreachable")

        try:
            confirmed = intents.confirm(
                mission,
                intent.effect_id,
                observation,
                action_id=action_id or logical_action_id,
                step_id=step_id,
            )
        except Exception as exc:
            # The side effect may already have happened. Prefer a durable UNKNOWN;
            # if persistence or fencing fails, leave DISPATCHING for next-claim recovery.
            self._mark_unknown_or_raise(mission, intent.effect_id, exc)
            raise AssertionError("unreachable")
        return EffectDispatchReceipt(confirmed, dict(observation))

    def _mark_unknown_or_raise(self, mission: Mission, effect_id: str, cause: Exception) -> NoReturn:
        from .mission_worker import LeaseLostError

        reason = f"effect outcome could not be durably confirmed after handler entry: {type(cause).__name__}"
        try:
            self.store.effect_intents.mark_unknown(mission, effect_id, reason=reason)
        except LeaseLostError:
            # A stale worker must not persist even an UNKNOWN result after reclaim.
            raise
        except Exception:
            # Keep the committed DISPATCHING row as the durable recovery signal.
            raise cause
        raise EffectOutcomeUnknownError(reason) from cause


__all__ = ["EffectDispatchReceipt", "EffectOutcomeUnknownError", "MissionEffectDispatcher"]
