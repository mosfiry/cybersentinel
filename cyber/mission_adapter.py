"""Mission runtime -> cyber case adapter (integration with Expert 2 scope).

Contract (see docs/MANUS_INTEGRATION_2026-09-22.md):
* READ-ONLY: this adapter consumes runtime artifacts and produces case DATA.
* DEFENSIVE: unknown event shapes are recorded as unknowns, never dropped.
* POISON-IMMUNE: authorization / scope / owner_instruction / identity keys are
  stripped from any event payload before it enters the case. Runtime events
  never grant or restore authority.
"""

from typing import Any, Iterable

from cyber.case_engine import CyberCase, EvidenceStatus, Provenance

_FORBIDDEN_KEYS = ("authorization", "scope", "owner_instruction", "identity", "authorization_context")


def _sanitize(payload: Any) -> Any:
    """Deep-copy a payload minus authority-bearing keys."""
    if isinstance(payload, dict):
        return {
            k: _sanitize(v)
            for k, v in payload.items()
            if k not in _FORBIDDEN_KEYS
        }
    if isinstance(payload, (list, tuple)):
        return [_sanitize(v) for v in payload]
    return payload


def _payload_text(event: dict[str, Any]) -> str:
    safe = _sanitize(event)
    parts = []
    for key in ("observation", "summary", "detail", "details", "tool", "tool_name", "reason", "message"):
        if key in safe and safe[key] is not None:
            parts.append("{}={}".format(key, safe[key]))
    if parts:
        return "; ".join(parts)
    return repr(safe)


def build_case_from_mission(
    mission: Any,
    events: Iterable[Any],
    *,
    source: str = "mission-runtime",
) -> CyberCase:
    """Build a cyber case from a mission object and its event stream.

    Works against the canonical MissionRuntime event vocabulary
    (ModelTurn, ObservationReceived, ObservationInterpreted, HypothesisUpdated,
    StrategyDecided, GoalVerified, ...). Unknown types are recorded as
    unknowns so no runtime signal is silently lost.
    """
    objective = getattr(mission, "objective", None) or getattr(mission, "mission_id", "unknown-mission")
    scope = getattr(mission, "scope", None)
    case = CyberCase(objective=str(objective), scope=str(scope) if scope is not None else None)

    provenance = Provenance(source=source, classification="REAL")

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            case.add_unknown("non-dict runtime event at index {}: {!r}".format(index, event))
            continue
        etype = event.get("type")
        payload = event.get("payload", event)
        if etype in ("ObservationReceived", "ObservationInterpreted"):
            case.add_observation(_payload_text(payload if isinstance(payload, dict) else event), provenance=provenance)
        elif etype == "HypothesisUpdated":
            statement = None
            if isinstance(payload, dict):
                statement = payload.get("statement") or payload.get("hypothesis") or payload.get("note")
            case.add_hypothesis(
                "h-{}".format(index),
                str(statement) if statement else _payload_text(payload if isinstance(payload, dict) else event),
            )
        elif etype == "StrategyDecided":
            decision = payload.get("decision") if isinstance(payload, dict) else None
            if decision in ("REPLAN", "ABORT"):
                case.add_next_action(
                    "strategy decision {} at event {}: review chain and replan".format(decision, index)
                )
        elif etype == "GoalVerified":
            statement = None
            if isinstance(payload, dict):
                statement = payload.get("criterion") or payload.get("summary")
            case.add_evidence(
                "goal verification at event {}: {}".format(index, statement or "goal verified"),
                provenance=provenance,
                status=EvidenceStatus.SUPPORTED,
            )
        elif etype is None:
            case.add_unknown("runtime event without a type at index {}".format(index))
        else:
            # Never silently drop: record that the runtime produced something
            # this layer does not yet understand.
            case.add_unknown("unhandled runtime event type {!r} at index {}".format(etype, index))

    return case
