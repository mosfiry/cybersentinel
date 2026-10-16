"""Privacy-preserving projections for local acceptance evidence."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

_SAFE_MACHINE_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{0,127}\Z")
_SAFE_OPAQUE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SAFE_EVENT_TRACE_DATA_FIELDS = frozenset({
    "action_id", "allowed", "authorization_context_id", "blocked_tool_call_ids",
    "budget", "cancelled", "detail_code", "dispatch_attempted", "dispatch_boundary",
    "exit_code", "failure_class", "kind", "mission_id", "name", "outcome",
    "process_id", "process_start_confirmed", "process_started", "process_started_at_utc",
    "reason_code", "recovery", "request_id", "run_id", "sandbox_backend",
    "scope_snapshot_id", "sequence", "status", "step_id", "target_identity",
    "timed_out", "tool_call_id", "turn_id",
})
_ID_FIELDS = frozenset({
    "action_id", "authorization_context_id", "mission_id", "request_id", "run_id",
    "scope_snapshot_id", "step_id", "task_id", "tool_call_id", "turn_id",
})
_CODE_FIELDS = frozenset({
    "class", "detail_code", "dispatch_boundary", "error_type", "event", "failure_class",
    "kind", "name", "outcome", "reason_code", "recovery", "sandbox_backend", "status",
})
_BOOL_FIELDS = frozenset({
    "allowed", "cancelled", "dispatch_attempted", "process_start_confirmed",
    "process_started", "timed_out", "ok", "retryable",
})
_INT_FIELDS = frozenset({"budget", "exit_code", "process_id", "sequence", "attempts", "current_step", "limit"})
_TIMESTAMP_FIELDS = frozenset({"process_started_at_utc", "timestamp_utc"})
_FAILURE_FIELDS = frozenset({
    "action_id", "blocked_tool_call_ids", "class", "detail_code", "dispatch_attempted",
    "error_type", "exit_code", "failure_class", "kind", "outcome", "process_id",
    "process_start_confirmed", "process_started", "reason_code", "recovery", "run_id",
    "sandbox_backend", "status", "step_id", "timed_out", "tool_call_id", "turn_id",
})
_SAFE_MISSION_STATUSES = frozenset({
    "CREATED", "PLANNING", "READY", "RUNNING", "OBSERVING", "VERIFYING", "REPLANNING",
    "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED", "AUTHORIZATION_BLOCKED",
    "SCOPE_BLOCKED", "RESOURCE_BLOCKED", "RECOVERY_REQUIRED", "SAFETY_BLOCKED",
    "FAILED_RETRY_EXHAUSTED", "CANCELLED",
})


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 80:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _safe_record(record: object, *, allowed_fields: frozenset[str] | None = None) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    fields = allowed_fields or _FAILURE_FIELDS
    result: dict[str, Any] = {}
    for key in fields:
        value = record.get(key)
        if key == "blocked_tool_call_ids" and isinstance(value, list):
            result[key] = [item for item in value[:32] if isinstance(item, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(item)]
        elif key in _TIMESTAMP_FIELDS:
            timestamp = _safe_timestamp(value)
            if timestamp:
                result[key] = timestamp
        elif key in _ID_FIELDS and isinstance(value, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(value):
            result[key] = value
        elif key in _CODE_FIELDS and isinstance(value, str) and _SAFE_MACHINE_CODE.fullmatch(value):
            result[key] = value
        elif key in _BOOL_FIELDS and type(value) is bool:
            result[key] = value
        elif key in _INT_FIELDS and type(value) is int and -1_000_000_000 <= value <= 2_147_483_647:
            result[key] = value
    return result


def safe_mission_event_trace(timeline: object, *, limit: int = 2_000) -> tuple[list[dict], bool]:
    """Keep ordered event metadata and a raw-data digest without serializing free-form payloads."""
    if not isinstance(timeline, list):
        return [], False
    trace: list[dict] = []
    for index, event in enumerate(timeline[:limit]):
        if not isinstance(event, dict):
            trace.append({"timeline_index": index, "sequence": index, "event": "<invalid_event>"})
            continue
        event_name = event.get("event")
        data = event.get("data")
        item: dict[str, object] = {
            "timeline_index": index,
            "sequence": event.get("sequence") if type(event.get("sequence")) is int else index,
            "event": event_name if isinstance(event_name, str) and _SAFE_MACHINE_CODE.fullmatch(event_name) else "<invalid_event>",
        }
        for key in ("mission_id", "request_id", "step_id", "task_id"):
            value = event.get(key)
            if isinstance(value, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(value):
                item[key] = value
        timestamp_value = next((
            event.get(key) for key in ("timestamp", "created_at_utc", "created_at", "occurred_at")
            if isinstance(event.get(key), str)
        ), None)
        timestamp = _safe_timestamp(timestamp_value)
        if timestamp:
            item["timestamp_utc"] = timestamp
        for hash_key in ("event_hash", "previous_hash"):
            value = event.get(hash_key)
            if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
                item[hash_key] = value.lower()
        if isinstance(data, dict):
            safe_data: dict[str, object] = {}
            for key in _SAFE_EVENT_TRACE_DATA_FIELDS:
                value = data.get(key)
                if key == "blocked_tool_call_ids" and isinstance(value, list):
                    safe_data[key] = [entry for entry in value[:32] if isinstance(entry, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(entry)]
                elif key == "process_started_at_utc":
                    parsed_timestamp = _safe_timestamp(value)
                    if parsed_timestamp:
                        safe_data[key] = parsed_timestamp
                elif key in _ID_FIELDS and isinstance(value, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(value):
                    safe_data[key] = value
                elif isinstance(value, str) and _SAFE_MACHINE_CODE.fullmatch(value):
                    safe_data[key] = value
                elif type(value) is bool:
                    safe_data[key] = value
                elif type(value) is int and -1_000_000_000 <= value <= 2_147_483_647:
                    safe_data[key] = value
            item["data"] = safe_data
            item["raw_data_available"] = True
            item["raw_data_sha256"] = _canonical_sha256(data)
        elif data is not None:
            item["raw_data_available"] = True
            item["raw_data_sha256"] = _canonical_sha256(data)
        else:
            item["raw_data_available"] = False
        trace.append(item)
    return trace, len(timeline) > limit


def _safe_tool_results(progress: object) -> tuple[list[dict], str]:
    if not isinstance(progress, dict):
        return [], "none"
    model_loop = progress.get("model_loop")
    model_results = model_loop.get("tool_results") if isinstance(model_loop, dict) else None
    top_results = progress.get("tool_results")
    if isinstance(model_results, list) and model_results:
        results, source = model_results, "model_loop"
    elif isinstance(top_results, list):
        results, source = top_results, "top_level"
    else:
        return [], "none"
    summary: list[dict] = []
    for record in results[:50]:
        if not isinstance(record, dict):
            continue
        item: dict[str, Any] = {}
        name = record.get("name")
        if isinstance(name, str) and _SAFE_MACHINE_CODE.fullmatch(name):
            item["name"] = name
        for key in ("tool_call_id", "action_id"):
            value = record.get(key)
            if isinstance(value, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(value):
                item[key] = value
        if type(record.get("ok")) is bool:
            item["ok"] = record["ok"]
        error = record.get("error")
        if isinstance(error, str) and _SAFE_MACHINE_CODE.fullmatch(error):
            item["error_code"] = error
        result = record.get("result")
        if isinstance(result, dict):
            item.update(_safe_record(result, allowed_fields=frozenset({
                "dispatch_attempted", "exit_code", "outcome", "process_id", "process_start_confirmed",
                "process_started", "process_started_at_utc", "reason_code", "sandbox_backend", "timed_out",
            })))
            result_error = result.get("error")
            if isinstance(result_error, str) and _SAFE_MACHINE_CODE.fullmatch(result_error):
                item["error_code"] = result_error
        if item:
            summary.append(item)
    return summary, source


def safe_mission_failure_snapshot(mission: object) -> dict[str, Any]:
    """Return a bounded failure snapshot; never serialize owner text or raw tool output."""
    if mission is None:
        return {}
    trajectory = getattr(mission, "trajectory", [])
    trajectory = trajectory if isinstance(trajectory, list) else []
    trace, truncated = safe_mission_event_trace(trajectory)
    try:
        from agent.trajectory import verify_trajectory
        trajectory_valid = verify_trajectory(trajectory)
    except Exception:
        trajectory_valid = False
    status = getattr(mission, "status", None)
    status = getattr(status, "value", status)
    status = status if isinstance(status, str) and status in _SAFE_MISSION_STATUSES else "UNKNOWN"
    mission_id = getattr(mission, "mission_id", None)
    request_id = getattr(mission, "request_id", None)
    plan = getattr(mission, "plan", None)
    steps = getattr(plan, "steps", [])
    steps = steps if isinstance(steps, (list, tuple)) else []
    current_step = getattr(mission, "current_step", None)
    current_step = current_step if type(current_step) is int and 0 <= current_step <= 1_000_000 else None
    evidence = getattr(mission, "evidence", [])
    evidence = evidence if isinstance(evidence, list) else []
    action_history = getattr(mission, "action_history", [])
    action_history = action_history if isinstance(action_history, list) else []
    failures = getattr(mission, "failures", [])
    failures = failures if isinstance(failures, list) else []
    checkpoint = getattr(mission, "checkpoint", {})
    progress = getattr(mission, "progress", {})
    tool_results, tool_results_source = _safe_tool_results(progress)
    try:
        integrity_valid = bool(mission.verify_integrity())
    except Exception:
        integrity_valid = False
    safe_mission_id = mission_id if isinstance(mission_id, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(mission_id) else None
    safe_request_id = request_id if isinstance(request_id, str) and _SAFE_OPAQUE_IDENTIFIER.fullmatch(request_id) else None
    return {
        "mission_id": safe_mission_id,
        "request_id": safe_request_id,
        "status_final": status,
        "current_step": current_step,
        "plan_step_count": len(steps),
        "mission_integrity_verified": integrity_valid,
        "trajectory_event_count": len(trajectory),
        "trajectory_sha256": _canonical_sha256(trajectory),
        "trajectory_integrity_verified": trajectory_valid,
        "trajectory_event_trace": trace,
        "trajectory_event_trace_truncated": truncated,
        "evidence_item_count": len(evidence),
        "evidence_sha256": _canonical_sha256(evidence),
        "action_history_count": len(action_history),
        "action_history_sha256": _canonical_sha256(action_history),
        "failure_diagnostics": [_safe_record(item) for item in failures[-5:] if isinstance(item, dict)],
        "checkpoint_diagnostics": _safe_record(checkpoint),
        "tool_result_diagnostics": tool_results,
        "tool_results_source": tool_results_source,
    }


def safe_acceptance_error(exc: BaseException) -> str:
    """Preserve only a machine-readable static error code; redact arbitrary exception text."""
    text = str(exc)
    if _SAFE_MACHINE_CODE.fullmatch(text):
        return text
    prefix = "integrated_mission_did_not_reach_goal_completed:"
    if text.startswith(prefix) and text[len(prefix):] in _SAFE_MISSION_STATUSES:
        return text
    return "failure_details_omitted_for_secret_safety"
