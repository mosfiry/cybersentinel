"""Privacy-preserving projections for local acceptance evidence."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

_SAFE_OPAQUE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SECRET_SHAPE_PATTERNS = (
    re.compile(r"(?i)(?:^|[^a-z0-9])(?:sk|rk|pk|ghp|gho|ghu|ghs|github_pat|xox[baprs]|AIza|AKIA|ASIA|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|bearer)[_-][A-Za-z0-9._~+-]{6,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_SAFE_EVENT_NAMES = frozenset({
    "MissionStarted", "PlanCreated", "PlanRevised", "StepSelected", "ToolProposed",
    "AuthorizationChecked", "ToolExecuted", "ObservationReceived", "ObservationInterpreted",
    "EvidenceAdded", "HypothesisUpdated", "StrategyDecided", "FailureDetected", "FailureDiagnosed",
    "RecoveryAttempted", "ReplanTriggered", "OwnerInputRequired", "GoalVerificationStarted",
    "GoalVerified", "MissionCompleted", "FinalReportApproved", "RecoveryRequired", "ModelTurn",
    "MissionCreated", "TaskStarted", "TaskCompleted", "AgentStarted", "AgentCompleted", "ToolCalled",
    "EvidenceCreated", "FindingCreated", "SkillUsed", "SkillLearned", "ProviderChanged",
    "RuntimeStarted", "RuntimeStopped", "MissionPaused", "MissionResumed", "HookInvoked", "HookBlocked",
    "HookFailed", "ProcessStarted",
})
_SAFE_TOOL_NAMES = frozenset({
    "status", "latest_intel", "refresh_intel", "local_security_check", "local_system_info", "search",
    "watch", "unwatch", "run_project_tests", "red_team_assess", "scoped_http_probe", "browser",
    "browser.fill", "web_research", "mcp.discover", "mcp.invoke",
})
_SAFE_REASON_CODES = frozenset({
    "authorization_expired", "authorization_refused", "backend_unavailable", "bubblewrap_missing",
    "command_nonzero_exit", "cgroup_memory_limit", "cgroup_process_count_limit", "cgroup_scope_missing",
    "cgroup_scope_setup_failed", "cpu_time_limit",
    "file_size_limit", "memory_max", "memory_oom_group_kill", "pids_max", "process_limit",
    "process_cancelled", "process_exit_zero", "process_timeout", "prlimit_missing",
    "sandbox_command_start_unconfirmed", "sandbox_launcher_failed", "sandbox_setup_failed",
    "process_sandbox_unavailable", "process_sandbox_setup_failed", "process_authorization_refused",
    "process_start_not_authorized", "process_cancelled_before_start",
    "windows_appcontainer_backend_unimplemented", "working_directory_fd_unavailable",
    "working_directory_unavailable", "workspace_fd_unavailable", "workspace_root_unavailable",
    "AUTHENTICATION_FAILURE", "AUTHORIZATION_REFUSED", "CANCELLED_BEFORE_DISPATCH", "DISPATCH_CANCELLED",
    "EFFECT_ALREADY_SUCCEEDED", "HANDLER_EXCEPTION", "INVALID_PROVIDER_PROOF", "NO_EFFECT_ALREADY_CONFIRMED",
    "NO_EFFECT_CONFIRMED_RETRY_POLICY", "OWNER_CANCELLED_BEFORE_DISPATCH", "OWNER_CONFIRMED_APPLIED",
    "OWNER_CONFIRMED_NO_EFFECT", "OWNER_CONFIRM_APPLIED", "OWNER_CONFIRM_NO_EFFECT",
    "PROCESS_AUTHORIZATION_REFUSED", "PROCESS_CANCELLED_BEFORE_START", "PROCESS_SANDBOX_SETUP_FAILED",
    "PROCESS_SANDBOX_UNAVAILABLE", "PROCESS_START_NOT_AUTHORIZED", "PROVIDER_DISPATCH_NOT_STARTED",
    "PROVIDER_FAILURE", "PROVIDER_LOOKUP_FAILED", "PROVIDER_SAYS_FAILED", "PROVIDER_STATUS_LOOKUP_UNAVAILABLE",
    "REMOTE_TOOL_ERROR", "REQUEST_REJECTED", "RESOURCE_LIMIT_EXCEEDED", "RESULT_BOUNDARY_FAILED",
    "SANDBOX_LAUNCH_FAILED", "STATUS_LOOKUP_UNAVAILABLE", "STATUS_UNAVAILABLE", "TOOL_TIMEOUT",
    "TOOL_TIMEOUT_BEFORE_PROCESS_START", "UNAUTHORIZED_TOOL", "UNKNOWN", "completed_tool_sequence_exceeds_limit",
    "invalid_credentials",
    "completed_tool_sequence_not_fully_evidenced", "completion_trajectory_not_qualified", "no_completed_tool_steps",
    "ready_for_owner_authored_candidate", "fenced_evidence_unavailable", "mission_not_terminal",
    "mission_not_verified", "mission_cancelled", "mission_failed", "owner_intervention_required",
    "mission_not_successfully_verified", "repeated_read_only_tool_call",
})
_SAFE_OUTCOMES = frozenset({
    "SUCCEEDED", "COMMAND_FAILED", "TIMED_OUT", "CANCELLED", "RESOURCE_LIMIT_EXCEEDED",
    "VERIFIED", "NOT_VERIFIED", "PARTIALLY_VERIFIED", "in_progress", "verified_success",
    "unverified_completion", "cancelled", "failed", "blocked", "owner_intervention",
})
_SAFE_STATUSES = frozenset({
    "CREATED", "PLANNING", "READY", "RUNNING", "OBSERVING", "VERIFYING", "REPLANNING",
    "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED", "AUTHORIZATION_BLOCKED",
    "SCOPE_BLOCKED", "RESOURCE_BLOCKED", "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED",
    "CANCELLED", "IN_PROGRESS", "PASS", "FAIL", "NOT_RUN", "BLOCKED", "queued", "executing",
    "paused", "needs_input", "completed", "failed", "active", "ready", "stopped", "not_dispatched",
    "budget_blocked",
})
_SAFE_FAILURE_CLASSES = frozenset({
    "TRANSIENT", "DEPENDENCY", "COMPILATION", "TEST_FAILURE", "NETWORK", "PROVIDER", "TOOL",
    "AUTHORIZATION", "SCOPE", "RESOURCE", "LOGIC", "UNKNOWN",
})
_SAFE_RECOVERY_CODES = frozenset({
    "RETRY", "REPLAN", "OWNER_INPUT_REQUIRED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED", "FAIL",
    "recovery_required", "recovery_attempted", "no_retry", "retryable", "not_retryable",
})
_SAFE_DETAIL_CODES = frozenset({
    "windows_appcontainer_backend_unimplemented", "backend_unavailable", "bubblewrap_missing",
    "prlimit_missing", "cgroup_scope_missing", "cgroup_scope_setup_failed", "sandbox_setup_failed",
    "cgroup_resource_event_attribution_unavailable", "sandbox_process_tree_cleanup_unverified",
    "working_directory_unavailable", "workspace_root_unavailable", "process_start_unconfirmed",
    "unclassified_model_manager_error",
})
_SAFE_ERROR_TYPES = frozenset({
    "Exception", "RuntimeError", "TimeoutError", "ValueError", "TypeError", "KeyError", "IndexError",
    "OSError", "PermissionError", "FileNotFoundError", "IsADirectoryError", "NotADirectoryError",
    "ConnectionError", "ConnectionRefusedError", "ConnectionResetError", "HTTPError", "URLError",
    "JSONDecodeError", "AssertionError", "ImportError", "ModuleNotFoundError", "CalledProcessError",
    "ProcessLookupError", "NotImplementedError", "AttributeError", "OverflowError", "UnicodeDecodeError",
})
_SAFE_ACCEPTANCE_STAGES = frozenset({
    "initialize_acceptance", "acceptance_complete", "installed_app_full_mission",
    "invalid_owner_login_renderer_state", "invalid_owner_login_request", "owner_logout_renderer_state",
    "owner_logout_request", "HypothesisUpdated",
})
_SAFE_BUDGET_CODES = frozenset({
    "model_loop_state", "max_execution_steps", "max_execution_time_seconds", "max_context_chars",
    "max_context_messages", "max_total_output_chars", "mission_runtime_seconds", "tool_call_count",
    "model_turn_count", "parallel_task_count",
})
_SAFE_CODE_ALLOWLISTS = {
    "event": _SAFE_EVENT_NAMES,
    "name": _SAFE_TOOL_NAMES,
    "reason_code": _SAFE_REASON_CODES,
    "detail_code": _SAFE_DETAIL_CODES | _SAFE_REASON_CODES,
    "code": _SAFE_REASON_CODES | _SAFE_DETAIL_CODES,
    "kind": _SAFE_REASON_CODES | _SAFE_FAILURE_CLASSES | frozenset({"PROCESS_SANDBOX_UNAVAILABLE", "OWNER_CANCELLATION", "RESOURCE_LIMIT"}),
    "failure_class": _SAFE_FAILURE_CLASSES,
    "class": _SAFE_FAILURE_CLASSES | frozenset({"authorization", "scope", "resource", "tool", "provider", "dependency", "transient", "logic"}),
    "outcome": _SAFE_OUTCOMES,
    "status": _SAFE_STATUSES,
    "recovery": _SAFE_RECOVERY_CODES,
    "budget": _SAFE_BUDGET_CODES,
    "resource_limit_reason": frozenset({
        "cgroup_memory_limit", "cgroup_process_count_limit", "memory_max", "memory_oom_group_kill",
        "pids_max", "cpu_time_limit", "file_size_limit", "process_limit", "resource_limit_signal",
    }),
    "sandbox_backend": frozenset({"bubblewrap+prlimit+cgroup-v2", "windows-appcontainer-job", "unsupported"}),
    "dispatch_boundary": frozenset({"workspace_process_start", "scope_pinned_http_send", "none"}),
    "error_type": _SAFE_ERROR_TYPES,
    "error_code": _SAFE_REASON_CODES | _SAFE_DETAIL_CODES,
    "stage": _SAFE_ACCEPTANCE_STAGES,
}


def safe_opaque_identifier(value: object) -> str | None:
    if not isinstance(value, str) or not _SAFE_OPAQUE_IDENTIFIER.fullmatch(value):
        return None
    if any(pattern.search(value) for pattern in _SECRET_SHAPE_PATTERNS):
        return None
    return value


def safe_static_code(field: str, value: object) -> str | None:
    allowed = _SAFE_CODE_ALLOWLISTS.get(field)
    return value if isinstance(value, str) and allowed is not None and value in allowed else None


def safe_exception_type(exc_or_name: BaseException | str) -> str:
    name = type(exc_or_name).__name__ if isinstance(exc_or_name, BaseException) else exc_or_name
    return name if isinstance(name, str) and name in _SAFE_ERROR_TYPES else "UnknownError"
_SAFE_EVENT_TRACE_DATA_FIELDS = frozenset({
    "action_id", "allowed", "authorization_context_id", "blocked_tool_call_ids",
    "budget", "cancelled", "detail_code", "dispatch_attempted", "dispatch_boundary",
    "exit_code", "failure_class", "kind", "mission_id", "name", "outcome",
    "process_id", "process_start_confirmed", "process_started", "process_started_at_utc",
    "limit", "reason_code", "resource_limit_reason", "recovery", "request_id", "run_id", "sandbox_backend",
    "scope_snapshot_id", "sequence", "status", "step_id", "target_identity",
    "started_at_utc", "timed_out", "tool_call_id", "turn_id",
})
_ID_FIELDS = frozenset({
    "action_id", "authorization_context_id", "mission_id", "request_id", "run_id",
    "scope_snapshot_id", "step_id", "task_id", "tool_call_id", "turn_id",
})
_CODE_FIELDS = frozenset({
    "budget", "class", "detail_code", "dispatch_boundary", "error_type", "event", "failure_class",
    "kind", "name", "outcome", "reason_code", "resource_limit_reason", "recovery", "sandbox_backend", "status",
})
_BOOL_FIELDS = frozenset({
    "allowed", "cancelled", "dispatch_attempted", "process_start_confirmed",
    "process_started", "timed_out", "ok", "retryable",
})
_INT_FIELDS = frozenset({"budget", "exit_code", "process_id", "sequence", "attempts", "current_step", "limit"})
_TIMESTAMP_FIELDS = frozenset({"process_started_at_utc", "started_at_utc", "timestamp_utc"})
_FAILURE_FIELDS = frozenset({
    "action_id", "blocked_tool_call_ids", "budget", "class", "detail_code", "dispatch_attempted",
    "error_type", "exit_code", "failure_class", "kind", "limit", "outcome", "process_id",
    "process_start_confirmed", "process_started", "reason_code", "resource_limit_reason", "recovery", "run_id",
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
            result[key] = [safe_id for item in value[:32] if (safe_id := safe_opaque_identifier(item)) is not None]
        elif key in _TIMESTAMP_FIELDS:
            timestamp = _safe_timestamp(value)
            if timestamp:
                result[key] = timestamp
        elif key in _ID_FIELDS and (safe_id := safe_opaque_identifier(value)) is not None:
            result[key] = safe_id
        elif key in _CODE_FIELDS and (safe_code := safe_static_code(key, value)) is not None:
            result[key] = safe_code
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
            "event": safe_static_code("event", event_name) or "<invalid_event>",
        }
        for key in ("mission_id", "request_id", "step_id", "task_id"):
            safe_id = safe_opaque_identifier(event.get(key))
            if safe_id is not None:
                item[key] = safe_id
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
                    safe_data[key] = [safe_id for entry in value[:32] if (safe_id := safe_opaque_identifier(entry)) is not None]
                elif key in {"process_started_at_utc", "started_at_utc"}:
                    parsed_timestamp = _safe_timestamp(value)
                    if parsed_timestamp:
                        safe_data[key] = parsed_timestamp
                elif key in _ID_FIELDS and (safe_id := safe_opaque_identifier(value)) is not None:
                    safe_data[key] = safe_id
                elif key in _CODE_FIELDS and (safe_code := safe_static_code(key, value)) is not None:
                    safe_data[key] = safe_code
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
        name = safe_static_code("name", record.get("name"))
        if name is not None:
            item["name"] = name
        for key in ("tool_call_id", "action_id"):
            safe_id = safe_opaque_identifier(record.get(key))
            if safe_id is not None:
                item[key] = safe_id
        if type(record.get("ok")) is bool:
            item["ok"] = record["ok"]
        error_code = safe_static_code("error_code", record.get("error"))
        if error_code is not None:
            item["error_code"] = error_code
        result = record.get("result")
        if isinstance(result, dict):
            item.update(_safe_record(result, allowed_fields=frozenset({
                "dispatch_attempted", "exit_code", "outcome", "process_id", "process_start_confirmed",
                "process_started", "process_started_at_utc", "reason_code", "resource_limit_reason",
                "sandbox_backend", "timed_out",
            })))
            result_error = safe_static_code("error_code", result.get("error"))
            if result_error is not None:
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
    safe_mission_id = safe_opaque_identifier(mission_id)
    safe_request_id = safe_opaque_identifier(request_id)
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
    prefix = "integrated_mission_did_not_reach_goal_completed:"
    if text.startswith(prefix) and text[len(prefix):] in _SAFE_MISSION_STATUSES:
        return text
    return "failure_details_omitted_for_secret_safety"
