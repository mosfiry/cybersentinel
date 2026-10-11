#!/usr/bin/env python3
"""Exercise an installed CyberSentinel Desktop window through its local CDP port.

The full mode uses only a disposable Windows runner profile and a generated Owner
password, performs a real Model Manager Qwen3 4B download/activation/inference,
then removes no files itself; the calling PowerShell wrapper owns cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import ProxyHandler, build_opener

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))
from agent.evidence import verify_chain as _verify_evidence_chain
from agent.mission import Mission as _Mission
from agent.reporting import build_mission_report as _build_mission_report
from agent.trajectory import EventType as _TrajectoryEventType, verify_trajectory as _verify_trajectory

# This is only the harness's HTTP-response wait; AgentCore remains bounded by the
# 300-second Owner mission limit, with a 30-second response-finalization margin.
OWNER_MISSION_RUNTIME_LIMIT_SECONDS = 300
OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS = 30
INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS = (
    OWNER_MISSION_RUNTIME_LIMIT_SECONDS + OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS
) * 1000
MODEL_STATE_API_RETRY_DELAY_SECONDS = 2
MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES = 5
MODEL_STATE_API_MAX_TOTAL_FAILURES = 10
QWEN_INSTALL_POST_RESPONSE_TIMEOUT_MS = 15_000
APPLICATION_RESTART_TIMEOUT_SECONDS = 180
APPLICATION_PROCESS_EXIT_TIMEOUT_SECONDS = 30
MODEL_RESTORE_TIMEOUT_SECONDS = 600
EXPECTED_QWEN3_4B_INSTALL_IDENTITY = {
    "model_id": "qwen3-4b-q4-k-m",
    "display_name": "Qwen3 4B",
    "repository": "unsloth/Qwen3-4B-GGUF",
    "revision": "22c9fc8a8c7700b76a1789366280a6a5a1ad1120",
    "filename": "Qwen3-4B-Q4_K_M.gguf",
    "size_bytes": 2497281312,
    "sha256": "f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a",
    "quantization": "Q4_K_M",
    "license": "Apache-2.0",
}


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


_SAFE_DIAGNOSTIC_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")


def _safe_failure_reason_code(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if value in {"repeated_read_only_tool_call", "repeated read-only tool call"}:
        return "repeated_read_only_tool_call"
    if value == "parallel task result exceeded the durable result bound":
        return "parallel_task_result_exceeded_durable_result_bound"
    if value.startswith("mission runtime budget exceeded: "):
        return "mission_runtime_budget_exceeded"
    return None


def _verify_durable_execution_chain(records: object) -> bool:
    if not isinstance(records, list) or not records:
        return False
    try:
        return _verify_evidence_chain(records)
    except Exception:
        return False


def _durable_tool_result_records(mission_state: dict) -> tuple[list, str]:
    progress = mission_state.get("progress")
    if not isinstance(progress, dict):
        return [], "unavailable"
    model_loop = progress.get("model_loop")
    candidates: list[tuple[str, object]] = []
    if isinstance(model_loop, dict) and "tool_results" in model_loop:
        candidates.append(("model_loop", model_loop["tool_results"]))
    elif "model_loop" in progress and model_loop is not None:
        candidates.append(("model_loop", None))
    if "tool_results" in progress:
        candidates.append(("top_level", progress["tool_results"]))

    result_lists: dict[str, list] = {}
    invalid_sources: list[str] = []
    for candidate_source, candidate in candidates:
        if isinstance(candidate, list):
            result_lists[candidate_source] = candidate
        else:
            invalid_sources.append(candidate_source)

    nested_results = result_lists.get("model_loop", [])
    top_level_results = result_lists.get("top_level", [])
    raw_results = list(nested_results)
    consumed_nested_mirrors: set[int] = set()
    for item in top_level_results:
        mirrored_index = None
        call_id = item.get("tool_call_id") if isinstance(item, dict) else None
        if isinstance(call_id, str) and call_id:
            mirrored_index = next((
                index for index, nested_item in enumerate(nested_results)
                if index not in consumed_nested_mirrors
                and isinstance(nested_item, dict)
                and nested_item.get("tool_call_id") == call_id
                and nested_item == item
            ), None)
        if mirrored_index is not None:
            consumed_nested_mirrors.add(mirrored_index)
            continue
        raw_results.append(item)

    raw_results.extend(None for _ in invalid_sources)
    populated_sources = [
        name for name, records in result_lists.items() if records
    ]
    if populated_sources:
        source = "+".join(populated_sources)
    elif result_lists:
        source = "empty"
    elif invalid_sources:
        source = "invalid"
    else:
        source = "unavailable"
    if invalid_sources and populated_sources:
        source += "+invalid"
    return raw_results, source


def _safe_tool_result_summary(mission_state: dict) -> tuple[list[dict], str]:
    raw_results, source = _durable_tool_result_records(mission_state)

    summary = []
    for item in raw_results:
        if not isinstance(item, dict):
            summary.append({"name": "<invalid_action_name>", "ok": None})
            continue
        raw_name = item.get("name")
        name = raw_name if isinstance(raw_name, str) and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(raw_name) else "<invalid_action_name>"
        safe_item = {"name": name, "ok": item.get("ok") if isinstance(item.get("ok"), bool) else None}
        call_id = item.get("tool_call_id")
        if isinstance(call_id, str) and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(call_id):
            safe_item["tool_call_id"] = call_id
        error_code = _safe_failure_reason_code(item.get("error"))
        if error_code:
            safe_item["error_code"] = error_code
        result = item.get("result")
        if isinstance(result, dict):
            for key in ("failure_class", "reason_code", "code", "kind"):
                value = result.get(key)
                if isinstance(value, str) and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(value):
                    safe_item[key] = value
            exception_type = result.get("exception")
            if isinstance(exception_type, str) and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(exception_type):
                safe_item["exception_type"] = exception_type
        summary.append(safe_item)
    return summary, source


def _safe_failure_diagnostics(mission_state: dict) -> list[dict]:
    failures = mission_state.get("failures")
    if not isinstance(failures, list):
        return []
    plan = mission_state.get("plan")
    steps = plan.get("steps") if isinstance(plan, dict) else None
    step_actions = {}
    if isinstance(steps, list):
        for index, step in enumerate(steps[:100], start=1):
            if not isinstance(step, dict):
                continue
            step_id = step.get("step_id")
            action = step.get("action")
            if isinstance(step_id, str) and step_id and isinstance(action, str) and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(action):
                step_actions[step_id] = (index, action)
    summary = []
    for failure in failures[-5:]:
        if not isinstance(failure, dict):
            continue
        item = {
            key: value
            for key in ("class", "budget", "kind", "reason_code", "recovery")
            if isinstance((value := failure.get(key)), str)
            and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(value)
        }
        limit = failure.get("limit")
        if isinstance(limit, int) and not isinstance(limit, bool) and 0 <= limit <= 1_000_000_000:
            item["limit"] = limit
        reason_code = _safe_failure_reason_code(failure.get("reason"))
        if reason_code:
            item.setdefault("reason_code", reason_code)
        step_info = step_actions.get(failure.get("step_id"))
        if step_info:
            item["plan_step_index"], item["step_action"] = step_info
        if item:
            summary.append(item)
    return summary


def _safe_exception_diagnostics(exc: BaseException) -> dict[str, str]:
    """Omit exception text because it may contain credentials or submitted form data."""
    return {
        "error_type": type(exc).__name__,
        "error": "failure details omitted for secret safety",
    }


def _safe_checkpoint_diagnostics(mission_state: dict) -> dict:
    checkpoint = mission_state.get("checkpoint")
    if not isinstance(checkpoint, dict):
        return {}
    summary = {
        key: value
        for key in ("status", "budget", "reason_code", "recovery")
        if isinstance((value := checkpoint.get(key)), str)
        and _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(value)
    }
    limit = checkpoint.get("limit")
    if isinstance(limit, int) and not isinstance(limit, bool) and 0 <= limit <= 1_000_000_000:
        summary["limit"] = limit
    return summary


def _tools_within_authorized_allowlist(tool_summary: list[dict], allowed_tools: object) -> bool:
    if not tool_summary or not isinstance(allowed_tools, list):
        return False
    return all(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item.get("name") != "<invalid_action_name>"
        and item.get("name") in allowed_tools
        for item in tool_summary
    )


def _local_health_status(page) -> int | None:
    try:
        parsed = urlsplit(str(page.url))
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
            return None
        health_url = f"http://127.0.0.1:{parsed.port}/api/public/health"
        opener = build_opener(ProxyHandler({}))
        with opener.open(health_url, timeout=2) as response:
            return int(response.status)
    except HTTPError as exc:
        return int(exc.code)
    except Exception:
        return None


def _model_state(page) -> dict:
    result = page.evaluate("""async () => {
      const response = await fetch('/api/public/desktop/models', {credentials: 'include'});
      const data = await response.json().catch(() => ({}));
      return {http_status: response.status, data};
    }""")
    if not isinstance(result, dict) or result.get("http_status") != 200:
        raise RuntimeError("desktop_model_manager_api_unavailable")
    return result.get("data", {})


def _find_qwen(state: dict) -> dict | None:
    models = state.get("models") if isinstance(state, dict) else None
    if not isinstance(models, list):
        return None
    return next((item for item in models if isinstance(item, dict)
                 and "qwen3" in str(item.get("model_id", "")).casefold()
                 and "4b" in str(item.get("model_id", "")).casefold()), None)


def _refresh_qwen_model_snapshot(report: dict, state: dict, *, phase: str) -> dict | None:
    qwen = _find_qwen(state)
    model_manager = report.setdefault("model_manager", {})
    if not isinstance(model_manager, dict):
        model_manager = {}
        report["model_manager"] = model_manager
    model_manager["qwen3_4b_present"] = qwen is not None
    model_manager["qwen3_4b_snapshot_phase"] = phase
    model_manager["qwen3_4b"] = ({
        "model_id": qwen.get("model_id"),
        "display_name": qwen.get("display_name"),
        "family": qwen.get("family"),
        "parameter_size": qwen.get("parameter_size"),
        "repository": qwen.get("repository"),
        "revision": qwen.get("revision"),
        "filename": qwen.get("filename"),
        "quantization": qwen.get("quantization"),
        "size_bytes": qwen.get("size_bytes"),
        "sha256": qwen.get("sha256"),
        "compatible": qwen.get("compatible"),
        "recommended": qwen.get("recommended"),
        "installed": qwen.get("installed"),
        "installed_sha256": qwen.get("installed_sha256") if qwen.get("installed") is True else None,
        "selected": qwen.get("selected"),
        "active": qwen.get("active"),
    } if qwen else None)
    return qwen


def _qwen_installed_digest_report(model: dict | None) -> dict:
    catalog_sha256 = model.get("sha256") if isinstance(model, dict) else None
    installed_sha256 = model.get("installed_sha256") if isinstance(model, dict) else None
    pinned_sha256 = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]
    installed = isinstance(model, dict) and model.get("installed") is True
    matches_catalog = isinstance(installed_sha256, str) and installed_sha256 == catalog_sha256
    matches_pinned = isinstance(installed_sha256, str) and installed_sha256 == pinned_sha256
    return {
        "installed": installed,
        "catalog_sha256": catalog_sha256,
        "pinned_sha256": pinned_sha256,
        "installed_sha256": installed_sha256 if isinstance(installed_sha256, str) else None,
        "matches_catalog": matches_catalog,
        "matches_pinned": matches_pinned,
        "verified": installed and matches_catalog and matches_pinned,
    }


def _require_qwen_installed_digest(digest_report: dict) -> None:
    if digest_report.get("verified") is not True:
        raise RuntimeError("qwen3_4b_installed_digest_missing_or_mismatched")


def _format_consent_bytes(value: int) -> str:
    size = max(0, float(value))
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    precision = 1 if unit >= 2 else 0
    return f"{size:.{precision}f} {units[unit]}"


def _build_expected_qwen_install_consent(model: object) -> str | None:
    if not isinstance(model, dict) or any(
        model.get(key) != value for key, value in EXPECTED_QWEN3_4B_INSTALL_IDENTITY.items()
    ):
        return None
    return (
        "تنزيل هذا الملف إلى جهازك؟\n\n"
        f"{model['display_name']} · {model['quantization']}\n"
        f"{model['repository']}@{model['revision']}\n"
        f"{model['filename']} · {_format_consent_bytes(model['size_bytes'])}\n"
        f"الرخصة في بطاقة التحويل: {model['license']}\n"
        f"SHA-256: {model['sha256']}\n\n"
        "سيُستخدم llama.cpp محليًا بعد التحقق. لا يبدأ التنزيل إلا بموافقتك."
    )


def _handle_qwen_install_dialog(
    dialog,
    expected_message: str | None,
    consent: dict,
    *,
    authorize_test_download: bool = False,
) -> None:
    consent["seen"] = True
    consent["authorized"] = authorize_test_download
    if (
        expected_message is None
        or getattr(dialog, "type", "") != "confirm"
        or getattr(dialog, "message", None) != expected_message
    ):
        consent["mismatch"] = True
        dialog.dismiss()
        return
    if not authorize_test_download:
        consent["unauthorized"] = True
        dialog.dismiss()
        return
    dialog.accept()
    consent["accepted"] = True


def _require_qwen_install_consent(consent: dict) -> None:
    if consent.get("authorized") is not True:
        raise RuntimeError("qwen3_4b_test_download_explicit_opt_in_required")
    if not consent.get("seen"):
        raise RuntimeError("qwen3_4b_install_consent_missing")
    if not consent.get("accepted") or consent.get("mismatch"):
        raise RuntimeError("qwen3_4b_install_consent_mismatch")


def _is_qwen_install_post_response(response) -> bool:
    if str(getattr(getattr(response, "request", None), "method", "")).upper() != "POST":
        return False
    path = unquote(urlsplit(str(getattr(response, "url", ""))).path).rstrip("/")
    prefix = "/api/public/desktop/models/"
    suffix = "/install"
    model_id = path[len(prefix):-len(suffix)] if path.startswith(prefix) and path.endswith(suffix) else ""
    return bool(model_id) and "/" not in model_id


def _is_expected_qwen_install_post_request(request, expected_model_id: str, expected_origin: str) -> bool:
    if str(getattr(request, "method", "")).upper() != "POST":
        return False
    parsed = urlsplit(str(getattr(request, "url", "")))
    request_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
    expected_path = f"/api/public/desktop/models/{expected_model_id}/install"
    return request_origin == expected_origin and unquote(parsed.path).rstrip("/") == expected_path


def _may_continue_qwen_install_post(
    request,
    expected_model_id: str,
    expected_origin: str,
    consent: dict,
) -> bool:
    return (
        consent.get("authorized") is True
        and consent.get("seen") is True
        and consent.get("accepted") is True
        and consent.get("mismatch") is not True
        and _is_expected_qwen_install_post_request(request, expected_model_id, expected_origin)
    )


def _validate_qwen_install_post_response(response, expected_model_id: str) -> dict:
    request_method = str(getattr(getattr(response, "request", None), "method", "")).upper()
    response_path = unquote(urlsplit(str(getattr(response, "url", ""))).path).rstrip("/")
    expected_path = f"/api/public/desktop/models/{expected_model_id}/install"
    if request_method != "POST" or response_path != expected_path:
        raise RuntimeError("qwen3_4b_install_post_unexpected_path")
    if getattr(response, "status", None) != 202:
        raise RuntimeError("qwen3_4b_install_post_unexpected_http_status")
    try:
        body = response.json()
    except Exception:
        raise RuntimeError("qwen3_4b_install_post_response_invalid") from None
    if not isinstance(body, dict):
        raise RuntimeError("qwen3_4b_install_post_response_invalid")
    manager = body.get("manager")
    operation = manager.get("operation") if isinstance(manager, dict) else None
    started_statuses = {"downloading", "verifying", "complete", "failed", "interrupted", "cancelling", "cancelled"}
    if (
        not isinstance(operation, dict)
        or operation.get("kind") != "install"
        or operation.get("model_id") != expected_model_id
        or operation.get("status") not in started_statuses
    ):
        raise RuntimeError("qwen3_4b_install_operation_not_started")
    return body


def _new_csrf_token(page) -> str:
    value = page.evaluate("""async () => {
      const response = await fetch('/api/public/session', {method: 'POST', credentials: 'include'});
      const body = await response.json().catch(() => ({}));
      return {status: response.status, csrf_token: body?.session?.csrf_token || ''};
    }""")
    token = value.get("csrf_token", "") if isinstance(value, dict) else ""
    if not isinstance(token, str) or len(token) < 32:
        raise RuntimeError("installed_app_public_csrf_session_unavailable")
    return token


def _public_api(page, method: str, path: str, *, csrf: str = "", payload: dict | None = None) -> dict:
    value = page.evaluate("""async ({method, path, csrf, payload}) => {
      const headers = {};
      if (payload !== null) headers['Content-Type'] = 'application/json';
      if (csrf) headers['X-CSRF-Token'] = csrf;
      const response = await fetch(path, {
        method, credentials: 'include', headers,
        ...(payload === null ? {} : {body: JSON.stringify(payload)})
      });
      const body = await response.json().catch(() => ({}));
      return {http_status: response.status, body};
    }""", {"method": method, "path": path, "csrf": csrf, "payload": payload})
    if not isinstance(value, dict) or not isinstance(value.get("body"), dict):
        raise RuntimeError("installed_app_api_response_invalid")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256(encoded)


_BLOCKED_STATUS_FIELDS = frozenset({
    "status", "mission_status", "outcome", "state", "result", "result_status",
    "verification", "verification_status", "verification_state", "report_verification",
    "report_status", "execution_chain_integrity", "evidence_status", "reason_code",
    "failure_class", "authorization_status", "decision", "error_code", "code",
    "validation_state", "result_validation_state",
})
_UNVERIFIED_STATUS_VALUES = frozenset({
    "UNVERIFIED", "USED_UNVERIFIED", "UNVERIFIED_PROVENANCE",
    "UNVERIFIED_MODEL_PROPOSAL", "UNVERIFIED_EVIDENCE_PROVENANCE",
    "PENDING_VALIDATION", "NOT_VERIFIED", "PARTIALLY_VERIFIED", "UNKNOWN",
    "INVALID", "UNREADABLE", "NOT_PRESENT", "RECOVERY_REQUIRED",
    "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED", "FAILED", "FAILURE",
    "CANCELLED", "INTERRUPTED", "REJECTED", "ERROR",
})
_STATUS_FAILURE_PHRASE_PREFIXES = (_UNVERIFIED_STATUS_VALUES - frozenset({"ERROR"})) | frozenset({
    "BLOCKED", "FAIL", "TOOL_FAILED", "TESTS_FAILED", "ACTION_FAILED",
    "EXECUTION_FAILED", "AUTHORIZATION_DENIED", "SCOPE_DENIED", "ERROR_OCCURRED",
    "ERROR_DETECTED", "ERROR_ENCOUNTERED", "ERROR_DURING", "ERROR_WHILE",
})


def _canonical_report_body_sha256(report: dict) -> str:
    """Reproduce the canonical digest computed before its digest/approval envelope is added."""
    body = dict(report)
    for envelope_field in ("report_sha256", "report_digest_scope", "final_report_approval"):
        body.pop(envelope_field, None)
    return _canonical_sha256(body)


_REPORT_DIGEST_SCOPE = (
    "SHA-256 over canonical sorted compact UTF-8 JSON report content before the digest and approval envelope."
)
_REPORT_APPROVAL_LIMITATION = (
    "Final report approval is a separate Owner decision bound to this report digest; it does not authorize actions or replace action-level approvals."
)
_EVIDENCE_RECEIPT_FIELDS = (
    "mission_id", "task_id", "execution_id", "request_id", "worker_id",
    "worker_instance_id", "runtime_generation", "lease_epoch", "task_version",
    "authorization_hash", "fence_id",
)


def _execution_evidence_receipts_match(
    full_chain: object, mission_state: dict, mission_id: str
) -> bool:
    """Match fenced global-chain records to exact receipts in this durable mission."""
    if not isinstance(full_chain, list) or not isinstance(mission_state, dict):
        return False
    progress = mission_state.get("progress")
    if not isinstance(progress, dict):
        return False
    raw_receipts = progress.get("execution_evidence_refs", [])
    if not isinstance(raw_receipts, list) or any(not isinstance(item, dict) for item in raw_receipts):
        return False
    expected_receipts: list[dict] = []
    for record in full_chain:
        if not isinstance(record, dict):
            return False
        if not record.get("fence_id"):
            continue
        # The full global chain is verified independently; this status response
        # carries receipts only for the current Mission's fenced records.
        if record.get("mission_id") != mission_id:
            continue
        try:
            expected_receipts.append({
                "evidence_id": record["evidence_id"],
                "sequence": int(record["sequence"]),
                "current_hash": str(record["current_hash"]),
                **{name: record[name] for name in _EVIDENCE_RECEIPT_FIELDS},
            })
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
    return raw_receipts == expected_receipts


def _independent_execution_chain_status(
    full_chain: object, mission_state: dict, mission_id: str, request_id: str
) -> str:
    if not isinstance(full_chain, list):
        return "UNREADABLE"
    if not full_chain:
        return "NOT_PRESENT"
    if not _verify_durable_execution_chain(full_chain):
        return "INVALID"
    mission_chain = [
        item for item in full_chain
        if isinstance(item, dict)
        and (
            item.get("mission_id") == mission_id
            or (not item.get("mission_id") and bool(request_id) and item.get("request_id") == request_id)
        )
    ]
    if not mission_chain:
        return "NOT_PRESENT"
    if not _execution_evidence_receipts_match(full_chain, mission_state, mission_id):
        return "INVALID"
    return "VALID"


def _producer_report_from_status(
    mission_state: dict, mission_chain: list, chain_integrity: str
) -> dict | None:
    """Rebuild the report body from the status payload using the actual producer."""
    try:
        mission_view = SimpleNamespace(**mission_state)
        expected = _build_mission_report(
            mission_view,
            execution_evidence=mission_chain,
            evidence_chain_integrity=chain_integrity,
        )
        limitations = expected.get("limitations")
        expected["limitations"] = (list(limitations) if isinstance(limitations, list) else []) + [
            _REPORT_APPROVAL_LIMITATION
        ]
        report_sha256 = _canonical_report_body_sha256(expected)
        expected["report_sha256"] = report_sha256
        expected["report_digest_scope"] = _REPORT_DIGEST_SCOPE
        progress = mission_state.get("progress")
        progress = progress if isinstance(progress, dict) else {}
        stored_approval = progress.get("final_report_approval")
        owner_identity_ref = str(mission_state.get("owner_identity_ref", "") or "")
        if not isinstance(stored_approval, dict):
            approval_view = {"status": "PENDING", "report_sha256": report_sha256}
        elif (
            stored_approval.get("decision") == "APPROVED"
            and stored_approval.get("report_sha256") == report_sha256
            and stored_approval.get("owner_identity_ref") == owner_identity_ref
        ):
            approval_view = {
                "status": "APPROVED",
                "report_sha256": report_sha256,
                "approved_at": str(stored_approval.get("approved_at", "")),
            }
        else:
            approval_view = {
                "status": "STALE",
                "report_sha256": str(stored_approval.get("report_sha256", "")),
                "current_report_sha256": report_sha256,
                "approved_at": str(stored_approval.get("approved_at", "")),
            }
        expected["final_report_approval"] = approval_view
        return expected
    except Exception:
        return None


def _is_structured_verification_summary(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    verified = value.get("verified")
    evidence_count = value.get("evidence_count")
    missing_criteria = value.get("missing_criteria", [])
    runtime_reported_verified = value.get("runtime_reported_verified")
    return (
        (verified is None or type(verified) is bool)
        and type(evidence_count) is int
        and evidence_count >= 0
        and isinstance(missing_criteria, list)
        and all(isinstance(item, str) for item in missing_criteria)
        and (
            "runtime_reported_verified" not in value
            or runtime_reported_verified is None
            or type(runtime_reported_verified) is bool
        )
    )


def _contains_status_failure_phrase(normalized_phrase: str) -> bool:
    negations = {"NO", "NOT", "NEVER", "WITHOUT"}
    for prefix in _STATUS_FAILURE_PHRASE_PREFIXES:
        pattern = re.compile(rf"(?:^|_){re.escape(prefix)}(?:_|$)")
        for match in pattern.finditer(normalized_phrase):
            before = normalized_phrase[:match.start()].rstrip("_")
            previous_word = before.rsplit("_", 1)[-1] if before else ""
            if previous_word not in negations:
                return True
    return False


def _contains_blocked_or_unverified_status(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            field = key.casefold() if isinstance(key, str) else ""
            if field in _BLOCKED_STATUS_FIELDS:
                if isinstance(child, str):
                    normalized = child.strip().upper().replace("-", "_").replace(" ", "_")
                    if field in {"reason_code", "error_code", "code", "failure_class"} and normalized:
                        return True
                    if (
                        normalized in _UNVERIFIED_STATUS_VALUES
                        or normalized.startswith("UNVERIFIED_")
                        or normalized == "BLOCKED"
                        or normalized.endswith("_BLOCKED")
                    ):
                        return True
                    allowed_statuses = _STATUS_SCALAR_ALLOWLISTS.get(field)
                    if allowed_statuses is not None and normalized not in allowed_statuses:
                        return True
                    if (
                        field == "result"
                        and re.search(r"\bERROR\s*:", child, flags=re.IGNORECASE)
                    ):
                        return True
                    phrase_normalized = re.sub(r"[^A-Z0-9]+", "_", child.strip().upper()).strip("_")
                    if (
                        field == "result"
                        and _contains_status_failure_phrase(phrase_normalized)
                    ):
                        return True
                    if (
                        field == "result"
                        and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*", child.strip())
                        and normalized not in _STATUS_GENERIC_VALUES
                    ):
                        return True
                elif field == "result":
                    pass
                elif field in {"verification", "verification_state"} and _is_structured_verification_summary(child):
                    pass
                else:
                    return True
            if _contains_blocked_or_unverified_status(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_blocked_or_unverified_status(item) for item in value)
    return False


def _mission_ids(value: object) -> list[object]:
    values: list[object] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "mission_id":
                values.append(child)
            values.extend(_mission_ids(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            values.extend(_mission_ids(child))
    return values


def _record_bound_to_mission(record: object, mission_id: str) -> bool:
    values = _mission_ids(record)
    return bool(values) and all(isinstance(value, str) and value == mission_id for value in values)


def _field_values(value: object, field: str) -> list[object]:
    values: list[object] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == field:
                values.append(child)
            values.extend(_field_values(child, field))
    elif isinstance(value, (list, tuple)):
        for child in value:
            values.extend(_field_values(child, field))
    return values


def _record_request_binding(record: object, request_id: str, *, require_present: bool) -> bool:
    values = _field_values(record, "request_id")
    return (bool(values) or not require_present) and all(
        isinstance(value, str) and value == request_id for value in values
    )


def _evidence_ref_matches(reference: object, record: object) -> bool:
    if not isinstance(reference, dict) or not isinstance(record, dict):
        return False
    sequence = reference.get("sequence")
    return (
        isinstance(reference.get("evidence_id"), str)
        and bool(reference.get("evidence_id"))
        and type(sequence) is int
        and sequence > 0
        and re.fullmatch(r"[0-9a-f]{64}", str(reference.get("current_hash", ""))) is not None
        and reference.get("evidence_id") == record.get("evidence_id")
        and sequence == record.get("sequence")
        and reference.get("current_hash") == record.get("current_hash")
    )


def _project_test_result_digest(result: dict) -> tuple[str, int] | None:
    observation_fields = {"type", "action_id", "step_id", "mission_id", "tool_call_id"}
    raw_result = {key: value for key, value in result.items() if key not in observation_fields}
    try:
        encoded = json.dumps(
            raw_result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False, default=str,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        return None
    return hashlib.sha256(encoded).hexdigest(), len(encoded)


def _durable_tool_result_linkage(record: object, mission_id: str, request_id: str) -> dict | None:
    if not isinstance(record, dict):
        return None
    name = record.get("name")
    call_id = record.get("tool_call_id")
    raw_action_id = record.get("action_id")
    raw_step_id = record.get("step_id")
    result = record.get("result")
    error = record.get("error")
    if (
        not isinstance(name, str)
        or _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(name) is None
        or not isinstance(call_id, str)
        or _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(call_id) is None
        or not isinstance(raw_action_id, str)
        or not isinstance(raw_step_id, str)
        or type(record.get("ok")) is not bool
        or not isinstance(result, dict)
        or not isinstance(error, str)
        or record.get("mission_id") != mission_id
        or not _record_bound_to_mission(record, mission_id)
        or not _record_request_binding(record, request_id, require_present=True)
    ):
        return None

    result_successful = record["ok"] is True and error == ""
    for status_field in ("ok", "success"):
        if status_field in result:
            if type(result[status_field]) is not bool or result[status_field] is not True:
                result_successful = False
    if "error" in result and (not isinstance(result["error"], str) or result["error"]):
        result_successful = False
    if _contains_blocked_or_unverified_status(result):
        result_successful = False

    return {
        "name": name,
        "tool_call_id": call_id,
        "raw_action_id": raw_action_id,
        "action_id": raw_action_id or call_id,
        "raw_step_id": raw_step_id,
        "step_id": raw_step_id or name,
        "status": "completed" if record["ok"] is True else "failed",
        "successful": result_successful,
    }


def _reconcile_tool_executed_timeline(
    mission_state: dict,
    timeline: object,
    tool_results: list,
    mission_id: str,
    request_id: str,
) -> dict:
    events = [
        item for item in timeline
        if isinstance(item, dict) and item.get("event") == "ToolExecuted"
    ] if isinstance(timeline, list) else []
    history = mission_state.get("action_history")
    history_records = history if isinstance(history, list) else []
    result_records = tool_results if isinstance(tool_results, list) else []
    result_linkages = [
        _durable_tool_result_linkage(record, mission_id, request_id)
        for record in result_records
    ]
    malformed_result_count = sum(linkage is None for linkage in result_linkages)
    failed_result_count = sum(
        linkage is not None and linkage["successful"] is not True
        for linkage in result_linkages
    )
    valid = (
        isinstance(timeline, list)
        and all(isinstance(item, dict) for item in timeline)
        and isinstance(history, list)
        and all(isinstance(item, dict) for item in history_records)
        and isinstance(tool_results, list)
        and len(events) == len(history_records) == len(result_records)
        and malformed_result_count == 0
        and failed_result_count == 0
    )
    matched_events = 0
    used_history: set[int] = set()
    used_results: set[int] = set()

    for event in events:
        data = event.get("data")
        action_id = data.get("action_id") if isinstance(data, dict) else None
        step_id = event.get("step_id")
        action_status = data.get("status") if isinstance(data, dict) else None
        if (
            not isinstance(data, dict)
            or not isinstance(action_id, str) or not action_id
            or not isinstance(step_id, str) or not step_id
            or not isinstance(action_status, str)
            or action_status not in {"completed", "failed"}
            or event.get("mission_id") != mission_id
            or event.get("request_id") != request_id
            or not _record_bound_to_mission(event, mission_id)
            or not _record_request_binding(event, request_id, require_present=True)
            or ("task_id" in event and event.get("task_id") != step_id)
            or ("step_id" in data and data.get("step_id") != step_id)
            or ("task_id" in data and data.get("task_id") != step_id)
        ):
            valid = False
            continue

        history_matches = [
            index for index, record in enumerate(history_records)
            if isinstance(record, dict)
            and record.get("action_id") == action_id
            and record.get("step_id") == step_id
            and record.get("status") == action_status
            and _record_bound_to_mission(record, mission_id)
        ]
        if len(history_matches) != 1 or history_matches[0] in used_history:
            valid = False
            continue

        history_record = history_records[history_matches[0]]
        observation = history_record.get("observation")
        if not isinstance(observation, dict) or not _record_bound_to_mission(observation, mission_id):
            valid = False
            continue
        result_matches = []
        for index, linkage in enumerate(result_linkages):
            if (
                linkage is None
                or index in used_results
                or linkage["action_id"] != action_id
                or linkage["step_id"] != step_id
                or linkage["status"] != action_status
                or observation.get("tool_call_id") != linkage["tool_call_id"]
                or observation.get("action_id", linkage["raw_action_id"]) != linkage["raw_action_id"]
                or observation.get("step_id", linkage["raw_step_id"]) != linkage["raw_step_id"]
                or ("tool_call_id" in data and data.get("tool_call_id") != linkage["tool_call_id"])
                or ("tool_name" in data and data.get("tool_name") != linkage["name"])
            ):
                continue
            result_matches.append(index)
        if len(result_matches) != 1:
            valid = False
            continue
        used_history.add(history_matches[0])
        used_results.add(result_matches[0])
        matched_events += 1

    unaccounted_results = max(0, len(result_records) - len(used_results))
    all_results_accounted = (
        isinstance(tool_results, list)
        and malformed_result_count == 0
        and unaccounted_results == 0
    )
    all_results_successful = (
        isinstance(tool_results, list)
        and malformed_result_count == 0
        and failed_result_count == 0
    )
    verified = (
        valid
        and matched_events == len(events)
        and len(used_history) == len(history_records)
        and all_results_accounted
        and all_results_successful
    )
    return {
        "verified": verified,
        "tool_executed_event_count": len(events),
        "action_history_record_count": len(history_records),
        "durable_tool_result_record_count": len(result_records),
        "matched_durable_call_count": len(used_results),
        "unaccounted_tool_executed_event_count": max(0, len(events) - matched_events),
        "unaccounted_action_history_record_count": max(0, len(history_records) - len(used_history)),
        "unaccounted_durable_tool_result_count": unaccounted_results,
        "malformed_durable_tool_result_count": malformed_result_count,
        "failed_durable_tool_result_count": failed_result_count,
        "all_durable_tool_results_accounted": all_results_accounted,
        "all_durable_tool_results_successful": all_results_successful,
    }


def _reconcile_tool_authorization_timeline(
    mission_state: dict, timeline: object, tool_results: list,
    mission_id: str, request_id: str,
) -> dict:
    """Require ordered, scope-bound authorization; never infer missing runtime scope fields."""
    if not isinstance(timeline, list) or not isinstance(tool_results, list):
        return {"verified": False, "all_call_decisions_reconciled": False,
                "fully_authorized_successful_execution": False,
                "unreconciled_authorization_event_count": 1, "call_classifications": [],
                "schema_status": "INVALID"}
    proposals: dict[str, list[tuple[int, dict]]] = {}
    decisions: dict[str, list[tuple[int, dict]]] = {}
    malformed = 0
    runtime_scope_schema_missing = False
    for index, event in enumerate(timeline):
        if not isinstance(event, dict) or event.get("event") not in {"ToolProposed", "AuthorizationChecked"}:
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            malformed += 1
            continue
        if "tool_call_id" not in data:
            malformed += 1
            continue
        call_id = data.get("tool_call_id")
        if not isinstance(call_id, str) or not call_id:
            malformed += 1
            continue
        target = proposals if event["event"] == "ToolProposed" else decisions
        target.setdefault(call_id, []).append((index, event))
        if event["event"] == "AuthorizationChecked" and not all(
            isinstance(data.get(field), str) and data[field]
            for field in ("action_id", "step_id", "authorization_context_id", "scope_snapshot_id")
        ):
            runtime_scope_schema_missing = True

    call_ids = [item.get("tool_call_id") for item in tool_results if isinstance(item, dict)]
    valid_ids = {item for item in call_ids if isinstance(item, str) and item}
    unaccounted = malformed + (len(call_ids) - len(valid_ids))
    unaccounted += sum(len(rows) for key, rows in (*proposals.items(), *decisions.items()) if key not in valid_ids)
    classifications: list[str] = []
    history = mission_state.get("action_history")
    history = history if isinstance(history, list) else []

    for result in tool_results:
        if not isinstance(result, dict):
            classifications.append("MALFORMED_RESULT")
            unaccounted += 1
            continue
        call_id, action_id, step_id = (
            result.get("tool_call_id"), result.get("action_id"), result.get("step_id")
        )
        context_id, scope_id = result.get("authorization_context_id"), result.get("scope_snapshot_id")
        if not all(isinstance(value, str) and value for value in (call_id, action_id, step_id, context_id, scope_id)):
            classifications.append("IDENTITY_OR_SCOPE_UNBOUND")
            unaccounted += 1
            continue
        proposed, checked = proposals.get(call_id, []), decisions.get(call_id, [])
        if len(proposed) != 1 or len(checked) != 1:
            classifications.append("MISSING_OR_DUPLICATE_AUTHORIZATION_RECORD")
            unaccounted += 1
            continue
        proposal_index, proposal_event = proposed[0]
        authorization_index, authorization_event = checked[0]
        proposal = proposal_event.get("data")
        authorization = authorization_event.get("data")
        expected = {
            "mission_id": mission_id, "request_id": request_id,
            "name": result.get("name"), "tool_call_id": call_id,
            "action_id": action_id, "step_id": step_id,
            "authorization_context_id": context_id, "scope_snapshot_id": scope_id,
        }
        if (
            not isinstance(proposal, dict) or not isinstance(authorization, dict)
            or any(proposal.get(key) != value for key, value in expected.items())
            or any(authorization.get(key) != value for key, value in expected.items() if key != "name")
            or proposal_event.get("mission_id") != mission_id
            or proposal_event.get("request_id") != request_id
            or authorization_event.get("mission_id") != mission_id
            or authorization_event.get("request_id") != request_id
            or type(authorization.get("allowed")) is not bool
            or proposal_index >= authorization_index
        ):
            classifications.append("AUTHORIZATION_IDENTITY_SCOPE_OR_ORDER_MISMATCH")
            unaccounted += 1
            continue
        executed = []
        for event_index, event in enumerate(timeline):
            data = event.get("data") if isinstance(event, dict) else None
            if (
                isinstance(event, dict) and event.get("event") == "ToolExecuted"
                and isinstance(data, dict) and data.get("action_id") == action_id
                and event.get("mission_id") == mission_id and event.get("request_id") == request_id
                and event.get("step_id") == step_id and event_index > authorization_index
                and isinstance(data.get("status"), str)
                and data.get("status") in {"completed", "failed"}
            ):
                executed.append((event_index, event))
        actions = [item for item in history if isinstance(item, dict)
                   and item.get("action_id") == action_id and item.get("step_id") == step_id
                   and isinstance(item.get("observation"), dict)
                   and item["observation"].get("tool_call_id") == call_id]
        if authorization["allowed"] is False:
            if result.get("ok") is False and isinstance(result.get("error"), str) and result["error"] and not executed and not actions:
                classifications.append("PRE_DISPATCH_DENIED")
            else:
                classifications.append("DENIAL_CONFLICTS_WITH_EXECUTION_OR_RESULT")
                unaccounted += 1
        elif len(executed) == 1 and len(actions) == 1:
            execution_status = executed[0][1]["data"].get("status")
            if result.get("ok") is True and execution_status == "completed":
                classifications.append("AUTHORIZED_EXECUTION_COMPLETED")
            elif result.get("ok") is False and execution_status == "failed":
                classifications.append("POST_DISPATCH_FAILURE")
            else:
                classifications.append("EXECUTION_RESULT_STATUS_MISMATCH")
                unaccounted += 1
        else:
            classifications.append("AUTHORIZED_CALL_EXECUTION_UNACCOUNTED")
            unaccounted += 1

    reconciled = unaccounted == 0 and len(classifications) == len(tool_results)
    return {
        "verified": reconciled,
        "all_call_decisions_reconciled": reconciled,
        "fully_authorized_successful_execution": bool(classifications) and reconciled
        and all(item == "AUTHORIZED_EXECUTION_COMPLETED" for item in classifications),
        "unreconciled_authorization_event_count": unaccounted,
        "call_classifications": classifications,
        "schema_status": "BLOCKED" if runtime_scope_schema_missing else ("VALID" if reconciled else "INVALID"),
    }


def _mission_project_test_execution_proof(
    mission_state: dict,
    timeline: object,
    mission_evidence: object,
    report_goal_evidence: object,
    execution_chain: object,
    mission_id: str,
    request_id: str,
    chain_integrity: object,
    *,
    full_execution_chain: object = None,
) -> dict:
    raw_results, _source = _durable_tool_result_records(mission_state)
    timeline_reconciliation = _reconcile_tool_executed_timeline(
        mission_state, timeline, raw_results, mission_id, request_id
    )
    authorization_reconciliation = _reconcile_tool_authorization_timeline(
        mission_state, timeline, raw_results, mission_id, request_id
    )
    durable_result_records_valid = (
        timeline_reconciliation["malformed_durable_tool_result_count"] == 0
        and timeline_reconciliation["all_durable_tool_results_accounted"] is True
        and timeline_reconciliation["all_durable_tool_results_successful"] is True
        and authorization_reconciliation["fully_authorized_successful_execution"] is True
    )
    test_results = [
        item for item in raw_results
        if isinstance(item, dict) and item.get("name") == "run_project_tests"
    ]
    successful_result_indices = {
        index for index, item in enumerate(test_results)
        if item.get("ok") is True
        or (
            isinstance(item.get("result"), dict)
            and (
                item["result"].get("ok") is True
                or (
                    type(item["result"].get("returncode")) is int
                    and item["result"].get("returncode") == 0
                )
            )
        )
    }
    evidence = mission_evidence if isinstance(mission_evidence, list) else []
    goal_evidence = report_goal_evidence if isinstance(report_goal_evidence, list) else []
    chain = execution_chain if isinstance(execution_chain, list) else []
    full_chain = full_execution_chain if isinstance(full_execution_chain, list) else []
    full_chain_receipts_valid = _execution_evidence_receipts_match(
        full_chain, mission_state, mission_id
    )
    full_chain_hash_valid = (
        _verify_durable_execution_chain(full_chain) and full_chain_receipts_valid
    )
    mission_filtered_global_chain = [
        item for item in full_chain
        if isinstance(item, dict)
        and (
            item.get("mission_id") == mission_id
            or (
                not item.get("mission_id")
                and bool(request_id)
                and item.get("request_id") == request_id
            )
        )
    ]
    report_chain_matches_global = (
        full_chain_hash_valid
        and isinstance(execution_chain, list)
        and mission_filtered_global_chain == chain
    )
    execution_chain_hash_valid = full_chain_hash_valid and report_chain_matches_global
    execution_chain_integrity_verified = (
        chain_integrity == "VALID" and execution_chain_hash_valid
    )
    process_records = [
        item for item in chain
        if isinstance(item, dict) and item.get("source") == "sandboxed-process:run_project_tests"
    ]
    native_records = [
        item for item in chain
        if isinstance(item, dict) and item.get("source") == "native-tool:run_project_tests"
    ]
    linked_call_records: list[dict] = []
    verified_candidates: list[dict] = []
    verified_successful_result_indices: set[int] = set()

    for call_index, call in enumerate(test_results):
        call_id = call.get("tool_call_id")
        action_id = call.get("action_id") or call_id
        task_id = call.get("step_id")
        result = call.get("result")
        if (
            not isinstance(call_id, str) or not call_id
            or not isinstance(action_id, str) or not action_id
            or not isinstance(task_id, str) or not task_id
            or not isinstance(result, dict)
            or not _record_bound_to_mission(call, mission_id)
            or not _record_request_binding(call, request_id, require_present=True)
        ):
            continue
        process_matches = [
            item for item in process_records
            if _evidence_ref_matches(result.get("evidence_ref"), item)
            and item.get("mission_id") == mission_id
            and item.get("request_id") == request_id
            and item.get("task_id") == task_id
            and item.get("execution_id") == action_id
            and _record_bound_to_mission(item, mission_id)
            and _record_request_binding(item, request_id, require_present=True)
        ]
        native_matches = [
            item for item in native_records
            if item.get("mission_id") == mission_id
            and item.get("request_id") == request_id
            and item.get("task_id") == task_id
            and item.get("execution_id") == action_id
            and _record_bound_to_mission(item, mission_id)
            and _record_request_binding(item, request_id, require_present=True)
            and isinstance(item.get("evidence"), dict)
            and item["evidence"].get("record_type") == "NATIVE_TOOL_RESULT"
            and item["evidence"].get("tool_name") == "run_project_tests"
            and item["evidence"].get("tool_call_id") == call_id
        ]
        event_matches = [
            item for item in (timeline if isinstance(timeline, list) else [])
            if isinstance(item, dict)
            and item.get("event") == "ToolExecuted"
            and item.get("mission_id") == mission_id
            and item.get("request_id") == request_id
            and _record_bound_to_mission(item, mission_id)
            and _record_request_binding(item, request_id, require_present=True)
            and item.get("step_id") == task_id
            and item.get("task_id", task_id) == task_id
            and isinstance(item.get("data"), dict)
            and item["data"].get("step_id", task_id) == task_id
            and item["data"].get("task_id", task_id) == task_id
            and item["data"].get("action_id") == action_id
            and item["data"].get("status") == "completed"
        ]
        if len(process_matches) != 1 or len(native_matches) != 1 or len(event_matches) != 1:
            continue
        linked_call_records.append(call)

        process_record = process_matches[0]
        process_payload = process_record.get("evidence")
        native_record = native_matches[0]
        native_payload = native_record.get("evidence")
        digest = _project_test_result_digest(result)
        if not isinstance(process_payload, dict) or not isinstance(native_payload, dict) or digest is None:
            continue
        digest_sha256, digest_bytes = digest
        process_payload_valid = (
            process_payload.get("record_type") == "UNTRUSTED_SANDBOX_PROCESS_RESULT"
            and process_payload.get("trust") == "untrusted_data"
            and process_payload.get("authority") == "none"
            and process_payload.get("sandbox_backend") == "bubblewrap+prlimit"
            and process_payload.get("network") == "disabled"
            and process_payload.get("workspace_mode") == "read_only"
            and type(process_payload.get("exit_code")) is int
            and process_payload.get("exit_code") == 0
            and process_payload.get("timed_out") is False
            and process_payload.get("cancelled") is False
            and re.fullmatch(r"[0-9a-f]{64}", str(process_payload.get("output_sha256", ""))) is not None
            and isinstance(process_payload.get("artifact_refs"), list)
            and isinstance(process_payload.get("artifact_capture_truncated"), bool)
            and process_record.get("verification") == "observed"
        )
        native_payload_valid = (
            native_record.get("verification") == "observed"
            and native_payload.get("trust_classification") == "untrusted_data"
            and native_payload.get("authority") == "none"
            and native_payload.get("authorized_tool") is True
            and native_payload.get("result_type") == "dict"
            and native_payload.get("result_sha256") == digest_sha256
            and type(native_payload.get("result_bytes")) is int
            and native_payload.get("result_bytes") == digest_bytes
            and isinstance(native_record.get("chain"), (list, tuple))
            and f"mission:{mission_id}" in native_record.get("chain", ())
            and "tool:run_project_tests" in native_record.get("chain", ())
            and f"call:{call_id}" in native_record.get("chain", ())
        )
        result_valid = (
            call.get("ok") is True
            and result.get("ok") is True
            and type(result.get("returncode")) is int
            and result.get("returncode") == 0
            and result.get("timed_out") is False
            and result.get("cancelled") is False
            and result.get("sandbox_backend") == "bubblewrap+prlimit"
            and result.get("network") == "disabled"
            and result.get("workspace_mode") == "read_only"
            and result.get("trust") == "untrusted_data"
            and result.get("authority") == "none"
            and _evidence_ref_matches(result.get("evidence_ref"), process_record)
            and result.get("mission_id") == mission_id
            and result.get("tool_call_id") == call_id
            and result.get("action_id") == call.get("action_id", "")
            and result.get("step_id") == call.get("step_id", "")
            and not _contains_blocked_or_unverified_status(call)
        )
        call_evidence = [
            item for item in evidence
            if isinstance(item, dict)
            and item.get("source") == "run_project_tests"
            and isinstance(item.get("provenance"), dict)
            and item["provenance"].get("tool_call_id") == call_id
            and item.get("passed") is True
            and _record_bound_to_mission(item, mission_id)
            and _record_request_binding(item, request_id, require_present=False)
            and isinstance(item.get("result"), dict)
            and item["result"].get("result") == result
            and item["provenance"].get("verification_authority") == "project_test_process_exit"
        ]
        report_call_evidence = [
            item for item in goal_evidence
            if isinstance(item, dict)
            and item.get("source") == "run_project_tests"
            and item.get("passed") is True
            and item.get("report_verification") == "TRUSTED_DETERMINISTIC_SOURCE"
            and isinstance(item.get("provenance"), dict)
            and item["provenance"].get("tool_call_id") == call_id
            and _record_bound_to_mission(item, mission_id)
            and _record_request_binding(item, request_id, require_present=False)
            and isinstance(item.get("result"), dict)
            and item["result"].get("result") == result
        ]
        if (
            process_payload_valid and native_payload_valid and result_valid
            and len(call_evidence) == 1 and len(report_call_evidence) == 1
        ):
            verified_candidates.append({
                "process_record": process_record,
                "native_record": native_record,
                "call_id": call_id,
                "action_id": action_id,
            })
            verified_successful_result_indices.add(call_index)

    unaccounted_successful_result_count = len(
        successful_result_indices - verified_successful_result_indices
    )
    unaccounted_result_record_count = len(
        set(range(len(test_results))) - verified_successful_result_indices
    )
    exactly_one = (
        durable_result_records_valid
        and execution_chain_integrity_verified
        and len(process_records) == 1
        and len(native_records) == 1
        and len(linked_call_records) == 1
        and len(verified_candidates) == 1
        and timeline_reconciliation.get("verified") is True
        and len(successful_result_indices) == 1
        and unaccounted_successful_result_count == 0
        and unaccounted_result_record_count == 0
    )
    verified = exactly_one and not _contains_blocked_or_unverified_status(
        (mission_state, evidence, goal_evidence, chain)
    )
    return {
        "verified": verified,
        "exactly_one_actual_execution_verified": verified,
        "durable_result_records_valid": durable_result_records_valid,
        "tool_executed_timeline_reconciled": timeline_reconciliation["verified"],
        "authorization_timeline_reconciled": authorization_reconciliation["verified"],
        "authorization_schema_status": authorization_reconciliation["schema_status"],
        "all_calls_fully_authorized_successful": authorization_reconciliation[
            "fully_authorized_successful_execution"
        ],
        "unreconciled_authorization_event_count": authorization_reconciliation[
            "unreconciled_authorization_event_count"
        ],
        "authorization_call_classifications": authorization_reconciliation[
            "call_classifications"
        ],
        "tool_executed_event_count": timeline_reconciliation["tool_executed_event_count"],
        "action_history_record_count": timeline_reconciliation["action_history_record_count"],
        "matched_durable_action_call_count": timeline_reconciliation["matched_durable_call_count"],
        "unaccounted_tool_executed_event_count": timeline_reconciliation["unaccounted_tool_executed_event_count"],
        "unaccounted_action_history_record_count": timeline_reconciliation["unaccounted_action_history_record_count"],
        "durable_tool_result_record_count": timeline_reconciliation["durable_tool_result_record_count"],
        "unaccounted_durable_tool_result_record_count": timeline_reconciliation["unaccounted_durable_tool_result_count"],
        "malformed_durable_tool_result_record_count": timeline_reconciliation["malformed_durable_tool_result_count"],
        "failed_durable_tool_result_record_count": timeline_reconciliation["failed_durable_tool_result_count"],
        "all_durable_tool_results_accounted": timeline_reconciliation["all_durable_tool_results_accounted"],
        "all_durable_tool_results_successful": timeline_reconciliation["all_durable_tool_results_successful"],
        "execution_chain_hash_valid": execution_chain_hash_valid,
        "execution_chain_receipts_verified": full_chain_receipts_valid,
        "global_execution_chain_hash_valid": full_chain_hash_valid,
        "report_execution_chain_matches_global": report_chain_matches_global,
        "execution_chain_integrity_verified": execution_chain_integrity_verified,
        "result_record_count": len(test_results),
        "successful_result_record_count": len(successful_result_indices),
        "unaccounted_successful_result_record_count": unaccounted_successful_result_count,
        "unaccounted_result_record_count": unaccounted_result_record_count,
        "all_project_test_results_accounted": unaccounted_result_record_count == 0,
        "sandbox_process_evidence_record_count": len(process_records),
        "native_tool_result_record_count": len(native_records),
        "linked_result_record_count": len(linked_call_records),
        "verified_linked_execution_count": len(verified_candidates),
        "mission_request_binding_verified": bool(request_id)
        and bool(process_records or native_records)
        and all(
            _record_request_binding(item, request_id, require_present=True)
            for item in (*process_records, *native_records)
        ),
        "sandbox_record_type": "UNTRUSTED_SANDBOX_PROCESS_RESULT" if verified else None,
        "sandbox_backend": "bubblewrap+prlimit" if verified else None,
        "network": "disabled" if verified else None,
        "workspace_mode": "read_only" if verified else None,
        "successful_exit_code": 0 if verified else None,
        "timed_out": False if verified else None,
        "cancelled": False if verified else None,
        "result_evidence_ref_matches_hash_chained_record": verified,
        "native_tool_result_digest_matches": verified,
        "mission_bound_validation_evidence_verified": verified,
    }


def _tool_execution_projection(mission_state: dict) -> dict:
    summary, source = _safe_tool_result_summary(mission_state)
    raw_results, raw_source = _durable_tool_result_records(mission_state)
    return {
        "source": source,
        "count": len(summary),
        "summary_sha256": _canonical_sha256(summary),
        "records_count": len(raw_results),
        "records_sha256": (
            _canonical_sha256({"source": raw_source, "records": raw_results})
            if raw_source != "unavailable" else None
        ),
        "run_project_tests_result_record_count": sum(
            item.get("name") == "run_project_tests" for item in summary
        ),
        "duplicate_tool_call_ids": len({item.get("tool_call_id") for item in summary if item.get("tool_call_id")})
        != sum(bool(item.get("tool_call_id")) for item in summary),
    }


def _effect_ledger_projection(records: object, mission_id: str) -> dict:
    if not isinstance(records, list):
        return {
            "available": False,
            "count": 0,
            "sha256": None,
            "full_records_sha256": None,
            "mission_binding_verified": False,
            "duplicate_effect_ids": False,
        }
    stable_records = []
    effect_ids = []
    mission_binding_verified = True
    for item in records:
        if not isinstance(item, dict):
            mission_binding_verified = False
            stable_records.append({"record_type": "invalid"})
            continue
        effect_id = item.get("effect_id")
        effect_mission_id = item.get("mission_id")
        if isinstance(effect_id, str) and effect_id:
            effect_ids.append(effect_id)
        if (
            effect_mission_id != mission_id
            or not _record_bound_to_mission(item, mission_id)
            or not isinstance(effect_id, str)
            or not effect_id
        ):
            mission_binding_verified = False
        stable = {}
        for key in (
            "effect_id", "mission_id", "task_id", "execution_id", "provider",
            "operation", "state", "requires_reconciliation", "owner_binding_status",
        ):
            value = item.get(key)
            if hasattr(value, "value"):
                value = value.value
            if isinstance(value, (str, int, bool)) or value is None:
                stable[key] = value
        stable_records.append(stable)
    return {
        "available": True,
        "count": len(records),
        "sha256": _canonical_sha256(stable_records),
        "full_records_sha256": _canonical_sha256(records),
        "mission_binding_verified": mission_binding_verified,
        "duplicate_effect_ids": len(effect_ids) != len(set(effect_ids)),
    }


def _may_resume_after_application_restart(
    *,
    mission_status: object,
    queue_state: object,
    pause_requested: object,
    owner_authorized: bool,
    runtime_ready: bool,
    execution_history_unchanged: bool,
) -> bool:
    terminal = {
        "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED",
        "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED",
        "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
    }
    reauth_quarantine = mission_status == "OWNER_REAUTH_REQUIRED" and queue_state == "needs_input"
    persisted_pause = (
        reauth_quarantine
        if mission_status == "OWNER_REAUTH_REQUIRED"
        else queue_state == "paused"
    )
    return (
        persisted_pause
        and pause_requested is True
        and mission_status not in terminal
        and owner_authorized
        and runtime_ready
        and execution_history_unchanged
    )


def _windows_process_alive(process_id: int) -> bool | None:
    if os.name != "nt" or process_id <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, process_id)
    if not handle:
        return False if ctypes.get_last_error() in {87, 1168} else None
    try:
        result = kernel32.WaitForSingleObject(handle, 0)
        if result == 258:
            return True
        if result == 0:
            return False
        return None
    finally:
        kernel32.CloseHandle(handle)


def _windows_process_image_path(process_id: int) -> str | None:
    if os.name != "nt" or process_id <= 0:
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x1000, False, process_id)
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            return None
        return buffer.value
    finally:
        kernel32.CloseHandle(handle)


def _windows_process_api():
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
        kernel32.GetProcessId.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        filetime_pointer = ctypes.POINTER(wintypes.FILETIME)
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE, filetime_pointer, filetime_pointer, filetime_pointer, filetime_pointer
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        return kernel32
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _windows_process_handle_identity(kernel32, handle: object) -> dict | None:
    import ctypes
    from ctypes import wintypes

    try:
        if kernel32.WaitForSingleObject(handle, 0) != 258:
            return None
        process_id = int(kernel32.GetProcessId(handle))
        if process_id <= 0:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            return None
        creation_time = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation_time),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        if kernel32.WaitForSingleObject(handle, 0) != 258:
            return None
        ticks = (int(creation_time.dwHighDateTime) << 32) | int(creation_time.dwLowDateTime)
        if ticks <= 0 or not buffer.value:
            return None
        return {
            "process_id": process_id,
            "image_path": buffer.value,
            "creation_time": str(ticks),
            "running": True,
        }
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _windows_process_identity(process_id: int) -> dict | None:
    if os.name != "nt" or type(process_id) is not int or process_id <= 0:
        return None
    kernel32 = _windows_process_api()
    if kernel32 is None:
        return None
    try:
        handle = kernel32.OpenProcess(0x0400 | 0x1000 | 0x00100000, False, process_id)
    except (OSError, TypeError, ValueError):
        return None
    if not handle:
        return None
    try:
        identity = _windows_process_handle_identity(kernel32, handle)
        return identity if isinstance(identity, dict) and identity.get("process_id") == process_id else None
    finally:
        kernel32.CloseHandle(handle)


def _valid_process_creation_time(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and value.isdecimal()
        and int(value) > 0
    )


def _normalized_process_image_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        normalized = os.path.normcase(os.path.realpath(os.path.expanduser(value)))
        return normalized if os.path.isabs(normalized) and os.path.isfile(normalized) else None
    except (OSError, TypeError, ValueError):
        return None


def _windows_process_snapshot() -> dict[int, dict] | None:
    if os.name != "nt":
        return None
    command = (
        "$ErrorActionPreference = 'Stop'; "
        "$processes = @(Get-CimInstance -ClassName Win32_Process); "
        "$processes | "
        "Select-Object @{Name='process_id';Expression={[int]$_.ProcessId}}, "
        "@{Name='parent_process_id';Expression={[int]$_.ParentProcessId}}, "
        "@{Name='creation_time';Expression={$_.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString([System.Globalization.CultureInfo]::InvariantCulture)}}, "
        "@{Name='image_path';Expression={$_.ExecutablePath}} | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        payload = json.loads(result.stdout.lstrip("\ufeff"))
    except (json.JSONDecodeError, TypeError):
        return None
    records = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    snapshot = {}
    for record in records:
        if not isinstance(record, dict):
            return None
        process_id = record.get("process_id")
        parent_process_id = record.get("parent_process_id")
        if type(process_id) is not int or type(parent_process_id) is not int:
            return None
        creation_time = record.get("creation_time")
        image_path = record.get("image_path")
        if (
            process_id <= 0
            or parent_process_id < 0
            or not _valid_process_creation_time(creation_time)
            or (image_path is not None and (not isinstance(image_path, str) or not image_path.strip()))
        ):
            return None
        if process_id in snapshot:
            return None
        snapshot[process_id] = {
            "parent_process_id": parent_process_id,
            "creation_time": creation_time,
            "image_path": image_path,
        }
    return snapshot or None


def _windows_process_tree_identities(snapshot: dict[int, dict] | None, root_process_id: int) -> dict[int, str] | None:
    if not isinstance(snapshot, dict) or root_process_id not in snapshot:
        return None
    tree_ids = {root_process_id}
    changed = True
    while changed:
        changed = False
        for process_id, record in snapshot.items():
            if process_id not in tree_ids and record.get("parent_process_id") in tree_ids:
                tree_ids.add(process_id)
                changed = True
    return {
        process_id: snapshot[process_id]["creation_time"]
        for process_id in sorted(tree_ids)
    }


def _windows_process_tree_identity_records(
    snapshot: dict[int, dict] | None, root_process_id: int
) -> dict[int, dict] | None:
    if type(root_process_id) is not int or root_process_id <= 0:
        return None
    try:
        tree_ids = _windows_process_tree_identities(snapshot, root_process_id)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if tree_ids is None:
        return None

    records = {}
    for process_id in tree_ids:
        record = snapshot.get(process_id)
        if not isinstance(record, dict):
            return None
        parent_process_id = record.get("parent_process_id")
        creation_time = record.get("creation_time")
        image_path = _normalized_process_image_path(record.get("image_path"))
        if (
            type(process_id) is not int
            or process_id <= 0
            or type(parent_process_id) is not int
            or parent_process_id < 0
            or parent_process_id == process_id
            or not _valid_process_creation_time(creation_time)
            or image_path is None
        ):
            return None
        records[process_id] = {
            "process_id": process_id,
            "parent_process_id": parent_process_id,
            "creation_time": creation_time,
            "image_path": image_path,
        }

    root_record = records.get(root_process_id)
    if root_record is None or root_record["parent_process_id"] in records:
        return None
    # A parent PID can be reused; a captured parent must predate each linked child.
    for process_id, record in records.items():
        if process_id == root_process_id:
            continue
        parent = records.get(record["parent_process_id"])
        if parent is None or int(parent["creation_time"]) >= int(record["creation_time"]):
            return None
    return records


def _process_identity_matches_tree_record(
    identity: object, process_id: int, expected: object
) -> bool:
    if not isinstance(expected, dict) or not isinstance(identity, dict):
        return False
    return (
        type(identity.get("process_id")) is int
        and identity.get("process_id") == process_id
        and identity.get("running") is True
        and _valid_process_creation_time(identity.get("creation_time"))
        and identity.get("creation_time") == expected.get("creation_time")
        and _normalized_process_image_path(identity.get("image_path")) == expected.get("image_path")
    )


def _close_windows_process_handles(kernel32, handles: dict[int, object]) -> None:
    close_failed = False
    for process_id in reversed(list(handles)):
        handle = handles.pop(process_id)
        try:
            if not handle or not kernel32.CloseHandle(handle):
                close_failed = True
        except Exception:
            close_failed = True
    if close_failed:
        raise RuntimeError("windows_process_handle_close_failed")


def _validate_pinned_windows_process_tree(pinned_tree: object, expected_tree: object) -> bool:
    if not isinstance(pinned_tree, dict) or not isinstance(expected_tree, dict):
        return False
    kernel32 = pinned_tree.get("kernel32")
    handles = pinned_tree.get("handles")
    if (
        kernel32 is None
        or not isinstance(handles, dict)
        or set(handles) != set(expected_tree)
    ):
        return False
    for process_id, expected in expected_tree.items():
        handle = handles.get(process_id)
        if not handle:
            return False
        identity = _windows_process_handle_identity(kernel32, handle)
        if not _process_identity_matches_tree_record(identity, process_id, expected):
            return False
    return True


def _pin_windows_process_tree(expected_tree: object) -> dict | None:
    if os.name != "nt" or not isinstance(expected_tree, dict) or not expected_tree:
        return None
    kernel32 = _windows_process_api()
    if kernel32 is None:
        return None
    handles: dict[int, object] = {}
    pinned = False
    try:
        # Keep each process instance pinned through the termination-safety decision.
        for process_id in sorted(expected_tree):
            expected = expected_tree[process_id]
            if type(process_id) is not int or process_id <= 0 or not isinstance(expected, dict):
                return None
            handle = kernel32.OpenProcess(0x0400 | 0x1000 | 0x00100000, False, process_id)
            if not handle:
                return None
            handles[process_id] = handle
            identity = _windows_process_handle_identity(kernel32, handle)
            if not _process_identity_matches_tree_record(identity, process_id, expected):
                return None
        result = {"kernel32": kernel32, "handles": handles}
        if not _validate_pinned_windows_process_tree(result, expected_tree):
            return None
        pinned = True
        return result
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    finally:
        if not pinned:
            _close_windows_process_handles(kernel32, handles)


def _release_pinned_windows_process_tree(pinned_tree: object) -> None:
    if not isinstance(pinned_tree, dict):
        raise RuntimeError("windows_process_tree_pin_invalid")
    kernel32 = pinned_tree.get("kernel32")
    handles = pinned_tree.get("handles")
    if kernel32 is None or not isinstance(handles, dict):
        raise RuntimeError("windows_process_tree_pin_invalid")
    _close_windows_process_handles(kernel32, handles)


def _remaining_process_tree_ids(original_tree: dict[int, str], snapshot: dict[int, dict]) -> set[int]:
    remaining = {
        process_id
        for process_id, creation_time in original_tree.items()
        if snapshot.get(process_id, {}).get("creation_time") == creation_time
    }
    parent_ids = set(original_tree)
    changed = True
    while changed:
        changed = False
        for process_id, record in snapshot.items():
            if process_id not in parent_ids and record.get("parent_process_id") in parent_ids:
                parent_ids.add(process_id)
                remaining.add(process_id)
                changed = True
    return remaining


def _process_tree_termination_status(
    *,
    taskkill_started: bool,
    taskkill_exit_code: int | None,
    initial_tree_verified: bool,
    remaining_process_count: int | None,
    process_id_stopped: bool | None,
    cdp_endpoint_unavailable: bool | None,
) -> str:
    # The current harness deliberately has no launch-bound process-tree
    # termination primitive; PID-only taskkill evidence can never establish PASS.
    return "NOT_RUN"


def _process_tree_termination_from_alive_probe(
    *,
    taskkill_started: bool,
    taskkill_exit_code: int | None,
    initial_tree_verified: bool,
    remaining_process_count: int | None,
    process_alive: bool | None,
    cdp_endpoint_unavailable: bool | None,
) -> tuple[str, bool | None]:
    process_stopped = None if process_alive is None else not process_alive
    return _process_tree_termination_status(
        taskkill_started=taskkill_started,
        taskkill_exit_code=taskkill_exit_code,
        initial_tree_verified=initial_tree_verified,
        remaining_process_count=remaining_process_count,
        process_id_stopped=process_stopped,
        cdp_endpoint_unavailable=cdp_endpoint_unavailable,
    ), process_stopped


def _cdp_version(port: int) -> dict | None:
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/json/version", timeout=2) as response:
            value = json.loads(response.read(64_000).decode("utf-8"))
        return value if isinstance(value, dict) and isinstance(value.get("Browser"), str) else None
    except Exception:
        return None


def _terminate_installed_process_tree(
    process_id: int, cdp_port: int, installed_executable: Path
) -> dict:
    if os.name != "nt":
        raise RuntimeError("native_windows_process_restart_required")

    def refuse_termination(reason: str, initial_member_count: int | None = None) -> dict:
        return {
            "taskkill_attempted": False,
            "taskkill_succeeded": False,
            "taskkill_exit_code": None,
            "taskkill_error_type": None,
            "process_tree_termination_status": "NOT_RUN",
            "process_tree_termination_verified": False,
            "process_tree_initial_member_count": initial_member_count,
            "process_tree_remaining_member_count": None,
            "descendant_termination_verified": None,
            "process_id_stopped": None,
            "old_cdp_endpoint_unavailable": None,
            "installed_process_identity_verified": False,
            "termination_refusal_reason": reason,
        }

    before_snapshot = _windows_process_snapshot()
    try:
        expected_image = _normalized_process_image_path(os.fspath(installed_executable))
    except (TypeError, ValueError):
        expected_image = None
    if not isinstance(before_snapshot, dict) or not expected_image:
        return refuse_termination("process_tree_snapshot_or_installed_image_unavailable")

    try:
        before_tree_records = _windows_process_tree_identity_records(before_snapshot, process_id)
    except (AttributeError, KeyError, TypeError, ValueError):
        before_tree_records = None
    if before_tree_records is None:
        return refuse_termination("process_tree_snapshot_unavailable")
    if before_tree_records[process_id]["image_path"] != expected_image:
        return refuse_termination("captured_installed_process_identity_unavailable", len(before_tree_records))
    before_tree = {
        member_id: record["creation_time"]
        for member_id, record in before_tree_records.items()
    }

    # Pin every process instance in the captured tree before evaluating whether
    # any PID-based termination mechanism could be used safely.
    pinned_tree = _pin_windows_process_tree(before_tree_records)
    if pinned_tree is None:
        return refuse_termination("process_tree_member_handle_or_identity_unavailable", len(before_tree))

    try:
        latest_tree_records = _windows_process_tree_identity_records(
            _windows_process_snapshot(), process_id
        )
        if latest_tree_records != before_tree_records:
            return refuse_termination("process_tree_changed_after_handle_pin", len(before_tree))
        if not _validate_pinned_windows_process_tree(pinned_tree, before_tree_records):
            return refuse_termination("pre_kill_pinned_process_tree_identity_mismatch", len(before_tree))
        # The CLI receives only a PID, and taskkill's /T performs a separate PID
        # lookup/tree walk. Retained handles cannot bind that operation to the
        # original launcher-owned process or constrain its descendant set.
        return refuse_termination(
            "launch_bound_process_identity_unavailable", len(before_tree)
        )
    finally:
        _release_pinned_windows_process_tree(pinned_tree)


def _launch_installed_application(executable: Path, profile_root: Path, cdp_port: int) -> subprocess.Popen:
    if os.name != "nt":
        raise RuntimeError("native_windows_process_restart_required")
    executable = executable.expanduser().resolve(strict=True)
    user_data = profile_root.expanduser().resolve() / "userData"
    appdata = profile_root.expanduser().resolve()
    local_appdata = appdata / "Local"
    user_data.mkdir(parents=True, exist_ok=True)
    local_appdata.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(local_appdata),
        "CYBERSENTINEL_TEST_USER_DATA_DIR": str(user_data),
        "CYBERSENTINEL_ACCEPTANCE_DIAGNOSTICS": "1",
    })
    creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return subprocess.Popen(
        [
            str(executable),
            "--disable-gpu",
            f"--remote-debugging-port={cdp_port}",
            "--remote-allow-origins=*",
        ],
        cwd=str(executable.parent),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creation_flags,
    )


def _connect_to_relaunched_application(playwright, cdp_port: int, expected_version: str):
    deadline = time.monotonic() + APPLICATION_RESTART_TIMEOUT_SECONDS
    last_error = ""
    while time.monotonic() < deadline:
        cdp = _cdp_version(cdp_port)
        if cdp is not None:
            browser = None
            try:
                browser = playwright.chromium.connect_over_cdp(
                    f"http://127.0.0.1:{cdp_port}", timeout=10_000
                )
                pages = [page for context in browser.contexts for page in context.pages]
                if pages:
                    page = pages[0]
                    health = page.evaluate("""async () => {
                      const response = await fetch('/api/public/health', {credentials: 'include'});
                      const body = await response.json().catch(() => ({}));
                      return {http_status: response.status, body};
                    }""")
                    version = health.get("body", {}).get("version") if isinstance(health, dict) else None
                    if (
                        isinstance(health, dict)
                        and health.get("http_status") == 200
                        and version == expected_version
                    ):
                        return browser, page, cdp, health
                    last_error = "relaunch_health_or_version_mismatch"
            except Exception as exc:
                last_error = type(exc).__name__
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
        time.sleep(1)
    raise TimeoutError("installed_application_relaunch_timeout:" + (last_error or "cdp_unavailable"))


def _installed_runtime_binary_evidence(executable: Path) -> dict:
    runtime_binary = executable.expanduser().resolve().parent / "resources" / "llama" / "llama-server.exe"
    if not runtime_binary.is_file():
        return {"exists": False, "sha256": None, "version": None}
    digest = hashlib.sha256()
    with runtime_binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    result = {
        "exists": True,
        "path": str(runtime_binary),
        "sha256": digest.hexdigest(),
        "version": None,
        "version_command_exit_code": None,
    }
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        version = subprocess.run(
            [str(runtime_binary), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
            creationflags=flags,
        )
        output = version.stdout or ""
        result["version_command_exit_code"] = version.returncode
        result["version_output_sha256"] = _sha256(output)
        match = re.search(r"(?i)(?:llama(?:-server)?|version)\s*[:= ]\s*([A-Za-z0-9_.+-]{1,64})", output)
        if match:
            result["version"] = match.group(1)
    except Exception as exc:
        result["version_command_error_type"] = type(exc).__name__
    return result


def _owner_auth_after_restart(
    page, mission_path: str, username: str, password: str, expected_owner_identity_ref: str | None
) -> dict:
    result = {
        "invalid_credentials_rejected": False,
        "invalid_login_preserved_existing_owner": None,
        "owner_session_restored": False,
        "valid_login_after_restart": False,
        "valid_login_credentials_submitted": False,
        "owner_identity_matches": False,
        "mission_read_authorized": False,
        "renderer_authenticated_after_restart": False,
    }
    try:
        before = _public_api(page, "GET", mission_path + "/status")
        before_status = before["http_status"]
        before_body = before["body"].get("status", {})
        before_identity = before_body.get("owner_identity_ref") if isinstance(before_body, dict) else None
        invalid = _login_owner_after_restart(page, username, "invalid-after-application-restart")
        invalid_http_status = invalid.get("http_status")
        invalid_error_code = invalid.get("error_code")
        invalid_rejected = (
            invalid.get("credentials_submitted") is True
            and invalid.get("submitted_username_matches") is True
            and invalid.get("submitted_password_matches") is True
            and invalid_http_status == 403
            and invalid.get("authenticated") is not True
            and invalid_error_code == "invalid_credentials"
        )
        after_invalid = _public_api(page, "GET", mission_path + "/status")
        after_invalid_state = after_invalid["body"].get("status", {})
        before_owner_authenticated = before_status == 200
        invalid_preserved = before_owner_authenticated and (
            after_invalid["http_status"] == 200
            and isinstance(after_invalid_state, dict)
            and after_invalid_state.get("owner_identity_ref") == before_identity
        )
        invalid_did_not_create_session = (
            before_status in (401, 403)
            and after_invalid["http_status"] in (401, 403)
        )
        invalid_auth_state_unchanged = invalid_preserved or invalid_did_not_create_session
        reauthenticated = False
        ui_login = {"http_status": None, "authenticated": False, "credentials_submitted": False}
        if before_owner_authenticated:
            page.locator("#loginForm").evaluate("(form) => form.classList.add('hidden')")
        if after_invalid["http_status"] != 200:
            ui_login = _login_owner_after_restart(page, username, password)
            reauthenticated = (
                ui_login.get("http_status") == 200
                and ui_login.get("authenticated") is True
                and ui_login.get("username") == username
                and ui_login.get("credentials_submitted") is True
                and ui_login.get("submitted_username_matches") is True
                and ui_login.get("submitted_password_matches") is True
            )
        final = _public_api(page, "GET", mission_path + "/status")
        final_state = final["body"].get("status", {})
        renderer_state = _renderer_owner_auth_state(page)
        owner_identity_matches = bool(
            isinstance(final_state, dict)
            and isinstance(expected_owner_identity_ref, str)
            and final_state.get("owner_identity_ref") == expected_owner_identity_ref
        )
        mission_read_authorized = (
            final["http_status"] == 200
            and isinstance(final_state, dict)
            and final_state.get("mission_id") == mission_path.rsplit("/", 1)[-1]
        )
        result.update({
            "invalid_credentials_rejected": invalid_rejected,
            "invalid_login_http_status": invalid_http_status,
            "invalid_login_error_code": invalid_error_code,
            "invalid_login_preserved_existing_owner": invalid_preserved,
            "invalid_login_did_not_create_owner_session": invalid_did_not_create_session,
            "invalid_login_authorization_state_unchanged": invalid_auth_state_unchanged,
            "owner_session_restored": before_owner_authenticated and invalid_preserved,
            "valid_login_after_restart": reauthenticated,
            "valid_login_credentials_submitted": ui_login.get("credentials_submitted") is True,
            "valid_login_submitted_username_matches": ui_login.get("submitted_username_matches") is True,
            "valid_login_submitted_password_matches": ui_login.get("submitted_password_matches") is True,
            "post_restart_authentication_mode": (
                "fresh_valid_login" if reauthenticated
                else "restored_session" if before_owner_authenticated and invalid_preserved
                else "not_authenticated"
            ),
            "owner_authenticated_after_restart": reauthenticated or (before_owner_authenticated and invalid_preserved),
            "owner_identity_matches": owner_identity_matches,
            "owner_identity_sha256": _sha256(str(final_state.get("owner_identity_ref", "")))
            if isinstance(final_state, dict) and final_state.get("owner_identity_ref") else None,
            "mission_read_authorized": mission_read_authorized,
            "mission_read_http_status": final["http_status"],
            "renderer_authenticated_after_restart": renderer_state.get("authenticated") is True,
            "renderer_login_form_hidden": renderer_state.get("login_form_hidden") is True,
            "renderer_logout_button_visible": renderer_state.get("logout_button_visible") is True,
            "valid_login_http_status": ui_login.get("http_status"),
            "valid_login_error_code": ui_login.get("error_code"),
        })
    except Exception as exc:
        result["error_type"] = type(exc).__name__
    result["status"] = "PASS" if all(
        result.get(key) is True for key in (
            "invalid_credentials_rejected", "invalid_login_authorization_state_unchanged",
            "owner_authenticated_after_restart", "owner_identity_matches", "mission_read_authorized",
            "renderer_authenticated_after_restart", "renderer_login_form_hidden",
            "renderer_logout_button_visible",
        )
    ) else "FAIL"
    return result


def _renderer_owner_auth_state(page) -> dict:
    try:
        page.wait_for_function(
            """() => {
                const label = (document.querySelector('#authStateSide')?.textContent || '').trim();
                const login = document.querySelector('#loginForm');
                const logout = document.querySelector('#logoutButton');
                return label.includes('مسجل الدخول') && !label.includes('غير مسجل الدخول')
                    && login !== null && login.classList.contains('hidden')
                    && logout !== null && !logout.classList.contains('hidden');
            }""",
            timeout=15_000,
        )
    except Exception:
        pass
    try:
        return page.evaluate("""() => {
            const label = (document.querySelector('#authStateSide')?.textContent || '').trim();
            const login = document.querySelector('#loginForm');
            const logout = document.querySelector('#logoutButton');
            return {
                authenticated: label.includes('مسجل الدخول') && !label.includes('غير مسجل الدخول'),
                login_form_hidden: login !== null && login.classList.contains('hidden'),
                logout_button_visible: logout !== null && !logout.classList.contains('hidden'),
            };
        }""") or {}
    except Exception:
        return {}


def _loopback_http_origin(value: object) -> tuple[str, str, int] | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.casefold()
    hostname = parsed.hostname.casefold() if parsed.hostname else ""
    if (
        scheme != "http"
        or hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    normalized_port = 80 if port is None else port
    if not 1 <= normalized_port <= 65535:
        return None
    return scheme, hostname, normalized_port


def _is_expected_owner_login_request(page, request) -> bool:
    if getattr(request, "method", None) != "POST":
        return False
    page_origin = _loopback_http_origin(getattr(page, "url", None))
    request_url = getattr(request, "url", None)
    request_origin = _loopback_http_origin(request_url)
    if page_origin is None or request_origin != page_origin or not isinstance(request_url, str):
        return False
    try:
        request_path = urlsplit(request_url).path
    except ValueError:
        return False
    return request_path == "/api/public/auth/login"


def _login_owner_after_restart(page, username: str, password: str) -> dict:
    credentials_submitted = False
    submitted_username_matches = False
    submitted_password_matches = False
    try:
        page.locator("#loginForm").evaluate("(form) => form.classList.remove('hidden')")
        page.locator("#loginUsername").fill(username)
        page.locator("#loginPassword").fill(password)
        with page.expect_response(
            lambda response: getattr(getattr(response, "request", None), "method", None) == "POST",
            timeout=30_000,
        ) as response_info:
            page.locator("#loginButton").click(timeout=30_000)
        response = response_info.value
        request_target_matches = _is_expected_owner_login_request(page, response.request)
        request_body = None
        try:
            post_data = response.request.post_data
            request_body = json.loads(post_data) if isinstance(post_data, str) else None
        except (TypeError, ValueError):
            request_body = None
        submitted_username_matches = (
            isinstance(request_body, dict) and request_body.get("username") == username
        )
        submitted_password_matches = (
            isinstance(request_body, dict)
            and isinstance(request_body.get("password"), str)
            and request_body.get("password") == password
        )
        credentials_submitted = bool(
            request_target_matches and submitted_username_matches and submitted_password_matches
        )
        body = response.json()
        if response.status == 200 and isinstance(body, dict):
            state = _renderer_owner_auth_state(page)
            return {
                "http_status": response.status,
                "authenticated": credentials_submitted and body.get("authenticated") is True,
                "username": body.get("username") if credentials_submitted else None,
                "renderer_authenticated": credentials_submitted and state.get("authenticated") is True,
                "credentials_submitted": credentials_submitted,
                "submitted_username_matches": submitted_username_matches,
                "submitted_password_matches": submitted_password_matches,
            }
        error_code = body.get("error") if isinstance(body, dict) else None
        return {
            "http_status": response.status,
            "authenticated": False,
            "credentials_submitted": credentials_submitted,
            "submitted_username_matches": submitted_username_matches,
            "submitted_password_matches": submitted_password_matches,
            "error_code": error_code
            if isinstance(error_code, str) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", error_code)
            else None,
        }
    except Exception as exc:
        return {
            "http_status": None,
            "authenticated": False,
            "credentials_submitted": credentials_submitted,
            "submitted_username_matches": submitted_username_matches,
            "submitted_password_matches": submitted_password_matches,
            "error_type": type(exc).__name__,
        }


def _model_runtime_after_restart(page, executable: Path, progress: list[dict], *, verify_inference: bool) -> dict:
    result: dict = {"status": "FAIL", "inference_after_restart": {"status": "NOT_RUN"}}
    try:
        state = _model_state(page)
        qwen = _find_qwen(state)
        if not qwen:
            raise RuntimeError("qwen3_4b_missing_after_application_restart")
        try:
            state = _wait_for_model(
                page,
                lambda current, model, operation: bool(
                    model
                    and model.get("model_id") == EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
                    and model.get("installed") is True
                    and model.get("selected") is True
                    and model.get("active") is True
                    and ((current.get("manager") or {}).get("runtime") or {}).get("status") == "ready"
                    and ((current.get("manager") or {}).get("runtime") or {}).get("model_id")
                    == EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
                    and operation.get("status") not in {"failed", "interrupted"}
                ),
                timeout=MODEL_RESTORE_TIMEOUT_SECONDS,
                phase="post_restart_model_runtime_restore",
                progress=progress,
            )
        except Exception as exc:
            result["restore_error_type"] = type(exc).__name__
            state = _model_state(page)
        qwen = _find_qwen(state)
        manager = state.get("manager") if isinstance(state.get("manager"), dict) else {}
        runtime = manager.get("runtime") if isinstance(manager.get("runtime"), dict) else {}
        operation = manager.get("operation") if isinstance(manager.get("operation"), dict) else {}
        digest = _qwen_installed_digest_report(qwen)
        runtime_binary = _installed_runtime_binary_evidence(executable)
        ready = bool(
            qwen
            and qwen.get("model_id") == EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
            and qwen.get("installed") is True
            and qwen.get("selected") is True
            and qwen.get("active") is True
            and runtime.get("status") == "ready"
            and runtime.get("model_id") == EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
            and digest.get("verified") is True
        )
        result.update({
            "model_id": qwen.get("model_id") if qwen else None,
            "catalog_sha256": qwen.get("sha256") if qwen else None,
            "installed_sha256": qwen.get("installed_sha256") if qwen else None,
            "installed_digest_verification": digest,
            "selected_after_restart": qwen.get("selected") is True if qwen else False,
            "active_after_restart": qwen.get("active") is True if qwen else False,
            "runtime_status_after_restart": runtime.get("status"),
            "runtime_model_id_after_restart": runtime.get("model_id"),
            "runtime_operation_after_restart": operation.get("status"),
            "runtime_binary": runtime_binary,
            "runtime_ready_after_restart": ready,
        })
        if verify_inference and ready:
            model_id = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
            response = _public_api(
                page, "POST", f"/api/public/desktop/models/{model_id}/test",
                csrf=_new_csrf_token(page), payload={},
            )
            inference = response["body"]
            state = _wait_for_model(
                page,
                lambda current, model, op: bool(
                    op.get("kind") == "inference_test"
                    and op.get("model_id") == model_id
                    and op.get("status") == "complete"
                    and isinstance(op.get("result"), str)
                    and op.get("result")
                ),
                timeout=300,
                phase="post_restart_real_local_inference",
                progress=progress,
            )
            operation = ((state.get("manager") or {}).get("operation") or {})
            inference_text = str(inference.get("response", operation.get("result", "")))
            inference_pass = (
                response["http_status"] == 200
                and inference.get("ok") is True
                and inference.get("provider") == "local_llama_cpp"
                and inference.get("model") == model_id
                and inference.get("real_inference") is True
                and bool(inference_text.strip())
            )
            result["inference_after_restart"] = {
                "status": "PASS" if inference_pass else "FAIL",
                "http_status": response["http_status"],
                "provider": inference.get("provider"),
                "model": inference.get("model"),
                "real_inference": inference.get("real_inference"),
                "response_bytes": len(inference_text.encode("utf-8")),
                "response_sha256": _sha256(inference_text),
            }
        elif verify_inference:
            result["inference_after_restart"] = {"status": "BLOCKED", "reason": "runtime_not_ready"}
        else:
            result["inference_after_restart"] = {"status": "NOT_RUN", "reason": "verified_on_first_restart_cycle"}
        result["status"] = "PASS" if ready and result["inference_after_restart"]["status"] in ("PASS", "NOT_RUN") else "FAIL"
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["status"] = "FAIL"
    return result


class _MissionAuditSnapshotError(RuntimeError):
    def __init__(self, failure_class: str, reason_code: str) -> None:
        super().__init__(reason_code)
        self.failure_class = failure_class
        self.reason_code = reason_code


def _mission_audit_snapshot(page, mission_id: str, profile_root: Path) -> dict:
    mission_path = "/api/public/missions/" + mission_id
    results = {
        "status": _public_api(page, "GET", mission_path + "/status"),
        "timeline": _public_api(page, "GET", mission_path + "/timeline"),
        "evidence": _public_api(page, "GET", mission_path + "/evidence"),
        "report": _public_api(page, "GET", mission_path + "/report"),
        "effects": _public_api(page, "GET", mission_path + "/effects"),
    }
    if any(item["http_status"] != 200 for item in results.values()):
        raise _MissionAuditSnapshotError("restoration", "mission_audit_endpoints_unavailable")
    status = results["status"]["body"].get("status")
    timeline = results["timeline"]["body"].get("timeline")
    evidence = results["evidence"]["body"].get("evidence")
    report = results["report"]["body"].get("report")
    effects = results["effects"]["body"].get("effects")
    if (
        not isinstance(status, dict)
        or not isinstance(timeline, list)
        or not isinstance(evidence, list)
        or not isinstance(report, dict)
        or not isinstance(effects, list)
    ):
        raise _MissionAuditSnapshotError("restoration", "mission_audit_payload_invalid")
    full_chain, full_chain_status = _read_profile_evidence_chain_diagnostic(profile_root)
    return {
        "status": status,
        "timeline": timeline,
        "evidence": evidence,
        "report": report,
        "effects": effects,
        "full_execution_chain": full_chain,
        "full_execution_chain_status": full_chain_status,
    }


_REPORT_MISSION_STATUSES = frozenset({
    "CREATED", "PLANNING", "READY", "RUNNING", "OBSERVING", "VERIFYING",
    "REPLANNING", "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED",
    "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED", "RECOVERY_REQUIRED",
    "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
})
_REPORT_OUTCOMES = frozenset({
    "RECOVERY_REQUIRED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED", "UNKNOWN",
    "VERIFIED", "NOT_VERIFIED", "PARTIALLY_VERIFIED",
})
_REPORT_FINDING_STATUSES = frozenset({
    "PASS", "FAIL", "UNKNOWN", "UNVERIFIED_PROVENANCE", "UNVERIFIED_MODEL_PROPOSAL",
})
_REPORT_CHAIN_STATUSES = frozenset({"VALID", "INVALID", "UNREADABLE", "UNKNOWN", "NOT_PRESENT"})
_REPORT_GOAL_VERIFICATION_STATUSES = frozenset({
    "TRUSTED_DETERMINISTIC_SOURCE", "UNVERIFIED_PROVENANCE",
})
_REPORT_CONFIDENCE_VERIFICATION_STATUSES = frozenset({
    "TRUSTED_SOURCE", "UNVERIFIED_PROVENANCE",
})
_REPORT_OWNER_APPROVAL_STATUSES = frozenset({
    "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED", "INVALID", "RECORDED", "NOT_RECORDED",
})
_REPORT_FINAL_APPROVAL_STATUSES = frozenset({"PENDING", "APPROVED", "STALE"})
_STATUS_GENERIC_VALUES = (
    _REPORT_MISSION_STATUSES | _REPORT_OUTCOMES | _REPORT_FINDING_STATUSES
    | _REPORT_CHAIN_STATUSES | _REPORT_GOAL_VERIFICATION_STATUSES
    | _REPORT_CONFIDENCE_VERIFICATION_STATUSES | _REPORT_OWNER_APPROVAL_STATUSES
    | _REPORT_FINAL_APPROVAL_STATUSES
    | frozenset({
        "COMPLETED", "SUCCEEDED", "SUCCESS", "PASSED", "OBSERVED", "VERIFIED",
        "NOT_RECORDED", "RECORDED", "PAUSED", "NEEDS_INPUT", "QUEUED", "ACTIVE",
        "EXECUTING", "SCHEDULED", "RETRY_SCHEDULED", "OCCURRENCE_SCHEDULED",
        "IN_FLIGHT", "IN_FLIGHT_PARALLEL", "NOT_DISPATCHED", "NOT_DISPATCHED_PARALLEL",
        "BUDGET_BLOCKED", "SPECIALISTS_QUARANTINED", "NOT_GENERATED_RESOURCE_LIMITED",
        "GENERATED_COMPACT_NO_TOOLS", "VALIDATED_STATUS_SNAPSHOT", "STARTING", "STOPPING",
        "STOPPED", "IDLE", "COMPLETE", "CANCELLING", "AUTHORIZED", "UNAUTHORIZED", "OK",
        "ALLOWED", "DENIED", "CHAIN_PROVENANCE_CLASSIFICATION", "PROVIDER_UNAVAILABLE",
        "INVALID_PROPOSAL", "QUARANTINED_PROVIDER_OUTCOME_UNKNOWN", "VALIDATED",
        "NOT_VALIDATED", "TRANSIENT", "DEPENDENCY", "COMPILATION", "TEST_FAILURE",
        "NETWORK", "PROVIDER", "TOOL", "AUTHORIZATION", "SCOPE", "RESOURCE", "LOGIC",
    })
)
_STATUS_SCALAR_ALLOWLISTS = {
    "status": _STATUS_GENERIC_VALUES,
    "mission_status": _REPORT_MISSION_STATUSES,
    "outcome": _REPORT_OUTCOMES,
    "state": _STATUS_GENERIC_VALUES,
    "result_status": _STATUS_GENERIC_VALUES,
    "verification": _REPORT_GOAL_VERIFICATION_STATUSES
    | _REPORT_CONFIDENCE_VERIFICATION_STATUSES
    | frozenset({"OBSERVED", "VERIFIED", "CHAIN_PROVENANCE_CLASSIFICATION"}),
    "verification_status": _REPORT_GOAL_VERIFICATION_STATUSES
    | _REPORT_CONFIDENCE_VERIFICATION_STATUSES
    | frozenset({"OBSERVED", "VERIFIED", "NOT_VERIFIED", "PARTIALLY_VERIFIED"}),
    "verification_state": _REPORT_GOAL_VERIFICATION_STATUSES
    | _REPORT_CONFIDENCE_VERIFICATION_STATUSES
    | frozenset({"OBSERVED", "VERIFIED", "NOT_VERIFIED", "PARTIALLY_VERIFIED"}),
    "report_verification": _REPORT_GOAL_VERIFICATION_STATUSES
    | _REPORT_CONFIDENCE_VERIFICATION_STATUSES
    | frozenset({"CHAIN_PROVENANCE_CLASSIFICATION"}),
    "report_status": _REPORT_MISSION_STATUSES | _REPORT_OUTCOMES | _REPORT_FINDING_STATUSES,
    "execution_chain_integrity": _REPORT_CHAIN_STATUSES,
    "evidence_status": _STATUS_GENERIC_VALUES,
    "authorization_status": frozenset({
        "ALLOWED", "DENIED", "AUTHORIZED", "UNAUTHORIZED", "APPROVED", "REJECTED", "PENDING",
    }),
    "decision": frozenset({
        "ALLOWED", "DENIED", "AUTHORIZED", "UNAUTHORIZED", "APPROVED", "REJECTED", "PENDING", "STALE",
    }),
    "failure_class": frozenset({
        "TRANSIENT", "DEPENDENCY", "COMPILATION", "TEST_FAILURE", "NETWORK", "PROVIDER",
        "TOOL", "AUTHORIZATION", "SCOPE", "RESOURCE", "LOGIC", "UNKNOWN",
    }),
    "validation_state": _STATUS_GENERIC_VALUES,
    "result_validation_state": _STATUS_GENERIC_VALUES,
}


def _report_status_is_allowed(value: object, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _completed_report_status_fields_are_valid(report: dict, summary: dict, verification: dict) -> bool:
    if (
        report.get("schema_version") != "cybersentinel.mission-report.v1"
        or not all(key in report for key in (
            "findings", "evidence", "confidence", "unknown_states",
            "owner_approval_status", "final_report_approval",
        ))
        or not _report_status_is_allowed(summary.get("mission_status"), _REPORT_MISSION_STATUSES)
        or summary.get("mission_status") != "GOAL_COMPLETED"
        or not _report_status_is_allowed(summary.get("outcome"), _REPORT_OUTCOMES)
        or summary.get("outcome") != "VERIFIED"
        or not all(key in verification for key in (
            "verified", "runtime_reported_verified", "missing_criteria", "evidence_count",
            "trusted_evidence_count", "unverified_evidence_count", "required_criteria_count",
        ))
        or verification.get("verified") is not True
        or verification.get("runtime_reported_verified") is not True
        or not isinstance(verification.get("missing_criteria"), list)
        or verification.get("missing_criteria")
        or not isinstance(report.get("unknown_states"), list)
        or report.get("unknown_states")
    ):
        return False

    for field in ("evidence_count", "trusted_evidence_count", "required_criteria_count"):
        if type(verification.get(field)) is not int or verification[field] <= 0:
            return False
    if (
        type(verification.get("unverified_evidence_count")) is not int
        or verification["unverified_evidence_count"] != 0
    ):
        return False

    findings = report.get("findings")
    if not isinstance(findings, list) or not findings or any(
        not isinstance(item, dict)
        or not _report_status_is_allowed(item.get("status"), _REPORT_FINDING_STATUSES)
        for item in findings
    ):
        return False

    evidence = report.get("evidence")
    if (
        not isinstance(evidence, dict)
        or not _report_status_is_allowed(evidence.get("execution_chain_integrity"), _REPORT_CHAIN_STATUSES)
        or not isinstance(evidence.get("goal"), list)
        or any(
            not isinstance(item, dict)
            or not _report_status_is_allowed(
                item.get("report_verification"), _REPORT_GOAL_VERIFICATION_STATUSES
            )
            for item in evidence["goal"]
        )
        or not isinstance(evidence.get("unverified_model_proposals"), list)
        or any(
            not isinstance(proposal, dict)
            or proposal.get("verification") != "UNVERIFIED_MODEL_PROPOSAL"
            or not isinstance(proposal.get("proposed_evidence"), list)
            or any(
                not isinstance(item, dict)
                or item.get("verification") != "UNVERIFIED_MODEL_PROPOSAL"
                for item in proposal["proposed_evidence"]
            )
            for proposal in evidence["unverified_model_proposals"]
        )
    ):
        return False

    confidence = report.get("confidence")
    if (
        not isinstance(confidence, dict)
        or not isinstance(confidence.get("items"), list)
        or any(
            not isinstance(item, dict)
            or not _report_status_is_allowed(
                item.get("verification"), _REPORT_CONFIDENCE_VERIFICATION_STATUSES
            )
            for item in confidence["items"]
        )
    ):
        return False

    owner_approval = report.get("owner_approval_status")
    if (
        not isinstance(owner_approval, dict)
        or not _report_status_is_allowed(
            owner_approval.get("status"), _REPORT_OWNER_APPROVAL_STATUSES
        )
        or owner_approval.get("status") not in {"RECORDED", "NOT_RECORDED"}
        or owner_approval.get("source") != "mission_authorization_snapshot"
        or owner_approval.get("scope") != "mission-level authorization only; action-level approval is not assessed"
        or owner_approval.get("current_authority") != "not_assessed"
    ):
        return False

    final_approval = report.get("final_report_approval")
    return (
        isinstance(final_approval, dict)
        and _report_status_is_allowed(
            final_approval.get("status"), _REPORT_FINAL_APPROVAL_STATUSES
        )
    )


def _completed_report_verification_is_consistent(
    report: dict, summary: dict, verification: dict
) -> bool:
    """Accept only the producer's complete, internally consistent verified status schema."""
    return _completed_report_status_fields_are_valid(report, summary, verification)


_TRAJECTORY_EVENT_FIELDS = frozenset({
    "event", "mission_id", "request_id", "step_id", "timestamp",
    "provenance", "data", "previous_hash", "event_hash",
})
_TRAJECTORY_EVENT_NAMES = frozenset(item.value for item in _TrajectoryEventType)


def _trajectory_timeline_integrity(timeline: object, mission_id: object, request_id: object) -> bool:
    """Validate the exact event shape and hash-linked order emitted by Mission.trajectory."""
    if (
        not isinstance(timeline, list) or not timeline
        or not isinstance(mission_id, str) or not mission_id.strip()
        or not isinstance(request_id, str) or not request_id.strip()
    ):
        return False
    previous_hash = ""
    seen_hashes: set[str] = set()
    for index, event in enumerate(timeline):
        if not isinstance(event, dict) or set(event) != _TRAJECTORY_EVENT_FIELDS:
            return False
        if (
            event.get("event") not in _TRAJECTORY_EVENT_NAMES
            or event.get("mission_id") != mission_id
            or event.get("request_id") != request_id
            or not isinstance(event.get("step_id"), str)
            or not isinstance(event.get("timestamp"), str)
            or not event["timestamp"].strip()
            or not isinstance(event.get("provenance"), dict)
            or not isinstance(event.get("data"), dict)
        ):
            return False
        try:
            timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            return False
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return False
        event_hash = event.get("event_hash")
        if (
            not isinstance(event_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", event_hash) is None
            or event_hash in seen_hashes
            or event.get("previous_hash") != previous_hash
        ):
            return False
        if index == 0 and event.get("event") != _TrajectoryEventType.MISSION_STARTED.value:
            return False
        seen_hashes.add(event_hash)
        previous_hash = event_hash
    try:
        return _verify_trajectory(timeline) is True
    except Exception:
        return False


def _mission_record_integrity_verified(status: object) -> bool:
    """Verify the persisted Mission envelope returned by status, excluding its API-only queue view."""
    if not isinstance(status, dict):
        return False
    record = dict(status)
    record.pop("queue", None)
    try:
        mission = _Mission.from_dict(record)
        return mission.verify_integrity() is True
    except Exception:
        return False


_RESTART_STABLE_PROJECTION_FIELDS = (
    "mission_id", "mission_record_integrity_verified",
    "timeline_matches_integrity_checked_mission", "timeline_integrity_verified",
    "status_mission_id_matches", "report_mission_id_matches", "provenance_mission_id_matches",
    "timeline_records_bound_to_mission", "evidence_and_chain_bound_to_mission",
    "evidence_records_bound_to_mission", "execution_chain_records_bound_to_mission",
    "execution_chain_provenance_bound_to_mission", "execution_chain_provenance_matches_payload",
    "mission_request_binding_verified", "project_test_evidence_source_verified",
    "project_test_execution_proof", "validation_record_bound_to_mission", "mission_status",
    "mission_plan_sha256", "mission_plan_history_sha256",
    "queue_state", "pause_requested", "tool_execution_count", "tool_projection",
    "action_history_count", "action_history_sha256", "timeline_event_count", "timeline_sha256",
    "evidence_item_count", "evidence_sha256", "validation_sha256", "report_sha256",
    "report_body_sha256", "report_digest_matches_canonical_body", "report_digest_scope_matches_producer",
    "report_producer_payload_matches_status", "report_producer_source_sha256", "report_provenance_sha256",
    "report_evidence_digest_matches_source",
    "report_execution_chain_head_matches_source", "report_verification_counts_match_source",
    "report_outcome", "report_verified", "report_verification_summary_consistent",
    "report_projection_valid", "completed_mission_inspectable",
    "effect_ledger", "execution_chain_integrity", "independent_execution_chain_integrity",
    "execution_chain_storage_status", "execution_chain_storage_verified",
    "execution_chain_receipts_verified", "full_execution_chain_count", "full_execution_chain_sha256",
    "execution_chain_hash_valid", "execution_chain_integrity_verified", "final_report_approval_status",
)

_RESTART_PROJECTION_HASH_FIELDS = frozenset({
    "mission_plan_sha256", "mission_plan_history_sha256", "action_history_sha256",
    "timeline_sha256", "evidence_sha256", "validation_sha256", "report_sha256",
    "report_body_sha256", "report_producer_source_sha256", "report_provenance_sha256",
    "full_execution_chain_sha256",
})
_RESTART_PROJECTION_BOOLEAN_FIELDS = frozenset({
    "mission_record_integrity_verified", "timeline_matches_integrity_checked_mission",
    "timeline_integrity_verified", "status_mission_id_matches", "report_mission_id_matches",
    "provenance_mission_id_matches", "timeline_records_bound_to_mission",
    "evidence_and_chain_bound_to_mission", "evidence_records_bound_to_mission",
    "execution_chain_records_bound_to_mission", "execution_chain_provenance_bound_to_mission",
    "execution_chain_provenance_matches_payload", "mission_request_binding_verified",
    "project_test_evidence_source_verified", "pause_requested",
    "report_digest_matches_canonical_body", "report_digest_scope_matches_producer",
    "report_producer_payload_matches_status", "report_evidence_digest_matches_source",
    "report_execution_chain_head_matches_source", "report_verification_counts_match_source",
    "report_verified", "report_verification_summary_consistent", "report_projection_valid",
    "completed_mission_inspectable", "execution_chain_storage_verified",
    "execution_chain_receipts_verified", "execution_chain_hash_valid",
    "execution_chain_integrity_verified",
})
_RESTART_PROJECTION_COUNT_FIELDS = frozenset({
    "tool_execution_count", "action_history_count", "timeline_event_count",
    "evidence_item_count", "full_execution_chain_count",
})
_RESTART_PROJECTION_TEXT_FIELDS = frozenset({
    "mission_id", "mission_status", "queue_state", "report_outcome",
    "execution_chain_integrity", "independent_execution_chain_integrity",
    "execution_chain_storage_status", "final_report_approval_status",
})
_RESTART_PROJECTION_MAPPING_FIELDS = frozenset({
    "project_test_execution_proof", "tool_projection", "effect_ledger",
})
_RESTART_REQUIRED_TRUE_FIELDS = frozenset({
    "mission_record_integrity_verified", "timeline_matches_integrity_checked_mission",
    "timeline_integrity_verified", "status_mission_id_matches", "report_mission_id_matches",
    "provenance_mission_id_matches", "timeline_records_bound_to_mission",
    "evidence_and_chain_bound_to_mission", "evidence_records_bound_to_mission",
    "execution_chain_records_bound_to_mission", "execution_chain_provenance_bound_to_mission",
    "execution_chain_provenance_matches_payload", "mission_request_binding_verified",
    "report_digest_matches_canonical_body", "report_digest_scope_matches_producer",
    "report_producer_payload_matches_status", "report_evidence_digest_matches_source",
    "report_execution_chain_head_matches_source", "report_verification_counts_match_source",
    "execution_chain_hash_valid", "execution_chain_integrity_verified",
    "execution_chain_storage_verified", "execution_chain_receipts_verified",
})


def _invalid_restart_projection_fields(projection: dict) -> set[str]:
    required = set(_RESTART_STABLE_PROJECTION_FIELDS) | _RESTART_PROJECTION_MAPPING_FIELDS
    invalid = {field for field in required if field not in projection}
    for field in required - invalid:
        value = projection[field]
        if value is None or (isinstance(value, str) and not value.strip()):
            invalid.add(field)
    for field in _RESTART_PROJECTION_HASH_FIELDS:
        if field not in projection or not isinstance(projection[field], str) or re.fullmatch(
            r"[0-9a-f]{64}", projection[field]
        ) is None:
            invalid.add(field)
    for field in _RESTART_PROJECTION_BOOLEAN_FIELDS:
        if field not in projection or type(projection[field]) is not bool:
            invalid.add(field)
    for field in _RESTART_PROJECTION_COUNT_FIELDS:
        if field not in projection or type(projection[field]) is not int or projection[field] < 0:
            invalid.add(field)
    for field in _RESTART_PROJECTION_TEXT_FIELDS:
        if field not in projection or not isinstance(projection[field], str) or not projection[field].strip():
            invalid.add(field)
    for field in _RESTART_PROJECTION_MAPPING_FIELDS:
        if field not in projection or not isinstance(projection[field], dict) or not projection[field]:
            invalid.add(field)
    return invalid


def _mission_restart_reconciliation(
    before: dict, after: dict, *, allow_owner_reauth_transition: bool = False
) -> dict:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return {"reconciled": False, "mismatched_fields": ["snapshot"]}
    invalid_fields = _invalid_restart_projection_fields(before) | _invalid_restart_projection_fields(after)
    invalid_fields.update(
        field for field in _RESTART_REQUIRED_TRUE_FIELDS
        if before.get(field) is not True or after.get(field) is not True
    )
    if before.get("mission_id") != after.get("mission_id"):
        invalid_fields.add("mission_id")
    owner_reauth_transition = (
        allow_owner_reauth_transition and not invalid_fields
        and before.get("mission_status") in {"RUNNING", "OBSERVING", "VERIFYING", "REPLANNING"}
        and before.get("queue_state") == "paused"
        and before.get("pause_requested") is True
        and before.get("report_digest_matches_canonical_body") is True
        and before.get("report_digest_scope_matches_producer") is True
        and before.get("report_producer_payload_matches_status") is True
        and before.get("report_evidence_digest_matches_source") is True
        and before.get("report_execution_chain_head_matches_source") is True
        and before.get("report_verification_counts_match_source") is True
        and after.get("mission_status") == "OWNER_REAUTH_REQUIRED"
        and after.get("queue_state") == "needs_input"
        and after.get("pause_requested") is True
        and after.get("report_digest_matches_canonical_body") is True
        and after.get("report_digest_scope_matches_producer") is True
        and after.get("report_producer_payload_matches_status") is True
        and after.get("report_evidence_digest_matches_source") is True
        and after.get("report_execution_chain_head_matches_source") is True
        and after.get("report_verification_counts_match_source") is True
        and isinstance(before.get("report_producer_source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", before["report_producer_source_sha256"]) is not None
        and before.get("report_producer_source_sha256") == after.get("report_producer_source_sha256")
        and isinstance(before.get("report_provenance_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", before["report_provenance_sha256"]) is not None
        and before.get("report_provenance_sha256") == after.get("report_provenance_sha256")
    )
    justified_transition_fields = {
        "mission_status", "queue_state", "validation_sha256", "project_test_evidence_source_verified",
        "project_test_execution_proof", "report_sha256", "report_body_sha256",
        "report_digest_matches_canonical_body", "report_producer_payload_matches_status",
        "report_evidence_digest_matches_source", "report_execution_chain_head_matches_source",
        "report_verification_counts_match_source", "report_outcome", "report_verified",
        "report_verification_summary_consistent", "report_projection_valid",
        "completed_mission_inspectable", "final_report_approval_status",
    } if owner_reauth_transition else set()
    mismatches = sorted(invalid_fields | {
        field for field in _RESTART_STABLE_PROJECTION_FIELDS
        if field not in justified_transition_fields and before.get(field) != after.get(field)
    })
    return {
        "reconciled": not mismatches,
        "mismatched_fields": mismatches,
        "owner_reauth_transition_justified": owner_reauth_transition,
        "report_digest_changed": before.get("report_sha256") != after.get("report_sha256"),
        "timeline_hash_unchanged": before.get("timeline_sha256") == after.get("timeline_sha256"),
        "action_history_hash_unchanged": before.get("action_history_sha256") == after.get("action_history_sha256"),
        "global_chain_hash_unchanged": before.get("full_execution_chain_sha256")
        == after.get("full_execution_chain_sha256"),
    }


def _report_status_scan_view(report: dict, mission_chain: list) -> dict:
    """Mask only the producer's non-authoritative confidence label for chain rows."""
    confidence = report.get("confidence")
    if not isinstance(confidence, dict) or not isinstance(confidence.get("items"), list):
        return report
    chain_confidence = {
        (record.get("source"), record.get("evidence_id")): record.get("confidence")
        for record in mission_chain
        if isinstance(record, dict)
    }
    normalized_items = []
    for item in confidence["items"]:
        if not isinstance(item, dict):
            normalized_items.append(item)
            continue
        key = (item.get("source"), item.get("evidence_id"))
        if (
            item.get("verification") == "UNVERIFIED_PROVENANCE"
            and key in chain_confidence
            and item.get("confidence") == chain_confidence[key]
        ):
            normalized_items.append({**item, "verification": "CHAIN_PROVENANCE_CLASSIFICATION"})
        else:
            normalized_items.append(item)
    return {**report, "confidence": {**confidence, "items": normalized_items}}


def _report_producer_source_sha256(status: dict) -> str:
    source_fields = (
        "mission_id", "request_id", "objective", "current_step", "iteration_count",
        "verification_state", "evidence", "completion_criteria", "failures",
        "action_history", "interpretations", "authorization_snapshot", "owner_identity_ref",
    )
    progress = status.get("progress")
    source = {field: status.get(field) for field in source_fields}
    source["final_report_approval"] = (
        progress.get("final_report_approval") if isinstance(progress, dict) else None
    )
    return _canonical_sha256(source)


def _mission_audit_projection(snapshot: dict, mission_id: str) -> dict:
    status = snapshot.get("status") if isinstance(snapshot.get("status"), dict) else {}
    timeline = snapshot.get("timeline") if isinstance(snapshot.get("timeline"), list) else []
    evidence = snapshot.get("evidence") if isinstance(snapshot.get("evidence"), list) else []
    report = snapshot.get("report") if isinstance(snapshot.get("report"), dict) else {}
    summary = report.get("mission_summary") if isinstance(report.get("mission_summary"), dict) else {}
    verification = summary.get("verification") if isinstance(summary.get("verification"), dict) else {}
    report_verification_consistent = _completed_report_verification_is_consistent(
        report, summary, verification
    )
    report_evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    chain = report_evidence.get("execution_chain") if isinstance(report_evidence.get("execution_chain"), list) else []
    full_chain = snapshot.get("full_execution_chain")
    full_chain_storage_status = snapshot.get("full_execution_chain_status")
    provenance = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    effects = _effect_ledger_projection(snapshot.get("effects", []), mission_id)
    request_id = provenance.get("request_id") if isinstance(provenance.get("request_id"), str) else ""
    status_request_id = status.get("request_id")
    provenance_chain = provenance.get("execution_chain") if isinstance(provenance.get("execution_chain"), list) else []
    timeline_records_bound = bool(timeline) and all(
        isinstance(item, dict)
        and _record_bound_to_mission(item, mission_id)
        and isinstance(status_request_id, str) and bool(status_request_id)
        and item.get("request_id") == status_request_id
        for item in timeline
    )
    timeline_integrity_verified = _trajectory_timeline_integrity(
        timeline, mission_id, status_request_id
    )
    mission_record_integrity_verified = _mission_record_integrity_verified(status)
    timeline_matches_integrity_checked_mission = (
        mission_record_integrity_verified
        and isinstance(status.get("trajectory"), list)
        and status["trajectory"] == timeline
    )
    evidence_records_bound = bool(evidence) and all(
        _record_bound_to_mission(item, mission_id)
        and _record_request_binding(item, request_id, require_present=False)
        for item in evidence
    )
    chain_records_bound = bool(chain) and all(
        isinstance(item, dict)
        and item.get("mission_id") == mission_id
        and item.get("request_id") == request_id
        and _record_bound_to_mission(item, mission_id)
        and _record_request_binding(item, request_id, require_present=True)
        and isinstance(item.get("evidence_id"), str)
        and bool(item.get("evidence_id"))
        and type(item.get("sequence")) is int
        and item.get("sequence") > 0
        and re.fullmatch(r"[0-9a-f]{64}", str(item.get("current_hash", ""))) is not None
        for item in chain
    )
    provenance_chain_bound = bool(provenance_chain) and all(
        isinstance(item, dict)
        and item.get("mission_id") == mission_id
        and item.get("request_id") == request_id
        and _record_bound_to_mission(item, mission_id)
        and _record_request_binding(item, request_id, require_present=True)
        for item in provenance_chain
    )
    chain_identity_fields = (
        "evidence_id", "source", "sequence", "previous_hash", "current_hash",
        "mission_id", "request_id", "task_id", "execution_id",
        "worker_id", "worker_instance_id", "runtime_generation", "lease_epoch",
        "task_version", "authorization_hash", "fence_id",
    )
    provenance_chain_matches_payload = (
        len(chain) == len(provenance_chain)
        and all(
            all(projected.get(key) == payload.get(key) for key in chain_identity_fields)
            for projected, payload in zip(provenance_chain, chain)
            if isinstance(projected, dict) and isinstance(payload, dict)
        )
    )
    chain_integrity = report_evidence.get("execution_chain_integrity")
    independent_chain_integrity = _independent_execution_chain_status(
        full_chain, status, mission_id, request_id
    )
    mission_filtered_global_chain = [
        item for item in full_chain
        if isinstance(item, dict)
        and (
            item.get("mission_id") == mission_id
            or (not item.get("mission_id") and bool(request_id) and item.get("request_id") == request_id)
        )
    ] if isinstance(full_chain, list) else []
    full_chain_storage_verified = (
        full_chain_storage_status == "VALID"
        and independent_chain_integrity == "VALID"
    )
    expected_report = _producer_report_from_status(
        status, mission_filtered_global_chain, independent_chain_integrity
    )
    report_producer_payload_matches = expected_report == report
    report_digest_scope_matches = report.get("report_digest_scope") == _REPORT_DIGEST_SCOPE
    expected_report_evidence = (
        expected_report.get("evidence") if isinstance(expected_report, dict) else None
    )
    report_evidence_digest_matches_source = (
        isinstance(expected_report_evidence, dict)
        and report_evidence.get("digest_sha256") == expected_report_evidence.get("digest_sha256")
    )
    report_execution_chain_head_matches = (
        isinstance(expected_report_evidence, dict)
        and report_evidence.get("execution_chain_head") == expected_report_evidence.get("execution_chain_head")
    )
    expected_verification = (
        (expected_report.get("mission_summary") or {}).get("verification")
        if isinstance(expected_report, dict) else None
    )
    report_verification_counts_match_source = (
        isinstance(expected_verification, dict)
        and verification == expected_verification
    )
    project_test_execution_proof = _mission_project_test_execution_proof(
        status,
        timeline,
        evidence,
        report_evidence.get("goal"),
        chain,
        mission_id,
        request_id,
        chain_integrity,
        full_execution_chain=full_chain,
    )
    project_test_evidence_sources = (
        ["sandboxed-process:run_project_tests"]
        if project_test_execution_proof.get("verified") is True else []
    )
    tool_execution_count = sum(
        isinstance(item, dict) and item.get("event") == "ToolExecuted" for item in timeline
    )
    mission_plan = status.get("plan")
    mission_plan_history = status.get("plan_history")
    binding_verified = (
        status.get("mission_id") == mission_id
        and summary.get("mission_id") == mission_id
        and summary.get("request_id") == request_id
        and provenance.get("mission_id") == mission_id
        and bool(request_id)
        and _record_bound_to_mission(status, mission_id)
        and _record_request_binding(status, request_id, require_present=False)
        and _record_bound_to_mission(summary, mission_id)
        and _record_request_binding(summary, request_id, require_present=True)
        and _record_bound_to_mission(provenance, mission_id)
        and _record_request_binding(provenance, request_id, require_present=True)
        and timeline_records_bound
        and evidence_records_bound
        and chain_records_bound
        and provenance_chain_bound
        and provenance_chain_matches_payload
        and effects.get("mission_binding_verified") is True
    )
    report_sha256 = report.get("report_sha256")
    report_provenance_sha256 = _canonical_sha256(report.get("provenance"))
    report_producer_source_sha256 = _report_producer_source_sha256(status)
    validation_sha256 = _canonical_sha256(verification)
    report_body_sha256 = _canonical_report_body_sha256(report)
    report_digest_matches_body = (
        isinstance(report_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", report_sha256) is not None
        and report_sha256 == report_body_sha256
    )
    report_verified = (
        summary.get("mission_status") == status.get("status")
        and report_digest_matches_body
        and report_digest_scope_matches
        and report_producer_payload_matches
        and full_chain_storage_verified
        and project_test_execution_proof.get("execution_chain_integrity_verified") is True
        and binding_verified
        and report_verification_consistent
        and _record_bound_to_mission(report, mission_id)
        and not _contains_blocked_or_unverified_status(
            (status, _report_status_scan_view(report, chain))
        )
    )
    return {
        "mission_id": mission_id,
        "mission_record_integrity_verified": mission_record_integrity_verified,
        "timeline_matches_integrity_checked_mission": timeline_matches_integrity_checked_mission,
        "status_mission_id_matches": status.get("mission_id") == mission_id,
        "report_mission_id_matches": summary.get("mission_id") == mission_id,
        "provenance_mission_id_matches": provenance.get("mission_id") == mission_id,
        "timeline_records_bound_to_mission": timeline_records_bound,
        "timeline_integrity_verified": timeline_integrity_verified,
        "evidence_and_chain_bound_to_mission": binding_verified,
        "evidence_records_bound_to_mission": evidence_records_bound,
        "execution_chain_records_bound_to_mission": chain_records_bound,
        "execution_chain_provenance_bound_to_mission": provenance_chain_bound,
        "execution_chain_provenance_matches_payload": provenance_chain_matches_payload,
        "mission_request_binding_verified": bool(request_id)
        and summary.get("request_id") == request_id
        and _record_request_binding(status, request_id, require_present=False),
        "evidence_record_count": len(evidence),
        "validation_record_mission_id": summary.get("mission_id"),
        "validation_record_bound_to_mission": (
            summary.get("mission_id") == mission_id
            and _record_bound_to_mission(summary, mission_id)
            and _record_request_binding(summary, request_id, require_present=True)
            and summary.get("mission_status") == status.get("status")
            and isinstance(verification.get("verified"), bool)
        ),
        "project_test_evidence_sources": project_test_evidence_sources,
        "project_test_evidence_source_verified": project_test_execution_proof.get("verified") is True,
        "project_test_execution_proof": project_test_execution_proof,
        "effect_ledger": effects,
        "mission_status": status.get("status"),
        "mission_plan_sha256": _canonical_sha256(mission_plan)
        if isinstance(mission_plan, dict) and mission_plan else None,
        "mission_plan_history_sha256": _canonical_sha256(mission_plan_history)
        if isinstance(mission_plan_history, list) and mission_plan_history else None,
        "queue_state": (status.get("queue") or {}).get("state") if isinstance(status.get("queue"), dict) else None,
        "pause_requested": (status.get("progress") or {}).get("pause_requested") is True
        if isinstance(status.get("progress"), dict) else False,
        "tool_execution_count": tool_execution_count,
        "tool_projection": _tool_execution_projection(status),
        "action_history_count": len(status.get("action_history"))
        if isinstance(status.get("action_history"), list) else None,
        "action_history_sha256": _canonical_sha256(status.get("action_history"))
        if isinstance(status.get("action_history"), list) else None,
        "timeline_event_count": len(timeline),
        "timeline_sha256": _canonical_sha256(timeline),
        "evidence_item_count": len(evidence),
        "evidence_sha256": _canonical_sha256(evidence),
        "validation_sha256": validation_sha256,
        "report_sha256": report_sha256,
        "report_body_sha256": report_body_sha256,
        "report_digest_matches_canonical_body": report_digest_matches_body,
        "report_digest_scope_matches_producer": report_digest_scope_matches,
        "report_producer_payload_matches_status": report_producer_payload_matches,
        "report_producer_source_sha256": report_producer_source_sha256,
        "report_provenance_sha256": report_provenance_sha256,
        "report_evidence_digest_matches_source": report_evidence_digest_matches_source,
        "report_execution_chain_head_matches_source": report_execution_chain_head_matches,
        "report_verification_counts_match_source": report_verification_counts_match_source,
        "report_outcome": summary.get("outcome"),
        "report_verified": verification.get("verified"),
        "report_verification_summary_consistent": report_verification_consistent,
        "execution_chain_integrity": chain_integrity,
        "execution_chain_hash_valid": (
            project_test_execution_proof.get("execution_chain_hash_valid") is True
        ),
        "execution_chain_integrity_verified": (
            project_test_execution_proof.get("execution_chain_integrity_verified") is True
        ),
        "independent_execution_chain_integrity": independent_chain_integrity,
        "execution_chain_storage_status": full_chain_storage_status,
        "execution_chain_storage_verified": full_chain_storage_verified,
        "execution_chain_receipts_verified": (
            project_test_execution_proof.get("execution_chain_receipts_verified") is True
        ),
        "full_execution_chain_count": len(full_chain) if isinstance(full_chain, list) else None,
        "full_execution_chain_sha256": _canonical_sha256(full_chain)
        if isinstance(full_chain, list) else None,
        "final_report_approval_status": (report.get("final_report_approval") or {}).get("status")
        if isinstance(report.get("final_report_approval"), dict) else None,
        "report_projection_valid": report_verified,
        "completed_mission_inspectable": (
            status.get("status") == "GOAL_COMPLETED"
            and summary.get("mission_status") == "GOAL_COMPLETED"
            and summary.get("outcome") == "VERIFIED"
            and report_verification_consistent
            and project_test_execution_proof.get("execution_chain_integrity_verified") is True
            and len(evidence) > 0
            and bool(chain)
            and evidence_records_bound
            and chain_records_bound
            and provenance_chain_bound
            and provenance_chain_matches_payload
            and project_test_execution_proof.get("verified") is True
            and effects.get("duplicate_effect_ids") is False
            and binding_verified
            and report_verified
        ),
    }


def _find_state_directory(profile_root: Path) -> Path:
    root = profile_root.expanduser().resolve(strict=True)
    for database in root.rglob("intel.sqlite3"):
        state = database.parent
        if state.name.casefold() == "state" and (state / "workspaces").is_dir():
            return state
    raise RuntimeError("installed_app_disposable_state_directory_not_found")


def _read_profile_evidence_chain_diagnostic(profile_root: Path) -> tuple[list[dict] | None, str]:
    """Read the complete profile chain read-only and keep storage vs integrity failures distinct."""
    try:
        root = profile_root.expanduser().resolve(strict=True)
        state_directory = (root / "userData" / "state").resolve(strict=True)
        if (
            not state_directory.is_relative_to(root)
            or not (state_directory / "intel.sqlite3").is_file()
            or not (state_directory / "workspaces").is_dir()
        ):
            return None, "UNREADABLE"
        evidence_path = state_directory / "evidence_chain.db"
        if not evidence_path.exists():
            return [], "NOT_PRESENT"
        evidence_path = evidence_path.resolve(strict=True)
        if not evidence_path.is_relative_to(state_directory):
            return None, "UNREADABLE"
        uri = "file:" + quote(str(evidence_path), safe="/:") + "?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            rows = db.execute(
                "SELECT sequence,current_hash,payload FROM evidence_chain ORDER BY sequence"
            ).fetchall()
        finally:
            db.close()
        records: list[dict] = []
        for row_sequence, row_hash, encoded_record in rows:
            if type(row_sequence) is not int or not isinstance(row_hash, str) or not isinstance(encoded_record, str):
                return None, "INVALID"
            record = json.loads(encoded_record)
            if (
                not isinstance(record, dict)
                or type(record.get("sequence")) is not int
                or record.get("sequence") != row_sequence
                or record.get("current_hash") != row_hash
            ):
                return None, "INVALID"
            records.append(record)
        if not records:
            return [], "NOT_PRESENT"
        if not _verify_durable_execution_chain(records):
            return None, "INVALID"
        receipt_status = _verify_profile_execution_chain_receipts(state_directory, records)
        return (records, "VALID") if receipt_status == "VALID" else (None, receipt_status)
    except (OSError, sqlite3.Error, json.JSONDecodeError, TypeError, ValueError, OverflowError, RuntimeError):
        return None, "UNREADABLE"


def _verify_profile_execution_chain_receipts(state_directory: Path, records: list[dict]) -> str:
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        return "INVALID"
    fenced_records = [record for record in records if isinstance(record, dict) and record.get("fence_id")]
    if not fenced_records:
        return "VALID"
    try:
        from agent.evidence import EvidenceChainStore
        from agent.mission import Mission

        expected_by_mission: dict[str, list[dict]] = {}
        for record in fenced_records:
            mission_id = record.get("mission_id")
            if not isinstance(mission_id, str) or not mission_id:
                return "INVALID"
            expected_by_mission.setdefault(mission_id, []).append(
                EvidenceChainStore._receipt(record)
            )
        state_root = state_directory.resolve(strict=True)
        mission_db_path = (state_root / "missions.sqlite3").resolve(strict=True)
        if not mission_db_path.is_relative_to(state_root) or not mission_db_path.is_file():
            return "UNREADABLE"
        uri = "file:" + quote(str(mission_db_path), safe="/:") + "?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            mission_rows = {}
            for mission_id in expected_by_mission:
                row = db.execute(
                    "SELECT payload FROM missions WHERE mission_id=?", (mission_id,)
                ).fetchone()
                if row is None or not isinstance(row[0], str):
                    return "INVALID"
                mission_rows[mission_id] = json.loads(row[0])
        finally:
            db.close()

        verified_missions = {}
        for mission_id, payload in mission_rows.items():
            if not isinstance(payload, dict) or payload.get("mission_id") != mission_id:
                return "INVALID"
            mission = Mission.from_dict(payload)
            if mission.mission_id != mission_id or not mission.verify_integrity():
                return "INVALID"
            refs = mission.progress.get("execution_evidence_refs")
            if not isinstance(refs, list) or any(not isinstance(item, dict) for item in refs):
                return "INVALID"
            verified_missions[mission_id] = refs
        for mission_id, expected_receipts in expected_by_mission.items():
            if verified_missions[mission_id] != expected_receipts:
                return "INVALID"
        return "VALID"
    except (sqlite3.Error, OSError, RuntimeError):
        return "UNREADABLE"
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return "INVALID"


def _read_profile_evidence_chain(profile_root: Path) -> list[dict] | None:
    """Compatibility wrapper for read-only loading of a fully valid profile chain."""
    records, status = _read_profile_evidence_chain_diagnostic(profile_root)
    return records if status == "VALID" else None


def _installed_app_mission(
    page, profile_root: Path, progress: list[dict], restart_callback, report: dict
) -> tuple[dict, object]:
    project_name = "Windows Acceptance " + secrets.token_hex(4)
    page.locator("#newProjectToggle").click(timeout=30_000)
    page.locator("#projectName").fill(project_name)
    page.locator("#projectDescription").fill("Disposable native Windows acceptance fixture; no external targets.")
    with page.expect_response(
        lambda response: response.request.method == "POST" and response.url.rstrip("/").endswith("/api/public/projects"),
        timeout=30_000,
    ) as project_response_info:
        page.locator("#projectForm button[type='submit']").click(timeout=30_000)
    project_response = project_response_info.value
    project_body = project_response.json()
    project = project_body.get("project") if isinstance(project_body, dict) else None
    project_id = str(project.get("project_id", "")) if isinstance(project, dict) else ""
    response_error = project_body.get("error") if isinstance(project_body, dict) else None
    progress.append({
        "phase": "installed_app_project_creation_response",
        "http_status": project_response.status,
        "response_ok": project_body.get("ok") is True if isinstance(project_body, dict) else False,
        "project_id_present": bool(project_id),
        "error_code": str(response_error)[:96] if response_error is not None else "",
    })
    if project_response.status != 201 or not project_id:
        raise RuntimeError("installed_app_disposable_project_creation_failed")

    state_directory = _find_state_directory(profile_root)
    project_root = (state_directory / "workspaces" / project_id).resolve(strict=True)
    if not project_root.is_relative_to(profile_root.expanduser().resolve(strict=True)):
        raise RuntimeError("installed_app_acceptance_project_escaped_disposable_profile")
    fixture = project_root / "test_windows_acceptance.py"
    fixture_source = (
        "def test_bounded_windows_acceptance_fixture():\n"
        "    assert 6 * 7 == 42\n"
    )
    fixture.write_text(fixture_source, encoding="utf-8")
    fixture_digest = _sha256(fixture_source)

    page.wait_for_function(
        "projectId => [...document.querySelector('#missionProject').options].some(option => option.value === projectId)",
        arg=project_id,
        timeout=30_000,
    )
    page.locator("#missionProject").select_option(project_id)
    objective = (
        "Perform one bounded, evidence-based acceptance mission using only this authorized local project and the active local model. "
        "Research the test fixture, state a concise hypothesis, run the project test suite exactly once with the native bounded project-test tool, "
        "record the observed result as evidence, validate that evidence, produce one finding and a concise report. "
        "Do not edit files, access the network, credentials, external paths, or use any tool outside the current authorization and workspace scope. "
        "Leave any final Owner report approval as a separate pending decision."
    )
    page.locator("#missionObjective").fill(objective)
    started_at = time.monotonic()
    with page.expect_response(
        lambda response: response.request.method == "POST" and response.url.rstrip("/").endswith("/api/public/missions"),
        timeout=INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS,
    ) as mission_response_info:
        page.locator("#createMission").click(timeout=30_000)
    create_response = mission_response_info.value
    create_body = create_response.json()
    mission_id = str(create_body.get("mission_id", "")) if isinstance(create_body, dict) else ""
    create_error = create_body.get("error") if isinstance(create_body, dict) else None
    create_diagnostic = create_body.get("acceptance_diagnostic", {}) if isinstance(create_body, dict) else {}
    if not isinstance(create_diagnostic, dict):
        create_diagnostic = {}
    diagnostic_stage = create_diagnostic.get("stage", "")
    exception_type = create_diagnostic.get("exception_type", "")
    diagnostic_stage = diagnostic_stage if isinstance(diagnostic_stage, str) and diagnostic_stage.isidentifier() else ""
    exception_type = exception_type if isinstance(exception_type, str) and exception_type.isidentifier() else ""
    diagnostic_frames = []
    raw_frames = create_diagnostic.get("traceback_frames", [])
    if isinstance(raw_frames, list):
        for frame in raw_frames[-6:]:
            if not isinstance(frame, dict):
                continue
            filename = frame.get("file", "")
            function = frame.get("function", "")
            line = frame.get("line")
            if (
                isinstance(filename, str)
                and Path(filename).name == filename
                and isinstance(function, str)
                and function.isidentifier()
                and isinstance(line, int)
                and not isinstance(line, bool)
                and line > 0
            ):
                diagnostic_frames.append({"file": filename, "function": function, "line": line})
    progress.append({
        "phase": "installed_app_mission_creation_response",
        "http_status": create_response.status,
        "response_ok": create_body.get("ok") is True if isinstance(create_body, dict) else False,
        "mission_id_present": bool(mission_id),
        "error_code": str(create_error)[:96] if create_error is not None else "",
        "diagnostic_stage": diagnostic_stage,
        "exception_type": exception_type,
        "diagnostic_traceback_frames": diagnostic_frames,
    })
    if create_response.status != 201 or not mission_id:
        raise RuntimeError("installed_app_real_mission_creation_failed")
    mission_path = "/api/public/missions/" + mission_id
    report["installed_app_mission"] = {
        "status": "IN_PROGRESS",
        "provenance": "installed_CyberSentinel_Desktop_public_API_and_bundled_backend",
        "mission_id": mission_id,
        "project_id": project_id,
        "project_name": project_name,
        "project_fixture_sha256": fixture_digest,
        "incomplete_operation_reported_truthfully": True,
    }

    def read_status() -> dict:
        result = _public_api(page, "GET", mission_path + "/status")
        if result["http_status"] != 200:
            raise RuntimeError("installed_app_mission_status_unavailable")
        value = result["body"].get("status")
        if not isinstance(value, dict):
            raise RuntimeError("installed_app_mission_status_shape_invalid")
        return value

    csrf = _new_csrf_token(page)
    pause_response = _public_api(page, "POST", mission_path + "/pause", csrf=csrf, payload={})
    pause_state = read_status()
    pause_verified = (
        pause_response["http_status"] == 200
        and pause_state.get("queue", {}).get("state") == "paused"
        and pause_state.get("progress", {}).get("pause_requested") is True
    )
    progress.append({
        "phase": "installed_app_mission_pause",
        "at_utc": datetime.now(timezone.utc).isoformat(),
        "http_status": pause_response["http_status"],
        "persisted_queue_state": pause_state.get("queue", {}).get("state"),
        "pause_requested": pause_state.get("progress", {}).get("pause_requested") is True,
    })
    paused_restart_cycle: dict = {"status": "NOT_RUN", "reason": "pause_not_verified"}
    paused_restart_snapshot: dict | None = None
    page_after_restart = page
    resume_response = {"http_status": 0, "body": {"error": "resume_not_authorized_by_restart_state"}}
    resume_queue_state = None
    resume_pause_requested = None
    resume_mission_status = None
    resume_attempted = False
    resume_verified = False
    persistence_verified = False
    no_automatic_resume_verified = False
    execution_history_unchanged = False
    resume_gate_verified = False
    before_projection: dict = {}
    after_projection: dict = {}
    if pause_verified:
        before_restart_snapshot = _mission_audit_snapshot(page, mission_id, profile_root)
        page_after_restart, paused_restart_cycle, paused_restart_snapshot = restart_callback(
            "paused_mission", mission_id, before_restart_snapshot, True
        )
        if page_after_restart is None or paused_restart_snapshot is None:
            failed_result = {
                "status": "FAIL",
                "provenance": "installed_CyberSentinel_Desktop_public_API_and_bundled_backend",
                "mission_id": mission_id,
                "project_id": project_id,
                "project_name": project_name,
                "project_fixture_sha256": fixture_digest,
                "project_fixture_size_bytes": len(fixture_source.encode("utf-8")),
                "mission_status": pause_state.get("status"),
                "queue_state": (pause_state.get("queue") or {}).get("state"),
                "pause_http_status": pause_response["http_status"],
                "application_restart": paused_restart_cycle,
                "resume_attempted": False,
                "incomplete_operation_reported_truthfully": True,
            }
            report["installed_app_mission"] = failed_result
            return failed_result, page_after_restart
        page = page_after_restart
        csrf = _new_csrf_token(page)
        persisted_status = paused_restart_snapshot.get("status", {})
        persisted_queue = persisted_status.get("queue", {}) if isinstance(persisted_status.get("queue"), dict) else {}
        before_tool = _tool_execution_projection(before_restart_snapshot.get("status", {}))
        after_tool = _tool_execution_projection(persisted_status)
        before_projection = _mission_audit_projection(before_restart_snapshot, mission_id)
        after_projection = _mission_audit_projection(paused_restart_snapshot, mission_id)
        restart_reconciliation = _mission_restart_reconciliation(
            before_projection, after_projection, allow_owner_reauth_transition=True
        )
        reauth_quarantine = (
            persisted_status.get("status") == "OWNER_REAUTH_REQUIRED"
            and persisted_queue.get("state") == "needs_input"
        )
        persistence_verified = (
            (persisted_queue.get("state") == "paused" or reauth_quarantine)
            and (persisted_status.get("progress") or {}).get("pause_requested") is True
        )
        no_automatic_resume_verified = False
        execution_history_unchanged = (
            before_tool["summary_sha256"] == after_tool["summary_sha256"]
            and before_tool["count"] == after_tool["count"]
            and before_tool["records_sha256"] == after_tool["records_sha256"]
            and before_tool["records_count"] == after_tool["records_count"]
            and before_tool["duplicate_tool_call_ids"] is False
            and after_tool["duplicate_tool_call_ids"] is False
            and before_projection["tool_execution_count"] == after_projection["tool_execution_count"]
            and before_projection["evidence_sha256"] == after_projection["evidence_sha256"]
            and before_projection["validation_sha256"] == after_projection["validation_sha256"]
            and before_projection["effect_ledger"].get("sha256") == after_projection["effect_ledger"].get("sha256")
            and before_projection["effect_ledger"].get("full_records_sha256")
            == after_projection["effect_ledger"].get("full_records_sha256")
            and before_projection["effect_ledger"].get("duplicate_effect_ids") is False
            and after_projection["effect_ledger"].get("duplicate_effect_ids") is False
            and after_projection.get("execution_chain_storage_verified") is True
            and restart_reconciliation.get("reconciled") is True
        )
        no_automatic_resume_verified = persistence_verified and execution_history_unchanged
        owner_authorized = paused_restart_cycle.get("owner_authentication", {}).get("status") == "PASS"
        runtime_ready = (
            paused_restart_cycle.get("model_runtime", {}).get("runtime_ready_after_restart") is True
            and paused_restart_cycle.get("model_runtime", {}).get("inference_after_restart", {}).get("status") == "PASS"
        )
        resume_eligible = _may_resume_after_application_restart(
            mission_status=persisted_status.get("status"),
            queue_state=persisted_queue.get("state"),
            pause_requested=(persisted_status.get("progress") or {}).get("pause_requested"),
            owner_authorized=owner_authorized,
            runtime_ready=runtime_ready,
            execution_history_unchanged=execution_history_unchanged,
        )
        if resume_eligible:
            resume_attempted = True
            resume_response = _public_api(
                page_after_restart, "POST", mission_path + "/resume",
                csrf=_new_csrf_token(page_after_restart), payload={},
            )
            resume_state = read_status()
            resume_queue = resume_state.get("queue", {}) if isinstance(resume_state.get("queue"), dict) else {}
            resume_mission_status = resume_state.get("status")
            resume_verified = (
                resume_response["http_status"] == 200
                and resume_queue.get("state") in {"queued", "executing"}
                and (resume_state.get("progress") or {}).get("pause_requested") is not True
                and resume_state.get("status") not in {
                    "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED",
                    "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED",
                    "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
                }
            )
            resume_gate_verified = resume_verified
            resume_queue_state = resume_queue.get("state")
            resume_pause_requested = (resume_state.get("progress") or {}).get("pause_requested") is True
        else:
            terminal_status = persisted_status.get("status") in {
                "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED",
                "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED",
                "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
            }
            resume_gate_verified = terminal_status and not resume_attempted
        paused_restart_cycle["mission"] = {
            "mission_id": mission_id,
            "before_restart": before_projection,
            "after_restart": after_projection,
            "restoration_status": "PASS",
            "execution_chain_storage_status": after_projection.get("execution_chain_storage_status"),
            "execution_chain_storage_verified": after_projection.get("execution_chain_storage_verified") is True,
            "storage_failure_class": None if after_projection.get("execution_chain_storage_verified") is True else "storage",
            "restart_reconciliation": restart_reconciliation,
            "reconciliation_status": "PASS" if restart_reconciliation.get("reconciled") is True else "FAIL",
            "paused_state_persisted": persistence_verified,
            "no_automatic_resume": no_automatic_resume_verified,
            "tool_history_unchanged_before_explicit_resume": execution_history_unchanged,
            "resume_eligibility_verified": resume_eligible,
            "resume_attempted": resume_attempted,
            "resume_http_status": resume_response["http_status"],
            "post_resume_queue_state": resume_queue_state,
            "post_resume_mission_status": resume_mission_status,
            "post_resume_pause_requested": resume_pause_requested,
            "resume_authorized_by_persisted_state_and_owner": resume_eligible and resume_attempted,
        }
        paused_restart_cycle["status"] = "PASS" if (
            paused_restart_cycle.get("process_restart_verified") is True
            and owner_authorized
            and runtime_ready
            and persistence_verified
            and no_automatic_resume_verified
            and execution_history_unchanged
            and resume_gate_verified
        ) else "FAIL"
    else:
        paused_restart_cycle["pause_http_status"] = pause_response["http_status"]
        paused_restart_cycle["persisted_queue_state"] = (pause_state.get("queue") or {}).get("state")

    deadline = started_at + 300.0
    mission_state: dict = {}
    terminal = {
        "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED",
        "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED",
        "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
    }
    persisted_status = paused_restart_snapshot.get("status", {}) if paused_restart_snapshot else {}
    persisted_queue = persisted_status.get("queue", {}) if isinstance(persisted_status.get("queue"), dict) else {}
    wait_skipped_for_safety = bool(
        paused_restart_snapshot
        and persisted_queue.get("state") == "paused"
        and persisted_status.get("status") not in terminal
        and (
            not resume_attempted
            or (resume_queue_state == "paused" and not resume_verified)
        )
    )
    if wait_skipped_for_safety:
        mission_state = persisted_status
    else:
        while time.monotonic() < deadline:
            mission_state = read_status()
            status = str(mission_state.get("status", ""))
            if status in terminal:
                break
            time.sleep(2)
        else:
            try:
                _public_api(page, "POST", mission_path + "/cancel", csrf=csrf, payload={})
            except Exception:
                pass
            raise TimeoutError("installed_app_mission_exceeded_300_second_wall_clock_bound")

    timeline_result = _public_api(page, "GET", mission_path + "/timeline")
    evidence_result = _public_api(page, "GET", mission_path + "/evidence")
    report_result = _public_api(page, "GET", mission_path + "/report")
    if any(item["http_status"] != 200 for item in (timeline_result, evidence_result, report_result)):
        raise RuntimeError("installed_app_mission_audit_endpoints_unavailable")
    timeline = timeline_result["body"].get("timeline", [])
    evidence = evidence_result["body"].get("evidence", [])
    report = report_result["body"].get("report", {})
    if not isinstance(timeline, list) or not isinstance(evidence, list) or not isinstance(report, dict):
        raise RuntimeError("installed_app_mission_audit_payload_invalid")
    tool_summary, tool_results_source = _safe_tool_result_summary(mission_state)
    report_summary = report.get("mission_summary", {})
    if not isinstance(report_summary, dict):
        report_summary = {}
    report_verification = report_summary.get("verification", {})
    if not isinstance(report_verification, dict):
        report_verification = {}
    report_evidence = report.get("evidence", {})
    if not isinstance(report_evidence, dict):
        report_evidence = {}
    owner_approval = report.get("owner_approval_status", {})
    if not isinstance(owner_approval, dict):
        owner_approval = {}
    final_report_approval = report.get("final_report_approval", {})
    if not isinstance(final_report_approval, dict):
        final_report_approval = {}
    authorization_snapshot = mission_state.get("authorization_snapshot", {})
    if not isinstance(authorization_snapshot, dict):
        authorization_snapshot = {}
    queue_state = mission_state.get("queue", {})
    if not isinstance(queue_state, dict):
        queue_state = {}
    network_boundary = authorization_snapshot.get("network_boundary", {})
    if not isinstance(network_boundary, dict):
        network_boundary = {}
    workspace_boundary = authorization_snapshot.get("workspace_boundary", {})
    if not isinstance(workspace_boundary, dict):
        workspace_boundary = {}
    allowed_tools = authorization_snapshot.get("allowed_tools", [])
    if not isinstance(allowed_tools, list):
        allowed_tools = []
    scope_items = authorization_snapshot.get("scope", [])
    if not isinstance(scope_items, list):
        scope_items = []
    allowed_networks = network_boundary.get("allowed")
    workspace_root_matches = False
    try:
        workspace_root_matches = Path(str(workspace_boundary.get("root", ""))).resolve(strict=True) == project_root
    except OSError:
        pass
    authorization_binding = (
        bool(authorization_snapshot)
        and authorization_snapshot.get("mission_id") == mission_id
        and authorization_snapshot.get("owner_identity") == mission_state.get("owner_identity_ref")
    )
    scope_firewall_verified = (
        authorization_snapshot.get("target_identity") == "local-project:" + project_id
        and "workspace" in scope_items
        and isinstance(allowed_networks, list)
        and len(allowed_networks) == 0
        and workspace_root_matches
    )
    tool_authorization_verified = _tools_within_authorized_allowlist(tool_summary, allowed_tools)
    report_outcome = str(report_summary.get("outcome", ""))
    chain_integrity = str(report_evidence.get("execution_chain_integrity", ""))
    project_test_execution_proof = (
        after_projection.get("project_test_execution_proof")
        if isinstance(after_projection.get("project_test_execution_proof"), dict) else {}
    )
    project_test_evidence_sources = after_projection.get("project_test_evidence_sources", [])
    if not isinstance(project_test_evidence_sources, list):
        project_test_evidence_sources = []
    project_test_evidence_source_verified = project_test_execution_proof.get("verified") is True
    blocked_or_unverified_status_present = _contains_blocked_or_unverified_status(
        (mission_state, report, tool_summary)
    )
    test_tool_pass = project_test_execution_proof.get("exactly_one_actual_execution_verified") is True
    event_types = [str(item.get("event", "")) for item in timeline if isinstance(item, dict)]
    research_stage = any(name in event_types for name in ("ObservationReceived", "ObservationInterpreted"))
    hypothesis_stage = "HypothesisUpdated" in event_types
    evidence_stage = (
        len(evidence) > 0
        and "EvidenceAdded" in event_types
        and project_test_evidence_source_verified
    )
    finding_count = len(report.get("findings", [])) if isinstance(report.get("findings"), list) else 0
    report_stage = (
        bool(report.get("report_sha256"))
        and bool(report_summary)
        and report.get("report_sha256") == _canonical_report_body_sha256(report)
    )
    approval_pending = final_report_approval.get("status") == "PENDING"
    terminal_restart_cycle: dict = {"status": "NOT_RUN", "reason": "mission_not_terminal_or_restart_unavailable"}
    terminal_restart_snapshot: dict | None = None
    terminal_restart_eligible = mission_state.get("status") in terminal and (
        paused_restart_cycle.get("status") in {"PASS", "NOT_RUN"}
    )
    if terminal_restart_eligible:
        before_terminal_snapshot = _mission_audit_snapshot(page, mission_id, profile_root)
        page_after_terminal_restart, terminal_restart_cycle, terminal_restart_snapshot = restart_callback(
            "terminal_mission", mission_id, before_terminal_snapshot, False
        )
        if page_after_terminal_restart is not None:
            page = page_after_terminal_restart
        if terminal_restart_snapshot is not None:
            before_terminal_projection = _mission_audit_projection(before_terminal_snapshot, mission_id)
            after_terminal_projection = _mission_audit_projection(terminal_restart_snapshot, mission_id)
            terminal_reconciliation = _mission_restart_reconciliation(
                before_terminal_projection, after_terminal_projection
            )
            terminal_records_unchanged = terminal_reconciliation.get("reconciled") is True
            terminal_restart_cycle["mission"] = {
                "mission_id": mission_id,
                "before_restart": before_terminal_projection,
                "after_restart": after_terminal_projection,
                "restoration_status": "PASS",
                "execution_chain_storage_status": after_terminal_projection.get("execution_chain_storage_status"),
                "execution_chain_storage_verified": after_terminal_projection.get("execution_chain_storage_verified") is True,
                "storage_failure_class": None if after_terminal_projection.get("execution_chain_storage_verified") is True else "storage",
                "restart_reconciliation": terminal_reconciliation,
                "reconciliation_status": "PASS" if terminal_records_unchanged else "FAIL",
                "terminal_state_and_records_unchanged": terminal_records_unchanged,
                "completed_mission_inspectable_after_restart": after_terminal_projection[
                    "completed_mission_inspectable"
                ],
            }
            terminal_restart_cycle["status"] = "PASS" if (
                terminal_restart_cycle.get("process_restart_verified") is True
                and terminal_restart_cycle.get("owner_authentication", {}).get("status") == "PASS"
                and terminal_restart_cycle.get("model_runtime", {}).get("status") == "PASS"
                and terminal_records_unchanged
                and after_terminal_projection.get("execution_chain_storage_verified") is True
                and after_terminal_projection.get("evidence_and_chain_bound_to_mission") is True
                and after_terminal_projection.get("report_projection_valid") is True
            ) else "FAIL"
    completed_mission_inspectable_after_restart = bool(
        terminal_restart_snapshot
        and _mission_audit_projection(terminal_restart_snapshot, mission_id)["completed_mission_inspectable"]
    )
    no_duplicate_tool_call_ids = not _tool_execution_projection(mission_state)["duplicate_tool_call_ids"]
    paused_restart_pass = paused_restart_cycle.get("status") == "PASS"
    terminal_restart_pass = terminal_restart_cycle.get("status") == "PASS"
    mission_pass = (
        mission_state.get("status") == "GOAL_COMPLETED"
        and not blocked_or_unverified_status_present
        and authorization_binding
        and scope_firewall_verified
        and tool_authorization_verified
        and research_stage
        and hypothesis_stage
        and test_tool_pass
        and project_test_execution_proof.get("verified") is True
        and project_test_execution_proof.get("verified_linked_execution_count") == 1
        and evidence_stage
        and project_test_evidence_source_verified
        and chain_integrity == "VALID"
        and report_outcome == "VERIFIED"
        and report_verification.get("verified") is True
        and finding_count > 0
        and report_stage
        and approval_pending
        and pause_verified is True
        and paused_restart_pass
        and persistence_verified is True
        and no_automatic_resume_verified is True
        and execution_history_unchanged is True
        and resume_gate_verified is True
        and resume_verified is True
        and not wait_skipped_for_safety
        and no_duplicate_tool_call_ids
        and terminal_restart_pass
        and completed_mission_inspectable_after_restart
    )
    result = {
        "status": "PASS" if mission_pass else "FAIL",
        "provenance": "installed_CyberSentinel_Desktop_public_API_and_bundled_backend",
        "mission_id": mission_id,
        "project_id": project_id,
        "project_name": project_name,
        "project_fixture_sha256": fixture_digest,
        "project_fixture_size_bytes": len(fixture_source.encode("utf-8")),
        "authorization_snapshot_present": bool(authorization_snapshot),
        "authorization_binding_verified": authorization_binding,
        "scope_firewall_verified": scope_firewall_verified,
        "scope_network_allowlist_count": len(allowed_networks) if isinstance(allowed_networks, list) else None,
        "mission_tools_within_authorized_allowlist": tool_authorization_verified,
        "target_identity": authorization_snapshot.get("target_identity"),
        "mission_status": mission_state.get("status"),
        "mission_id_matches_readback": mission_state.get("mission_id") == mission_id,
        "queue_state": queue_state.get("state"),
        "resource_failure_diagnostics": _safe_failure_diagnostics(mission_state),
        "resource_checkpoint_diagnostics": _safe_checkpoint_diagnostics(mission_state),
        "tool_calls": tool_summary,
        "run_project_tests_result_record_count": project_test_execution_proof.get("result_record_count", 0),
        "run_project_tests_successful_result_record_count": project_test_execution_proof.get(
            "successful_result_record_count", 0
        ),
        "run_project_tests_unaccounted_successful_result_record_count": project_test_execution_proof.get(
            "unaccounted_successful_result_record_count", 0
        ),
        "run_project_tests_sandbox_process_evidence_record_count": project_test_execution_proof.get(
            "sandbox_process_evidence_record_count"
        ),
        "run_project_tests_verified_actual_execution_count": project_test_execution_proof.get(
            "verified_linked_execution_count"
        ),
        "run_project_tests_exactly_once_verified": project_test_execution_proof.get(
            "exactly_one_actual_execution_verified"
        ) is True,
        "project_test_evidence_sources": project_test_evidence_sources,
        "project_test_evidence_source_verified": project_test_evidence_source_verified,
        "project_test_execution_proof": project_test_execution_proof,
        "blocked_or_unverified_status_present": blocked_or_unverified_status_present,
        "duplicate_tool_call_ids": not no_duplicate_tool_call_ids,
        "tool_results_source": tool_results_source,
        "research_stage": research_stage,
        "hypothesis_stage": hypothesis_stage,
        "bounded_project_test_pass": test_tool_pass,
        "evidence_stage": evidence_stage,
        "validator_verified": report_verification.get("verified"),
        "finding_count": finding_count,
        "report_stage": report_stage,
        "timeline_event_count": len(timeline),
        "timeline_event_types": event_types,
        "evidence_item_count": len(evidence),
        "evidence_records_bound_to_mission": after_projection.get("evidence_records_bound_to_mission"),
        "validation_record_bound_to_mission": after_projection.get("validation_record_bound_to_mission"),
        "execution_chain_integrity": chain_integrity,
        "report_outcome": report_outcome,
        "report_verified": report_verification.get("verified"),
        "report_sha256": report.get("report_sha256"),
        "effect_ledger": after_projection.get("effect_ledger"),
        "mission_authorization_owner_status": owner_approval.get("status"),
        "final_report_approval_status": final_report_approval.get("status"),
        "human_release_approval": "PENDING",
        "persistence_after_application_restart": persistence_verified,
        "no_automatic_resume_after_restart": no_automatic_resume_verified,
        "tool_history_unchanged_before_explicit_resume": execution_history_unchanged,
        "effect_history_unchanged_before_explicit_resume": execution_history_unchanged,
        "no_duplicate_effect_ids": after_projection.get("effect_ledger", {}).get("duplicate_effect_ids") is False,
        "resume_eligibility_verified": paused_restart_cycle.get("mission", {}).get("resume_eligibility_verified"),
        "resume_attempted": resume_attempted,
        "resume_after_persisted_pause": resume_verified,
        "resume_guard_verified": resume_gate_verified,
        "wait_skipped_to_preserve_paused_mission": wait_skipped_for_safety,
        "paused_application_restart_status": paused_restart_cycle.get("status"),
        "terminal_application_restart_status": terminal_restart_cycle.get("status"),
        "terminal_mission_persisted_after_restart": terminal_restart_cycle.get("mission", {}).get(
            "terminal_state_and_records_unchanged"
        ),
        "completed_mission_inspectable_after_restart": completed_mission_inspectable_after_restart,
        "elapsed_seconds": round(time.monotonic() - started_at, 3),
        "pause_http_status": pause_response["http_status"],
        "resume_http_status": resume_response["http_status"],
    }
    report["installed_app_mission"] = result
    return result, page


def _wait_for_model(page, predicate, *, timeout: float, phase: str, progress: list[dict]) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    consecutive_fetch_failures = 0
    total_fetch_failures = 0
    while time.monotonic() < deadline:
        try:
            state = _model_state(page)
        except Exception as exc:
            consecutive_fetch_failures += 1
            total_fetch_failures += 1
            exception_type = type(exc).__name__
            if not _SAFE_DIAGNOSTIC_IDENTIFIER.fullmatch(exception_type):
                exception_type = "Error"
            progress.append({
                "phase": phase + "_api_fetch_retry",
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "api_fetch_error_type": exception_type,
                "local_health_status": _local_health_status(page),
                "consecutive_failures": consecutive_fetch_failures,
                "total_failures": total_fetch_failures,
            })
            if (
                consecutive_fetch_failures >= MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES
                or total_fetch_failures >= MODEL_STATE_API_MAX_TOTAL_FAILURES
            ):
                raise RuntimeError("desktop_model_manager_api_unavailable_after_bounded_retries") from None
            time.sleep(min(MODEL_STATE_API_RETRY_DELAY_SECONDS, max(0, deadline - time.monotonic())))
            continue
        if consecutive_fetch_failures:
            progress.append({
                "phase": phase + "_api_fetch_recovered",
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "status_api_recovered": True,
                "consecutive_failures": consecutive_fetch_failures,
                "total_failures": total_fetch_failures,
            })
            consecutive_fetch_failures = 0
        model = _find_qwen(state)
        operation = (state.get("manager") or {}).get("operation") or {}
        marker = (operation.get("status"), operation.get("kind"), operation.get("progress"),
                  operation.get("error"), bool(model and model.get("installed")),
                  bool(model and model.get("active")),
                  ((state.get("manager") or {}).get("runtime") or {}).get("status"))
        if marker != last:
            progress.append({
                "phase": phase,
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "operation_status": operation.get("status"),
                "operation_kind": operation.get("kind"),
                "progress_percent": operation.get("progress"),
                "downloaded_bytes": operation.get("bytes_downloaded"),
                "total_bytes": operation.get("total_bytes"),
                "model_installed": bool(model and model.get("installed")),
                "model_active": bool(model and model.get("active")),
                "runtime_status": ((state.get("manager") or {}).get("runtime") or {}).get("status"),
                "error": operation.get("error"),
            })
            last = marker
        if operation.get("status") == "failed":
            raise RuntimeError("model_manager_operation_failed:" + str(operation.get("error", "unknown"))[:200])
        if operation.get("status") == "interrupted":
            raise RuntimeError("model_manager_operation_interrupted")
        if predicate(state, model, operation):
            return state
        time.sleep(2)
    raise TimeoutError(f"{phase}_timeout_after_{timeout:g}_seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cdp-port", required=True, type=int)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--profile-root", required=True, type=Path)
    parser.add_argument("--installed-executable", type=Path)
    parser.add_argument("--application-pid", type=int)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-timeout-seconds", type=int, default=2400)
    parser.add_argument(
        "--authorize-qwen3-4b-test-download",
        action="store_true",
        help="explicitly authorize only the curated Qwen3 4B test-model download in full mode",
    )
    args = parser.parse_args()
    if args.authorize_qwen3_4b_test_download and args.mode != "full":
        parser.error("--authorize-qwen3-4b-test-download requires --mode full")
    if args.mode == "full" and (args.installed_executable is None or not args.application_pid):
        parser.error("--mode full requires --installed-executable and --application-pid for real process restart coverage")
    started = time.monotonic()

    report: dict[str, object] = {
        "schema": "cybersentinel-windows-installed-desktop-acceptance-v2",
        "status": "FAIL",
        "mode": args.mode,
        "qwen3_4b_test_download_authorized": args.authorize_qwen3_4b_test_download,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_version": args.expected_version,
        "version_endpoint": {},
        "cdp_port": args.cdp_port,
        "installed_executable": str(args.installed_executable) if args.installed_executable else None,
        "initial_application_pid": args.application_pid,
        "installed_executable_launch": {"status": "NOT_RUN"},
        "application_restart": {
            "status": "NOT_RUN",
            "close_method": "NOT_RUN: PID-only tree termination is not safely bound to the launched process",
            "graceful_quit_claimed": False,
            "renderer_reload_used": False,
            "cycles": [],
        },
        "first_run": {},
        "hardware": {},
        "model_manager": {},
        "owner_authentication": {},
        "installed_app_mission": {"status": "NOT_RUN"},
        "progress": [],
    }
    browser = None
    inference_api_result: dict | None = None
    inference_response_status: int | None = None
    inference_response_fields: list[str] = []
    stage = "initialize_acceptance"
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(
                f"http://127.0.0.1:{args.cdp_port}", timeout=30_000
            )
            contexts = browser.contexts
            pages = [page for context in contexts for page in context.pages]
            if not pages:
                raise RuntimeError("installed_desktop_has_no_renderer_page")
            page = pages[0]
            if args.mode == "full":
                actual_image = _windows_process_image_path(args.application_pid)
                expected_image = str(args.installed_executable.expanduser().resolve(strict=True))
                image_matches = bool(
                    actual_image
                    and os.path.normcase(actual_image) == os.path.normcase(expected_image)
                )
                report["installed_executable_launch"] = {
                    "status": "PASS" if image_matches else "FAIL",
                    "process_id": args.application_pid,
                    "expected_image_path": expected_image,
                    "actual_image_path": actual_image,
                    "matches_installed_path": image_matches,
                }
                if not image_matches:
                    raise RuntimeError("initial_application_process_not_running_from_installed_path")
            version_endpoint = page.evaluate("""async () => {
              const response = await fetch('/api/public/health', {credentials: 'include'});
              const body = await response.json().catch(() => ({}));
              return {http_status: response.status, body};
            }""")
            reported_version = (
                version_endpoint.get("body", {}).get("version")
                if isinstance(version_endpoint, dict) and isinstance(version_endpoint.get("body"), dict)
                else None
            )
            report["version_endpoint"] = {
                "route": "GET /api/public/health",
                "http_status": version_endpoint.get("http_status") if isinstance(version_endpoint, dict) else None,
                "version": reported_version,
                "matches_expected_version": (
                    isinstance(version_endpoint, dict)
                    and version_endpoint.get("http_status") == 200
                    and reported_version == args.expected_version
                ),
            }
            if report["version_endpoint"]["matches_expected_version"] is not True:
                raise RuntimeError("installed_desktop_version_endpoint_mismatch")
            page.wait_for_selector("#firstRunOverlay", state="attached", timeout=90_000)
            page.wait_for_function(
                "() => document.querySelector('#setupHardware')?.textContent.trim() "
                "&& !document.querySelector('#setupHardware').textContent.includes('جارٍ فحص')",
                timeout=90_000,
            )
            overlay_visible = page.locator("#firstRunOverlay").is_visible()
            hardware_text = page.locator("#setupHardware").inner_text().strip()
            model_cards = page.locator("#setupModelList .model-card").count()
            model_list_text = page.locator("#setupModelList").inner_text().strip()
            owner_form_visible = page.locator("#ownerSetupForm").is_visible()
            try:
                page.screenshot(path=str(args.output.with_suffix(".first-run.png")), full_page=True)
                first_run_screenshot = str(args.output.with_suffix(".first-run.png"))
            except Exception:
                first_run_screenshot = None
            report["first_run"] = {
                "overlay_visible": overlay_visible,
                "owner_setup_form_visible": owner_form_visible,
                "title": page.title(),
                "renderer_url": page.url,
                "model_card_count": model_cards,
                "model_list_text_sha256": _sha256(model_list_text),
                "screenshot": first_run_screenshot,
            }
            report["hardware"] = {
                "detected": bool(hardware_text and "جارٍ فحص" not in hardware_text),
                "display_text": hardware_text,
                "sha256": _sha256(hardware_text),
            }
            state = _model_state(page)
            report["model_manager"] = {"catalog_loaded": bool(model_cards > 0)}
            qwen = _refresh_qwen_model_snapshot(report, state, phase="initial_catalog_state")
            smoke_pass = overlay_visible and owner_form_visible and model_cards > 0 and qwen is not None and bool(hardware_text)
            if args.mode == "smoke":
                report["status"] = "PASS" if smoke_pass else "FAIL"
                report["checks"] = {"fresh_first_run": overlay_visible, "hardware_detected": bool(hardware_text),
                                    "model_manager_loaded": model_cards > 0, "qwen3_4b_listed": qwen is not None}
                return_code = 0 if report["status"] == "PASS" else 2
            else:
                if not smoke_pass:
                    raise RuntimeError("first_run_hardware_or_qwen_catalog_check_failed")
                if qwen.get("compatible") is not True:
                    raise RuntimeError("qwen3_4b_not_compatible_with_actual_windows_runner_hardware")
                progress = report["progress"]
                model_id = str(qwen["model_id"])
                card = page.locator("#setupModelList .model-card").filter(has_text="Qwen3").filter(has_text="4B").first
                install_button = card.locator('button[data-model-action="install"]')
                if not qwen.get("installed"):
                    if install_button.count() != 1 or install_button.is_disabled():
                        raise RuntimeError("qwen3_4b_install_action_unavailable")
                    expected_model_id = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"]
                    if model_id != expected_model_id or install_button.get_attribute("data-model-id") != expected_model_id:
                        raise RuntimeError("qwen3_4b_install_action_model_identity_mismatch")
                    expected_consent = _build_expected_qwen_install_consent(qwen)
                    if expected_consent is None:
                        raise RuntimeError("qwen3_4b_catalog_identity_mismatch")
                    page_url = urlsplit(str(page.url))
                    if (
                        page_url.scheme != "http"
                        or page_url.hostname not in {"127.0.0.1", "localhost"}
                        or page_url.port is None
                    ):
                        raise RuntimeError("qwen3_4b_install_origin_not_loopback")
                    expected_origin = f"http://{page_url.netloc}"
                    consent = {
                        "seen": False,
                        "accepted": False,
                        "mismatch": False,
                        "authorized": args.authorize_qwen3_4b_test_download,
                        "post_seen": False,
                        "post_allowed": False,
                        "post_blocked": False,
                    }

                    def handle_install_dialog(dialog) -> None:
                        _handle_qwen_install_dialog(
                            dialog,
                            expected_consent,
                            consent,
                            authorize_test_download=args.authorize_qwen3_4b_test_download,
                        )

                    install_route_pattern = "**/api/public/desktop/models/*/install"

                    def guard_install_post(route) -> None:
                        consent["post_seen"] = True
                        if _may_continue_qwen_install_post(
                            route.request,
                            expected_model_id,
                            expected_origin,
                            consent,
                        ):
                            consent["post_allowed"] = True
                            route.continue_()
                        else:
                            consent["post_blocked"] = True
                            route.abort("blockedbyclient")

                    page.route(install_route_pattern, guard_install_post)
                    page.on("dialog", handle_install_dialog)
                    try:
                        try:
                            with page.expect_response(
                                lambda response: (
                                    _is_qwen_install_post_response(response)
                                    and _is_expected_qwen_install_post_request(
                                        response.request,
                                        expected_model_id,
                                        expected_origin,
                                    )
                                ),
                                timeout=QWEN_INSTALL_POST_RESPONSE_TIMEOUT_MS,
                            ) as install_response_info:
                                install_button.click(timeout=30_000)
                        except PlaywrightTimeoutError:
                            if consent.get("post_blocked") is True:
                                raise RuntimeError("qwen3_4b_install_post_blocked_by_guard") from None
                            _require_qwen_install_consent(consent)
                            raise RuntimeError("qwen3_4b_install_post_not_observed") from None
                    finally:
                        page.remove_listener("dialog", handle_install_dialog)
                        page.unroute(install_route_pattern, guard_install_post)
                        progress.append({
                            "phase": "qwen_install_authorization",
                            "at_utc": datetime.now(timezone.utc).isoformat(),
                            "explicit_opt_in": args.authorize_qwen3_4b_test_download,
                            "dialog_seen": consent.get("seen") is True,
                            "dialog_accepted": consent.get("accepted") is True,
                            "dialog_mismatched": consent.get("mismatch") is True,
                            "install_post_observed": consent.get("post_seen") is True,
                            "install_post_allowed": consent.get("post_allowed") is True,
                            "install_post_blocked": consent.get("post_blocked") is True,
                        })
                    _require_qwen_install_consent(consent)
                    if consent.get("post_allowed") is not True:
                        raise RuntimeError("qwen3_4b_install_post_not_authorized_by_guard")
                    install_response = install_response_info.value
                    progress.append({
                        "phase": "qwen_install_post_response",
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "http_status": install_response.status,
                        "consent_accepted": consent.get("accepted") is True,
                        "post_guard_allowed": consent.get("post_allowed") is True,
                    })
                    state = _validate_qwen_install_post_response(install_response, expected_model_id)
                    operation = ((state.get("manager") or {}).get("operation") or {})
                    progress.append({
                        "phase": "qwen_install_operation_started",
                        "at_utc": datetime.now(timezone.utc).isoformat(),
                        "operation_status": operation.get("status"),
                        "operation_kind": operation.get("kind"),
                    })
                    state = _wait_for_model(
                        page, lambda current, model, operation: bool(model and model.get("installed")),
                        timeout=args.model_timeout_seconds, phase="qwen_download_and_verify", progress=progress,
                    )
                    _refresh_qwen_model_snapshot(
                        report, state, phase="post_install_verification_poll"
                    )
                qwen = _find_qwen(state)
                if not qwen or not qwen.get("installed"):
                    raise RuntimeError("qwen3_4b_install_not_persisted")
                card = page.locator("#setupModelList .model-card").filter(has_text="Qwen3").filter(has_text="4B").first
                if not qwen.get("active"):
                    try:
                        page.wait_for_function(
                            """modelId => Array.from(document.querySelectorAll(
                                '#setupModelList button[data-model-action="activate"]'
                            )).some(button => button.dataset.modelId === modelId && !button.disabled)""",
                            arg=model_id,
                            timeout=60_000,
                        )
                    except Exception:
                        report["model_manager"]["activate_action_ui_state"] = page.evaluate(
                            """modelId => {
                                const buttons = Array.from(document.querySelectorAll(
                                    '#setupModelList button[data-model-action="activate"]'
                                )).filter(button => button.dataset.modelId === modelId);
                                return {
                                    matching_button_count: buttons.length,
                                    matching_buttons_disabled: buttons.map(button => button.disabled),
                                    model_card_count: document.querySelectorAll('#setupModelList .model-card').length
                                };
                            }""",
                            model_id,
                        )
                        raise RuntimeError("qwen3_4b_activate_action_not_rendered_after_install")
                    activate = card.locator('button[data-model-action="activate"]')
                    if activate.count() != 1 or activate.is_disabled():
                        raise RuntimeError("qwen3_4b_activate_action_unavailable")
                    activate.click(timeout=30_000)
                    state = _wait_for_model(
                        page, lambda current, model, operation: bool(
                            model and model.get("active")
                            and ((current.get("manager") or {}).get("runtime") or {}).get("status") == "ready"
                        ),
                        timeout=600, phase="qwen_runtime_initialization", progress=progress,
                    )
                    _refresh_qwen_model_snapshot(
                        report, state, phase="post_activation_poll"
                    )
                qwen = _refresh_qwen_model_snapshot(
                    report, state, phase="post_install_activation_poll"
                )
                runtime = (state.get("manager") or {}).get("runtime") or {}
                if not qwen or not qwen.get("active") or runtime.get("status") != "ready":
                    raise RuntimeError("qwen3_4b_runtime_not_ready")
                try:
                    page.wait_for_function(
                        """modelId => Array.from(document.querySelectorAll(
                            '#setupModelList button[data-model-action="test"]'
                        )).some(button => button.dataset.modelId === modelId && !button.disabled)""",
                        arg=model_id,
                        timeout=60_000,
                    )
                except Exception:
                    report["model_manager"]["test_action_ui_state"] = page.evaluate(
                        """modelId => {
                            const buttons = Array.from(document.querySelectorAll(
                                '#setupModelList button[data-model-action="test"]'
                            )).filter(button => button.dataset.modelId === modelId);
                            return {
                                matching_button_count: buttons.length,
                                matching_buttons_disabled: buttons.map(button => button.disabled),
                                model_card_count: document.querySelectorAll('#setupModelList .model-card').length
                            };
                        }""",
                        model_id,
                    )
                    raise RuntimeError("qwen3_4b_local_inference_test_action_not_rendered_after_activation")
                card = page.locator("#setupModelList .model-card").filter(has_text="Qwen3").filter(has_text="4B").first
                test_button = card.locator('button[data-model-action="test"]')
                if test_button.count() != 1 or test_button.is_disabled():
                    raise RuntimeError("qwen3_4b_local_inference_test_action_unavailable")
                expected_test_path = f"/api/public/desktop/models/{model_id}/test"
                def is_expected_inference_response(response) -> bool:
                    response_path = response.url.split("?", 1)[0].rstrip("/")
                    return (
                        response.request.method == "POST"
                        and response_path.endswith(expected_test_path)
                    )
                with page.expect_response(is_expected_inference_response, timeout=120_000) as inference_response_info:
                    test_button.click(timeout=30_000)
                inference_response = inference_response_info.value
                inference_response_status = inference_response.status
                try:
                    value = inference_response.json()
                    if isinstance(value, dict):
                        inference_api_result = value
                        inference_response_fields = sorted(str(key) for key in value)[:16]
                except Exception:
                    inference_api_result = None
                state = _wait_for_model(
                    page, lambda current, model, operation: bool(
                        operation.get("kind") == "inference_test"
                        and operation.get("status") == "complete"
                        and isinstance(operation.get("result"), str)
                        and operation.get("result")
                    ),
                    timeout=300, phase="real_local_inference", progress=progress,
                )
                qwen = _refresh_qwen_model_snapshot(
                    report, state, phase="post_activation_inference_poll"
                )
                digest_verification = _qwen_installed_digest_report(qwen)
                report["model_manager"]["installed_digest_verification"] = digest_verification
                _require_qwen_installed_digest(digest_verification)
                operation = (state.get("manager") or {}).get("operation") or {}
                runtime = (state.get("manager") or {}).get("runtime") or {}
                inference_text = str((inference_api_result or {}).get("response", operation.get("result", "")))
                provider = str((inference_api_result or {}).get("provider", ""))
                model_name = str((inference_api_result or {}).get("model", ""))
                if "نجح الاستدلال المحلي الحقيقي" not in page.locator("#setupModelMessage").inner_text():
                    raise RuntimeError("desktop_ui_did_not_report_local_inference_success")
                report["model_manager"].update({
                    "qwen3_4b_downloaded_and_installed": bool(qwen and qwen.get("installed")),
                    "qwen3_4b_active": bool(qwen and qwen.get("active")),
                    "runtime_status": runtime.get("status"),
                    "runtime_binary_sha256": runtime.get("binary_sha256"),
                    "provider": provider,
                    "model": model_name,
                    "inference_response_http_status": inference_response_status,
                    "inference_response_fields": inference_response_fields,
                    "inference_provider_matches_expected": provider == "local_llama_cpp",
                    "inference_model_matches_expected": model_name == model_id,
                    "expected_model_size_bytes": (qwen or {}).get("size_bytes"),
                    "real_inference_completed": True,
                    "real_inference_flag": (inference_api_result or {}).get("real_inference"),
                    "inference_result_bytes": len(inference_text.encode("utf-8")),
                    "inference_result_sha256": _sha256(inference_text),
                    "model_file_sha256": (qwen or {}).get("installed_sha256"),
                    "downloaded_bytes": next((item.get("downloaded_bytes") for item in reversed(progress)
                                               if item.get("phase") == "qwen_download_and_verify"), None),
                    "download_total_bytes": next((item.get("total_bytes") for item in reversed(progress)
                                                   if item.get("phase") == "qwen_download_and_verify"), None),
                })
                if (provider != "local_llama_cpp" or model_name != model_id
                        or (inference_api_result or {}).get("real_inference") is not True
                        or not inference_text.strip()):
                    raise RuntimeError("real_inference_provider_or_model_identity_mismatch")

                username = page.locator("#setupOwnerUsername").inner_text().strip()
                owner_password = secrets.token_urlsafe(24)
                page.locator("#ownerSetupPassword").fill(owner_password)
                page.locator("#ownerSetupConfirm").fill(owner_password)
                page.locator("#ownerSetupSubmit").click(timeout=30_000)
                page.wait_for_function(
                    "() => document.querySelector('#firstRunOverlay')?.classList.contains('hidden')",
                    timeout=60_000,
                )
                page.wait_for_function(
                    "() => (document.querySelector('#authStateSide')?.textContent || '').includes('مسجل الدخول')",
                    timeout=60_000,
                )
                report["owner_authentication"] = {
                    "first_run_owner_creation_succeeded": True,
                    "owner_username": username,
                    "first_run_authenticated": True,
                }
                stage = "owner_logout_request"
                with page.expect_response(
                    lambda response: response.request.method == "POST"
                    and response.url.rstrip("/").endswith("/api/public/auth/logout"),
                    timeout=30_000,
                ) as initial_logout_response_info:
                    page.locator("#logoutButton").click(timeout=30_000)
                initial_logout_response = initial_logout_response_info.value
                initial_logout_body = initial_logout_response.json()
                report["owner_authentication"]["initial_logout_http_status"] = initial_logout_response.status
                report["owner_authentication"]["initial_logout_authenticated"] = initial_logout_body.get("authenticated")
                if initial_logout_response.status != 200 or initial_logout_body.get("authenticated") is not False:
                    raise RuntimeError("owner_logout_after_first_run_not_verified")
                stage = "owner_logout_renderer_state"
                try:
                    page.wait_for_function(
                        """() => {
                            const label = (document.querySelector('#authStateSide')?.textContent || '').trim();
                            const loginForm = document.querySelector('#loginForm');
                            const logoutButton = document.querySelector('#logoutButton');
                            return label === 'غير مسجل الدخول'
                                && loginForm !== null && !loginForm.classList.contains('hidden')
                                && logoutButton !== null && logoutButton.classList.contains('hidden');
                        }""",
                        timeout=30_000,
                    )
                except Exception:
                    report["owner_authentication"]["renderer_state_after_initial_logout"] = page.evaluate(
                        """() => ({
                            auth_state: document.querySelector('#authStateSide')?.textContent || null,
                            login_form_hidden: document.querySelector('#loginForm')?.classList.contains('hidden') ?? null,
                            logout_button_hidden: document.querySelector('#logoutButton')?.classList.contains('hidden') ?? null,
                            auth_message: document.querySelector('#authMessage')?.textContent || null
                        })"""
                    )
                    try:
                        page.screenshot(path=str(args.output.with_suffix(".initial-logout-failure.png")), full_page=True)
                    except Exception:
                        pass
                    raise
                report["owner_authentication"]["initial_logout_renderer_state_verified"] = True
                page.screenshot(path=str(args.output.with_suffix(".first-run-logged-out.png")), full_page=True)
                report["owner_authentication"]["initial_logout_screenshot"] = str(
                    args.output.with_suffix(".first-run-logged-out.png")
                )
                stage = "invalid_owner_login_request"
                page.locator("#loginUsername").fill(username)
                page.locator("#loginPassword").fill("intentionally-invalid-windows-acceptance-password")
                with page.expect_response(
                    lambda response: getattr(getattr(response, "request", None), "method", None) == "POST",
                    timeout=30_000,
                ) as invalid_response_info:
                    page.locator("#loginButton").click(timeout=30_000)
                invalid_response = invalid_response_info.value
                invalid_body = invalid_response.json()
                invalid_login_request_target_matches = _is_expected_owner_login_request(
                    page, invalid_response.request
                )
                stage = "invalid_owner_login_renderer_state"
                page.wait_for_function(
                    "() => document.querySelector('#authStateSide')?.textContent.trim() === 'غير مسجل الدخول'",
                    timeout=30_000,
                )
                invalid_rejected = (
                    invalid_login_request_target_matches
                    and invalid_response.status in (400, 401, 403)
                    and invalid_body.get("authenticated") is not True
                )
                report["owner_authentication"].update({
                    "invalid_credentials_rejected": invalid_rejected,
                    "invalid_login_request_target_matches": invalid_login_request_target_matches,
                    "invalid_login_http_status": invalid_response.status,
                    "invalid_login_error": invalid_body.get("error"),
                    "invalid_login_left_owner_unauthenticated": "غير مسجل الدخول" in page.locator("#authStateSide").inner_text(),
                })
                if not invalid_rejected:
                    raise RuntimeError("invalid_owner_credentials_not_safely_rejected")

                page.locator("#loginUsername").fill(username)
                page.locator("#loginPassword").fill(owner_password)
                with page.expect_response(
                    lambda response: getattr(getattr(response, "request", None), "method", None) == "POST",
                    timeout=30_000,
                ) as valid_response_info:
                    page.locator("#loginButton").click(timeout=30_000)
                valid_response = valid_response_info.value
                valid_body = valid_response.json()
                valid_login_request_target_matches = _is_expected_owner_login_request(
                    page, valid_response.request
                )
                page.wait_for_function(
                    "() => (document.querySelector('#authStateSide')?.textContent || '').includes('مسجل الدخول')",
                    timeout=30_000,
                )
                valid_login = (
                    valid_login_request_target_matches
                    and valid_response.status == 200
                    and valid_body.get("authenticated") is True
                    and valid_body.get("username") == username
                )
                report["owner_authentication"].update({
                    "valid_credentials_accepted": valid_login,
                    "valid_login_request_target_matches": valid_login_request_target_matches,
                    "valid_login_http_status": valid_response.status,
                    "valid_login_identity_matches_owner": valid_body.get("username") == username,
                })
                if not valid_login:
                    raise RuntimeError("valid_owner_credentials_were_not_accepted")

                active_application_pid = args.application_pid
                relaunched_application_process = None
                report["application_restart"]["status"] = "IN_PROGRESS"

                def restart_installed_application(cycle_name: str, mission_id: str, before_snapshot: dict, verify_inference: bool):
                    nonlocal browser, page, active_application_pid, relaunched_application_process
                    cycle = {
                        "cycle": cycle_name,
                        "status": "FAIL",
                        "close_method": "NOT_RUN: PID-only tree termination is not safely bound to the launched process",
                        "execution_chain_storage_status": "NOT_READ",
                        "restoration_status": "NOT_RUN",
                        "reconciliation_status": "NOT_RUN",
                        "graceful_quit_claimed": False,
                        "renderer_reload_used": False,
                        "installed_executable": str(args.installed_executable),
                        "old_process_id": active_application_pid,
                        "same_disposable_profile_root": True,
                        "post_restart_inference_requested": verify_inference,
                    }
                    after_snapshot = None
                    try:
                        if browser is not None:
                            try:
                                browser.close()
                            except Exception as exc:
                                cycle["browser_detach_error_type"] = type(exc).__name__
                            finally:
                                browser = None
                                page = None
                        termination = _terminate_installed_process_tree(
                            active_application_pid, args.cdp_port, args.installed_executable
                        )
                        cycle.update(termination)
                        if termination.get("process_tree_termination_verified") is not True:
                            raise RuntimeError("installed_application_process_tree_did_not_stop")

                        relaunched_application_process = _launch_installed_application(
                            args.installed_executable, args.profile_root, args.cdp_port
                        )
                        active_application_pid = relaunched_application_process.pid
                        cycle["new_process_id"] = active_application_pid
                        actual_image = _windows_process_image_path(active_application_pid)
                        expected_image = str(args.installed_executable.expanduser().resolve(strict=True))
                        image_matches = bool(
                            actual_image
                            and os.path.normcase(actual_image) == os.path.normcase(expected_image)
                        )
                        cycle["new_process_image_path"] = actual_image
                        cycle["relaunch_from_installed_path_verified"] = image_matches
                        cycle["same_profile_user_data_dir"] = str(
                            (args.profile_root.expanduser().resolve() / "userData")
                        )

                        browser, page, cdp_info, health = _connect_to_relaunched_application(
                            playwright, args.cdp_port, args.expected_version
                        )
                        cycle["cdp_browser_after_restart"] = cdp_info.get("Browser")
                        cycle["health_http_status_after_restart"] = health.get("http_status")
                        cycle["application_version_after_restart"] = health.get("body", {}).get("version")
                        cycle["application_version_matches_expected"] = (
                            health.get("body", {}).get("version") == args.expected_version
                        )
                        cycle["renderer_page_present_after_restart"] = bool(page)

                        pre_restart_status = before_snapshot.get("status", {})
                        expected_owner_identity_ref = (
                            pre_restart_status.get("owner_identity_ref")
                            if isinstance(pre_restart_status, dict) else None
                        )
                        cycle["owner_authentication"] = _owner_auth_after_restart(
                            page,
                            "/api/public/missions/" + mission_id,
                            username,
                            owner_password,
                            expected_owner_identity_ref,
                        )
                        cycle["model_runtime"] = _model_runtime_after_restart(
                            page, args.installed_executable, progress, verify_inference=verify_inference
                        )
                        if cycle["owner_authentication"].get("status") == "PASS":
                            after_snapshot = _mission_audit_snapshot(page, mission_id, args.profile_root)
                            before_projection = _mission_audit_projection(before_snapshot, mission_id)
                            after_projection = _mission_audit_projection(after_snapshot, mission_id)
                            restart_reconciliation = _mission_restart_reconciliation(
                                before_projection,
                                after_projection,
                                allow_owner_reauth_transition=(cycle_name == "paused_mission"),
                            )
                            cycle["restoration_status"] = "PASS"
                            cycle["execution_chain_storage_status"] = after_projection.get(
                                "execution_chain_storage_status"
                            )
                            cycle["execution_chain_storage_verified"] = (
                                after_projection.get("execution_chain_storage_verified") is True
                            )
                            cycle["storage_failure_class"] = (
                                None if cycle["execution_chain_storage_verified"] else "storage"
                            )
                            cycle["reconciliation_status"] = (
                                "PASS" if restart_reconciliation.get("reconciled") is True else "FAIL"
                            )
                            cycle["mission"] = {
                                "mission_id": mission_id,
                                "before_restart": before_projection,
                                "after_restart": after_projection,
                                "restart_reconciliation": restart_reconciliation,
                                "mission_id_and_report_binding_verified": (
                                    before_projection.get("evidence_and_chain_bound_to_mission") is True
                                    and after_projection.get("evidence_and_chain_bound_to_mission") is True
                                ),
                            }
                        cycle["process_restart_verified"] = bool(
                            cycle.get("process_tree_termination_verified") is True
                            and cycle.get("relaunch_from_installed_path_verified") is True
                            and cycle.get("application_version_matches_expected") is True
                            and cycle.get("renderer_page_present_after_restart") is True
                            and _windows_process_alive(active_application_pid) is True
                        )
                        cycle["status"] = "PASS" if (
                            cycle["process_restart_verified"]
                            and cycle["owner_authentication"].get("status") == "PASS"
                            and cycle["model_runtime"].get("status") == "PASS"
                            and cycle.get("mission", {}).get("mission_id_and_report_binding_verified") is True
                            and cycle.get("restoration_status") == "PASS"
                            and cycle.get("execution_chain_storage_verified") is True
                            and cycle.get("reconciliation_status") == "PASS"
                        ) else "FAIL"
                        if cycle_name == "terminal_mission" and after_snapshot is not None:
                            try:
                                screenshot_path = args.output.with_suffix(".mission-after-application-restart.png")
                                page.screenshot(path=str(screenshot_path), full_page=True)
                                cycle["final_state_screenshot"] = str(screenshot_path)
                            except Exception:
                                cycle["final_state_screenshot"] = None
                    except Exception as exc:
                        cycle["status"] = "FAIL"
                        cycle["restart_error_type"] = type(exc).__name__
                        if isinstance(exc, _MissionAuditSnapshotError):
                            cycle["restart_failure_class"] = exc.failure_class
                            cycle["restart_error_code"] = exc.reason_code
                            cycle["restoration_status"] = "FAIL"
                        elif after_snapshot is not None:
                            cycle["restart_failure_class"] = "reconciliation"
                            cycle["restart_error_code"] = "mission_audit_reconciliation_failed"
                            cycle["reconciliation_status"] = "FAIL"
                        else:
                            cycle["restart_failure_class"] = "restart_validation"
                            cycle["restart_error_code"] = "installed_application_restart_validation_failed"
                    cycle["current_process_id_after_cycle"] = active_application_pid
                    report["application_restart"]["cycles"].append(cycle)
                    report["application_restart"]["current_process_id"] = active_application_pid
                    report["owner_authentication"].setdefault("after_application_restart", []).append({
                        "cycle": cycle_name,
                        **cycle.get("owner_authentication", {}),
                    })
                    progress.append({
                        "phase": "installed_application_process_restart",
                        "cycle": cycle_name,
                        "process_restart_verified": cycle.get("process_restart_verified") is True,
                        "owner_authentication_status": cycle.get("owner_authentication", {}).get("status"),
                        "model_runtime_status": cycle.get("model_runtime", {}).get("status"),
                        "status": cycle.get("status"),
                    })
                    return page, cycle, after_snapshot

                stage = "installed_app_full_mission"
                installed_mission, page = _installed_app_mission(
                    page, args.profile_root, progress, restart_installed_application, report
                )
                report["installed_app_mission"] = installed_mission
                restart_cycles = report["application_restart"].get("cycles", [])
                paused_cycle = next((item for item in restart_cycles if item.get("cycle") == "paused_mission"), {})
                terminal_cycle = next((item for item in restart_cycles if item.get("cycle") == "terminal_mission"), {})
                recovery_cycle = paused_cycle if paused_cycle else terminal_cycle
                terminal_mission_inspectable = (
                    terminal_cycle.get("mission", {}).get("completed_mission_inspectable_after_restart") is True
                )
                report["application_restart"]["gates"] = {
                    "paused_mission_restart_and_authorized_resume": paused_cycle.get("status", "NOT_RUN"),
                    "terminal_mission_records_persisted": terminal_cycle.get("status", "NOT_RUN"),
                    "previously_completed_mission_inspectable": "PASS" if terminal_mission_inspectable else (
                        "NOT_RUN" if installed_mission.get("mission_status") != "GOAL_COMPLETED" else "FAIL"
                    ),
                    "post_restart_owner_authentication": recovery_cycle.get("owner_authentication", {}).get("status", "NOT_RUN"),
                    "post_restart_model_and_runtime": recovery_cycle.get("model_runtime", {}).get("status", "NOT_RUN"),
                }
                report["application_restart"]["status"] = "PASS" if (
                    paused_cycle.get("status") == "PASS"
                    and terminal_cycle.get("status") == "PASS"
                    and terminal_mission_inspectable
                ) else "FAIL"
                if installed_mission.get("status") != "PASS":
                    raise RuntimeError("installed_candidate_full_mission_acceptance_failed")

                page.locator("#settingsLink").click(timeout=30_000)
                stop_button = page.locator('#settingsModelList button[data-model-action="stop"]')
                stop_button.wait_for(state="visible", timeout=30_000)
                if stop_button.is_disabled():
                    raise RuntimeError("installed_model_runtime_stop_action_unavailable")
                stop_button.click(timeout=30_000)
                state = _wait_for_model(
                    page, lambda current, model, operation: (
                        operation.get("kind") == "stop" and operation.get("status") == "complete"
                    ) or ((current.get("manager") or {}).get("runtime") or {}).get("status") == "stopped",
                    timeout=180, phase="qwen_runtime_shutdown", progress=progress,
                )
                runtime_final = (state.get("manager") or {}).get("runtime") or {}
                report["model_manager"]["runtime_shutdown_verified"] = runtime_final.get("status") in ("stopped", "idle", None)
                if not report["model_manager"]["runtime_shutdown_verified"]:
                    raise RuntimeError("qwen_runtime_shutdown_not_verified")

                try:
                    page.screenshot(path=str(args.output.with_suffix(".owner-authenticated.png")), full_page=True)
                    report["owner_authentication"]["screenshot"] = str(args.output.with_suffix(".owner-authenticated.png"))
                except Exception:
                    pass
                with page.expect_response(
                    lambda response: response.request.method == "POST" and "/api/public/auth/logout" in response.url,
                    timeout=30_000,
                ) as logout_response_info:
                    page.locator("#logoutButton").click(timeout=30_000)
                logout_response = logout_response_info.value
                page.wait_for_function(
                    "() => document.querySelector('#authStateSide')?.textContent.trim() === 'غير مسجل الدخول'",
                    timeout=30_000,
                )
                report["owner_authentication"]["logout_after_login_verified"] = logout_response.status == 200
                if logout_response.status != 200:
                    raise RuntimeError("owner_logout_after_login_not_verified")
                try:
                    page.screenshot(path=str(args.output.with_suffix(".owner-logged-out.png")), full_page=True)
                    report["owner_authentication"]["logged_out_screenshot"] = str(args.output.with_suffix(".owner-logged-out.png"))
                except Exception:
                    pass
                report["checks"] = {
                    "fresh_first_run": overlay_visible,
                    "hardware_detection": bool(hardware_text),
                    "qwen3_4b_model_manager": bool(qwen and qwen.get("installed") is True),
                    "qwen3_4b_installed_digest_matches_catalog_and_pin": digest_verification["verified"] is True,
                    "qwen3_4b_runtime_active": bool(
                        qwen and qwen.get("active") is True
                        and runtime.get("status") == "ready"
                        and runtime.get("model_id") == model_id
                    ),
                    "local_runtime_initialization": runtime.get("status") == "ready",
                    "real_qwen_local_inference": provider == "local_llama_cpp" and model_name == model_id and bool(inference_text.strip()),
                    "owner_valid_login": report["owner_authentication"].get("valid_credentials_accepted") is True,
                    "owner_invalid_login_rejected": report["owner_authentication"].get("invalid_credentials_rejected") is True,
                    "installed_app_full_mission": report["installed_app_mission"].get("status") == "PASS",
                    "installed_executable_launch_from_installed_path": report["installed_executable_launch"].get("status") == "PASS",
                    "application_restart_and_durable_mission_recovery": report["application_restart"].get("status") == "PASS",
                    "runtime_shutdown": report["model_manager"].get("runtime_shutdown_verified") is True,
                }
                report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
                stage = "acceptance_complete"
                return_code = 0 if report["status"] == "PASS" else 2
            report["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return return_code
    except Exception as exc:
        report["failure_stage"] = stage
        safe_error = _safe_exception_diagnostics(exc)
        report.update(safe_error)
        report["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        report["status"] = "FAIL"
        if report.get("application_restart", {}).get("status") == "IN_PROGRESS":
            report["application_restart"]["status"] = "FAIL"
        mission_report = report.get("installed_app_mission")
        if isinstance(mission_report, dict) and mission_report.get("status") == "IN_PROGRESS":
            mission_report["status"] = "FAIL"
            mission_report["incomplete_operation_reported_truthfully"] = True
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], **safe_error}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        # A CDP disconnect must not close the installed Electron process; the
        # PowerShell wrapper stops its full process tree after evidence is saved.
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
