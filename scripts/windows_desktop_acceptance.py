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
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit
from urllib.request import ProxyHandler, build_opener

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


def _durable_tool_result_records(mission_state: dict) -> tuple[list, str]:
    progress = mission_state.get("progress")
    if not isinstance(progress, dict):
        return [], "unavailable"
    model_loop = progress.get("model_loop")
    nested_results = model_loop.get("tool_results") if isinstance(model_loop, dict) else None
    candidates = (("model_loop", nested_results), ("top_level", progress.get("tool_results")))
    raw_results: list = []
    source = "unavailable"
    for candidate_source, candidate in candidates:
        if not isinstance(candidate, list):
            continue
        if candidate:
            raw_results = candidate
            source = candidate_source
            break
        if source == "unavailable":
            source = "empty"

    return raw_results, source


def _safe_tool_result_summary(mission_state: dict) -> tuple[list[dict], str]:
    raw_results, source = _durable_tool_result_records(mission_state)

    summary = []
    for item in raw_results:
        if not isinstance(item, dict):
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
    return all(isinstance(item, dict) and item.get("name") in allowed_tools for item in tool_summary)


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
        "run_project_tests_count": sum(item.get("name") == "run_project_tests" for item in summary),
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
        if effect_mission_id != mission_id or not isinstance(effect_id, str) or not effect_id:
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


def _cdp_version(port: int) -> dict | None:
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/json/version", timeout=2) as response:
            value = json.loads(response.read(64_000).decode("utf-8"))
        return value if isinstance(value, dict) and isinstance(value.get("Browser"), str) else None
    except Exception:
        return None


def _terminate_installed_process_tree(process_id: int, cdp_port: int) -> dict:
    if os.name != "nt":
        raise RuntimeError("native_windows_process_restart_required")
    result = subprocess.run(
        ["taskkill.exe", "/PID", str(process_id), "/T", "/F"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=APPLICATION_PROCESS_EXIT_TIMEOUT_SECONDS,
        check=False,
    )
    deadline = time.monotonic() + APPLICATION_PROCESS_EXIT_TIMEOUT_SECONDS
    process_stopped = False
    while time.monotonic() < deadline:
        process_stopped = _windows_process_alive(process_id) is False
        endpoint_stopped = _cdp_version(cdp_port) is None
        if process_stopped and endpoint_stopped:
            return {
                "taskkill_exit_code": result.returncode,
                "process_id_stopped": True,
                "old_cdp_endpoint_unavailable": True,
                "process_tree_termination_verified": True,
            }
        time.sleep(0.5)
    return {
        "taskkill_exit_code": result.returncode,
        "process_id_stopped": process_stopped,
        "old_cdp_endpoint_unavailable": _cdp_version(cdp_port) is None,
        "process_tree_termination_verified": False,
    }


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
        "owner_identity_matches": False,
        "mission_read_authorized": False,
        "renderer_authenticated_after_restart": False,
    }
    try:
        before = _public_api(page, "GET", mission_path + "/status")
        before_status = before["http_status"]
        before_body = before["body"].get("status", {})
        before_identity = before_body.get("owner_identity_ref") if isinstance(before_body, dict) else None
        csrf = _new_csrf_token(page)
        invalid = _public_api(
            page, "POST", "/api/public/auth/login", csrf=csrf,
            payload={"username": username, "password": "invalid-after-application-restart"},
        )
        invalid_rejected = (
            invalid["http_status"] == 403
            and invalid["body"].get("authenticated") is not True
            and invalid["body"].get("error") == "invalid_credentials"
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
        ui_login = {"http_status": None, "authenticated": False}
        if after_invalid["http_status"] != 200:
            ui_login = _login_owner_after_restart(page, username, password)
            reauthenticated = (
                ui_login.get("http_status") == 200
                and ui_login.get("authenticated") is True
                and ui_login.get("username") == username
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
            "invalid_login_http_status": invalid["http_status"],
            "invalid_login_preserved_existing_owner": invalid_preserved,
            "invalid_login_did_not_create_owner_session": invalid_did_not_create_session,
            "invalid_login_authorization_state_unchanged": invalid_auth_state_unchanged,
            "owner_session_restored": before_owner_authenticated and invalid_preserved,
            "valid_login_after_restart": reauthenticated or (before_owner_authenticated and invalid_preserved),
            "owner_identity_matches": owner_identity_matches,
            "owner_identity_sha256": _sha256(str(final_state.get("owner_identity_ref", "")))
            if isinstance(final_state, dict) and final_state.get("owner_identity_ref") else None,
            "mission_read_authorized": mission_read_authorized,
            "mission_read_http_status": final["http_status"],
            "renderer_authenticated_after_restart": renderer_state.get("authenticated") is True,
            "renderer_login_form_hidden": renderer_state.get("login_form_hidden") is True,
            "renderer_logout_button_visible": renderer_state.get("logout_button_visible") is True,
            "valid_login_http_status": ui_login.get("http_status"),
        })
    except Exception as exc:
        result["error_type"] = type(exc).__name__
    result["status"] = "PASS" if all(
        result.get(key) is True for key in (
            "invalid_credentials_rejected", "invalid_login_authorization_state_unchanged",
            "valid_login_after_restart", "owner_identity_matches", "mission_read_authorized",
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


def _login_owner_after_restart(page, username: str, password: str) -> dict:
    try:
        page.locator("#loginUsername").fill(username)
        page.locator("#loginPassword").fill(password)
        with page.expect_response(
            lambda response: response.request.method == "POST"
            and "/api/public/auth/login" in response.url,
            timeout=30_000,
        ) as response_info:
            page.locator("#loginButton").click(timeout=30_000)
        response = response_info.value
        body = response.json()
        if response.status == 200 and isinstance(body, dict):
            state = _renderer_owner_auth_state(page)
            return {
                "http_status": response.status,
                "authenticated": body.get("authenticated") is True,
                "username": body.get("username"),
                "renderer_authenticated": state.get("authenticated") is True,
            }
        return {"http_status": response.status, "authenticated": False}
    except Exception as exc:
        return {"http_status": None, "authenticated": False, "error_type": type(exc).__name__}


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


def _mission_audit_snapshot(page, mission_id: str) -> dict:
    mission_path = "/api/public/missions/" + mission_id
    results = {
        "status": _public_api(page, "GET", mission_path + "/status"),
        "timeline": _public_api(page, "GET", mission_path + "/timeline"),
        "evidence": _public_api(page, "GET", mission_path + "/evidence"),
        "report": _public_api(page, "GET", mission_path + "/report"),
        "effects": _public_api(page, "GET", mission_path + "/effects"),
    }
    if any(item["http_status"] != 200 for item in results.values()):
        raise RuntimeError("installed_app_mission_audit_endpoints_unavailable_after_restart")
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
        raise RuntimeError("installed_app_mission_audit_payload_invalid_after_restart")
    return {"status": status, "timeline": timeline, "evidence": evidence, "report": report, "effects": effects}


def _mission_audit_projection(snapshot: dict, mission_id: str) -> dict:
    status = snapshot.get("status") if isinstance(snapshot.get("status"), dict) else {}
    timeline = snapshot.get("timeline") if isinstance(snapshot.get("timeline"), list) else []
    evidence = snapshot.get("evidence") if isinstance(snapshot.get("evidence"), list) else []
    report = snapshot.get("report") if isinstance(snapshot.get("report"), dict) else {}
    summary = report.get("mission_summary") if isinstance(report.get("mission_summary"), dict) else {}
    verification = summary.get("verification") if isinstance(summary.get("verification"), dict) else {}
    report_evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
    chain = report_evidence.get("execution_chain") if isinstance(report_evidence.get("execution_chain"), list) else []
    provenance = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    effects = _effect_ledger_projection(snapshot.get("effects", []), mission_id)
    evidence_mission_ids = []
    for item in evidence:
        if not isinstance(item, dict):
            evidence_mission_ids.append(None)
            continue
        evidence_provenance = item.get("provenance") if isinstance(item.get("provenance"), dict) else {}
        evidence_mission_ids.append(item.get("mission_id") or evidence_provenance.get("mission_id"))
    evidence_records_bound = all(item == mission_id for item in evidence_mission_ids)
    tool_execution_count = sum(
        isinstance(item, dict) and item.get("event") == "ToolExecuted" for item in timeline
    )
    binding_verified = (
        status.get("mission_id") == mission_id
        and summary.get("mission_id") == mission_id
        and provenance.get("mission_id") == mission_id
        and all(isinstance(item, dict) and item.get("mission_id") == mission_id for item in chain)
        and evidence_records_bound
        and effects.get("mission_binding_verified") is True
    )
    report_sha256 = report.get("report_sha256")
    validation_sha256 = _canonical_sha256(verification)
    report_verified = (
        summary.get("mission_status") == status.get("status")
        and isinstance(report_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", report_sha256) is not None
        and isinstance(report_evidence.get("execution_chain_integrity"), str)
    )
    return {
        "mission_id": mission_id,
        "status_mission_id_matches": status.get("mission_id") == mission_id,
        "report_mission_id_matches": summary.get("mission_id") == mission_id,
        "provenance_mission_id_matches": provenance.get("mission_id") == mission_id,
        "evidence_and_chain_bound_to_mission": binding_verified,
        "evidence_records_bound_to_mission": evidence_records_bound,
        "evidence_record_count": len(evidence),
        "validation_record_mission_id": summary.get("mission_id"),
        "validation_record_bound_to_mission": (
            summary.get("mission_id") == mission_id
            and summary.get("mission_status") == status.get("status")
            and isinstance(verification.get("verified"), bool)
        ),
        "effect_ledger": effects,
        "mission_status": status.get("status"),
        "queue_state": (status.get("queue") or {}).get("state") if isinstance(status.get("queue"), dict) else None,
        "pause_requested": (status.get("progress") or {}).get("pause_requested") is True
        if isinstance(status.get("progress"), dict) else False,
        "tool_execution_count": tool_execution_count,
        "tool_projection": _tool_execution_projection(status),
        "timeline_event_count": len(timeline),
        "timeline_sha256": _canonical_sha256(timeline),
        "evidence_item_count": len(evidence),
        "evidence_sha256": _canonical_sha256(evidence),
        "validation_sha256": validation_sha256,
        "report_sha256": report_sha256,
        "report_outcome": summary.get("outcome"),
        "report_verified": verification.get("verified"),
        "execution_chain_integrity": report_evidence.get("execution_chain_integrity"),
        "final_report_approval_status": (report.get("final_report_approval") or {}).get("status")
        if isinstance(report.get("final_report_approval"), dict) else None,
        "report_projection_valid": report_verified,
        "completed_mission_inspectable": (
            status.get("status") == "GOAL_COMPLETED"
            and summary.get("mission_status") == "GOAL_COMPLETED"
            and summary.get("outcome") == "VERIFIED"
            and verification.get("verified") is True
            and report_evidence.get("execution_chain_integrity") == "VALID"
            and len(evidence) > 0
            and bool(chain)
            and evidence_records_bound
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
    if pause_verified:
        before_restart_snapshot = _mission_audit_snapshot(page, mission_id)
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
    test_tool_pass = any(item.get("name") == "run_project_tests" and item.get("ok") is True for item in tool_summary)
    event_types = [str(item.get("event", "")) for item in timeline if isinstance(item, dict)]
    research_stage = any(name in event_types for name in ("ObservationReceived", "ObservationInterpreted"))
    hypothesis_stage = "HypothesisUpdated" in event_types
    evidence_stage = len(evidence) > 0 and "EvidenceAdded" in event_types
    finding_count = len(report.get("findings", [])) if isinstance(report.get("findings"), list) else 0
    report_stage = bool(report.get("report_sha256")) and bool(report_summary)
    approval_pending = final_report_approval.get("status") == "PENDING"
    terminal_restart_cycle: dict = {"status": "NOT_RUN", "reason": "mission_not_terminal_or_restart_unavailable"}
    terminal_restart_snapshot: dict | None = None
    terminal_restart_eligible = mission_state.get("status") in terminal and (
        paused_restart_cycle.get("status") in {"PASS", "NOT_RUN"}
    )
    if terminal_restart_eligible:
        before_terminal_snapshot = _mission_audit_snapshot(page, mission_id)
        page_after_terminal_restart, terminal_restart_cycle, terminal_restart_snapshot = restart_callback(
            "terminal_mission", mission_id, before_terminal_snapshot, False
        )
        if page_after_terminal_restart is not None:
            page = page_after_terminal_restart
        if terminal_restart_snapshot is not None:
            before_terminal_projection = _mission_audit_projection(before_terminal_snapshot, mission_id)
            after_terminal_projection = _mission_audit_projection(terminal_restart_snapshot, mission_id)
            stable_fields = (
                "status_mission_id_matches", "report_mission_id_matches", "provenance_mission_id_matches",
                "evidence_and_chain_bound_to_mission", "evidence_records_bound_to_mission",
                "validation_record_bound_to_mission", "mission_status", "queue_state", "tool_execution_count",
                "evidence_sha256", "validation_sha256", "report_sha256", "report_outcome", "report_verified",
                "effect_ledger",
                "execution_chain_integrity", "final_report_approval_status",
            )
            terminal_records_unchanged = all(
                before_terminal_projection.get(key) == after_terminal_projection.get(key)
                for key in stable_fields
            )
            terminal_restart_cycle["mission"] = {
                "mission_id": mission_id,
                "before_restart": before_terminal_projection,
                "after_restart": after_terminal_projection,
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
                and after_terminal_projection.get("evidence_and_chain_bound_to_mission") is True
                and after_terminal_projection.get("report_projection_valid") is True
            ) else "FAIL"
    completed_mission_inspectable_after_restart = bool(
        terminal_restart_snapshot
        and _mission_audit_projection(terminal_restart_snapshot, mission_id)["completed_mission_inspectable"]
    )
    run_project_tests_calls = [item for item in tool_summary if item.get("name") == "run_project_tests"]
    no_duplicate_tool_call_ids = not _tool_execution_projection(mission_state)["duplicate_tool_call_ids"]
    paused_restart_pass = paused_restart_cycle.get("status") == "PASS"
    terminal_restart_pass = terminal_restart_cycle.get("status") == "PASS"
    mission_pass = (
        mission_state.get("status") == "GOAL_COMPLETED"
        and authorization_binding
        and scope_firewall_verified
        and tool_authorization_verified
        and research_stage
        and hypothesis_stage
        and test_tool_pass
        and evidence_stage
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
        and len(run_project_tests_calls) == 1
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
        "run_project_tests_invocation_count": len(run_project_tests_calls),
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
            "close_method": "taskkill.exe /PID <pid> /T /F",
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
                    lambda response: response.request.method == "POST" and "/api/public/auth/login" in response.url,
                    timeout=30_000,
                ) as invalid_response_info:
                    page.locator("#loginButton").click(timeout=30_000)
                invalid_response = invalid_response_info.value
                invalid_body = invalid_response.json()
                stage = "invalid_owner_login_renderer_state"
                page.wait_for_function(
                    "() => document.querySelector('#authStateSide')?.textContent.trim() === 'غير مسجل الدخول'",
                    timeout=30_000,
                )
                invalid_rejected = (
                    invalid_response.status in (400, 401, 403)
                    and invalid_body.get("authenticated") is not True
                )
                report["owner_authentication"].update({
                    "invalid_credentials_rejected": invalid_rejected,
                    "invalid_login_http_status": invalid_response.status,
                    "invalid_login_error": invalid_body.get("error"),
                    "invalid_login_left_owner_unauthenticated": "غير مسجل الدخول" in page.locator("#authStateSide").inner_text(),
                })
                if not invalid_rejected:
                    raise RuntimeError("invalid_owner_credentials_not_safely_rejected")

                page.locator("#loginUsername").fill(username)
                page.locator("#loginPassword").fill(owner_password)
                with page.expect_response(
                    lambda response: response.request.method == "POST" and "/api/public/auth/login" in response.url,
                    timeout=30_000,
                ) as valid_response_info:
                    page.locator("#loginButton").click(timeout=30_000)
                valid_response = valid_response_info.value
                valid_body = valid_response.json()
                page.wait_for_function(
                    "() => (document.querySelector('#authStateSide')?.textContent || '').includes('مسجل الدخول')",
                    timeout=30_000,
                )
                valid_login = (
                    valid_response.status == 200
                    and valid_body.get("authenticated") is True
                    and valid_body.get("username") == username
                )
                report["owner_authentication"].update({
                    "valid_credentials_accepted": valid_login,
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
                        "close_method": "taskkill.exe /PID <pid> /T /F",
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
                        termination = _terminate_installed_process_tree(active_application_pid, args.cdp_port)
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
                            after_snapshot = _mission_audit_snapshot(page, mission_id)
                            before_projection = _mission_audit_projection(before_snapshot, mission_id)
                            after_projection = _mission_audit_projection(after_snapshot, mission_id)
                            cycle["mission"] = {
                                "mission_id": mission_id,
                                "before_restart": before_projection,
                                "after_restart": after_projection,
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
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)[:500]
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
        print(json.dumps({"status": report["status"], "error_type": report["error_type"], "error": report["error"]}, ensure_ascii=False), file=sys.stderr)
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
