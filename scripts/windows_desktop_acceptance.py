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
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
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


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


_SAFE_DIAGNOSTIC_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")


def _safe_failure_diagnostics(mission_state: dict) -> list[dict]:
    failures = mission_state.get("failures")
    if not isinstance(failures, list):
        return []
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
        if item:
            summary.append(item)
    return summary


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


def _find_state_directory(profile_root: Path) -> Path:
    root = profile_root.expanduser().resolve(strict=True)
    for database in root.rglob("intel.sqlite3"):
        state = database.parent
        if state.name.casefold() == "state" and (state / "workspaces").is_dir():
            return state
    raise RuntimeError("installed_app_disposable_state_directory_not_found")


def _installed_app_mission(page, profile_root: Path, progress: list[dict]) -> dict:
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
    if pause_verified:
        page.reload(wait_until="domcontentloaded", timeout=60_000)
        page.wait_for_function(
            "() => (document.querySelector('#authStateSide')?.textContent || '').includes('مسجل الدخول')",
            timeout=60_000,
        )
        persisted = read_status()
        persistence_verified = (
            persisted.get("queue", {}).get("state") == "paused"
            and persisted.get("progress", {}).get("pause_requested") is True
        )
        csrf = _new_csrf_token(page)
        resume_response = _public_api(page, "POST", mission_path + "/resume", csrf=csrf, payload={})
        resume_verified = resume_response["http_status"] == 200
    else:
        persistence_verified = False
        resume_response = {"http_status": 0, "body": {"error": "pause_not_verified"}}
        resume_verified = False

    deadline = started_at + 300.0
    mission_state: dict = {}
    terminal = {
        "GOAL_COMPLETED", "OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED",
        "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "RESOURCE_BLOCKED",
        "RECOVERY_REQUIRED", "SAFETY_BLOCKED", "FAILED_RETRY_EXHAUSTED", "CANCELLED",
    }
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
    mission_progress = mission_state.get("progress", {})
    if not isinstance(mission_progress, dict):
        mission_progress = {}
    tool_results = mission_progress.get("tool_results", [])
    tool_summary = [
        {"name": item.get("name"), "ok": item.get("ok"), "tool_call_id": item.get("tool_call_id")}
        for item in tool_results if isinstance(item, dict)
    ]
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
    tool_authorization_verified = all(item.get("name") in allowed_tools for item in tool_summary)
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
        and persistence_verified is True
        and resume_verified is True
    )
    return {
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
        "queue_state": queue_state.get("state"),
        "resource_failure_diagnostics": _safe_failure_diagnostics(mission_state),
        "tool_calls": tool_summary,
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
        "execution_chain_integrity": chain_integrity,
        "report_outcome": report_outcome,
        "report_verified": report_verification.get("verified"),
        "report_sha256": report.get("report_sha256"),
        "mission_authorization_owner_status": owner_approval.get("status"),
        "final_report_approval_status": final_report_approval.get("status"),
        "human_release_approval": "PENDING",
        "persistence_after_renderer_reload": persistence_verified,
        "resume_after_persisted_pause": resume_verified,
        "elapsed_seconds": round(time.monotonic() - started_at, 3),
        "pause_http_status": pause_response["http_status"],
        "resume_http_status": resume_response["http_status"],
    }


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
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model-timeout-seconds", type=int, default=2400)
    args = parser.parse_args()
    started = time.monotonic()

    report: dict[str, object] = {
        "schema": "cybersentinel-windows-installed-desktop-acceptance-v1",
        "status": "FAIL",
        "mode": args.mode,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_version": args.expected_version,
        "version_endpoint": {},
        "cdp_port": args.cdp_port,
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
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(
                f"http://127.0.0.1:{args.cdp_port}", timeout=30_000
            )
            contexts = browser.contexts
            pages = [page for context in contexts for page in context.pages]
            if not pages:
                raise RuntimeError("installed_desktop_has_no_renderer_page")
            page = pages[0]
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
            qwen = _find_qwen(state)
            report["model_manager"] = {
                "catalog_loaded": bool(model_cards > 0),
                "qwen3_4b_present": qwen is not None,
                "qwen3_4b": ({
                    "model_id": qwen.get("model_id"),
                    "display_name": qwen.get("display_name"),
                    "family": qwen.get("family"),
                    "parameter_size": qwen.get("parameter_size"),
                    "quantization": qwen.get("quantization"),
                    "size_bytes": qwen.get("size_bytes"),
                    "sha256": qwen.get("sha256"),
                    "compatible": qwen.get("compatible"),
                    "recommended": qwen.get("recommended"),
                    "installed": qwen.get("installed"),
                    "active": qwen.get("active"),
                    "installed_sha256": qwen.get("installed_sha256"),
                } if qwen else None),
            }
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
                    install_button.click(timeout=30_000)
                    state = _wait_for_model(
                        page, lambda current, model, operation: bool(model and model.get("installed")),
                        timeout=args.model_timeout_seconds, phase="qwen_download_and_verify", progress=progress,
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
                qwen = _find_qwen(state)
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
                qwen = _find_qwen(state)
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

                stage = "installed_app_full_mission"
                installed_mission = _installed_app_mission(page, args.profile_root, progress)
                report["installed_app_mission"] = installed_mission
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
                    "qwen3_4b_model_manager": bool(qwen and qwen.get("installed")),
                    "local_runtime_initialization": runtime.get("status") == "ready",
                    "real_qwen_local_inference": provider == "local_llama_cpp" and model_name == model_id and bool(inference_text.strip()),
                    "owner_valid_login": report["owner_authentication"].get("valid_credentials_accepted") is True,
                    "owner_invalid_login_rejected": report["owner_authentication"].get("invalid_credentials_rejected") is True,
                    "installed_app_full_mission": report["installed_app_mission"].get("status") == "PASS",
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
