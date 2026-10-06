#!/usr/bin/env python3
"""Browser-in-Mission acceptance against a narrow, public HTTPS origin.

A deterministic planner proposes one canonical browser operation. The real
Owner-bound MissionRuntime, ScopeStore, Chromium BrowserService, DNS-pinned HTTP
transport, evidence chain, and mission validator perform the work.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from scripts.acceptance_result import apply_cleanup_gate

_BROWSER_FEATURE_CHECKS = (
    "real_owner_mission_completed",
    "browser_was_the_mission_tool",
    "real_chromium_navigation_and_extraction",
    "evidence_and_validator_passed",
    "page_data_remains_untrusted",
    "session_is_bound_to_this_mission",
)
_BROWSER_CLEANUP_CHECKS = (
    "cleanup_browser_session_stopped",
    "cleanup_environment_patch_reverted",
)


def _browser_acceptance_checks_pass(result: dict) -> bool:
    checks = result.get("checks")
    if (
        not isinstance(checks, dict)
        or result.get("error_type")
        or result.get("error")
        or not all(checks.get(name) is True for name in _BROWSER_FEATURE_CHECKS)
        or not all(checks.get(name) is True for name in _BROWSER_CLEANUP_CHECKS)
    ):
        return False
    return all(value is True for value in checks.values())


class BrowserPlanner:
    name = "browser-acceptance-planner"
    model = "deterministic-browser-tool-proposal"

    def __init__(self, url: str):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.url = url

    def tool_calling(self, _messages, tools, **_kwargs):
        from agent.provider_api import ProviderResponse, ToolCall
        available = {item.get("function", {}).get("name") for item in tools if isinstance(item, dict)}
        if "browser" not in available:
            return ProviderResponse(content="browser tool unavailable")
        return ProviderResponse(tool_calls=[
            ToolCall("browser", {"operation": "open", "url": self.url}, "browser-open-example-domain")
        ])

    def generate(self, _messages, **_kwargs):
        return {"content": "unused"}


def _find_page_result(value):
    if isinstance(value, dict):
        if value.get("ok") is True and isinstance(value.get("title"), str) and isinstance(value.get("text"), str) and isinstance(value.get("session_id"), str):
            return value
        for item in value.values():
            found = _find_page_result(item)
            if found is not None:
                return found
    elif isinstance(value, (list, tuple)):
        for item in value:
            found = _find_page_result(item)
            if found is not None:
                return found
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--url", default="https://example.com/")
    args = parser.parse_args()
    artifact_path = args.artifact.expanduser().resolve()
    run_dir = args.state_dir.expanduser().resolve() / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(parents=True, exist_ok=False)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "schema": "browser-in-mission-acceptance-v1",
        "status": "FAIL",
        "url": args.url,
        "planner_mode": "deterministic tool proposal; browser and mission execution are real",
        "state_dir": str(run_dir),
        "checks": {},
    }
    patcher = None
    browser_service = None
    try:
        import pytest
        from owner_session_testutils import allow_owner_sessions
        import security.scope_store as scope_store
        from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
        from security.session_reference import session_reference
        from agent.agent_core import AgentCore
        from agent.mission import MissionStore
        from agent.model_router import ModelRouter
        from agent.provider_api import ProviderCapabilities
        from security.scope_store import save_snapshot
        from tools.browser import get_browser_service, shutdown_browser_service

        token = "browser-acceptance-owner-session"
        host = "example.com"
        now = datetime.now(timezone.utc)
        created = now.isoformat()
        expires = (now + timedelta(minutes=20)).isoformat()
        program_id = "owner-browser-acceptance-" + uuid.uuid4().hex[:12]
        target_id = "public-https-example-domain-" + uuid.uuid4().hex[:8]
        patcher = pytest.MonkeyPatch()
        allow_owner_sessions(patcher, token)
        patcher.setattr(scope_store, "SCOPE_DB_PATH", run_dir / "scope.sqlite3")
        scope_store.init_scope_store()
        authorization = ProgramAuthorization(
            program_id=program_id,
            platform="owner-approved-read-only-browser-acceptance",
            scope_version="1",
            retrieved_at=created,
            in_scope_assets=({"host": host, "schemes": ["https"], "ports": [443], "paths": ["/"]},),
            owner_session_id=session_reference(token),
            source="owner",
        )
        target = TargetIdentity(
            target_id=target_id,
            program_id=program_id,
            host=host,
            asset_type="public_website",
            environment="public",
            allowed_ports=(443,),
            allowed_paths=("/",),
        )
        scope_snapshot = make_snapshot(
            "scope-" + uuid.uuid4().hex,
            authorization,
            [target],
            created_at=created,
            expires_at=expires,
        )
        save_snapshot(scope_snapshot, owner_session_token=token)
        scope_context = {
            "program_id": program_id,
            "target_id": target_id,
            "scope_snapshot_id": scope_snapshot.snapshot_id,
            "url": args.url,
            "method": "GET",
            "scope": ["host:" + host],
            "allowed_networks": [host],
            "allowed_credentials": [],
        }
        store = MissionStore(run_dir / "missions.sqlite3")
        browser_service = get_browser_service()
        if browser_service._sessions:
            raise RuntimeError("acceptance browser process unexpectedly contains prior sessions")

        core = AgentCore(ModelRouter([BrowserPlanner(args.url)]), store=store)
        mission = core.run_owner_mission(
            "Open the scoped browser on https://example.com/ and extract its page title and body text",
            owner_session_token=token,
            scope_context=scope_context,
            completion_criteria=[{
                "criterion_id": "browser-page-observation",
                "description": "A scoped browser navigation and page extraction produced evidence",
                "check": "browser_extraction",
                "expected_title": "Example Domain",
                "expected_text": "This domain is for use in documentation examples without needing permission.",
                "required": True,
            }],
        )
        tool_names = [step.action for step in mission.plan.steps]
        page_result = _find_page_result(mission.progress.get("model_loop", {}))
        if page_result is None:
            page_result = _find_page_result(mission.observations)
        sessions = [session for session in browser_service._sessions.values() if session.mission_id == mission.mission_id]
        browser_session = sessions[0] if len(sessions) == 1 else None
        page_title = str(page_result.get("title", "")) if page_result else ""
        page_text = str(page_result.get("text", "")) if page_result else ""
        browser_evidence = [
            item for item in mission.evidence
            if isinstance(item, dict)
            and (
                str(item.get("source", "")).startswith("browser:")
                or item.get("record_type") == "UNTRUSTED_BROWSER_OBSERVATION"
                or (item.get("source") == "browser" and (item.get("provenance") or {}).get("verification_authority") == "scoped_browser_extraction_observation")
            )
        ]
        result["checks"]["real_owner_mission_completed"] = (
            mission.status.value == "GOAL_COMPLETED"
            and mission.verify_integrity()
            and mission.verification_state.get("verified") is True
        )
        result["checks"]["browser_was_the_mission_tool"] = tool_names == ["browser"]
        result["checks"]["real_chromium_navigation_and_extraction"] = (
            page_result is not None
            and page_title == "Example Domain"
            and "This domain is for use in documentation examples without needing permission." in page_text
            and page_result.get("scope_enforced") is True
            and page_result.get("network_transport") == "dns_pinned"
        )
        result["checks"]["evidence_and_validator_passed"] = bool(browser_evidence) and bool(mission.evidence) and mission.verification_state.get("verified") is True
        result["checks"]["page_data_remains_untrusted"] = (
            page_result is not None
            and page_result.get("trust") == "untrusted_page_data"
            and page_result.get("authority") == "none"
        )
        result["checks"]["session_is_bound_to_this_mission"] = (
            browser_session is not None
            and browser_session.owner_identity == mission.owner_identity_ref
            and browser_session.mission_id == mission.mission_id
            and browser_session.scope_snapshot_id == scope_snapshot.snapshot_id
            and browser_session.target_id == target_id
            and browser_session.budget.request_count >= 1
        )
        result["mission"] = {
            "mission_id": mission.mission_id,
            "status": mission.status.value,
            "integrity_verified": mission.verify_integrity(),
            "plan_tools": tool_names,
            "evidence_count": len(mission.evidence),
            "browser_evidence_count": len(browser_evidence),
            "validator_verified": mission.verification_state.get("verified") is True,
            "page_title": page_title,
            "contains_expected_text": "This domain is for use in documentation examples without needing permission." in page_text,
            "body_text_excerpt": page_text[:240],
            "browser_session_id": str(page_result.get("session_id", "")) if page_result else "",
            "browser_requests": browser_session.budget.request_count if browser_session else 0,
            "browser_response_bytes": browser_session.budget.byte_count if browser_session else 0,
            "scope_snapshot_id": scope_snapshot.snapshot_id,
            "target_id": target_id,
        }
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:300]
    finally:
        browser_cleanup_ok = False
        try:
            if browser_service is not None:
                from tools.browser import shutdown_browser_service
                shutdown_browser_service()
                result["browser_session_cleanup"] = {
                    "service_stopped": bool(browser_service._stopped),
                    "sessions_remaining": len(browser_service._sessions),
                }
                result["checks"]["acceptance_browser_session_cleaned_up"] = (
                    browser_service._stopped and not browser_service._sessions
                )
                browser_cleanup_ok = result["checks"]["acceptance_browser_session_cleaned_up"] is True
        except Exception as exc:
            result["browser_session_cleanup_error"] = type(exc).__name__
            result["checks"]["acceptance_browser_session_cleaned_up"] = False
        patcher_reverted = patcher is None
        if patcher is not None:
            try:
                patcher.undo()
                patcher_reverted = True
            except Exception as exc:
                result["environment_patch_cleanup_error"] = type(exc).__name__
        apply_cleanup_gate(result, {
            "browser_session_stopped": browser_cleanup_ok,
            "environment_patch_reverted": patcher_reverted,
        })

    result["checks"]["all_browser_acceptance_checks_pass"] = _browser_acceptance_checks_pass(result)
    result["status"] = "PASS" if result["checks"]["all_browser_acceptance_checks_pass"] else "FAIL"
    artifact_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
