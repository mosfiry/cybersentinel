from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_full_e2e_gate_acceptance import _safe_action_names, find_llama_server_binary
import scripts.windows_desktop_acceptance as windows_acceptance
from scripts.windows_desktop_acceptance import (
    INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS,
    MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES,
    MODEL_STATE_API_MAX_TOTAL_FAILURES,
    OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS,
    OWNER_MISSION_RUNTIME_LIMIT_SECONDS,
    _local_health_status,
    _safe_checkpoint_diagnostics,
    _safe_failure_diagnostics,
    _safe_tool_result_summary,
    _tools_within_authorized_allowlist,
)

ROOT = Path(__file__).resolve().parents[1]


def test_installed_mission_http_wait_matches_bounded_policy_budget() -> None:
    policy = json.loads((ROOT / "security" / "owner_policy.json").read_text(encoding="utf-8"))
    runtime_limit = int(policy["runtime_limits"]["max_execution_time_seconds"])

    assert runtime_limit == OWNER_MISSION_RUNTIME_LIMIT_SECONDS == 300
    assert OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS == 30
    assert INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS == (runtime_limit + 30) * 1000


def test_full_e2e_runtime_preflight_accepts_native_windows_server_name(tmp_path: Path) -> None:
    executable = tmp_path / "llama-server.exe"
    executable.write_bytes(b"test fixture")

    assert find_llama_server_binary(tmp_path, is_windows=True) == executable


def test_full_e2e_runtime_preflight_accepts_posix_server_name(tmp_path: Path) -> None:
    executable = tmp_path / "llama-server"
    executable.write_bytes(b"test fixture")

    assert find_llama_server_binary(tmp_path, is_windows=False) == executable


def test_failure_diagnostics_keep_only_safe_codes_and_bounded_limits() -> None:
    result = _safe_failure_diagnostics({
        "plan": {"steps": [
            {"step_id": "step-1-browser", "action": "browser", "objective": "private objective"},
            {"step_id": "step-2-status", "action": "status", "objective": "another private objective"},
        ]},
        "failures": [{
            "class": "resource",
            "budget": "model_loop_state",
            "reason_code": "repeated_read_only_tool_call",
            "limit": 0,
            "reason": "untrusted arbitrary mission text",
            "step_id": "step-1-browser",
            "details": {"prompt": "must not be serialized"},
        }, {
            "class": "RESOURCE",
            "reason": "repeated read-only tool call",
            "step_id": "step-2-status",
        }],
    })

    assert result == [
        {
            "class": "resource",
            "budget": "model_loop_state",
            "reason_code": "repeated_read_only_tool_call",
            "limit": 0,
            "plan_step_index": 1,
            "step_action": "browser",
        },
        {
            "class": "RESOURCE",
            "reason_code": "repeated_read_only_tool_call",
            "plan_step_index": 2,
            "step_action": "status",
        },
    ]
    assert "private objective" not in repr(result)
    assert "untrusted arbitrary mission text" not in repr(result)


def test_tool_result_summary_reads_nested_model_loop_and_redacts_payloads() -> None:
    summary, source = _safe_tool_result_summary({
        "progress": {"model_loop": {"tool_results": [{
            "name": "browser",
            "arguments": {"url": "secret.example"},
            "tool_call_id": "call_123",
            "ok": False,
            "error": "repeated_read_only_tool_call",
            "result": {
                "failure_class": "RESOURCE",
                "exception": "RuntimeError",
                "error": "untrusted observation text",
            },
        }]}}
    })

    assert source == "model_loop"
    assert summary == [{
        "name": "browser",
        "ok": False,
        "tool_call_id": "call_123",
        "error_code": "repeated_read_only_tool_call",
        "failure_class": "RESOURCE",
        "exception_type": "RuntimeError",
    }]
    assert "secret.example" not in repr(summary)
    assert "untrusted observation text" not in repr(summary)


def test_tool_result_summary_falls_back_to_top_level_results() -> None:
    summary, source = _safe_tool_result_summary({
        "progress": {
            "model_loop": {"tool_results": []},
            "tool_results": [{"name": "run_project_tests", "ok": True}],
        }
    })

    assert source == "top_level"
    assert summary == [{"name": "run_project_tests", "ok": True}]


def test_empty_tool_results_do_not_vacuously_pass_authorization_gate() -> None:
    assert not _tools_within_authorized_allowlist([], ["browser"])
    assert _tools_within_authorized_allowlist([{"name": "browser"}], ["browser"])
    assert not _tools_within_authorized_allowlist([{"name": "mcp.invoke"}], ["browser"])


def test_checkpoint_diagnostics_expose_only_safe_budget_metadata() -> None:
    result = _safe_checkpoint_diagnostics({
        "checkpoint": {
            "status": "budget_blocked",
            "budget": "max_execution_steps",
            "limit": 18,
            "run_id": "private-run-id",
        }
    })

    assert result == {"status": "budget_blocked", "budget": "max_execution_steps", "limit": 18}
    assert "private-run-id" not in repr(result)


def test_qwen_action_diagnostics_reject_non_identifier_model_text() -> None:
    assert _safe_action_names(["mcp.discover", "arbitrary model text: secret"]) == [
        "mcp.discover",
        "<invalid_action_name>",
    ]


def test_model_state_fetch_retries_are_bounded_and_auditable(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0
    state = {"manager": {"operation": {"status": "ready"}}, "models": []}

    def transient_failure(_page):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("untrusted text must not be recorded")
        return state

    monkeypatch.setattr(windows_acceptance, "_model_state", transient_failure)
    monkeypatch.setattr(windows_acceptance, "_local_health_status", lambda _page: 200)
    monkeypatch.setattr(windows_acceptance.time, "sleep", lambda _seconds: None)
    progress: list[dict] = []

    result = windows_acceptance._wait_for_model(
        object(), lambda _state, _model, _operation: True,
        timeout=10, phase="test", progress=progress,
    )

    assert result is state
    assert attempts == 3
    phases = [item["phase"] for item in progress]
    assert phases[:3] == [
        "test_api_fetch_retry",
        "test_api_fetch_retry",
        "test_api_fetch_recovered",
    ]
    assert phases[3:] == ["test"]
    assert progress[0]["local_health_status"] == 200
    assert progress[2]["consecutive_failures"] == 2
    assert "untrusted text" not in repr(progress)


def test_model_state_fetch_fails_after_bounded_consecutive_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        windows_acceptance, "_model_state",
        lambda _page: (_ for _ in ()).throw(RuntimeError("private text")),
    )
    monkeypatch.setattr(windows_acceptance, "_local_health_status", lambda _page: None)
    monkeypatch.setattr(windows_acceptance.time, "sleep", lambda _seconds: None)
    progress: list[dict] = []

    with pytest.raises(RuntimeError, match="desktop_model_manager_api_unavailable_after_bounded_retries"):
        windows_acceptance._wait_for_model(
            object(), lambda _state, _model, _operation: False,
            timeout=60, phase="test", progress=progress,
        )

    assert len(progress) == MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES == 5
    assert MODEL_STATE_API_MAX_TOTAL_FAILURES == 10
    assert all(item["phase"] == "test_api_fetch_retry" for item in progress)
    assert "private text" not in repr(progress)


def test_health_probe_refuses_non_loopback_url() -> None:
    class Page:
        url = "http://example.com:1234/"

    assert _local_health_status(Page()) is None
