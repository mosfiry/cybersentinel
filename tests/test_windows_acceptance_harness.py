from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.local_runtime.catalog import get_model
from scripts.run_full_e2e_gate_acceptance import _safe_action_names, find_llama_server_binary
import scripts.windows_desktop_acceptance as windows_acceptance
from scripts.windows_desktop_acceptance import (
    EXPECTED_QWEN3_4B_INSTALL_IDENTITY,
    INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS,
    MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES,
    MODEL_STATE_API_MAX_TOTAL_FAILURES,
    OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS,
    OWNER_MISSION_RUNTIME_LIMIT_SECONDS,
    _build_expected_qwen_install_consent,
    _canonical_sha256,
    _effect_ledger_projection,
    _handle_qwen_install_dialog,
    _local_health_status,
    _is_expected_qwen_install_post_request,
    _may_continue_qwen_install_post,
    _may_resume_after_application_restart,
    _mission_audit_projection,
    _model_runtime_after_restart,
    _owner_auth_after_restart,
    _qwen_installed_digest_report,
    _require_qwen_installed_digest,
    _require_qwen_install_consent,
    _refresh_qwen_model_snapshot,
    _safe_checkpoint_diagnostics,
    _safe_failure_diagnostics,
    _safe_tool_result_summary,
    _tool_execution_projection,
    _tools_within_authorized_allowlist,
    _validate_qwen_install_post_response,
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


def test_restart_resume_requires_persisted_pause_authorization_and_unchanged_execution_history() -> None:
    accepted = {
        "mission_status": "RUNNING",
        "queue_state": "paused",
        "pause_requested": True,
        "owner_authorized": True,
        "runtime_ready": True,
        "execution_history_unchanged": True,
    }
    assert _may_resume_after_application_restart(**accepted)
    for key, value in (
        ("queue_state", "running"),
        ("pause_requested", False),
        ("owner_authorized", False),
        ("runtime_ready", False),
        ("execution_history_unchanged", False),
        ("mission_status", "RESOURCE_BLOCKED"),
    ):
        candidate = {**accepted, key: value}
        assert not _may_resume_after_application_restart(**candidate), key


def test_owner_reauthentication_after_restart_rejects_invalid_password_and_restores_same_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id = "mission-acceptance-1"
    identity = "owner:0123456789abcdef"
    responses = [
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 403, "body": {"error": "invalid_credentials", "authenticated": False}},
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 200, "body": {"status": {"mission_id": mission_id, "owner_identity_ref": identity}}},
    ]

    def fake_api(_page, _method, _path, *, csrf="", payload=None):
        if payload is not None and payload.get("password") == "correct-test-only-password":
            assert csrf == "csrf-test-token"
        return responses.pop(0)

    monkeypatch.setattr(windows_acceptance, "_public_api", fake_api)
    monkeypatch.setattr(windows_acceptance, "_new_csrf_token", lambda _page: "csrf-test-token")
    monkeypatch.setattr(
        windows_acceptance, "_login_owner_after_restart",
        lambda *_args: {"http_status": 200, "authenticated": True, "username": "mosfiry"},
    )
    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True, "login_form_hidden": True, "logout_button_visible": True},
    )

    result = _owner_auth_after_restart(
        object(), f"/api/public/missions/{mission_id}", "mosfiry",
        "correct-test-only-password", identity,
    )

    assert result["status"] == "PASS"
    assert result["invalid_credentials_rejected"] is True
    assert result["invalid_login_preserved_existing_owner"] is False
    assert result["invalid_login_did_not_create_owner_session"] is True
    assert result["invalid_login_authorization_state_unchanged"] is True
    assert result["valid_login_after_restart"] is True
    assert result["owner_identity_matches"] is True
    assert result["mission_read_authorized"] is True
    assert "correct-test-only-password" not in repr(result)


def test_owner_session_survives_restart_but_invalid_login_does_not_replace_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id = "mission-acceptance-1"
    identity = "owner:0123456789abcdef"
    status_body = {"status": {"mission_id": mission_id, "owner_identity_ref": identity}}
    responses = [
        {"http_status": 200, "body": status_body},
        {"http_status": 403, "body": {"error": "invalid_credentials", "authenticated": False}},
        {"http_status": 200, "body": status_body},
        {"http_status": 200, "body": status_body},
    ]

    monkeypatch.setattr(windows_acceptance, "_public_api", lambda *_args, **_kwargs: responses.pop(0))
    monkeypatch.setattr(windows_acceptance, "_new_csrf_token", lambda _page: "csrf-test-token")
    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True, "login_form_hidden": True, "logout_button_visible": True},
    )

    result = _owner_auth_after_restart(
        object(), f"/api/public/missions/{mission_id}", "mosfiry", "test-only-password", identity
    )

    assert result["status"] == "PASS"
    assert result["owner_session_restored"] is True
    assert result["valid_login_after_restart"] is True
    assert result["invalid_login_preserved_existing_owner"] is True
    assert result["invalid_login_did_not_create_owner_session"] is False
    assert result["invalid_login_authorization_state_unchanged"] is True
    assert "test-only-password" not in repr(result)


def test_post_restart_model_gate_reports_unrestored_selection_and_runtime_truthfully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    digest = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]
    state = {
        "models": [{
            **_qwen_model_payload(), "installed": True, "installed_sha256": digest,
            "selected": False, "active": False,
        }],
        "manager": {"runtime": {"status": "stopped", "model_id": None}, "operation": {"status": "complete"}},
    }
    monkeypatch.setattr(windows_acceptance, "_model_state", lambda _page: state)
    monkeypatch.setattr(windows_acceptance, "_wait_for_model", lambda _page, _predicate, **_kwargs: state)
    monkeypatch.setattr(
        windows_acceptance, "_installed_runtime_binary_evidence",
        lambda _executable: {"exists": True, "sha256": "c" * 64, "version": "test-version"},
    )

    result = _model_runtime_after_restart(object(), tmp_path / "CyberSentinel.exe", [], verify_inference=False)

    assert result["status"] == "FAIL"
    assert result["selected_after_restart"] is False
    assert result["active_after_restart"] is False
    assert result["runtime_ready_after_restart"] is False
    assert result["runtime_binary"]["version"] == "test-version"


def test_tool_execution_projection_detects_replayed_call_ids_without_payloads() -> None:
    mission = {
        "progress": {"model_loop": {"tool_results": [
            {"name": "run_project_tests", "tool_call_id": "call_once", "ok": True,
             "arguments": {"workspace": "private-path", "secret": "must-not-appear"}},
            {"name": "run_project_tests", "tool_call_id": "call_once", "ok": True,
             "arguments": {"workspace": "private-path", "secret": "must-not-appear"}},
        ]}}
    }

    projection = _tool_execution_projection(mission)

    assert projection["count"] == 2
    assert projection["run_project_tests_count"] == 2
    assert projection["duplicate_tool_call_ids"] is True
    assert "private-path" not in repr(projection)
    assert "must-not-appear" not in repr(projection)


def test_effect_ledger_projection_detects_duplicate_or_misbound_effects_without_payloads() -> None:
    mission_id = "mission-acceptance-1"
    records = [
        {
            "effect_id": "effect-1", "mission_id": mission_id, "task_id": "step-1",
            "execution_id": "execution-1", "provider": "local", "operation": "inspect",
            "state": "completed", "requires_reconciliation": False, "owner_binding_status": "bound",
            "updated_at": "2026-10-10T00:00:00Z", "private_payload": "must-not-appear",
        },
        {
            "effect_id": "effect-1", "mission_id": mission_id, "task_id": "step-1",
            "execution_id": "execution-1", "provider": "local", "operation": "inspect",
            "state": "completed", "requires_reconciliation": False, "owner_binding_status": "bound",
            "updated_at": "2026-10-11T00:00:00Z", "private_payload": "must-not-appear",
        },
    ]

    projection = _effect_ledger_projection(records, mission_id)
    misbound = _effect_ledger_projection([{**records[0], "mission_id": "another-mission"}], mission_id)
    timestamp_only_change = _effect_ledger_projection(
        [{**records[0], "updated_at": "2026-10-12T00:00:00Z"},
         {**records[1], "updated_at": "2026-10-13T00:00:00Z"}], mission_id
    )

    assert projection["available"] is True
    assert projection["count"] == 2
    assert projection["duplicate_effect_ids"] is True
    assert projection["mission_binding_verified"] is True
    assert projection["sha256"] == timestamp_only_change["sha256"]
    assert misbound["mission_binding_verified"] is False
    assert "must-not-appear" not in repr(projection)


def test_mission_audit_projection_requires_mission_bound_validation_evidence_and_report() -> None:
    mission_id = "mission-acceptance-1"
    report_sha = "a" * 64
    snapshot = {
        "status": {
            "mission_id": mission_id,
            "status": "GOAL_COMPLETED",
            "queue": {"state": "completed"},
            "progress": {"pause_requested": False, "model_loop": {"tool_results": [
                {"name": "run_project_tests", "tool_call_id": "call_once", "ok": True}
            ]}},
        },
        "timeline": [{"event": "ToolExecuted"}],
        "evidence": [{"evidence_id": "evidence-1", "provenance": {"mission_id": mission_id}}],
        "effects": [],
        "report": {
            "mission_summary": {
                "mission_id": mission_id,
                "mission_status": "GOAL_COMPLETED",
                "outcome": "VERIFIED",
                "verification": {"verified": True, "evidence_count": 1},
            },
            "provenance": {"mission_id": mission_id, "execution_chain": []},
            "evidence": {
                "execution_chain": [{"mission_id": mission_id, "current_hash": "b" * 64}],
                "execution_chain_integrity": "VALID",
            },
            "report_sha256": report_sha,
            "final_report_approval": {"status": "PENDING"},
        },
    }

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["evidence_and_chain_bound_to_mission"] is True
    assert projection["report_projection_valid"] is True
    assert projection["completed_mission_inspectable"] is True
    assert projection["evidence_records_bound_to_mission"] is True
    assert projection["validation_record_bound_to_mission"] is True
    assert projection["report_sha256"] == report_sha
    assert projection["validation_sha256"] == _canonical_sha256({"verified": True, "evidence_count": 1})

    snapshot["report"]["mission_summary"]["mission_id"] = "another-mission"
    wrong_mission_projection = _mission_audit_projection(snapshot, mission_id)
    assert wrong_mission_projection["evidence_and_chain_bound_to_mission"] is False
    assert wrong_mission_projection["completed_mission_inspectable"] is False

    snapshot["report"]["mission_summary"]["mission_id"] = mission_id
    snapshot["evidence"][0]["provenance"]["mission_id"] = "another-mission"
    unbound_evidence_projection = _mission_audit_projection(snapshot, mission_id)
    assert unbound_evidence_projection["evidence_records_bound_to_mission"] is False
    assert unbound_evidence_projection["completed_mission_inspectable"] is False


def test_native_acceptance_restart_is_not_a_renderer_reload_or_in_process_refresh() -> None:
    driver = (ROOT / "scripts" / "windows_desktop_acceptance.py").read_text(encoding="utf-8")
    powershell = (ROOT / "scripts" / "windows_installer_acceptance.ps1").read_text(encoding="utf-8")

    assert "taskkill.exe\", \"/PID\", str(process_id), \"/T\", \"/F\"" in driver
    assert "--installed-executable" in powershell
    assert "--application-pid" in powershell
    assert "process_tree_termination_verified" in driver
    assert "initial_application_process_not_running_from_installed_path" in driver
    assert "--mode full requires --installed-executable and --application-pid" in driver
    assert '"renderer_reload_used": False' in driver
    assert "page.reload(" not in driver
    assert "Stop-InstalledProcessTrees" in powershell
    assert "remaining_process_ids" in powershell


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


def _qwen_model_payload() -> dict:
    model = get_model("qwen3-4b-q4-k-m")
    return {key: getattr(model, key) for key in EXPECTED_QWEN3_4B_INSTALL_IDENTITY}


@pytest.mark.parametrize(
    "installed,installed_sha256,catalog_sha256",
    [
        (True, None, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (True, "0" * 64, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (False, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"], EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (True, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"], "0" * 64),
    ],
)
def test_final_qwen_digest_gate_rejects_missing_or_mismatched_digest(
    installed, installed_sha256, catalog_sha256
) -> None:
    model = {
        **_qwen_model_payload(),
        "installed": installed,
        "installed_sha256": installed_sha256,
        "sha256": catalog_sha256,
    }

    digest_report = _qwen_installed_digest_report(model)
    assert digest_report["installed"] is installed
    assert digest_report["verified"] is False
    with pytest.raises(RuntimeError, match="qwen3_4b_installed_digest_missing_or_mismatched"):
        _require_qwen_installed_digest(digest_report)


def test_final_qwen_digest_gate_accepts_only_pinned_installed_digest() -> None:
    digest = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]
    model = {
        **_qwen_model_payload(),
        "installed": True,
        "installed_sha256": digest,
    }

    digest_report = _qwen_installed_digest_report(model)
    assert digest_report["matches_catalog"] is True
    assert digest_report["matches_pinned"] is True
    assert digest_report["verified"] is True
    _require_qwen_installed_digest(digest_report)


def test_qwen_snapshot_refreshes_from_final_post_activation_poll_state() -> None:
    initial_model = {
        **_qwen_model_payload(),
        "family": "Qwen3",
        "parameter_size": "4B",
        "compatible": True,
        "recommended": True,
        "installed": False,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": False,
        "active": False,
    }
    report = {"model_manager": {"catalog_loaded": True}}

    _refresh_qwen_model_snapshot(
        report, {"models": [initial_model]}, phase="initial_catalog_state"
    )
    assert report["model_manager"]["qwen3_4b"]["installed"] is False
    assert report["model_manager"]["qwen3_4b"]["installed_sha256"] is None

    final_model = {
        **initial_model,
        "installed": True,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": True,
        "active": True,
    }
    returned_model = _refresh_qwen_model_snapshot(
        report, {"models": [final_model]}, phase="post_activation_inference_poll"
    )

    assert returned_model is final_model
    assert report["model_manager"]["qwen3_4b_snapshot_phase"] == "post_activation_inference_poll"
    assert report["model_manager"]["qwen3_4b"] == {
        "model_id": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"],
        "display_name": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["display_name"],
        "family": "Qwen3",
        "parameter_size": "4B",
        "repository": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["repository"],
        "revision": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["revision"],
        "filename": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["filename"],
        "quantization": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["quantization"],
        "size_bytes": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["size_bytes"],
        "sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "compatible": True,
        "recommended": True,
        "installed": True,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": True,
        "active": True,
    }

    source = (ROOT / "scripts" / "windows_desktop_acceptance.py").read_text(encoding="utf-8")
    snapshot_phases = [
        'phase="post_install_verification_poll"',
        'phase="post_activation_poll"',
        'phase="post_install_activation_poll"',
        'phase="post_activation_inference_poll"',
    ]
    phase_positions = [source.index(phase) for phase in snapshot_phases]
    assert phase_positions == sorted(phase_positions)
    assert source.index('timeout=300, phase="real_local_inference"') < phase_positions[-1]
    assert phase_positions[-1] < source.index("_require_qwen_installed_digest(digest_verification)")
    assert '"qwen3_4b_model_manager":' in source
    assert '"qwen3_4b_installed_digest_matches_catalog_and_pin":' in source
    assert '"qwen3_4b_runtime_active":' in source
    assert '"real_qwen_local_inference":' in source


class _FakeDialog:
    def __init__(self, message: str, *, dialog_type: str = "confirm") -> None:
        self.message = message
        self.type = dialog_type
        self.accepted = False
        self.dismissed = False

    def accept(self) -> None:
        self.accepted = True

    def dismiss(self) -> None:
        self.dismissed = True


def test_qwen_install_consent_is_pinned_to_curated_model_identity() -> None:
    model = get_model("qwen3-4b-q4-k-m")
    catalog_identity = {
        key: getattr(model, key)
        for key in EXPECTED_QWEN3_4B_INSTALL_IDENTITY
    }

    assert EXPECTED_QWEN3_4B_INSTALL_IDENTITY == catalog_identity
    assert _build_expected_qwen_install_consent(_qwen_model_payload()) == (
        "تنزيل هذا الملف إلى جهازك؟\n\n"
        "Qwen3 4B · Q4_K_M\n"
        "unsloth/Qwen3-4B-GGUF@22c9fc8a8c7700b76a1789366280a6a5a1ad1120\n"
        "Qwen3-4B-Q4_K_M.gguf · 2.3 GiB\n"
        "الرخصة في بطاقة التحويل: Apache-2.0\n"
        "SHA-256: f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a\n\n"
        "سيُستخدم llama.cpp محليًا بعد التحقق. لا يبدأ التنزيل إلا بموافقتك."
    )


def test_matching_qwen_install_consent_is_accepted() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected)
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent, authorize_test_download=True)
    _require_qwen_install_consent(consent)

    assert dialog.accepted and not dialog.dismissed
    assert consent == {"seen": True, "accepted": True, "mismatch": False, "authorized": True}


def test_matching_qwen_install_consent_is_dismissed_without_explicit_opt_in() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected)
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent)

    assert dialog.dismissed and not dialog.accepted
    assert consent["authorized"] is False
    with pytest.raises(RuntimeError, match="qwen3_4b_test_download_explicit_opt_in_required"):
        _require_qwen_install_consent(consent)


def test_mismatched_qwen_install_consent_is_dismissed_and_fails_closed() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected.replace("2.3 GiB", "2.4 GiB"))
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent, authorize_test_download=True)

    assert dialog.dismissed and not dialog.accepted
    with pytest.raises(RuntimeError, match="qwen3_4b_install_consent_mismatch"):
        _require_qwen_install_consent(consent)


def test_missing_qwen_install_consent_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="qwen3_4b_install_consent_missing"):
        _require_qwen_install_consent({"seen": False, "accepted": False, "mismatch": False, "authorized": True})


def test_qwen_install_consent_refuses_catalog_identity_drift() -> None:
    model = _qwen_model_payload()
    model["revision"] = "0" * 40

    assert _build_expected_qwen_install_consent(model) is None


def test_qwen_install_post_guard_requires_exact_explicit_authorization_and_loopback_route() -> None:
    origin = "http://127.0.0.1:4312"
    expected_id = "qwen3-4b-q4-k-m"
    consent = {"authorized": True, "seen": True, "accepted": True, "mismatch": False}
    request = _FakeInstallRequest(f"{origin}/api/public/desktop/models/{expected_id}/install")

    assert _is_expected_qwen_install_post_request(request, expected_id, origin)
    assert _may_continue_qwen_install_post(request, expected_id, origin, consent)
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "authorized": False})
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "accepted": False})
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "mismatch": True})
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"https://127.0.0.1:4312/api/public/desktop/models/{expected_id}/install"),
        expected_id,
        origin,
    )
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"{origin}/api/public/desktop/models/other-model/install"),
        expected_id,
        origin,
    )
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"{origin}/api/public/desktop/models/{expected_id}/install", method="GET"),
        expected_id,
        origin,
    )


class _FakeInstallRequest:
    def __init__(
        self,
        url: str = "http://127.0.0.1:4312/api/public/desktop/models/qwen3-4b-q4-k-m/install",
        method: str = "POST",
    ) -> None:
        self.url = url
        self.method = method


class _FakeInstallResponse:
    request = _FakeInstallRequest()
    url = "http://127.0.0.1:4312/api/public/desktop/models/qwen3-4b-q4-k-m/install"

    def __init__(self, status: int, body: dict) -> None:
        self.status = status
        self._body = body

    def json(self) -> dict:
        return self._body


def test_qwen_install_post_rejects_unexpected_http_status() -> None:
    response = _FakeInstallResponse(409, {"ok": False, "error": "model_manager_busy"})

    with pytest.raises(RuntimeError, match="qwen3_4b_install_post_unexpected_http_status"):
        _validate_qwen_install_post_response(response, "qwen3-4b-q4-k-m")


@pytest.mark.parametrize(
    "body",
    [
        {"ok": True, "manager": {"operation": {"kind": "install", "model_id": "qwen3-4b-q4-k-m", "status": "idle"}}},
        {"ok": True, "manager": {"operation": {"kind": "install", "model_id": "qwen3-4b-q4-k-m"}}},
        {"ok": True, "manager": {"operation": {"kind": "activate", "model_id": "qwen3-4b-q4-k-m", "status": "downloading"}}},
    ],
)
def test_qwen_install_post_without_started_install_operation_fails_immediately(body: dict) -> None:
    response = _FakeInstallResponse(202, body)

    with pytest.raises(RuntimeError, match="qwen3_4b_install_operation_not_started"):
        _validate_qwen_install_post_response(response, "qwen3-4b-q4-k-m")
