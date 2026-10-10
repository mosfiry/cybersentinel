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
    _handle_qwen_install_dialog,
    _local_health_status,
    _is_expected_qwen_install_post_request,
    _may_continue_qwen_install_post,
    _qwen_installed_digest_report,
    _require_qwen_installed_digest,
    _require_qwen_install_consent,
    _refresh_qwen_model_snapshot,
    _safe_checkpoint_diagnostics,
    _safe_failure_diagnostics,
    _safe_tool_result_summary,
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
