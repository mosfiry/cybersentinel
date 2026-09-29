from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_manual_scope_snapshot_ui_is_arabic_bounded_and_does_not_collect_target_credentials():
    page = (ROOT / "web/index.html").read_text(encoding="utf-8")
    script = (ROOT / "web/app.js").read_text(encoding="utf-8")

    assert '<html lang="ar" dir="rtl">' in page
    assert 'data-view="scope-snapshot"' in page
    assert 'id="scopeSnapshotView"' in page
    assert 'id="scopeSnapshotForm"' in page
    assert 'id="scopeSnapshotFields" disabled' in page
    assert 'id="createScopeSnapshot" type="submit" disabled' in page

    scope_form = page.split('<section id="scopeSnapshotView"', 1)[1].split("</section>", 1)[0]
    assert not re.search(r'type=["\']password|autocomplete=["\'](?:username|current-password)', scope_form, re.IGNORECASE)
    assert not re.search(r"(?:owner|session)[_-]?(?:token|secret)|csrf[_-]?token", scope_form, re.IGNORECASE)
    assert "لا تُدخل بيانات اعتماد أو أسرار للهدف" in scope_form
    for template_id in ("inScopeAssetTemplate", "outOfScopeAssetTemplate", "scopeTargetTemplate"):
        assert f'id="{template_id}"' in page
    for bounded_length in ('maxlength="128"', 'maxlength="253"', 'maxlength="119"', 'maxlength="8192"'):
        assert bounded_length in page

    for limit in (
        "MAX_SCOPE_ASSETS = 32",
        "MAX_SCOPE_TARGETS = 32",
        "MAX_SCOPE_PORTS = 20",
        "MAX_SCOPE_PATHS = 32",
        "MAX_SCOPE_METHODS = 9",
    ):
        assert limit in script


def test_manual_scope_submission_uses_api_cookie_csrf_path_only_after_owner_action_and_preserves_missions():
    page = (ROOT / "web/index.html").read_text(encoding="utf-8")
    script = (ROOT / "web/app.js").read_text(encoding="utf-8")

    reset_start = script.index("function resetWorkspaceState()")
    reset_end = script.index("\nfunction rememberConversation", reset_start)
    assert 'showView("overview")' in script[reset_start:reset_end]
    assert '$("#scopeSnapshotView").classList.toggle("hidden", !isScopeSnapshot)' in script

    submit_start = script.index('$("#scopeSnapshotForm").onsubmit')
    submit_end = script.index("\n};", submit_start)
    submit_handler = script[submit_start:submit_end]
    assert "event.preventDefault()" in submit_handler
    assert "if (!state.ownerAuthenticated)" in submit_handler
    assert 'api("/api/public/program-authorizations"' in submit_handler
    assert 'method: "POST"' in submit_handler
    assert script.count("/api/public/program-authorizations") == 1
    assert 'credentials: "include"' in script
    assert '"X-CSRF-Token"' in script
    assert 'fetch(apiUrl("/api/public/program-authorizations")' not in script

    builder_start = script.index("function buildManualScopePayload()")
    builder_end = script.index("\nfunction renderScopeSnapshotSummary", builder_start)
    builder = script[builder_start:builder_end]
    for key in (
        "program_id", "platform", "scope_version", "in_scope_assets", "out_of_scope_assets",
        "targets", "allowed_methods", "prohibited_methods", "rate_limits", "expires_at",
    ):
        mapped = re.search(rf'^\s*(?:"{re.escape(key)}"|{re.escape(key)})\s*:', builder, re.MULTILINE)
        shorthand = re.search(rf'^\s*{re.escape(key)}\s*,\s*$', builder, re.MULTILINE)
        assert mapped or shorthand
    assert "renderScopeSnapshotSummary(data.snapshot)" in submit_handler
    assert 'api("/api/public/chat"' in script
    assert 'api("/api/public/missions"' in script
    assert 'data-view="scope-snapshot"' in page
    assert "localStorage.setItem(CONVERSATION_STORAGE_KEY" in script
    assert "localStorage.setItem(\"scope" not in script


def test_snapshot_success_renderer_reads_only_allowlisted_server_summary_fields():
    script = (ROOT / "web/app.js").read_text(encoding="utf-8")
    start = script.index("function renderScopeSnapshotSummary(snapshot)")
    end = script.index("\nfunction ", start + 10)
    renderer = script[start:end]

    for field in (
        "snapshot_id", "program_id", "platform", "scope_version", "in_scope_asset_count",
        "out_of_scope_asset_count", "target_count", "allowed_methods", "prohibited_methods",
        "rate_limits", "created_at", "expires_at",
    ):
        assert f"snapshot.{field}" in renderer
    assert "textContent" in renderer
    assert "JSON.stringify" not in renderer
    assert "snapshot.targets" not in renderer
    assert "snapshot.owner_session_id" not in renderer
    assert "snapshot.in_scope_assets" not in renderer
