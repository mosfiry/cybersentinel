"""Contract tests for the CyberSentinel X Agent Workspace frontend.

These tests pin the product model of the web client:

- natural-language-first input (no predefined command buttons, no hidden
  text-to-command mappings),
- mission-centric workspace backed only by server state,
- truthful unavailable states instead of fabricated data,
- untrusted client (no token or session storage in the browser),
- reconnect behavior that re-fetches server state,
- desktop-ready transport boundary (configurable API base).
"""

from __future__ import annotations

import re
from pathlib import Path

SCRIPT = Path("web/app.js").read_text(encoding="utf-8")
PAGE = Path("web/index.html").read_text(encoding="utf-8")
STYLE = Path("web/style.css").read_text(encoding="utf-8")


def test_page_declares_the_workspace_layout():
    markers = (
        'id="missionList"',
        'id="missionHeader"',
        'id="missionView"',
        'id="transcript"',
        'id="activityPanel"',
        'id="composerForm"',
        'id="composerInput"',
        'id="missionForm"',
        'id="missionObjective"',
        'data-view="findings"',
        'data-view="conversation"',
        'data-view="evidence"',
        'data-mission-action="start"',
        'data-mission-action="resume"',
        'data-mission-action="pause"',
        'data-mission-action="cancel"',
    )
    for marker in markers:
        assert marker in PAGE
    assert ".auth-card" in STYLE
    assert ".mission-item" in STYLE
    assert ".activity-item" in STYLE


def test_multi_element_queries_use_collection_helper():
    # $() is querySelector (one element); $$() is querySelectorAll (a collection).
    assert not re.search(r"(?m)^\s*\$\([^\)\n]*\)\.forEach\(", SCRIPT)
    assert '$$("[data-side-view]").forEach' in SCRIPT
    assert '$$("#missionTabs .tab").forEach' in SCRIPT


def test_interaction_is_natural_language_without_predefined_commands():
    # The composer is a free-text input bound to the chat API.
    assert 'id="composerInput"' in PAGE
    assert "صف هدفك أو سؤالك أو خطوتك التالية" in PAGE
    assert "/api/public/chat" in SCRIPT
    # The old predefined command UX must not come back.
    assert "data-p=" not in PAGE
    assert "data-p" not in SCRIPT
    for removed in ("intelBtn", "localBtn", "تحليل الأحداث", "تحديث الاستخبارات", "فحص محلي"):
        assert removed not in PAGE
        assert removed not in SCRIPT


def test_composer_sends_owner_text_verbatim_without_client_side_command_mapping():
    # The text typed by the owner is forwarded as-is; no command strings are
    # minted in the browser.
    assert 'body: JSON.stringify({ text' in SCRIPT
    for mapping in ('== "scan"', '=== "scan"', '"scan"', "sendCommand", "runCommand"):
        assert mapping not in SCRIPT


def test_lifecycle_controls_call_real_server_actions():
    # Owner controls are lifecycle endpoints, not chat messages.
    assert "function missionEndpoint(action)" in SCRIPT
    assert "runMissionAction" in SCRIPT
    assert 'await api(missionEndpoint(action), { method: "POST", body: "{}" });' in SCRIPT
    assert "/api/public/missions" in SCRIPT
    assert "reconcile" in SCRIPT


def test_client_stores_no_tokens_or_sessions_in_the_browser():
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "BRIDGE_TOKEN",
        "OWNER_TOKEN",
        "cs_bridge_token",
        "cs_owner_token",
        "prompt(",
    ):
        assert forbidden not in SCRIPT


def test_reconnect_refetches_server_state():
    assert 'window.addEventListener("online"' in SCRIPT
    assert "visibilitychange" in SCRIPT
    # Mission state is reloaded from the server on reconnect, not from memory.
    assert "refreshConnection" in SCRIPT
    assert "loadMission" in SCRIPT
    refresh_function = SCRIPT.split("async function refreshConnection() {", 1)[1].split("\n}", 1)[0]
    assert "await loadMissions()" in refresh_function


def test_unavailable_contracts_render_truthful_states():
    # No fake tool list, no invented activity, no fallback completion.
    assert "لا يوجد نشاط حالي من الخادم." in SCRIPT
    assert "عقد مفقود" in SCRIPT
    assert '|| "completed"' not in SCRIPT
    assert '"ONLINE"' not in SCRIPT
    activity_writer = SCRIPT.split('function pushActivity(text, kind = "", timestamp = "")', 1)[1].split("\n}", 1)[0]
    assert "new Date()" not in activity_writer
    assert "pushActivity(`أُنشئت مهمة:" not in SCRIPT
    assert "const label = item.event || item.type || item.tool" in SCRIPT
    # Evidence-backed findings only: model text is never a confirmed finding.
    assert "system_evidence" in SCRIPT
    assert "لا ينشئ النظام سجل نتائج مستقلًا" in SCRIPT


def test_transport_boundary_is_desktop_ready():
    assert "CYBERSENTINEL_API_BASE" in SCRIPT
    assert "function apiUrl(path)" in SCRIPT
    assert "apiUrl(" in SCRIPT


def test_completion_and_verification_states_come_from_the_server():
    assert 'selectedMission.status === "GOAL_COMPLETED"' in SCRIPT
    assert "verification.verified === true" in SCRIPT
    assert "completion_proof" in SCRIPT
