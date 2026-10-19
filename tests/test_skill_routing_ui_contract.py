from __future__ import annotations

from pathlib import Path

import pytest

import bridge
from test_public_web_boundary import public_server, _owner_session, _public_session, _request


def test_auto_skill_validation_requires_an_exact_boolean_and_exclusive_selection():
    assert bridge._validate_auto_skill_selection({}, None) is False
    assert bridge._validate_auto_skill_selection({"auto_skill": False}, "explicit-skill") is False
    assert bridge._validate_auto_skill_selection({"auto_skill": True}, None) is True
    for invalid in (None, 0, 1, "true", [], {}):
        with pytest.raises(ValueError, match="invalid_auto_skill"):
            bridge._validate_auto_skill_selection({"auto_skill": invalid}, None)
    with pytest.raises(ValueError, match="conflicting_skill_selection"):
        bridge._validate_auto_skill_selection({"auto_skill": True}, "explicit-skill")


def test_public_mission_summary_exposes_only_bounded_routing_and_binding_metadata():
    mission = {
        "mission_id": "mission-1",
        "status": "READY",
        "provenance": {
            "source": "owner_instruction",
            "owner_private_detail": "must not be exposed",
            "skill_routing": {
                "version": 1,
                "outcome": "selected",
                "reason_code": "eligible_positive_match",
                "skill_id": "triage",
                "skill_version": 7,
                "content_hash": "a" * 64,
                "score": 3,
                "catalog_count": 10,
                "eligible_count": 2,
                "matched_count": 2,
                "arbitrary_instruction": "never serialize this",
            },
        },
        "skill_binding": {
            "schema_version": 1,
            "owner_identity_ref": "owner:secret",
            "mission_id": "mission-1",
            "skill_id": "triage",
            "version": 7,
            "content_hash": "a" * 64,
            "required_tools": ["status"],
            "allowed_scope": ["project"],
            "instruction": "must not be exposed",
        },
    }

    summary = bridge.Handler._public_mission_summary(mission, "project-1")
    assert summary["skill_routing"] == {
        "routing_version": 1,
        "outcome": "selected",
        "reason_code": "eligible_positive_match",
        "catalog_count": 10,
        "eligible_count": 2,
        "matched_count": 2,
        "score": 3,
        "skill_id": "triage",
        "version": 7,
        "content_hash": "a" * 64,
    }
    assert summary["skill_binding"] == {
        "skill_id": "triage",
        "version": 7,
        "content_hash": "a" * 64,
    }
    assert "provenance" not in summary
    assert "owner_identity_ref" not in str(summary)
    assert "arbitrary_instruction" not in str(summary)


def test_public_mission_detail_withholds_provenance_but_keeps_existing_view_fields():
    detail = bridge.Handler._public_mission_detail({
        "status": "RUNNING",
        "error": "bounded error",
        "current_step": 2,
        "plan": {"steps": []},
        "provenance": {"skill_routing": {
            "version": 1,
            "outcome": "ambiguous",
            "reason_code": "top_score_tie",
            "catalog_count": 3,
            "eligible_count": 3,
            "matched_count": 3,
        }, "sensitive": "secret"},
    })
    assert detail["status"] == "RUNNING"
    assert detail["error"] == "bounded error"
    assert detail["current_step"] == 2
    assert detail["skill_routing"]["outcome"] == "ambiguous"
    assert "provenance" not in detail
    assert "sensitive" not in str(detail)


def test_public_routing_summary_rejects_unknown_reasons_and_caps_counts():
    summary = bridge.Handler._public_skill_routing({
        "provenance": {"skill_routing": {
            "version": 1,
            "outcome": "no_match",
            "reason_code": "made_up_reason",
            "catalog_count": 999_999,
        }},
    })
    assert summary is None

    summary = bridge.Handler._public_skill_routing({
        "provenance": {"skill_routing": {
            "version": 1,
            "outcome": "no_match",
            "reason_code": "no_positive_match",
            "catalog_count": 501,
            "eligible_count": True,
        }},
    })
    assert summary == {
        "routing_version": 1,
        "outcome": "no_match",
        "reason_code": "no_positive_match",
    }


def test_auto_skill_ui_contract_is_opt_in_mutually_exclusive_and_text_only():
    html = Path("web/index.html").read_text(encoding="utf-8")
    script = Path("web/app.js").read_text(encoding="utf-8")
    checkbox = html.split('id="missionAutoSkill"', 1)[1].split(">", 1)[0]
    assert 'type="checkbox"' in checkbox
    assert "checked" not in checkbox
    assert 'id="missionSkill"' in html
    assert 'auto_skill: $("#missionAutoSkill").checked' in script
    assert 'if ($("#missionAutoSkill").checked) $("#missionSkill").value = ""' in script
    assert 'selector.disabled = !!document.querySelector("#missionAutoSkill")?.checked' in script
    assert "routingBlock.textContent = lines.join" in script


def test_http_auto_skill_keeps_owner_csrf_and_strict_input_gates(public_server, monkeypatch, tmp_path):
    from types import SimpleNamespace

    project_id = "a" * 32
    calls = []
    project = SimpleNamespace(project_id=project_id, root_path=tmp_path)
    projects = SimpleNamespace(
        get=lambda *_args, **_kwargs: project,
        assign_mission=lambda *_args: None,
    )

    class Core:
        def __init__(self, *_args, **_kwargs):
            pass

        def run_owner_mission(self, objective, **kwargs):
            calls.append((objective, kwargs))
            return SimpleNamespace(mission_id="routed-http")

    service = SimpleNamespace(
        start_mission=lambda *_args, **_kwargs: {"mission_id": "routed-http"},
        status=lambda *_args, **_kwargs: {"mission_id": "routed-http", "status": "QUEUED"},
    )
    monkeypatch.setattr(bridge, "AgentCore", Core)
    monkeypatch.setattr(bridge, "_project_store", lambda: projects)
    monkeypatch.setattr(bridge, "_skill_registry", lambda: object())
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda _self: service)
    payload = {"objective": "Check local status", "project_id": project_id, "auto_skill": True}
    assert _request(public_server, "POST", "/api/public/missions", body=payload)[0] == 401
    public_cookie, public_csrf, _ = _public_session(public_server)
    assert _request(public_server, "POST", "/api/public/missions", body=payload,
                    headers={"Cookie": public_cookie, "X-CSRF-Token": public_csrf})[0] == 403
    cookie, csrf = _owner_session(public_server)
    assert _request(public_server, "POST", "/api/public/missions", body=payload, headers={"Cookie": cookie})[0] == 401
    assert calls == []
    headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
    for extra in ({"auto_skill": "true"}, {"auto_skill": 1}, {"auto_skill": None}, {"skill_id": "explicit"}):
        status, response, _ = _request(
            public_server, "POST", "/api/public/missions", body={**payload, **extra}, headers=headers,
        )
        assert status == 400
        assert response["error"] in {"invalid_auto_skill", "conflicting_skill_selection"}
    assert calls == []
    status, _, _ = _request(public_server, "POST", "/api/public/missions", body=payload, headers=headers)
    assert status == 201
    assert len(calls) == 1
    assert calls[0][1]["auto_skill"] is True
    assert calls[0][1]["skill_id"] is None
    assert calls[0][1]["run"] is False
