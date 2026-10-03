from __future__ import annotations

from pathlib import Path
import json

import pytest

import agent.memory as memory
import agent.task_manager as task_db
import bridge
import core.db as core_db
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse
from owner_session_testutils import allow_owner_sessions


class FinalProvider:
    name = "live-path"
    model = "live-path-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def __init__(self, responses=None):
        self.responses = list(responses or [ProviderResponse(text=json.dumps({"type": "final", "content": "valid answer"}))])
        self.calls = 0

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, messages, **kwargs):
        self.calls += 1
        return {"content": "valid answer"}


@pytest.fixture
def live_dbs(tmp_path, monkeypatch):
    monkeypatch.setattr(task_db, "DB_PATH", Path(tmp_path) / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_db._init_db()
    memory._init_memory_db()
    core_db.connect().close()
    return tmp_path


def test_valid_session_chats_and_persists(live_dbs, monkeypatch):
    import api.chat as chat_mod
    provider = FinalProvider()
    monkeypatch.setattr(chat_mod.RUNTIME, "router", ModelRouter([provider]))
    allow_owner_sessions(monkeypatch, "live-session")
    result = chat_mod.chat({"text": "hello", "conversation_id": "live-valid"}, owner_session_token="live-session")
    assert result["answer"] == "valid answer"
    assert provider.calls == 1
    assert core_db.conversation_messages("live-valid")


def test_missing_or_unknown_session_rejects_before_provider_and_persistence(live_dbs, monkeypatch):
    import api.chat as chat_mod
    provider = FinalProvider()
    monkeypatch.setattr(chat_mod.RUNTIME, "router", ModelRouter([provider]))
    with pytest.raises(PermissionError):
        chat_mod.chat({"text": "hello", "conversation_id": "live-missing"}, owner_session_token="unknown-session")
    assert provider.calls == 0
    assert core_db.conversation_messages("live-missing") == []


def test_revoked_session_rejects_before_provider_and_persistence(live_dbs, monkeypatch):
    import api.chat as chat_mod
    provider = FinalProvider()
    monkeypatch.setattr(chat_mod.RUNTIME, "router", ModelRouter([provider]))
    allow_owner_sessions(monkeypatch, "live-session")
    allow_owner_sessions(monkeypatch)
    with pytest.raises(PermissionError):
        chat_mod.chat({"text": "hello", "conversation_id": "live-revoked"}, owner_session_token="live-session")
    assert provider.calls == 0
    assert core_db.conversation_messages("live-revoked") == []


def test_bridge_owner_session_resolves_server_side_session(monkeypatch):
    allow_owner_sessions(monkeypatch, "live-session")
    handler = bridge.Handler.__new__(bridge.Handler)
    handler.headers = {"X-CyberSentinel-Owner-Session": "live-session"}
    assert bridge.Handler._owner_session(handler) is not None


@pytest.mark.parametrize("action", ("start", "resume"))
def test_bridge_queued_mission_route_passes_authenticated_session(action):
    calls = []

    class Service:
        def start_mission(self, mission_id, *, owner_session_token=None):
            calls.append(("start", mission_id, owner_session_token))
            return {"state": "queued"}

        def resume_mission(self, mission_id, *, owner_session_token=None):
            calls.append(("resume", mission_id, owner_session_token))
            return {"status": "READY"}

    handler = bridge.Handler.__new__(bridge.Handler)
    handler.path = f"/api/missions/mission-1/{action}"
    handler._mission_owner = lambda: {"session_id": "live-session"}
    handler._mission_service = lambda: Service()
    handler._send = lambda status, payload: (status, payload)

    status, response = handler.do_POST()

    assert status == 200
    assert response["ok"] is True
    assert calls == [(action, "mission-1", "live-session")]


def test_bridge_transport_token_is_never_owner_identity():
    handler = bridge.Handler.__new__(bridge.Handler)
    handler.headers = {"X-CyberSentinel-Owner-Session": "transport-secret", "X-CyberSentinel-Token": "transport-secret"}
    assert bridge.Handler._owner_session(handler) is None


@pytest.mark.parametrize(
    ("path", "expected_call", "expected_payload"),
    [
        ("/api/missions/mission-1/effects", ("effects", "mission-1", "owner-session"), {"ok": True, "mission_id": "mission-1", "effects": [{"effect_id": "effect-1", "state": "DISPATCHED"}]}),
        ("/api/missions/mission-1/effects/effect-1", ("inspect", "mission-1", "effect-1", "owner-session"), {"ok": True, "mission_id": "mission-1", "effect": {"effect_id": "effect-1", "state": "DISPATCHED"}}),
    ],
)
def test_bridge_effect_get_routes_bind_authenticated_owner(path, expected_call, expected_payload):
    calls = []

    class Service:
        def effects(self, mission_id, *, owner_session_token=None):
            calls.append(("effects", mission_id, owner_session_token))
            return [{"effect_id": "effect-1", "state": "DISPATCHED"}]

        def inspect_effect(self, mission_id, effect_id, *, owner_session_token=None):
            calls.append(("inspect", mission_id, effect_id, owner_session_token))
            return {"effect_id": effect_id, "state": "DISPATCHED"}

    handler = bridge.Handler.__new__(bridge.Handler)
    handler.path = path
    handler._mission_owner = lambda: {"session_id": "owner-session"}
    handler._mission_service = lambda: Service()
    handler._send = lambda status, payload: (status, payload)

    status, payload = handler.do_GET()

    assert status == 200
    assert payload == expected_payload
    assert calls == [expected_call]


def test_bridge_effect_reconcile_route_passes_typed_owner_decision():
    calls = []

    class Service:
        def reconcile_effect(self, mission_id, effect_id, *, owner_session_token=None, outcome="", evidence_reference=""):
            calls.append((mission_id, effect_id, owner_session_token, outcome, evidence_reference))
            return {"status": "OWNER_CONFIRMED_APPLIED", "dispatch_authorized": False}

    handler = bridge.Handler.__new__(bridge.Handler)
    handler.path = "/api/missions/mission-1/effects/effect-1/reconcile"
    handler._mission_owner = lambda: {"session_id": "owner-session"}
    handler._mission_service = lambda: Service()
    handler._read_json = lambda: {"outcome": "OWNER_CONFIRM_APPLIED", "evidence_reference": "owner-receipt-reference"}
    handler._send = lambda status, payload: (status, payload)

    status, payload = handler.do_POST()

    assert status == 200
    assert payload["reconciliation"]["dispatch_authorized"] is False
    assert calls == [
        ("mission-1", "effect-1", "owner-session", "OWNER_CONFIRM_APPLIED", "owner-receipt-reference")
    ]


def test_bridge_effect_route_maps_foreign_owner_denial_to_403():
    class Service:
        def effects(self, _mission_id, *, owner_session_token=None):
            raise PermissionError("mission access denied")

    handler = bridge.Handler.__new__(bridge.Handler)
    handler.path = "/api/missions/mission-1/effects"
    handler._mission_owner = lambda: {"session_id": "foreign-owner-session"}
    handler._mission_service = lambda: Service()
    handler._send = lambda status, payload: (status, payload)

    status, payload = handler.do_GET()

    assert status == 403
    assert payload["error"] == "mission access denied"
