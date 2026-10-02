from __future__ import annotations

import uuid

import pytest

from agent.agent_core import AgentCore, validated_request_id
from api.chat import _conversation_id, sse


def test_validated_request_id_accepts_conforming_identifiers():
    assert validated_request_id("req-1") == "req-1"
    generated = uuid.uuid4().hex
    assert validated_request_id(generated) == generated
    long_id = "a" * 128
    assert validated_request_id(long_id) == long_id


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "a" * 129, "req 1", "req.1", "req/1", "req\u00e9", "req'--", None, 5, ["x"], {"id": 1}],
)
def test_validated_request_id_rejects_nonconforming_identifiers(bad):
    with pytest.raises(ValueError):
        validated_request_id(bad)


def test_run_owner_mission_rejects_malformed_request_id_before_authorization(tmp_path):
    core = AgentCore(router=object(), db_path=tmp_path / "missions.sqlite3")
    with pytest.raises(ValueError):
        core.run_owner_mission("objective", owner_session_token="token", request_id="bad id")


def test_auth_rejects_malformed_request_id():
    with pytest.raises(ValueError):
        AgentCore._auth("objective", "token", "bad id")


@pytest.mark.parametrize("bad", ["x" * 129, "bad id", "bad/id", "bad.id"])
def test_conversation_id_is_validated_fail_closed(bad):
    with pytest.raises(ValueError):
        _conversation_id({"conversation_id": bad})


def test_conversation_id_defaults_to_server_generated_when_absent():
    value = _conversation_id({})
    assert len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def test_sse_wire_format_is_deterministic():
    import json

    payload = {"event": "tool_activity", "data": {"tool": "scan", "note": "تحقق"}}
    raw = sse(payload).decode("utf-8")
    assert raw.startswith("event: tool_activity\ndata: ")
    assert raw.endswith("\n\n")
    assert json.loads(raw.split("data: ", 1)[1].strip()) == {"tool": "scan", "note": "تحقق"}
