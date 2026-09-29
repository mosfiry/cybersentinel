from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid

import pytest

from agent.context import sanitize_model_data, sanitize_model_text
from agent.evidence import EvidenceChainStore
from agent.mission import Mission, MissionStore
from agent.planning import Plan


def _marker() -> str:
    return f"persistence-canary-{uuid.uuid4().hex}"


def test_central_redactor_covers_common_credentials_and_preserves_safe_evidence_and_refs():
    marker = _marker()
    text = "\n".join(
        (
            f"Authorization: Bearer {marker}",
            f"Authorization: Basic {marker}",
            f"Cookie: session={marker}; theme=dark",
            f"Set-Cookie: session={marker}; HttpOnly; Secure",
            f"password={marker}",
            f"token={marker}",
            f"secret={marker}",
            f"api_key={marker}",
            f"https://operator:{marker}@example.test/probe?api_key={marker}&status=200",
        )
    )
    safe_text = sanitize_model_text(text)
    safe_data = sanitize_model_data(
        {
            "status": 200,
            "safe_evidence": "GET /health returned HTTP 200",
            "password": marker,
            "api_key": marker,
            "headers": {"Set-Cookie": f"session={marker}; HttpOnly"},
            "secret_ref": "vault://owner/opaque-reference-7",
        }
    )

    assert marker not in safe_text
    assert marker not in json.dumps(safe_data)
    assert "status=200" in safe_text
    assert safe_data["status"] == 200
    assert safe_data["safe_evidence"] == "GET /health returned HTTP 200"
    assert safe_data["secret_ref"] == "vault://owner/opaque-reference-7"


def test_mission_store_redacts_serialized_mission_logs_and_rechains_trajectory(tmp_path):
    marker = _marker()
    mission = Mission.create(
        f"Review Authorization: Bearer {marker}",
        "Preserve the HTTP status evidence",
        Plan.initial("Preserve the HTTP status evidence"),
        mission_id="mission-redaction-canary",
    )
    mission.authorization_snapshot = {
        "authorization_hash": "a" * 64,
        "owner_session_token": marker,
        "allowed_tools": ["status"],
    }
    mission.progress["logs"] = [
        {"message": f"Cookie: session={marker}; HttpOnly", "status": 200}
    ]
    mission.evidence.append(
        {
            "password": marker,
            "status": 200,
            "secret_ref": "vault://owner/opaque-reference-7",
        }
    )
    from agent.trajectory import EventType, verify_trajectory

    mission.emit(
        EventType.OBSERVATION_RECEIVED,
        data={"headers": {"Set-Cookie": f"sid={marker}; Secure"}, "status": 200},
    )
    database = tmp_path / "missions.sqlite3"
    store = MissionStore(database)
    store.save(mission)

    with sqlite3.connect(database) as db:
        serialized = db.execute(
            "SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()[0]
    loaded = store.load(mission.mission_id)

    assert marker not in serialized
    assert marker not in json.dumps(loaded.to_dict())
    assert loaded.evidence[0]["status"] == 200
    assert loaded.evidence[0]["secret_ref"] == "vault://owner/opaque-reference-7"
    assert loaded.progress["logs"][0]["status"] == 200
    assert loaded.authorization_snapshot["authorization_hash"] == "a" * 64
    assert loaded.authorization_snapshot["owner_session_token"] == "[REDACTED]"
    assert verify_trajectory(loaded.trajectory)


def test_signed_owner_session_is_redacted_and_persisted_context_fails_closed(tmp_path, monkeypatch):
    import core.db as application_db
    from owner_session_testutils import allow_owner_sessions
    from agent.agent_core import AgentCore
    from agent.model_router import ModelRouter
    from agent.provider_api import ProviderResponse, ToolCall
    from security.authorization_context import AuthorizationContext

    marker = _marker()
    allow_owner_sessions(monkeypatch, marker)
    monkeypatch.setattr(application_db, "DB_PATH", tmp_path / "conversation.sqlite3")

    class OneStatusProvider:
        name = "mission-test"
        model = "mission-test-1"

        def __init__(self):
            from agent.provider_api import ProviderCapabilities
            self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
            self.responses = [ProviderResponse(tool_calls=[ToolCall("status", {}, "canary-call")])]

        def tool_calling(self, messages, tools, **kwargs):
            return self.responses.pop(0)

        def generate(self, messages, **kwargs):
            return {"content": json.dumps({"type": "final", "content": "unused"})}

    database = tmp_path / "signed-missions.sqlite3"
    store = MissionStore(database)
    core = AgentCore(ModelRouter([OneStatusProvider()]), store=store)
    mission = core.run_owner_mission(
        "Check system status and verify",
        owner_session_token=marker,
        run=False,
    )

    with sqlite3.connect(database) as db:
        serialized = db.execute(
            "SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()[0]
    loaded = store.load(mission.mission_id)

    assert marker not in serialized
    assert loaded.authorization_context is None
    with pytest.raises((KeyError, PermissionError, TypeError, ValueError)):
        AuthorizationContext.from_dict(loaded.authorization_context or {})


def test_evidence_chain_redacts_before_hashing_and_keeps_technical_observation(tmp_path):
    marker = _marker()
    database = tmp_path / "evidence.sqlite3"
    store = EvidenceChainStore(database)
    stored = store.append(
        {
            "claim": "The endpoint returned an HTTP response",
            "source": "test-fixture",
            "evidence": {
                "headers": {
                    "Authorization": f"Basic {marker}",
                    "Cookie": f"session={marker}",
                },
                "response": f"HTTP 200; api_key={marker}",
                "status": 200,
                "secret_ref": "vault://owner/opaque-reference-7",
            },
            "verification": "observed",
            "confidence": 10,
        }
    )

    with sqlite3.connect(database) as db:
        serialized = db.execute(
            "SELECT payload FROM evidence_chain ORDER BY sequence"
        ).fetchone()[0]

    assert marker not in serialized
    assert marker not in json.dumps(stored)
    assert stored["evidence"]["status"] == 200
    assert stored["evidence"]["secret_ref"] == "vault://owner/opaque-reference-7"
    assert store.verify()


def test_durable_memory_redacts_content_and_metadata_and_recomputes_content_hash(tmp_path, monkeypatch):
    from agent import memory

    marker = _marker()
    database = tmp_path / "memory.sqlite3"
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", database)
    memory._init_memory_db()
    item = memory.MemoryItem.create(
        "conversation-redaction-canary",
        f"HTTP 200; password={marker}",
        memory.MemoryType.FACT,
        memory.TrustClassification.UNTRUSTED_DATA,
        "user",
        "canary fixture",
        metadata={"api_key": marker, "secret_ref": "vault://owner/opaque-reference-7"},
    )
    memory.MemoryProvider.store_memory(item)

    with sqlite3.connect(database) as db:
        content, metadata, content_hash = db.execute(
            "SELECT content,metadata,content_hash FROM memory_items WHERE memory_id=?",
            (item.memory_id,),
        ).fetchone()
    decoded_metadata = json.loads(metadata)

    assert marker not in content
    assert marker not in metadata
    assert "HTTP 200" in content
    assert decoded_metadata["secret_ref"] == "vault://owner/opaque-reference-7"
    assert content_hash == hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def test_application_event_reasoning_memory_and_chat_logs_are_sanitized(tmp_path, monkeypatch):
    import core.db as application_db
    from agent.loop import _sanitize_for_logging

    marker = _marker()
    database = tmp_path / "application.sqlite3"
    monkeypatch.setattr(application_db, "DB_PATH", database)
    application_db.add_event(
        "canary",
        f"Authorization: Bearer {marker}",
        f"Set-Cookie: session={marker}; HttpOnly",
        "canary-fixture",
        metadata={"password": marker, "status": 200},
    )
    application_db.save_reasoning_memory(
        "request-redaction-canary",
        {"summary": f"token={marker}", "status": 200},
        {"secret": marker},
    )
    application_db.ensure_conversation("conversation-redaction-canary", "owner-canary")
    application_db.add_conversation_message(
        "conversation-redaction-canary",
        "user",
        f"Please inspect https://operator:{marker}@example.test/health?api_key={marker}&status=200",
        {"secret_ref": "vault://owner/opaque-reference-7"},
        owner_id="owner-canary",
    )

    events = application_db.recent()
    reasoning = application_db.reasoning_for_request("request-redaction-canary")
    messages = application_db.conversation_messages("conversation-redaction-canary")
    serialized_logs = json.dumps([events, reasoning, messages], sort_keys=True)

    assert marker not in serialized_logs
    assert "status" in serialized_logs
    assert messages[0]["metadata"]["secret_ref"] == "vault://owner/opaque-reference-7"
    assert marker not in _sanitize_for_logging(f"Authorization: Basic {marker}")


def test_lifecycle_execution_result_and_errors_are_sanitized_before_storage(tmp_path, monkeypatch):
    import core.db as application_db
    from core.lifecycle import begin, complete, transition

    marker = _marker()
    database = tmp_path / "lifecycle.sqlite3"
    monkeypatch.setattr(application_db, "DB_PATH", database)
    request_id = "lifecycle-redaction-canary"
    begin(request_id, "canary")
    for state in ("planned", "validated", "authorized", "executing"):
        transition(request_id, state)
    result = complete(
        request_id,
        {"summary": f"Authorization: Bearer {marker}; HTTP 200", "password": marker, "status": 200},
        success=True,
        error=f"Cookie: session={marker}; HttpOnly",
    )

    with sqlite3.connect(database) as db:
        final_result, error = db.execute(
            "SELECT final_result_json,error FROM executions WHERE request_id=?",
            (request_id,),
        ).fetchone()
    serialized = json.dumps([final_result, error, result.final_result, result.error])

    assert marker not in serialized
    assert result.final_result["status"] == 200
    assert result.final_result["password"] == "[REDACTED]"
    assert result.error == "Cookie: [REDACTED]"


def test_mission_serialization_preserves_token_count_telemetry_and_redacts_credentials(tmp_path, monkeypatch):
    from agent import redaction

    marker = _marker()
    monkeypatch.setattr(
        redaction,
        "_SENSITIVE_KEY_MARKERS",
        (*redaction._SENSITIVE_KEY_MARKERS, "token"),
    )
    mission = Mission.create(
        "Record model invocation telemetry",
        "Preserve token usage metrics without credential material",
        Plan.initial("Preserve token usage metrics without credential material"),
        mission_id="mission-token-telemetry-canary",
    )
    mission.provenance["model_invocation"] = {
        "input_tokens_estimated": 128,
        "input_tokens": 128,
        "input_tokens_reported": 120,
        "output_tokens": 32,
        "output_tokens_reported": 32,
        "prompt_tokens": 128,
        "completion_tokens": 32,
        "max_total_tokens": 1024,
        "token": marker,
        "access_token": marker,
        "api_key": marker,
    }
    store = MissionStore(tmp_path / "mission-token-telemetry.sqlite3")
    store.save(mission)

    with sqlite3.connect(store.db_path) as db:
        serialized = db.execute(
            "SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)
        ).fetchone()[0]
    payload = json.loads(serialized)
    invocation = payload["provenance"]["model_invocation"]

    assert invocation["input_tokens_estimated"] == 128
    assert invocation["input_tokens"] == 128
    assert invocation["input_tokens_reported"] == 120
    assert invocation["output_tokens"] == 32
    assert invocation["output_tokens_reported"] == 32
    assert invocation["prompt_tokens"] == 128
    assert invocation["completion_tokens"] == 32
    assert invocation["max_total_tokens"] == 1024
    assert invocation["token"] == "[REDACTED]"
    assert invocation["access_token"] == "[REDACTED]"
    assert invocation["api_key"] == "[REDACTED]"
    assert marker not in serialized
