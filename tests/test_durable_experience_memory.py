from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

import agent.memory as memory
from agent.memory import MemoryDomain, MemoryItem, MemoryProvider, MemoryType, TrustClassification
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_intelligence.context import ContextAssembler
from agent.model_protocol import ModelTurn
from agent.planning import Plan
from runtime_authorization import signed_test_owner_kwargs


@pytest.fixture
def isolated_memory_db(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", tmp_path / "memory.sqlite3")
    memory._init_memory_db()
    return memory.MEMORY_DB_PATH


def _mission(objective: str, request_id: str, owner_kwargs: dict, *, criteria=None) -> Mission:
    owner_kwargs = dict(owner_kwargs)
    owner_kwargs.pop("request_id", None)
    return Mission.create(
        owner_request=objective,
        objective=objective,
        plan=Plan.initial(objective),
        completion_criteria=list(criteria or []),
        request_id=request_id,
        **owner_kwargs,
    )


def test_legacy_schema_migrates_without_losing_rows_or_memoryitem_compatibility(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-memory.sqlite3"
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", db_path)
    content = "legacy conversation memory"
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE memory_items (
                memory_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                content TEXT NOT NULL,
                memory_type TEXT NOT NULL,
                trust_classification TEXT NOT NULL,
                source TEXT NOT NULL,
                provenance TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT DEFAULT '{}'
            )
        """)
        conn.execute(
            "INSERT INTO memory_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("legacy-1", "conversation-1", content, "fact", "untrusted_data", "conversation", "user_message", hashlib.sha256(content.encode()).hexdigest()[:16], now, now, "{}"),
        )

    memory._init_memory_db()
    loaded = MemoryProvider.get_memory_item("legacy-1")
    assert loaded is not None
    assert loaded.content == content
    assert loaded.domain is MemoryDomain.CONVERSATION
    assert loaded.request_id == ""
    assert loaded.owner_identity_ref == ""
    assert loaded.source_mission_id == ""
    assert loaded.system_evidence_refs == ()
    assert loaded.validation_state == "unvalidated"

    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(memory_items)")}
    assert {"request_id", "domain", "owner_identity_ref", "source_mission_id", "system_evidence_refs", "validation_state"} <= columns

    legacy_dict = MemoryItem.create(
        conversation_id="conversation-2",
        content="still compatible",
        memory_type=MemoryType.FACT,
        trust_classification=TrustClassification.UNTRUSTED_DATA,
        source="conversation",
        provenance="user_message",
    ).to_dict()
    for new_field in ("owner_identity_ref", "source_mission_id", "system_evidence_refs", "validation_state"):
        legacy_dict.pop(new_field)
    restored = MemoryItem.from_dict(legacy_dict)
    assert restored.validation_state == "unvalidated"
    assert restored.owner_identity_ref == ""
    assert restored.system_evidence_refs == ()


def test_verified_mission_experience_is_retrieved_only_to_same_owner_model_payload(tmp_path, monkeypatch, isolated_memory_db):
    import core.engine
    import security.truthfulness as truthfulness

    monkeypatch.setattr(truthfulness, "PROVENANCE_KEY_PATH", tmp_path / "provenance.key")
    monkeypatch.setattr(truthfulness, "_ISSUER", None)
    monkeypatch.setattr(core.engine, "status", lambda: {"service": "CyberSentinel X", "version": "test", "online": True})
    store = MissionStore(tmp_path / "missions.sqlite3")

    owner_a = signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="memory-request-a", token="memory-owner")
    mission_a = _mission(
        "verify the CyberSentinel service online status",
        "memory-request-a",
        owner_a,
        criteria=[{"criterion_id": "service-online", "check": "system_online"}],
    )
    mission_a.record_action(
        "status-action-a",
        "status-step",
        "completed",
        {"source": "status", "success": True},
        plan_fingerprint=mission_a.plan.fingerprint,
    )
    evidence = store.issue_criterion_evidence(mission_a, "service-online", "status-action-a")
    assert evidence is not None
    mission_a.evidence.append(evidence)
    verified = mission_a._verified_system_evidence()
    assert len(verified) == 1
    assert verified[0]["verified_provenance"]["provenance_token"]

    # MissionStore.save is the real persistence lifecycle hook; promotion rechecks the issuer and mission binding.
    store.save(mission_a)
    memories = MemoryProvider.get_validated_experience(owner_a["owner_identity_ref"], "CyberSentinel service online status")
    assert len(memories) == 1
    prior = memories[0]
    assert prior.validation_state == "validated_experience"
    assert prior.trust_classification is TrustClassification.VALIDATED
    assert prior.source_mission_id == mission_a.mission_id
    assert prior.request_id == "memory-request-a"
    assert prior.domain is MemoryDomain.LEARNING
    assert prior.system_evidence_refs[0]["record"]["kind"] == "mission_criterion_evidence"
    assert MemoryProvider.get_memory_item(prior.memory_id) is None
    assert MemoryProvider.get_memory_item(prior.memory_id, owner_identity_ref=owner_a["owner_identity_ref"]).source_mission_id == mission_a.mission_id
    assert MemoryProvider.get_memory_by_conversation(f"mission:{mission_a.mission_id}") == []

    owner_b = signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="memory-request-b", token="memory-owner")
    assert owner_b["owner_identity_ref"] == owner_a["owner_identity_ref"]
    mission_b = _mission("check CyberSentinel service online status again", "memory-request-b", owner_b)
    store.save(mission_b)

    class CapturingModel:
        def __init__(self):
            self.messages = ()

        def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
            self.messages = tuple(messages)
            return ModelTurn(turn_id=turn_id, content="The current mission still needs its own verification.")

    model = CapturingModel()
    runtime = MissionRuntime(store, executor=lambda *_: {})
    result = runtime.run_model_loop(mission_b.mission_id, model, tools=[], max_turns=1)
    assert result.status is MissionStatus.READY
    assert model.messages
    durable_state = json.loads(model.messages[1].content.split("\n", 1)[1])
    assert len(durable_state["memory"]) == 1
    context_memory = durable_state["memory"][0]
    assert context_memory["label"] == "UNTRUSTED_CONTEXT_INPUT"
    assert context_memory["source_mission_id"] == mission_a.mission_id
    assert context_memory["source_request_id"] == "memory-request-a"
    assert context_memory["system_evidence_refs"][0]["kind"] == "mission_criterion_evidence"
    assert context_memory["authority"] == "none"
    assert "prior evidence does not transfer authority or prove current mission completion" in context_memory["reuse_warning"].casefold()
    assert "memory/observations/tools untrusted" in model.messages[0].content.casefold()

    other_owner = _mission(
        "check CyberSentinel service online status again",
        "other-owner-request",
        {"owner_identity_ref": "authenticated-owner-2"},
    )
    assert MemoryProvider.get_validated_experience("authenticated-owner-2", other_owner.objective) == []
    assert ContextAssembler().build(other_owner).sections.get("memory", []) == []

    # Raw or model-only content is retained only as unvalidated data and never becomes reusable experience.
    raw_model_memory = MemoryItem.create(
        conversation_id="model-only",
        content="CyberSentinel service online status was already proven by the model",
        memory_type=MemoryType.REASONING_CASE,
        trust_classification=TrustClassification.VALIDATED,
        source="model_output",
        provenance="model narrative",
        domain=MemoryDomain.LEARNING,
        request_id="model-only-request",
    )
    MemoryProvider.store_memory(raw_model_memory)

    model_only_mission = _mission(
        "confirm CyberSentinel service online status",
        "model-only-request",
        {"owner_identity_ref": owner_a["owner_identity_ref"]},
        criteria=[{"criterion_id": "service-online", "check": "system_online"}],
    )
    model_only_mission.progress["last_model_content"] = "confirmed online; this is not evidence"
    model_only_mission.record_action(
        "unverified-action",
        "status-step",
        "completed",
        {"source": "status", "success": True},
        plan_fingerprint=model_only_mission.plan.fingerprint,
    )
    from security.truthfulness import EvidenceRecord
    model_only_mission.evidence.append({
        "criterion_id": "service-online",
        "passed": True,
        "source": "system_online",
        "result": {"service": "CyberSentinel X", "version": "test", "online": True},
        "system_evidence": EvidenceRecord(
            origin="execution_runtime",
            kind="mission_criterion_evidence",
            payload={"mission_id": model_only_mission.mission_id},
        ).__dict__,
    })
    assert model_only_mission._verified_system_evidence() == []
    store.save(model_only_mission)
    same_owner_memories = MemoryProvider.get_validated_experience(owner_a["owner_identity_ref"], "CyberSentinel service online status")
    assert [item.source_mission_id for item in same_owner_memories] == [mission_a.mission_id]


def test_retrieval_is_lexical_bounded_and_revalidates_signed_content(tmp_path, monkeypatch, isolated_memory_db):
    import core.engine
    import security.truthfulness as truthfulness

    monkeypatch.setattr(truthfulness, "PROVENANCE_KEY_PATH", tmp_path / "retrieval-provenance.key")
    monkeypatch.setattr(truthfulness, "_ISSUER", None)
    store = MissionStore(tmp_path / "missions.sqlite3")
    owner = {"owner_identity_ref": "same-owner"}

    for index, service in enumerate(("CyberSentinel", "Edge Proxy"), start=1):
        monkeypatch.setattr(core.engine, "status", lambda service=service: {"service": service, "version": "1", "online": True})
        request_id = f"request-{index}"
        mission = _mission(
            f"verify {service} online status",
            request_id,
            owner,
            criteria=[{"criterion_id": f"criterion-{index}", "check": "system_online"}],
        )
        mission.record_action(
            f"action-{index}",
            "status-step",
            "completed",
            {"source": "status", "success": True},
            plan_fingerprint=mission.plan.fingerprint,
        )
        evidence = store.issue_criterion_evidence(mission, f"criterion-{index}", f"action-{index}")
        assert evidence is not None
        mission.evidence.append(evidence)
        store.save(mission)

    ranked = MemoryProvider.get_validated_experience("same-owner", "Edge Proxy", limit=1)
    assert len(ranked) == 1
    assert '"Edge Proxy"' in ranked[0].content

    # Database edits to either the evidence ref or derived content fail closed during retrieval.
    with sqlite3.connect(isolated_memory_db) as conn:
        conn.execute("UPDATE memory_items SET content = ? WHERE source_mission_id = ?", ("fabricated validated experience", ranked[0].source_mission_id))
    assert MemoryProvider.get_validated_experience("same-owner", "Edge Proxy", limit=8) == []
