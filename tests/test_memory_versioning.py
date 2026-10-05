from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import sqlite3

import pytest


def _legacy_schema(path):
    content = "legacy remembered fact"
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE memory_items (
                memory_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, content TEXT NOT NULL,
                memory_type TEXT NOT NULL, trust_classification TEXT NOT NULL, source TEXT NOT NULL,
                provenance TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, metadata TEXT DEFAULT '{}'
            )
        """)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO memory_items VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("legacy-id", "conv-1", content, "fact", "untrusted_data", "old-client", "legacy", hashlib.sha256(content.encode()).hexdigest()[:16], now, now, json.dumps({"legacy": True})),
        )


@pytest.fixture

def memory_db(tmp_path, monkeypatch):
    from agent import memory

    path = tmp_path / "memory.sqlite3"
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", path)
    memory._init_memory_db()
    return memory, path


def test_v1_database_migrates_atomically_and_preserves_legacy_rows(memory_db, tmp_path, monkeypatch):
    from agent import memory

    path = tmp_path / "old.sqlite3"
    _legacy_schema(path)
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", path)
    memory._init_memory_db()
    old = memory.MemoryProvider.get_memory_item("legacy-id")
    assert old is not None
    assert old.content == "legacy remembered fact"
    assert old.domain is memory.MemoryDomain.CONVERSATION
    assert old.request_id == ""
    assert old.content_hash == hashlib.sha256(old.content.encode()).hexdigest()[:16]

    new = memory.MemoryItem.create(
        "conv-1", "Research finding", memory.MemoryType.FACT, memory.TrustClassification.UNTRUSTED_DATA,
        "search", "request=req-7", domain=memory.MemoryDomain.RESEARCH, request_id="req-7",
        owner_identity_ref="owner-7", mission_id="mission-7", agent_id="agent-2",
        scope=("host:example.test",), confidence=0.91, sensitivity=memory.MemorySensitivity.SENSITIVE,
        validation_state=memory.MemoryValidationState.PENDING_VALIDATION,
    )
    memory.MemoryProvider.store_memory(new)
    restored = memory.MemoryProvider.get_memory_item(new.memory_id)
    assert restored is not None
    assert restored.content_hash == hashlib.sha256(new.content.encode()).hexdigest()
    assert restored.domain is memory.MemoryDomain.RESEARCH
    assert restored.request_id == "req-7"
    assert restored.owner_identity_ref == "owner-7"
    assert restored.scope == ("host:example.test",)
    assert restored.confidence == 0.91
    assert restored.sensitivity is memory.MemorySensitivity.SENSITIVE
    assert restored.validation_state is memory.MemoryValidationState.PENDING_VALIDATION
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version FROM memory_schema_versions WHERE component='memory_items'").fetchone()[0] == 4


def test_v3_database_upgrade_is_idempotent(memory_db, tmp_path, monkeypatch):
    from agent import memory

    path = tmp_path / "v3.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE memory_items (
                memory_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, content TEXT NOT NULL,
                memory_type TEXT NOT NULL, trust_classification TEXT NOT NULL, source TEXT NOT NULL,
                provenance TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, metadata TEXT DEFAULT '{}', domain TEXT NOT NULL DEFAULT 'conversation',
                request_id TEXT NOT NULL DEFAULT '', superseded_by TEXT
            )
        """)
        db.execute("CREATE TABLE memory_schema_versions(component TEXT PRIMARY KEY, version INTEGER NOT NULL)")
        db.execute("INSERT INTO memory_schema_versions VALUES('memory_items', 3)")
        now = datetime.now(timezone.utc).isoformat()
        content = "v3 preserved"
        db.execute(
            "INSERT INTO memory_items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("v3-id", "conv", content, "fact", "untrusted_data", "source", "v3", hashlib.sha256(content.encode()).hexdigest()[:16], now, now, "{}", "research", "request-v3", None),
        )
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", path)
    memory._init_memory_db()
    memory._init_memory_db()
    item = memory.MemoryProvider.get_memory_item("v3-id")
    assert item is not None and item.domain is memory.MemoryDomain.RESEARCH
    assert item.request_id == "request-v3"
    assert item.owner_identity_ref == "" and item.mission_id == ""
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version FROM memory_schema_versions WHERE component='memory_items'").fetchone()[0] == 4


def test_round_trip_and_filtered_retrieval_preserve_domain_request_and_trust(memory_db):
    memory, _ = memory_db
    records = [
        memory.MemoryItem.create("conv", "research secret project", memory.MemoryType.FACT, memory.TrustClassification.UNTRUSTED_DATA, "user", "r1", domain=memory.MemoryDomain.RESEARCH, request_id="r1", owner_identity_ref="owner-1", mission_id="mission-1", agent_id="agent-1", scope=("host:example.test",), confidence=0.95, sensitivity=memory.MemorySensitivity.SENSITIVE),
        memory.MemoryItem.create("conv", "other research project", memory.MemoryType.FACT, memory.TrustClassification.VALIDATED, "evidence", "r1", domain=memory.MemoryDomain.RESEARCH, request_id="r1"),
        memory.MemoryItem.create("conv", "secret project in conversation", memory.MemoryType.FACT, memory.TrustClassification.UNTRUSTED_DATA, "user", "r1", domain=memory.MemoryDomain.CONVERSATION, request_id="r1"),
        memory.MemoryItem.create("conv", "secret project from another request", memory.MemoryType.FACT, memory.TrustClassification.UNTRUSTED_DATA, "user", "r2", domain=memory.MemoryDomain.RESEARCH, request_id="r2"),
    ]
    for item in records:
        memory.MemoryProvider.store_memory(item)
    found = memory.MemoryProvider.get_relevant_memory(
        "conv", "secret project", limit=10, domain=memory.MemoryDomain.RESEARCH, request_id="r1",
        trust_classification=memory.TrustClassification.UNTRUSTED_DATA,
        owner_identity_ref="owner-1", mission_id="mission-1", agent_id="agent-1", minimum_confidence=0.9,
    )
    assert [item.memory_id for item in found] == [records[0].memory_id]
    restored = memory.MemoryProvider.get_memory_item(records[1].memory_id)
    assert restored.domain is memory.MemoryDomain.RESEARCH
    assert restored.request_id == "r1"
    assert restored.trust_classification is memory.TrustClassification.VALIDATED
    rich = memory.MemoryProvider.get_memory_item(records[0].memory_id)
    assert rich.owner_identity_ref == "owner-1"
    assert rich.mission_id == "mission-1"
    assert rich.agent_id == "agent-1"
    assert rich.scope == ("host:example.test",)
    assert rich.confidence == 0.95
    assert rich.sensitivity is memory.MemorySensitivity.SENSITIVE
    assert rich.validation_state is memory.MemoryValidationState.UNVERIFIED


def test_query_relevance_precedes_type_priority_but_empty_query_keeps_priority(memory_db):
    memory, _ = memory_db
    objective = memory.MemoryItem.create("conv", "active objective: harden the firewall", memory.MemoryType.ACTIVE_OBJECTIVE, memory.TrustClassification.UNTRUSTED_DATA, "owner", "objective")
    fact = memory.MemoryItem.create("conv", "database backup failure details", memory.MemoryType.FACT, memory.TrustClassification.UNTRUSTED_DATA, "tool", "inspection")
    memory.MemoryProvider.store_memory(objective)
    memory.MemoryProvider.store_memory(fact)
    assert memory.MemoryProvider.get_relevant_memory("conv", "backup failure", limit=2)[0].memory_id == fact.memory_id
    assert memory.MemoryProvider.get_relevant_memory("conv", limit=2)[0].memory_id == objective.memory_id


def test_consolidation_is_extractive_auditable_and_preserves_superseded_sources(memory_db):
    memory, _ = memory_db
    originals = []
    for index in range(60):
        item = memory.MemoryItem.create(
            "conv", f"message-{index}: observed indicator-{index}", memory.MemoryType.RECENT,
            memory.TrustClassification.UNTRUSTED_DATA, "conversation", f"turn-{index}",
            domain=memory.MemoryDomain.CONVERSATION, request_id="req-A",
        )
        originals.append(item)
        memory.MemoryProvider.store_memory(item)
    result = memory.ConversationMemory.consolidate_memory("conv", max_items=50)
    assert result["consolidated"] is True
    summary = memory.MemoryProvider.get_memory_item(result["summary_ids"][0])
    assert summary.memory_type is memory.MemoryType.SUMMARY
    assert "Previous conversation summary" not in summary.content
    assert "observed indicator" in summary.content
    assert summary.trust_classification is memory.TrustClassification.UNTRUSTED_DATA
    assert summary.metadata["source_count"] == 10
    assert len(summary.metadata["source_ids"]) == len(summary.metadata["source_hashes"]) == 10
    all_records = memory.MemoryProvider.get_memory_by_conversation("conv")
    assert len([item for item in all_records if item.memory_type is memory.MemoryType.RECENT]) == 60
    active = memory.MemoryProvider.get_memory_by_conversation("conv", active_only=True)
    assert len([item for item in active if item.memory_type is memory.MemoryType.RECENT]) == 50
    archived_ids = {item.memory_id for item in all_records if item.superseded_by}
    assert set(summary.metadata["source_ids"]) == archived_ids
    assert not any(item.memory_id in archived_ids for item in memory.MemoryProvider.get_relevant_memory("conv", limit=100))


def test_failed_compaction_insert_rolls_back_without_orphaning_sources(memory_db):
    memory, path = memory_db
    for request_id in ("req-B", "req-A"):
        for index in range(51):
            memory.MemoryProvider.store_memory(memory.MemoryItem.create(
                "conv", f"message-{request_id}-{index}", memory.MemoryType.RECENT,
                memory.TrustClassification.UNTRUSTED_DATA, "conversation", "test", request_id=request_id,
            ))
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TRIGGER reject_summary BEFORE INSERT ON memory_items
            WHEN NEW.memory_type='summary' AND NEW.request_id='req-A'
            BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END
        """)
    with pytest.raises(sqlite3.IntegrityError, match="injected insert failure"):
        memory.ConversationMemory.consolidate_memory("conv", max_items=1)
    active = memory.MemoryProvider.get_memory_by_conversation("conv", active_only=True)
    assert len(active) == 102
    assert not any(item.memory_type is memory.MemoryType.SUMMARY for item in active)


def test_context_adapter_carries_provenance_and_enforces_optional_request_filter(memory_db):
    memory, _ = memory_db
    for request_id in ("req-A", "req-B"):
        memory.MemoryProvider.store_memory(memory.MemoryItem.create(
        "conv", f"shared text {request_id}", memory.MemoryType.FACT,
        memory.TrustClassification.UNTRUSTED_DATA, "tool", "source", domain=memory.MemoryDomain.TASK_STATE,
        request_id=request_id, owner_identity_ref="owner-1", mission_id="mission-1", agent_id="agent-1",
        confidence=0.8,
        ))
    from agent.context import DurableMemoryProvider

    results = DurableMemoryProvider(
        "conv", request_id="req-A", domain=memory.MemoryDomain.TASK_STATE,
        owner_identity_ref="owner-1", mission_id="mission-1", agent_id="agent-1", minimum_confidence=0.7,
    ).retrieve_relevant("shared", limit=10)
    assert len(results) == 1
    assert results[0]["request_id"] == "req-A"
    assert results[0]["domain"] == "task_state"
    assert results[0]["mission_id"] == "mission-1"
    assert results[0]["validation_state"] == "unverified"
    assert len(results[0]["content_hash"]) == 64
