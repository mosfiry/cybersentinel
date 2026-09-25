import core.db as db


def test_event_queries_and_database_clear_are_deterministic(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "core.sqlite3")

    first_id = db.add_event(
        "intel",
        "Critical finding",
        "CVE-2026-0001 affects gateway",
        "scanner",
        severity="critical",
        trusted=True,
        metadata={"request_id": "req-1", "source": "scanner"},
    )
    db.add_event("audit", "Routine check", "No issue", "operator", severity="info")

    assert first_id == 1
    assert db.recent(1)[0]["title"] == "Routine check"
    assert db.events_for_request("req-1")[0]["metadata_json"]
    assert db.counts() == {"critical": 1, "info": 1}
    search = db.search_all("gateway")
    assert [item["title"] for item in search["events"]] == ["Critical finding"]
    assert search["intel"] == []

    db.clear_database()
    assert db.recent() == []
    assert db.counts() == {}


def test_intelligence_is_deduplicated_and_searchable(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "intel.sqlite3")

    assert db.add_intel(
        "CVE-2026-0001",
        "CISA",
        "Gateway exposure",
        "Affects gateway appliances",
        severity="high",
        metadata={"kev": True},
    ) is True
    assert db.add_intel("CVE-2026-0001", "CISA", "Changed", "Should be ignored") is False
    assert db.intel_recent(10)[0]["title"] == "Gateway exposure"

    result = db.search_all("GATEWAY")
    assert [item["external_id"] for item in result["intel"]] == ["CVE-2026-0001"]
    assert result["intel"][0]["metadata_json"] == '{"kev": true}'


def test_reasoning_memory_and_watch_list_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "state.sqlite3")

    assert db.reasoning_for_request("req-unknown") is None
    db.save_reasoning_memory("req-1", {"finding": "CVE-2026-0001"}, {"confidence": 0.8})
    saved = db.reasoning_for_request("req-1")
    assert saved["case"] == {"finding": "CVE-2026-0001"}
    assert saved["critic"] == {"confidence": 0.8}

    db.add_watch("  Gateway  ")
    db.add_watch("gateway")
    db.add_watch("Database")
    assert db.watches() == ["Database", "Gateway", "gateway"]
    db.remove_watch(" gateway ")
    assert db.watches() == ["Database"]
