from concurrent.futures import ThreadPoolExecutor

import pytest

import core.db as db
import core.lifecycle as lifecycle
from core.lifecycle import begin, complete, get, is_cancelled, recover_incomplete, request_cancel, transition
from tools import registry
from tools.registry import ToolSpec, ToolTimeout, execute


def isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "lifecycle.sqlite3")


def test_duplicate_request_has_one_execution_claim(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(lambda _: begin("same-request", "test"), range(2)))
    assert sum(record.claimed for record in records) == 1
    assert get("same-request").status == "created"


def test_crash_recovery_never_reports_success(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    begin("crashed", "test")
    transition("crashed", "planned")
    transition("crashed", "validated")
    transition("crashed", "authorized")
    transition("crashed", "executing")
    recovered = recover_incomplete()
    assert recovered[0].status == "completed"
    record = get("crashed")
    assert record.final_result["ok"] is False
    assert record.final_result["recovered"] is True
    assert record.error == "recovered after interrupted execution"


def test_cancellation_is_persisted(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    begin("cancel-me", "test")
    record = request_cancel("cancel-me")
    assert record.cancel_requested is True
    assert get("cancel-me").cancel_requested is True


def test_completed_request_replays_one_final_result(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    begin("done", "test")
    transition("done", "failed", error="tool timeout")
    complete("done", {"ok": False, "error": "tool timeout"}, success=False, error="tool timeout")
    replay = begin("done", "test")
    assert replay.claimed is False
    assert replay.status == "completed"
    assert replay.final_result["ok"] is False


def test_lifecycle_rejects_unknown_and_invalid_operations(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)

    assert get("missing") is None
    assert is_cancelled("missing") is False
    with pytest.raises(ValueError, match="unknown request_id"):
        request_cancel("missing")
    with pytest.raises(ValueError, match="unknown lifecycle state"):
        transition("missing", "not-a-state")
    with pytest.raises(ValueError, match="unknown request_id"):
        transition("missing", "created")

    record = begin("same-state", "test")
    same_state = transition("same-state", "created")
    assert same_state.request_id == record.request_id
    assert same_state.status == record.status == "created"
    assert same_state.claimed is False
    with pytest.raises(ValueError, match="invalid lifecycle transition created->completed"):
        transition("same-state", "completed")
    with pytest.raises(ValueError, match="unknown request_id"):
        complete("missing", {"ok": False}, success=False)


def test_complete_persists_success_and_is_idempotent_after_completion(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    begin("successful", "test")
    transition("successful", "planned")
    transition("successful", "validated")
    transition("successful", "authorized")
    transition("successful", "executing")

    first = complete("successful", {"ok": True}, success=True)
    second = complete("successful", {"ok": False}, success=False, error="late update")

    assert first.status == "completed"
    assert first.final_result == {"ok": True}
    assert second == first


def test_recovery_ignores_race_when_transition_loses_request(monkeypatch, tmp_path):
    isolated_db(monkeypatch, tmp_path)
    begin("racing", "test")
    monkeypatch.setattr(
        lifecycle,
        "transition",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("request disappeared")),
    )

    assert recover_incomplete() == []


def test_tool_timeout_is_explicit(monkeypatch):
    def slow(_):
        import time
        time.sleep(0.05)
        return {"ok": True}
    monkeypatch.setitem(registry.REGISTRY, "slow_test", ToolSpec("slow_test", "test", "read", True, None, slow))
    with __import__("pytest").raises(ToolTimeout):
        execute("slow_test", timeout=0.001)
