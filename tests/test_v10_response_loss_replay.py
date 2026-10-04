from __future__ import annotations

import core.db as db
import pytest
from core.lifecycle import get as get_lifecycle
from owner_session_testutils import allow_owner_sessions
import security.owner_policy as owner_policy


class _DeterministicRuntime:
    def __init__(self):
        self.plan_calls = 0

    def plan(self, _text, *, policy_context=""):
        self.plan_calls += 1
        return {
            "tools": ["status"],
            "provider": "local",
            "model": "v10-response-loss-fixture",
            "planner": "local",
            "rationale": "deterministic response-loss test",
            "fallback_reason": "test fixture",
        }

    def status(self):
        return {"models": [], "provider_count": 0, "policy_fingerprint": "v10-fixture"}


def test_lost_completed_response_replays_without_replanning_or_reexecution(monkeypatch, tmp_path):
    request_id = "v10-response-loss-request"
    owner_session_token = "v10-response-loss-owner-token"
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "response-loss.sqlite3")
    import core.engine as engine

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    allow_owner_sessions(monkeypatch, owner_session_token)
    runtime = _DeterministicRuntime()
    monkeypatch.setattr(engine, "RUNTIME", runtime)

    def request_with_dropped_response():
        response = engine.handle(
            "Owner status",
            source="v10-test",
            owner_session_token=owner_session_token,
            request_id=request_id,
        )
        assert response["ok"] is True
        # The server committed the response, but the caller never received it.
        raise ConnectionError("simulated transport loss after completion")

    with pytest.raises(ConnectionError, match="simulated transport loss"):
        request_with_dropped_response()

    persisted = get_lifecycle(request_id)
    assert persisted is not None
    assert persisted.status == "completed"
    assert runtime.plan_calls == 1

    replay = engine.handle(
        "Owner status",
        source="v10-test",
        owner_session_token=owner_session_token,
        request_id=request_id,
    )

    assert replay["idempotent_replay"] is True
    assert runtime.plan_calls == 1
    replay_without_marker = {key: value for key, value in replay.items() if key != "idempotent_replay"}
    assert replay_without_marker == persisted.final_result
