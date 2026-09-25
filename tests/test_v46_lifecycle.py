from concurrent.futures import ThreadPoolExecutor

import core.db as db
from core.lifecycle import begin, complete, get, recover_incomplete, request_cancel, transition
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


def test_tool_timeout_is_explicit(monkeypatch):
    def slow(_):
        import time
        time.sleep(0.05)
        return {"ok": True}
    monkeypatch.setitem(registry.REGISTRY, "slow_test", ToolSpec("slow_test", "test", "read", True, None, slow))
    # KNOWN_TOOLS is captured from REGISTRY at import time, so a test tool
    # registered afterwards must also be added to the authorization allowlist
    # the same way production tools are declared before import.
    monkeypatch.setattr("security.authorization.KNOWN_TOOLS", registry.KNOWN_TOOLS | {"slow_test"})
    import security.owner_policy as owner_policy
    from security.authorization import authorize_tool
    from security.authorization_context import AuthorizationContext
    from security.execution_boundary import OwnerDirectBoundary

    evidence = owner_policy._issue_evidence("owner_token", "v46-timeout", "test")
    auth_context = AuthorizationContext("v46-timeout", evidence, owner_policy.capture_policy_snapshot("v46-timeout", evidence))
    decision = authorize_tool(["slow_test", None], context=auth_context)
    assert decision.allowed
    with __import__("pytest").raises(ToolTimeout):
        OwnerDirectBoundary.execute(tool="slow_test", argument=None, decision=decision.decision, request_id="v46-timeout", tool_call_id="v46-timeout:slow", timeout=0.001)
