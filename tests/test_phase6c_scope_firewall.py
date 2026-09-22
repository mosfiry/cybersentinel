from __future__ import annotations

from pathlib import Path

import pytest

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.task_runtime import AgentTaskRuntime
from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
from security.scope_resolver import resolve
from security.scope_store import init_scope_store, save_snapshot
from tools.registry import execute
import security.scope_store as scope_store
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.owner_policy import _issue_evidence, capture_policy_snapshot


@pytest.fixture
def snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    import security.owner_policy as owner_policy
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "scope-owner")
    init_scope_store()
    auth = ProgramAuthorization(
        program_id="program-1",
        platform="test",
        scope_version="v1",
        retrieved_at="2026-09-21T00:00:00+00:00",
        in_scope_assets=({"host": "target.example.com", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        out_of_scope_assets=({"host": "target.example.com", "paths": ["/admin"]},),
        allowed_methods=("GET", "HEAD"),
        prohibited_methods=("POST", "PUT", "PATCH", "DELETE"),
        rate_limits={"requests_per_minute": 2},
    )
    target = TargetIdentity("target-1", "program-1", "target.example.com", allowed_ports=(443,), allowed_paths=("/api",), excluded_paths=("/api/private",))
    return save_snapshot(make_snapshot("snapshot-1", auth, [target]), owner_token="scope-owner")


def context(url="https://target.example.com/api/v1"):
    return {"program_id": "program-1", "target_id": "target-1", "scope_snapshot_id": "snapshot-1", "url": url, "method": "GET"}


def test_scope_requires_snapshot_and_target(snapshot):
    assert not resolve("missing", "target-1", "https://target.example.com/api/v1").allowed
    assert not resolve(snapshot.snapshot_id, "wrong-target", "https://target.example.com/api/v1").allowed
    assert resolve(snapshot.snapshot_id, "target-1", "https://target.example.com/api/v1", consume_rate=False).allowed


def test_scope_blocks_host_path_method_and_redirect(snapshot):
    assert not resolve("snapshot-1", "target-1", "https://other.example.com/api").allowed
    assert not resolve("snapshot-1", "target-1", "https://target.example.com/admin").allowed
    assert not resolve("snapshot-1", "target-1", "https://target.example.com/api", method="POST").allowed
    assert not resolve("snapshot-1", "target-1", "https://target.example.com/api", redirect_chain=["https://other.example.com/api"]).allowed
    assert not resolve("snapshot-1", "target-1", "https://target.example.com/api/private").allowed


def test_direct_registry_execution_cannot_bypass_scope(snapshot):
    with pytest.raises(PermissionError, match="scope-bound AuthorizationDecision"):
        execute("scoped_http_probe", "https://target.example.com/api")
    evidence = _issue_evidence("owner_token", "scope-direct", "scope-direct")
    auth_context = AuthorizationContext("scope-direct", evidence, capture_policy_snapshot("scope-direct", evidence), scope_snapshot=snapshot)
    denied = authorize_tool(["scoped_http_probe", "https://other.example.com/api"], context=auth_context)
    with pytest.raises(PermissionError, match="scope denied"):
        execute("scoped_http_probe", "https://other.example.com/api", authorization_decision=denied.decision, scope_context=context("https://other.example.com/api"), request_id="scope-direct")
    allowed = authorize_tool(["scoped_http_probe", "https://target.example.com/api"], context=auth_context)
    result = execute("scoped_http_probe", "https://target.example.com/api", authorization_decision=allowed.decision, scope_context=context(), request_id="scope-direct")
    assert result["ok"] is True


def test_rate_limit_is_persistent_and_enforced(snapshot):
    assert resolve("snapshot-1", "target-1", "https://target.example.com/api/a").allowed
    assert resolve("snapshot-1", "target-1", "https://target.example.com/api/b").allowed
    third = resolve("snapshot-1", "target-1", "https://target.example.com/api/c")
    assert not third.allowed
    assert third.reason == "rate_limit_exceeded"


def test_task_runtime_enforces_scope_before_custom_executor(snapshot, monkeypatch, tmp_path):
    import agent.task_manager as task_manager
    import agent.memory as memory
    import core.db as core_db
    monkeypatch.setattr(task_manager, "DB_PATH", Path(tmp_path) / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_manager._init_db(); memory._init_memory_db(); core_db.connect().close()
    import security.owner_policy as owner_policy
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "owner")

    class Provider:
        name = "scope-test"
        model = "scope-test"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        def tool_calling(self, messages, tools, temperature=0, **kwargs):
            return ProviderResponse(tool_calls=[ToolCall("scoped_http_probe", {"query": "https://target.example.com/api"}, "scope-call")])

    executions = []
    runtime = AgentTaskRuntime(ModelRouter([Provider()]), executor=lambda command, **kwargs: executions.append(command) or {"ok": True})
    task = runtime.create_task("scope-conv", "probe", scope_context=context("https://other.example.com/api"))
    result = runtime.run_slice(task.task_id, owner_token="owner", owner_session_id=None)
    assert result.tool_calls[0]["status"] == "denied"
    assert executions == []


def test_canonicalization_and_snapshot_integrity(snapshot):
    assert resolve("snapshot-1", "target-1", "HTTPS://TARGET.EXAMPLE.COM:443/api", consume_rate=False).allowed
    assert not resolve("snapshot-1", "target-1", "https://user:pass@target.example.com/api", consume_rate=False).allowed
    with pytest.raises(ValueError, match="scope_evidence_hash_mismatch"):
        import sqlite3
        with sqlite3.connect(str(scope_store.SCOPE_DB_PATH)) as conn:
            row = conn.execute("SELECT snapshot_json FROM scope_snapshots WHERE snapshot_id='snapshot-1'").fetchone()
            payload = row[0].replace("target.example.com", "evil.example.com", 1)
            conn.execute("UPDATE scope_snapshots SET snapshot_json=? WHERE snapshot_id='snapshot-1'", (payload,))
        scope_store.get_snapshot("snapshot-1")


def test_registry_rejects_scoped_namespace_without_firewall_metadata():
    from tools.registry import ToolSpec, build_registry
    with pytest.raises(ValueError, match="invalid registry metadata"):
        build_registry([ToolSpec("recon.http_probe", "probe", "network-read", True, str, lambda value: value)])


def test_scope_snapshot_write_requires_owner_token(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    init_scope_store()
    auth = ProgramAuthorization("p-write", "test", "v1", "2026-09-21T00:00:00+00:00", ({"host": "target.example.com", "schemes": ["https"]},))
    target = TargetIdentity("t-write", "p-write", "target.example.com")
    with pytest.raises(PermissionError):
        save_snapshot(make_snapshot("s-write", auth, [target]))
