from __future__ import annotations

import json
import os
import stat
from dataclasses import replace

import pytest

import security.owner_policy as owner_policy
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.execution_boundary import OwnerDirectBoundary
from tools.registry import REGISTRY, execute


def _authorized_status(monkeypatch, tmp_path, request_id="proof-test"):
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy-state.json")
    evidence = owner_policy._issue_evidence("username_password", request_id, "proof-test-owner")
    context = AuthorizationContext(request_id, evidence, owner_policy.capture_policy_snapshot(request_id, evidence))
    decision = authorize_tool(["status", None], context=context)
    assert decision.allowed and decision.decision is not None
    return decision.decision


def test_registry_rejects_missing_proof_and_replay_before_second_handler_call(monkeypatch, tmp_path):
    request_id = "proof-replay-test"
    monkeypatch.setenv("CYBERSENTINEL_EXECUTION_LEDGER", str(tmp_path / "execution-ledger.sqlite3"))
    decision = _authorized_status(monkeypatch, tmp_path, request_id)
    calls = []
    monkeypatch.setitem(REGISTRY, "status", replace(REGISTRY["status"], handler=lambda _argument: calls.append("executed") or {"online": True}))

    with pytest.raises(PermissionError, match="PROOF_REQUIRED"):
        execute("status", None, authorization_decision=decision, request_id=request_id, tool_call_id="missing-proof-call")

    proof = OwnerDirectBoundary.derive(tool="status", argument=None, decision=decision, request_id=request_id, tool_call_id="status-call-1")
    kwargs = {
        "authorization_decision": decision,
        "request_id": request_id,
        "tool_call_id": "status-call-1",
        "execution_proof": proof,
        "execution_class": "OWNER_DIRECT",
    }
    assert execute("status", None, **kwargs) == {"online": True}
    with pytest.raises(PermissionError, match="PROOF_REPLAY"):
        execute("status", None, **kwargs)

    assert calls == ["executed"]
    assert stat.S_IMODE(os.stat(tmp_path / "execution-ledger.sqlite3").st_mode) == 0o600


def test_execution_proof_is_bound_to_argument_call_id_and_class(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERSENTINEL_EXECUTION_LEDGER", str(tmp_path / "execution-ledger.sqlite3"))
    request_id = "proof-binding-test"
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy-state.json")
    evidence = owner_policy._issue_evidence("username_password", request_id, "proof-test-owner")
    context = AuthorizationContext(request_id, evidence, owner_policy.capture_policy_snapshot(request_id, evidence))
    search_decision = authorize_tool(["search", "safe query"], context=context).decision
    assert search_decision is not None
    proof = OwnerDirectBoundary.derive(tool="search", argument="safe query", decision=search_decision, request_id=request_id, tool_call_id="search-call-1")

    with pytest.raises(PermissionError, match="argument binding mismatch"):
        execute("search", "different query", authorization_decision=search_decision, request_id=request_id, tool_call_id="search-call-1", execution_proof=proof, execution_class="OWNER_DIRECT")
    with pytest.raises(PermissionError, match="another tool call"):
        execute("search", "safe query", authorization_decision=search_decision, request_id=request_id, tool_call_id="different-call", execution_proof=proof, execution_class="OWNER_DIRECT")
    with pytest.raises(PermissionError, match="class does not match"):
        execute("search", "safe query", authorization_decision=search_decision, request_id=request_id, tool_call_id="search-call-1", execution_proof=proof, execution_class="MISSION_BOUND")


def test_owner_tool_budget_is_captured_and_cannot_be_widened_later(monkeypatch, tmp_path):
    policy_path = tmp_path / "owner-policy.json"
    policy = json.loads(owner_policy.POLICY_PATH.read_text(encoding="utf-8"))
    policy["owner_tool_budget"] = ["status"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(owner_policy, "POLICY_PATH", policy_path)
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy-state.json")
    request_id = "owner-budget-test"
    evidence = owner_policy._issue_evidence("username_password", request_id, "budget-test-owner")
    context = AuthorizationContext(request_id, evidence, owner_policy.capture_policy_snapshot(request_id, evidence))

    policy["owner_tool_budget"] = ["status", "search"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    denied = authorize_tool(["search", "query"], context=context)
    assert denied.allowed is False
    assert "outside the captured Owner tool budget" in denied.reason
    allowed = authorize_tool(["status", None], context=context)
    assert allowed.allowed is True
