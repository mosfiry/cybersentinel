from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from agent.conversation import ConversationContext, ConversationInput, IntentType
from agent.conversation_provider import ConversationSchemaError, LocalModelConversationProvider
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.model_router import ModelRouter
from agent.task_runtime import AgentTaskRuntime
from evaluation.conversation_benchmark import run_conversation_contract_benchmark
from security.authorization import authorize_tool, authorize_plan
from security.authorization_context import AuthorizationContext, AuthorizationDecision
from security.owner_policy import _issue_evidence, capture_policy_snapshot


class JsonProvider:
    name = "local-test"
    model = "local-test-1"
    capabilities = ProviderCapabilities(generate=True, structured_output=True)

    def __init__(self, value):
        self.value = value

    def generate(self, messages, **kwargs):
        return ProviderResponse(text=json.dumps(self.value, ensure_ascii=False), provider=self.name, model=self.model)


def make_context(monkeypatch, tmp_path, request_id="req-6k6"):
    import security.owner_policy as policy
    monkeypatch.setattr(policy, "STATE_PATH", Path(tmp_path) / "owner-policy.json")
    evidence = policy._issue_evidence("owner_token", request_id, "proof-6k6")
    snapshot = capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=snapshot)


def test_authorization_context_is_immutable_and_has_single_request_binding(monkeypatch, tmp_path):
    context = make_context(monkeypatch, tmp_path)
    with pytest.raises(Exception):
        context.request_id = "other"
    decision = AuthorizationDecision.issue(context, allowed=True, reason="schema and policy accepted", tool="search", risk_class="read", argument="CVE-2026")
    assert decision.request_id == context.request_id
    assert decision.owner_evidence_fingerprint == context.owner_evidence_fingerprint
    assert decision.policy_fingerprint == context.policy_fingerprint
    assert decision.scope_fingerprint == ""
    assert decision.arguments_hash
    assert "authority_granted" not in decision.to_dict()


def test_boolean_cannot_create_or_authorize_sensitive_context(monkeypatch, tmp_path):
    context = make_context(monkeypatch, tmp_path)
    with pytest.raises(TypeError):
        AuthorizationContext(request_id="r", owner_authenticated=True)  # type: ignore[call-arg]
    structural = authorize_tool(["red_team_assess", "safe assessment"])
    assert not structural.allowed
    assert "AuthorizationContext" in structural.reason
    result = authorize_tool(["red_team_assess", "safe assessment"], context=context)
    assert result.allowed
    assert isinstance(result.decision, AuthorizationDecision)
    with pytest.raises(TypeError):
        AuthorizationContext(request_id=context.request_id, owner_evidence=context.owner_evidence, policy_snapshot=context.policy_snapshot, scope_snapshot="scope=*" )  # type: ignore[arg-type]


def test_decision_argument_binding_blocks_confused_deputy(monkeypatch, tmp_path):
    context = make_context(monkeypatch, tmp_path)
    decision = AuthorizationDecision.issue(context, allowed=True, reason="accepted", tool="search", risk_class="read", argument="safe")
    from tools.registry import execute
    with pytest.raises(PermissionError, match="argument-mismatched"):
        execute("search", "different", authorization_decision=decision, request_id=context.request_id)


def test_parallel_contexts_cannot_cross_authorize(monkeypatch, tmp_path):
    context_a = make_context(monkeypatch, tmp_path, "request-a")
    context_b = make_context(monkeypatch, tmp_path, "request-b")

    def decide(context, argument):
        result = authorize_tool(["search", argument], context=context)
        return result.decision.request_id, result.decision.arguments_hash

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = list(pool.map(lambda pair: decide(*pair), ((context_a, "A"), (context_b, "B"))))
    assert values[0][0] == "request-a"
    assert values[1][0] == "request-b"
    assert values[0][1] != values[1][1]


def test_context_round_trip_reloads_from_provenance(monkeypatch, tmp_path):
    context = make_context(monkeypatch, tmp_path)
    restored = AuthorizationContext.from_dict(context.to_dict())
    assert restored.request_id == context.request_id
    assert restored.policy_snapshot.owner_instruction_fingerprint == context.policy_snapshot.owner_instruction_fingerprint
    assert restored.owner_evidence_fingerprint == context.owner_evidence_fingerprint


def test_persisted_context_after_process_restart_is_denied_deterministically(monkeypatch, tmp_path):
    import security.owner_policy as policy
    context = make_context(monkeypatch, tmp_path, "restart-request")
    monkeypatch.setattr(policy, "_EVIDENCE_SECRET", b"different-process-secret")
    with pytest.raises(PermissionError, match="stale or invalid"):
        AuthorizationContext.from_dict(context.to_dict())


def test_local_provider_strict_structured_output_and_no_authority_fields():
    provider = LocalModelConversationProvider(JsonProvider({"intent": "LEARN", "action_proposal": "explain", "arguments": {"topic": "SQL injection"}, "evidence_needed": []}))
    response = provider.respond(ConversationInput("علمني SQL injection", "conv", "req"), ConversationContext("conv", "req"))
    assert response.intent.intent_type is IntentType.LEARN
    assert response.action_proposal.status == "PROPOSED"
    assert "authority_granted" not in response.public()

    forbidden = LocalModelConversationProvider(JsonProvider({"intent": "LEARN", "action_proposal": None, "arguments": {}, "evidence_needed": [], "owner_authenticated": True}))
    with pytest.raises(ConversationSchemaError, match="authority"):
        forbidden.respond(ConversationInput("teach", "conv", "req"), ConversationContext("conv", "req"))


def test_local_provider_rejects_unknown_and_invalid_semantics():
    unknown = LocalModelConversationProvider(JsonProvider({"intent": "LEARN", "unexpected": 1}))
    with pytest.raises(ConversationSchemaError, match="unknown"):
        unknown.respond(ConversationInput("teach", "conv", "req"), ConversationContext("conv", "req"))
    invalid = LocalModelConversationProvider(JsonProvider({"intent": "EXECUTE", "action_proposal": "run", "arguments": {}, "evidence_needed": []}))
    with pytest.raises(ConversationSchemaError, match="known"):
        invalid.respond(ConversationInput("execute", "conv", "req"), ConversationContext("conv", "req"))


def test_contract_benchmark_reports_explicit_pass_fail_expected_actual():
    result = run_conversation_contract_benchmark(LocalModelConversationProvider(JsonProvider({"intent": "LEARN", "action_proposal": None, "arguments": {}, "evidence_needed": []})), cases=(
        __import__("evaluation.conversation_benchmark", fromlist=["ConversationBenchmarkCase"]).ConversationBenchmarkCase("learning", "علمني", IntentType.LEARN),
    ))
    assert result["total"] == 1
    assert result["cases"][0]["status"] == "PASS"
    assert {"expected", "actual"}.issubset(result["cases"][0])


def test_task_persists_bound_context_and_uses_snapshot(monkeypatch, tmp_path):
    import agent.task_manager as task_manager
    import agent.memory as memory
    import core.db as core_db
    monkeypatch.setattr(task_manager, "DB_PATH", Path(tmp_path) / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_manager._init_db(); memory._init_memory_db(); core_db.connect().close()
    context = make_context(monkeypatch, tmp_path, "task-request")
    provider = JsonProvider({"intent": "GENERAL_CONVERSATION", "action_proposal": None, "arguments": {}, "evidence_needed": []})
    runtime = AgentTaskRuntime(ModelRouter([provider]), executor=lambda command, **kwargs: {"ok": True})
    task = runtime.create_task("conv-task", "read status", authorization_context=context)
    restored = task_manager.TaskManager.get_task(task.task_id)
    assert restored.execution_state["authorization_context"]["request_id"] == "task-request"
    assert restored.execution_state["authorization_context"]["task_id"] == task.task_id
    result = runtime.run_slice(task.task_id)
    assert result.status.value in {"completed", "waiting_for_model", "needs_input"}


def test_task_without_context_cannot_execute_sensitive_model_proposal(monkeypatch, tmp_path):
    import agent.task_manager as task_manager
    import agent.memory as memory
    import core.db as core_db
    import security.owner_policy as policy
    monkeypatch.setattr(task_manager, "DB_PATH", Path(tmp_path) / "tasks.sqlite3")
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    monkeypatch.setattr(policy, "OWNER_TOKEN", "owner")
    task_manager._init_db(); memory._init_memory_db(); core_db.connect().close()
    class SensitiveProvider(JsonProvider):
        capabilities = ProviderCapabilities(generate=True, tool_calling=True)

        def tool_calling(self, messages, tools, **kwargs):
            return ProviderResponse(tool_calls=[ToolCall("red_team_assess", {"query": "safe"}, "sensitive-call")])

    provider = SensitiveProvider({"intent": "SCOPED_TEST", "action_proposal": "red_team_assess", "arguments": {"query": "safe"}, "evidence_needed": []})
    runtime = AgentTaskRuntime(ModelRouter([provider]), executor=lambda command, **kwargs: pytest.fail("sensitive executor must not run"))
    task = runtime.create_task("conv-task", "red team")
    result = runtime.run_slice(task.task_id, owner_token="owner")
    assert result.tool_calls[0]["status"] == "denied"
