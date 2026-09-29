from __future__ import annotations

import json

import pytest

from agent.mind import CyberSentinelMind
from agent.model_intelligence.context import ContextAssembler
from agent.model_orchestrator import ModelOrchestrator
from agent.model_router import ModelRouter
from agent.mission import Mission, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.model_protocol import MindNativeModel
from agent.planning import Plan
from agent.provider_api import ProviderCapabilities, ProviderFailure, ProviderResponse, ProviderTimeout, ToolCall


# These are deliberately synthetic, deterministic test doubles. They never make
# network requests and do not establish that a live Owner provider is configured.
class UnitTestProvider:
    def __init__(
        self,
        profile_id: str,
        capabilities: set[str],
        *,
        priority: int = 10,
        base_url: str = "https://models.test/v1",
        tool_calling: bool = True,
        critic_response: str | None = None,
        analysis_text: str | None = None,
        failure: Exception | None = None,
        cost_per_1k_tokens_usd: float | None = None,
    ):
        self.profile_id = profile_id
        self.name = profile_id
        self.model = f"{profile_id}-unit-test-model"
        self.model_capabilities = frozenset(capabilities)
        self.capabilities = ProviderCapabilities(
            generate=True,
            tool_calling=tool_calling,
            native_chat=tool_calling,
        )
        self.priority = priority
        self.base_url = base_url
        self.cost_per_1k_tokens_usd = cost_per_1k_tokens_usd
        self.critic_response = critic_response or json.dumps(
            {
                "hypothesis": "The proposed read-only check can test the current hypothesis.",
                "supporting_evidence": ["verified-evidence-1"],
                "contradicting_evidence": [],
                "missing_evidence": ["A current system observation"],
                "confidence": 0.4,
                "required_validation": ["Use the authorized read-only status tool."],
                "decision": "accept",
            }
        )
        self.analysis_text = analysis_text or f"Untrusted analysis from {profile_id}."
        self.failure = failure
        self.calls: list[dict] = []
        self.last_timeout: int | None = None
        self.last_max_tokens: int | None = None

    def generate(self, messages, *, temperature=0.0, timeout=90, max_tokens=1024, **_kwargs):
        self.calls.append({"method": "generate", "messages": messages})
        self.last_timeout = timeout
        self.last_max_tokens = max_tokens
        if self.failure is not None:
            raise self.failure
        last = str(messages[-1].get("content", "")) if messages else ""
        content = self.critic_response if "Independent Critic:" in last else self.analysis_text
        return ProviderResponse(
            text=content,
            provider=self.name,
            model=self.model,
            usage={"prompt_tokens": 12, "completion_tokens": 8},
            capability="generate",
        )

    def tool_calling(self, messages, tools, *, temperature=0.0, timeout=90, max_tokens=1024, **_kwargs):
        self.calls.append({"method": "tool_calling", "messages": messages, "tools": tools})
        self.last_timeout = timeout
        self.last_max_tokens = max_tokens
        if self.failure is not None:
            raise self.failure
        return ProviderResponse(
            text="An untrusted read-only proposal.",
            tool_calls=[ToolCall("status", {"target": "current", "api_key": "tool-canary-secret"}, "unit-call-1")],
            provider=self.name,
            model=self.model,
            usage={"prompt_tokens": 12, "completion_tokens": 8},
            capability="tool_calling",
        )


def _router(*providers: UnitTestProvider) -> ModelRouter:
    return ModelRouter(list(providers), configured_profiles={item.profile_id: item for item in providers})


def _orchestrate(router: ModelRouter, *, preference="balanced", objective="Review this authorized security task", tools=None, **kwargs):
    context_provenance = kwargs.pop("context_provenance", [{"source": "unit_test_fixture", "retrieved": True}])
    return ModelOrchestrator(router, policy_max_models=4).orchestrate(
        [{"role": "system", "content": "CyberSentinel test system context."}, {"role": "user", "content": "Inspect the authorized target."}],
        list(tools or []),
        objective=objective,
        request_id="request-unit-test",
        mission_id="mission-unit-test",
        task_id="task-unit-test",
        context_hash="shared-context-hash",
        context_provenance=context_provenance,
        preference=preference,
        verified_evidence_ids=("verified-evidence-1",),
        **kwargs,
    )


def test_agent_core_semantic_intent_uses_mind_fast_mode_not_direct_router_inference():
    from agent.agent_core import AgentCore

    proposal = {
        "objective": "Review the authorized test workspace",
        "constraints": ["read-only"],
        "requested_artifacts": ["review summary"],
        "verification_criteria": ["separate facts from hypotheses"],
        "scope_references": [],
        "authorization_requirements": [],
        "entities": ["test workspace"],
        "ambiguities": [],
    }
    provider = UnitTestProvider(
        "intent-parser",
        {"reasoning"},
        tool_calling=False,
        analysis_text=json.dumps(proposal),
    )
    router = _router(provider)
    core = AgentCore(router)
    recorded = {}
    original_orchestrate = core.mind.orchestrate

    def capture_mind_request(**kwargs):
        recorded.update(kwargs)
        return original_orchestrate(**kwargs)

    core.mind.orchestrate = capture_mind_request
    router.generate = lambda *_args, **_kwargs: pytest.fail("direct router inference bypassed CyberSentinelMind")

    intent = core.understand_mission_intent("Review the authorized test workspace")

    assert intent.source == "model"
    assert intent.objective == proposal["objective"]
    assert recorded["preference"] == "fast"
    assert recorded["tools"] == []
    assert recorded["mission_id"] == recorded["request_id"]
    assert provider.calls and provider.calls[0]["method"] == "generate"


def test_balanced_runs_independent_analyst_and_structured_critic_on_one_context():
    analyst = UnitTestProvider("analyst", {"reasoning", "planning", "coding"}, priority=1)
    critic = UnitTestProvider("critic", {"critique"}, priority=2, tool_calling=False)
    router = _router(analyst, critic)

    result = _orchestrate(
        router,
        objective="Implement a source code security review",
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
    )

    trace = result["orchestration"]
    assert trace["record_type"] == "MODEL_ORCHESTRATION"
    assert trace["status"] == "multi_model"
    assert trace["model_outputs_are_evidence"] is False
    assert trace["budget"]["max_model_profiles"] == 2
    assert trace["max_parallelism_used"] == 1
    assert trace["critic_status"] == "validated_schema_untrusted_claims"
    assert trace["critic_report"]["authority"] == "diagnostic_only"
    assert trace["critic_report"]["semantic_truth_claimed"] is False
    assert result["tool_calls"][0]["name"] == "status"
    invocations = trace["invocations"]
    assert {item["profile_id"] for item in invocations} == {"analyst", "critic"}
    assert {item["context_hash"] for item in invocations} == {"shared-context-hash"}
    assert [item["role"] for item in invocations] == ["planning", "independent_critic", "synthesis"]
    assert all("request_hash" in item and "response_hash" in item for item in invocations)
    assert "api_key" not in json.dumps(trace).casefold()


def test_deep_budget_can_use_four_independent_profiles_but_never_exceeds_limit():
    planning = UnitTestProvider("planner", {"reasoning", "planning"}, priority=1)
    coder = UnitTestProvider("coder", {"coding", "security_analysis"}, priority=2)
    researcher = UnitTestProvider("researcher", {"web_analysis"}, priority=3, tool_calling=False)
    critic = UnitTestProvider("critic", {"critique"}, priority=4, tool_calling=False)
    result = _orchestrate(
        _router(planning, coder, researcher, critic),
        preference="deep",
        objective="Research and implement a source security-code review",
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
    )

    invocations = result["orchestration"]["invocations"]
    assert result["orchestration"]["budget"]["max_model_profiles"] == 4
    assert len({item["profile_id"] for item in invocations}) == 4
    assert len(invocations) <= result["orchestration"]["budget"]["max_calls"]
    assert result["orchestration"]["budget"]["max_parallelism"] == 1
    assert result["orchestration"]["critic_status"] == "validated_schema_untrusted_claims"
    assert "untrusted" in result["orchestration"]["critic_report"]["confidence_trust"]


def test_fast_preference_uses_one_profile_and_applies_timeout_and_token_caps():
    fast = UnitTestProvider("fast", {"reasoning"}, priority=1)
    unused = UnitTestProvider("unused", {"critique"}, priority=2, tool_calling=False)
    result = _orchestrate(_router(fast, unused), preference="fast")

    assert result["orchestration"]["budget"]["max_model_profiles"] == 1
    assert len({item["profile_id"] for item in result["orchestration"]["invocations"]}) == 1
    assert len(fast.calls) == 1
    assert fast.last_timeout <= result["orchestration"]["budget"]["time_budget_seconds"]
    assert fast.last_max_tokens <= result["orchestration"]["budget"]["max_output_tokens_per_call"]
    assert result["orchestration"]["structural_critic"] == "not_run"


def test_non_accepting_critic_decision_withholds_all_tool_proposals():
    analyst = UnitTestProvider("analyst", {"reasoning", "planning"})
    objection = json.dumps({
        "hypothesis": "The requested check is insufficient.",
        "supporting_evidence": [],
        "contradicting_evidence": [],
        "missing_evidence": ["independent evidence"],
        "confidence": 0.5,
        "required_validation": ["collect another read-only observation"],
        "decision": "challenge",
    })
    critic = UnitTestProvider("critic", {"critique"}, tool_calling=False, critic_response=objection)
    result = _orchestrate(
        _router(analyst, critic),
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
    )

    assert result["orchestration"]["status"] == "critic_rejected"
    assert result["tool_calls"] == []
    assert result["orchestration"]["critic_report"]["decision"] == "challenge"
    assert result["orchestration"]["structural_critic"] == "diagnostic_only"


@pytest.mark.parametrize("bad_output", ["not json", "[]", "{\"decision\": []}"])
def test_invalid_critic_output_fails_closed_without_forwarding_actions(bad_output):
    analyst = UnitTestProvider("analyst", {"reasoning", "planning"})
    critic = UnitTestProvider("critic", {"critique"}, tool_calling=False, critic_response=bad_output)
    result = _orchestrate(
        _router(analyst, critic),
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
    )

    assert result["orchestration"]["status"] == "critic_rejected"
    assert result["tool_calls"] == []
    assert result["orchestration"]["critic_report"] is None


def test_critic_cannot_promote_unverified_evidence_ids_or_confidence():
    analyst = UnitTestProvider("analyst", {"reasoning", "planning"})
    critic_output = json.dumps({
        "hypothesis": "The claim remains unverified.",
        "supporting_evidence": ["invented-evidence"],
        "contradicting_evidence": ["verified-evidence-1"],
        "missing_evidence": [],
        "confidence": 0.99,
        "required_validation": [],
        "decision": "accept",
    })
    critic = UnitTestProvider("critic", {"critique"}, tool_calling=False, critic_response=critic_output)
    result = _orchestrate(_router(analyst, critic))
    report = result["orchestration"]["critic_report"]

    assert report["supporting_evidence"] == []
    assert report["contradicting_evidence"] == ["verified-evidence-1"]
    assert report["unverified_evidence_ids"] == ["invented-evidence"]
    assert report["confidence"] == 0.99
    assert report["confidence_trust"] == "untrusted_model_claim"
    assert report["can_change_authorization_or_completion"] is False


def test_only_native_tool_capable_profile_can_synthesize_execution_proposal():
    text_only = UnitTestProvider("text-only", {"reasoning", "planning"}, priority=1, tool_calling=False)
    critic = UnitTestProvider("critic", {"critique"}, priority=2, tool_calling=False)
    native = UnitTestProvider("native", {"coding", "security_analysis"}, priority=3, tool_calling=True)
    result = _orchestrate(
        _router(text_only, critic, native),
        objective="Implement a security source code review",
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
        require_tool_calling=True,
    )

    trace = result["orchestration"]
    assert trace["require_tool_calling"] is True
    assert result["tool_calls"][0]["name"] == "status"
    synthesis = next(item for item in trace["invocations"] if item["role"] == "synthesis")
    assert synthesis["profile_id"] == "native"
    assert "text-only" not in {item["profile_id"] for item in trace["invocations"]}


def test_failed_primary_profile_falls_back_to_another_configured_profile_without_fabricating_output():
    broken = UnitTestProvider("broken", {"reasoning"}, priority=1, failure=ProviderTimeout("fixture timeout"))
    available = UnitTestProvider("available", {"reasoning"}, priority=2, analysis_text="verified fixture response")
    result = _orchestrate(_router(broken, available), preference="balanced")

    assert result["content"] == "verified fixture response"
    assert result["orchestration"]["fallback_used"] is True
    assert any(item["failure_kind"] == "TIMEOUT" for item in result["orchestration"]["invocations"])
    assert result["orchestration"]["model_outputs_are_evidence"] is False
    assert broken.calls and available.calls


def test_local_preference_excludes_non_private_profiles_without_dns_or_network_use():
    local = UnitTestProvider("local", {"reasoning"}, base_url="http://localhost:8000/v1")
    remote = UnitTestProvider("remote", {"reasoning"}, base_url="https://remote.example/v1", priority=1)
    result = _orchestrate(_router(local, remote), preference="local")

    assert {item["profile_id"] for item in result["orchestration"]["invocations"]} == {"local"}
    assert local.calls
    assert remote.calls == []


def test_model_boundary_redacts_secrets_from_shared_context_analysis_trace_and_tool_arguments():
    analyst = UnitTestProvider(
        "analyst", {"reasoning", "planning"},
        analysis_text="Do not forward Authorization: Bearer highentropysecretvalue12345 to another role.",
    )
    analyst.tool_response = None
    critic = UnitTestProvider("critic", {"critique"}, tool_calling=False)
    result = _orchestrate(
        _router(analyst, critic),
        objective="Review this security task",
        tools=[{"type": "function", "function": {"name": "status", "parameters": {}}}],
        context_provenance=[{"source": "test", "owner_session_token": "session-canary-secret"}],
    )

    all_provider_messages = json.dumps([call["messages"] for provider in (analyst, critic) for call in provider.calls])
    encoded_result = json.dumps(result, sort_keys=True)
    assert "highentropysecretvalue12345" not in all_provider_messages
    assert "session-canary-secret" not in all_provider_messages
    assert "highentropysecretvalue12345" not in encoded_result
    assert "session-canary-secret" not in encoded_result
    assert "tool-canary-secret" not in encoded_result
    assert "[REDACTED]" in all_provider_messages
    assert result["orchestration"]["context_provenance"][0]["owner_session_token"] == "[REDACTED]"
    assert result["orchestration"]["critic_report"]["authority"] == "diagnostic_only"


def test_opaque_secret_reference_survives_schema_sanitization_but_actual_credentials_do_not():
    from agent.context import sanitize_model_data

    provider = UnitTestProvider("reference-model", {"reasoning", "planning"})
    schema = {
        "type": "function",
        "function": {
            "name": "use_owner_secret_reference",
            "parameters": {
                "type": "object",
                "properties": {"secret_ref": {"type": "string", "description": "Opaque Owner vault reference"}},
                "required": ["secret_ref"],
            },
        },
    }
    _orchestrate(_router(provider), preference="fast", tools=[schema])
    transmitted_schema = provider.calls[0]["tools"][0]
    sanitized_values = sanitize_model_data({
        "secret_ref": "vault://owner/opaque-reference-7",
        "api_key": "synthetic-api-key-value",
        "token": "synthetic-token-value",
    })

    assert transmitted_schema["function"]["parameters"]["properties"]["secret_ref"] == {
        "type": "string",
        "description": "Opaque Owner vault reference",
    }
    assert sanitized_values["secret_ref"] == "vault://owner/opaque-reference-7"
    assert sanitized_values["api_key"] == "[REDACTED]"
    assert sanitized_values["token"] == "[REDACTED]"


def test_budget_refuses_unknown_cost_models_when_owner_sets_cost_ceiling(monkeypatch):
    model = UnitTestProvider("model", {"reasoning"}, cost_per_1k_tokens_usd=None)
    monkeypatch.setenv("CYBERSENTINEL_MODEL_MAX_COST_USD", "0.25")
    result = _orchestrate(_router(model), preference="fast")

    assert result["orchestration"]["cost_budget_enforced"] is True
    assert result["orchestration"]["invocations"][0]["failure_kind"] == "PROVIDER_FAILURE"
    assert model.calls == []


def test_explicit_cost_budget_uses_declared_rates_only(monkeypatch):
    model = UnitTestProvider("model", {"reasoning"}, cost_per_1k_tokens_usd=0.01)
    monkeypatch.setenv("CYBERSENTINEL_MODEL_MAX_COST_USD", "0.25")
    result = _orchestrate(_router(model), preference="fast")

    assert model.calls
    assert result["orchestration"]["cost_budget_enforced"] is True
    assert result["orchestration"]["cost_estimate_usd"] is not None
    assert result["orchestration"]["cost_estimate_usd"] <= 0.25


def test_owner_scoped_transcript_is_included_only_for_matching_owner_and_redacted(tmp_path, monkeypatch):
    import core.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "chat.sqlite3")
    db.ensure_conversation("conversation-owner-a", "owner-a")
    db.add_conversation_message(
        "conversation-owner-a", "user", "Review this record; api_key=conversation-canary-secret", owner_id="owner-a"
    )
    mission_a = Mission.create(
        "inspect the authorized workspace",
        "inspect the authorized workspace",
        Plan.initial("inspect the authorized workspace"),
        request_id="owner-a-request",
        owner_identity_ref="owner-a",
        provenance={"conversation_id": "conversation-owner-a"},
    )
    context_a = ContextAssembler().build(mission_a)
    rendered_a = json.dumps([item.to_dict() for item in context_a.messages], ensure_ascii=False)

    mission_b = Mission.create(
        "inspect the authorized workspace",
        "inspect the authorized workspace",
        Plan.initial("inspect the authorized workspace"),
        request_id="owner-b-request",
        owner_identity_ref="owner-b",
        provenance={"conversation_id": "conversation-owner-a"},
    )
    context_b = ContextAssembler().build(mission_b)
    rendered_b = json.dumps([item.to_dict() for item in context_b.messages], ensure_ascii=False)

    assert "Review this record" in rendered_a
    assert "conversation-canary-secret" not in rendered_a
    assert "[REDACTED]" in rendered_a
    assert "Review this record" not in rendered_b
    assert "conversation-canary-secret" not in rendered_b
    assert context_a.context_hash != context_b.context_hash


def test_owner_validated_memory_adapter_preserves_structured_evidence_references(monkeypatch):
    from agent.context import DurableMemoryProvider
    from agent.memory import MemoryDomain, MemoryItem, MemoryProvider as DurableProvider, MemoryType, TrustClassification

    reference = {"record": {"kind": "mission_criterion_evidence", "provenance_token": "signed-fixture"}}
    item = MemoryItem.create(
        conversation_id="mission:prior",
        content="validated prior status result",
        memory_type=MemoryType.REASONING_CASE,
        trust_classification=TrustClassification.VALIDATED,
        source="system_issuer",
        provenance="execution_runtime:mission_criterion_evidence",
        domain=MemoryDomain.LEARNING,
        request_id="prior-request",
        owner_identity_ref="owner-memory-fixture",
        source_mission_id="prior-mission",
        system_evidence_refs=(reference,),
        validation_state="validated_experience",
    )
    monkeypatch.setattr(DurableProvider, "get_relevant_memory", staticmethod(lambda *_args, **_kwargs: []))
    monkeypatch.setattr(DurableProvider, "get_validated_experience", staticmethod(lambda *_args, **_kwargs: [item]))

    results = DurableMemoryProvider("new-conversation", owner_identity_ref="owner-memory-fixture").retrieve_relevant("prior status")

    assert len(results) == 1
    assert results[0]["source_mission_id"] == "prior-mission"
    assert results[0]["system_evidence_refs"] == [reference]
    assert results[0]["validation_state"] == "validated_experience"


def test_native_mission_model_shares_durable_reasoning_scope_and_knowledge_across_roles(tmp_path):
    analyst = UnitTestProvider("analyst", {"reasoning", "planning"})
    critic = UnitTestProvider("critic", {"critique"}, tool_calling=False)
    router = _router(analyst, critic)
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create(
        "analyze the authorized test repository",
        "analyze the authorized test repository",
        Plan.initial("analyze the authorized test repository"),
        mission_id="durable-shared-mission",
        request_id="durable-shared-request",
        owner_identity_ref="durable-test-owner",
        scope_snapshot={"scope_snapshot_id": "scope-safe-id", "target_id": "test-repo", "authorized_assets": ["test-repo"]},
        authorization_snapshot={"allowed_tools": [], "allowed_actions": [], "forbidden_actions": []},
        provenance={"conversation_id": "durable-test-conversation"},
    )
    mission.interpretations.append({"reasoning_case": {
        "record_type": "REASONING_CASE",
        "case_id": "reasoning-case-shared",
        "observations": ["An authorized fixture observation."],
        "candidate_hypotheses": [{"hypothesis_id": "hypothesis-1", "statement": "A test-only candidate", "status": "UNVALIDATED"}],
        "supporting_evidence": [],
        "contradicting_evidence": [],
        "system_validation": {"state": "UNVALIDATED"},
    }})
    mission.knowledge_context = [{"chunk_id": "knowledge-receipt-1", "text": "UNTRUSTED_CONTEXT_INPUT: fixture reference only."}]
    store.save(mission)

    runtime = MissionRuntime(store, executor=lambda *_: {"success": False, "source": "test_fixture"})
    model = MindNativeModel(router, CyberSentinelMind(router), store, preference="balanced")
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)

    assert analyst.calls and critic.calls
    for provider in (analyst, critic):
        rendered = json.dumps([call["messages"] for call in provider.calls], ensure_ascii=False)
        assert "durable-shared-mission" in rendered
        assert "scope-safe-id" in rendered
        assert "reasoning-case-shared" in rendered
        assert "knowledge-receipt-1" in rendered
    persisted = store.load(mission.mission_id)
    assert persisted is not None
    turn = persisted.progress["model_loop"]["turns"][-1]
    assert turn["orchestration"]["model_outputs_are_evidence"] is False
    assert turn["orchestration"]["context_hash"]
    assert any(item.get("event") == "ModelInvocation" for item in persisted.trajectory)
    assert any(item.get("event") == "ModelOrchestration" for item in persisted.trajectory)
    assert persisted.evidence == []
    assert result.mission_id == mission.mission_id


def test_mind_starts_new_owner_mission_with_only_preference_and_shared_conversation():
    router = ModelRouter([])

    class CoreStub:
        def __init__(self):
            self.router = router
            self.created = None

        def run_owner_mission(self, objective, **kwargs):
            self.created = {"objective": objective, **kwargs}
            return self.created

    core = CoreStub()
    mind = CyberSentinelMind(router)
    result = mind.chat(
        core=core,
        payload={"model_preference": "deep", "request_id": "mind-entry-request"},
        text="Inspect this authorized fixture.",
        owner_session_token="test-owner-session",
        owner_id="test-owner",
        conversation_id="test-conversation",
        run_mission=False,
    )

    assert result is core.created
    assert core.created["model_preference"] == "deep"
    assert core.created["conversation_id"] == "test-conversation"
    assert core.created["run"] is False
    assert core.created["model_id"] == "auto"


def test_api_chat_continuation_uses_mind_and_keeps_existing_queued_mission(tmp_path, monkeypatch):
    import api.chat as chat_api
    import core.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "chat.sqlite3")
    owner_id = "owner-queue-test"
    conversation_id = "conversation-queue-test"
    db.ensure_conversation(conversation_id, owner_id)
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create(
        "review an authorized repository",
        "review an authorized repository",
        Plan.initial("review an authorized repository"),
        request_id="queued-chat-request",
        owner_identity_ref=owner_id,
        provenance={"conversation_id": conversation_id},
    )
    mission.model_selection = {"mode": "auto", "preference": "balanced"}
    store.save(mission)
    queue = MissionQueue(tmp_path / "mission_queue.sqlite3")
    queue.enqueue(mission.mission_id)

    class CoreStub:
        def __init__(self):
            self.store = store
            self.router = ModelRouter([])
            self.resume_args = None

        def resume_mission(self, mission_id, **kwargs):
            self.resume_args = {"mission_id": mission_id, **kwargs}
            current = self.store.load(mission_id)
            preference = kwargs.get("model_preference")
            if preference:
                current.model_selection["preference"] = preference
                self.store.save(current)
            return current

    core = CoreStub()
    monkeypatch.setattr(chat_api, "_owner_session", lambda _token: {"owner_id": owner_id, "session_id": "session-test"})
    monkeypatch.setattr(chat_api, "_agent_core", lambda: core)
    result = chat_api.chat(
        {
            "text": "Continue using the deep preference",
            "conversation_id": conversation_id,
            "mission_id": mission.mission_id,
            "model_preference": "deep",
        },
        owner_session_token="session-test",
    )

    assert core.resume_args["mission_id"] == mission.mission_id
    assert core.resume_args["model_preference"] == "deep"
    assert core.resume_args["run"] is False
    assert result["queued"] is True
    assert result["queue_state"] == WorkerMissionState.QUEUED.value
    assert result["mission_id"] == mission.mission_id
    assert "saved" in result["answer"].casefold() or "حفظ" in result["answer"]
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    stored = db.conversation_messages(conversation_id)
    assert stored[-2]["content"] == "Continue using the deep preference"
    assert stored[-1]["metadata"]["mission_id"] == mission.mission_id


def test_api_chat_rejects_live_worker_collision_before_persisting_owner_message(tmp_path, monkeypatch):
    import api.chat as chat_api
    import core.db as db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "chat.sqlite3")
    owner_id = "owner-live-test"
    conversation_id = "conversation-live-test"
    db.ensure_conversation(conversation_id, owner_id)
    store = MissionStore(tmp_path / "missions.sqlite3")
    mission = Mission.create(
        "review an authorized repository",
        "review an authorized repository",
        Plan.initial("review an authorized repository"),
        request_id="live-chat-request",
        owner_identity_ref=owner_id,
        provenance={"conversation_id": conversation_id},
    )
    store.save(mission)
    queue = MissionQueue(tmp_path / "mission_queue.sqlite3")
    queue.enqueue(mission.mission_id)
    queue.claim_next(worker_id="fixture-worker", lease_seconds=60)

    class CoreStub:
        router = ModelRouter([])
        def __init__(self):
            self.store = store

    core = CoreStub()
    monkeypatch.setattr(chat_api, "_owner_session", lambda _token: {"owner_id": owner_id, "session_id": "session-test"})
    monkeypatch.setattr(chat_api, "_agent_core", lambda: core)
    before = db.conversation_messages(conversation_id)

    with pytest.raises(chat_api.MissionBusyError, match="mission_busy"):
        chat_api.chat(
            {"text": "Do not race the active worker", "conversation_id": conversation_id, "mission_id": mission.mission_id},
            owner_session_token="session-test",
        )

    assert db.conversation_messages(conversation_id) == before
    assert queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING


def test_model_preference_contract_is_localized_and_does_not_expose_provider_selector():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    script = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert 'id="modelPreference"' in html
    assert "fast" in html and "balanced" in html and "deep" in html and "local" in html
    assert "model_preference" in script
    assert "selectedModelId" not in script
    assert "modelProfileId" not in script
    assert "/api/public/models" not in script


def test_owner_preference_parser_accepts_only_supported_modes_and_disallows_mixed_selection():
    from api.models import requested_model_preference

    for preference in ("fast", "balanced", "deep", "local"):
        assert requested_model_preference({"model_preference": preference}) == preference
    for preference in ("https://arbitrary.example", "openai/gpt-model", ""):
        with pytest.raises(ValueError, match="invalid_model_preference"):
            requested_model_preference({"model_preference": preference})
    assert requested_model_preference({"model_preference": None}) is None


def test_empty_runtime_router_reports_no_configured_provider_without_live_calls(monkeypatch):
    suffixes = (
        "BASE_URL", "MODEL", "API_KEY", "TOOL_CALLING", "STREAMING",
        "STRUCTURED_OUTPUT", "PRIORITY", "CAPABILITIES", "COST_PER_1K_TOKENS_USD",
    )
    for prefix in ("LOCAL_LLM", "COLAB_LLM", "HF_LLM", "LLM"):
        for suffix in suffixes:
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)

    router = ModelRouter.from_env()
    result = _orchestrate(router, preference="balanced")

    assert router.providers == []
    assert result["provider"] == "unavailable"
    assert result["orchestration"]["status"] == "no_provider"
    assert result["orchestration"]["reason"] == "no_configured_model_profile"
    assert result["orchestration"]["invocations"] == []


def test_provider_status_never_exposes_endpoint_credentials_or_raw_url():
    from agent.providers import OpenAICompatibleProvider

    provider = OpenAICompatibleProvider(
        "status-api-key-canary",
        "https://user:password-canary@private.example/v1?access_token=query-canary",
        "model",
        "provider-key-canary",
    )
    provider.last_error = "Authorization: Bearer error-token-canary-12345678"
    rendered = json.dumps(provider.status(), sort_keys=True)

    for canary in (
        "password-canary", "private.example", "query-canary",
        "provider-key-canary", "error-token-canary-12345678",
    ):
        assert canary not in rendered
    assert "base_url" not in provider.status()
    assert provider.status()["endpoint_configured"] is True
