from __future__ import annotations

from pathlib import Path
import time

from agent.agent_core import AgentCore
from agent.mission import MissionStore
from agent.observation_intelligence import ObservationInterpreter
from agent.provider_api import ProviderRequestRejected


class CapturingRouter:
    context_length = 4096

    def __init__(self):
        self.messages = []
        self.kwargs = {}

    def generate(self, messages, **kwargs):
        self.messages = list(messages)
        self.kwargs = dict(kwargs)
        return {"content": '{"summary":"model proposal"}'}


def test_observation_proposal_omits_full_mission_snapshots_and_respects_local_budget(tmp_path: Path):
    router = CapturingRouter()
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    policy_sentinel = "POLICY_SNAPSHOT_SENTINEL_" + "p" * 12000
    history_sentinel = "MISSION_HISTORY_SENTINEL_" + "h" * 12000
    scope_sentinel = "SCOPE_SNAPSHOT_SENTINEL_" + "s" * 12000

    result = core._observation_proposal({
        "mission": {
            "mission_id": "context-budget-mission",
            "request_id": "context-budget-request",
            "objective": "verify local status",
            "owner_instruction": "preserve evidence and do not change authority",
            "policy_snapshot": {"body": policy_sentinel},
            "scope_snapshot": {"body": scope_sentinel},
            "progress": {"history": history_sentinel},
        },
        "plan": {"steps": [{"step_id": "step-1", "action": "status"}]},
        "current_step": {"step_id": "step-1", "objective": "observe current status"},
        "action": "status",
        "observation": {"success": True, "summary": "OBSERVATION_SENTINEL"},
        "evidence": [{"evidence_id": "status-evidence-1", "summary": "EVIDENCE_SENTINEL"}],
        "hypothesis_state": [],
        "knowledge_context": [],
        "conversation_context": [],
    })

    assert result == {"summary": "model proposal"}
    serialized = "\n".join(str(item.get("content", "")) for item in router.messages)
    assert "OBSERVATION_SENTINEL" in serialized
    assert "EVIDENCE_SENTINEL" in serialized
    assert "verify local status" in serialized
    assert "POLICY_SNAPSHOT_SENTINEL" not in serialized
    assert "MISSION_HISTORY_SENTINEL" not in serialized
    assert "SCOPE_SNAPSHOT_SENTINEL" not in serialized
    assert sum(len(str(item.get("content", ""))) for item in router.messages) <= 4096 * 2


def test_observation_proposal_passes_owner_deadline_to_router(tmp_path: Path):
    router = CapturingRouter()
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    deadline = time.monotonic() + 5.0

    core._observation_proposal({
        "_owner_deadline_monotonic": deadline,
        "mission": {"mission_id": "bounded-observation-proposal", "request_id": "bounded-observation-request"},
        "plan": {},
        "current_step": {"objective": "interpret bounded local evidence"},
        "action": "latest_intel",
        "observation": {"success": True, "summary": "bounded observation"},
        "evidence": [],
        "hypothesis_state": [],
    })

    assert 0 < router.kwargs["timeout"] <= 5.0


def test_observation_fallback_keeps_typed_provider_error_provenance():
    rejected = ProviderRequestRejected(
        "provider request rejected (HTTP 400)",
        provider="local_llama_cpp",
        model="qwen3-4b-q4-k-m",
        status_code=400,
    )

    def fail(_payload):
        raise rejected

    proposal = ObservationInterpreter(proposer=fail).interpret(
        mission={"mission_id": "fallback-mission"},
        plan={},
        current_step=None,
        action="status",
        observation={"success": True, "summary": "deterministic observation retained"},
        evidence=[],
        hypothesis_state={},
    )

    assert proposal.summary == "deterministic observation retained"
    assert proposal.provenance["model_status"] == "unavailable_or_malformed"
    assert proposal.provenance["model_error"] == "ProviderRequestRejected"
    assert proposal.provenance["model_error_kind"] == "REQUEST_REJECTED"
    assert proposal.provenance["model_http_status"] == 400


def test_initial_planning_uses_provider_context_window_token_budget(tmp_path: Path, monkeypatch):
    import agent.agent_core as agent_core_module

    router = CapturingRouter()
    router.tool_calling = lambda messages, schemas, **_kwargs: {"content": "planning response"}
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    captured = {}

    class MinimalContext:
        def provider_messages(self):
            return [{"role": "user", "content": "bounded"}]

    def capture_build(cls, **kwargs):
        captured.update(kwargs)
        return MinimalContext()

    monkeypatch.setattr(agent_core_module.ContextEngine, "build", classmethod(capture_build))
    monkeypatch.setattr(core, "_schemas", lambda: [{"type": "function", "function": {"name": "status"}}])

    response = core._ask("current Owner task", policy_context="active policy", conversation_id="budget-test")

    assert response["content"] == "planning response"
    limits = captured["runtime_limits"]
    assert limits.max_context_tokens == router.context_length * 4 // 5
    assert limits.max_context_chars <= router.context_length * 2
    assert captured["include_tool_summary"] is False
    assert captured["include_tool_schema_tokens"] is True


def test_agent_core_runtime_limits_are_loaded_from_owner_policy(tmp_path: Path, monkeypatch):
    import json

    import security.owner_policy as owner_policy

    policy = json.loads(owner_policy.POLICY_PATH.read_text(encoding="utf-8"))
    policy["runtime_limits"]["max_same_tool_calls"] = 2
    policy["runtime_limits"]["max_execution_time_seconds"] = 120
    policy_path = tmp_path / "owner_policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    monkeypatch.setattr(owner_policy, "POLICY_PATH", policy_path)

    router = CapturingRouter()
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    limits = core._context_runtime_limits()

    assert limits.max_same_tool_calls == 2
    assert limits.max_execution_time_seconds == 120
    assert limits.max_context_chars == min(policy["runtime_limits"]["max_context_chars"], router.context_length * 2)
    assert limits.max_context_tokens == router.context_length * 4 // 5


def test_explicit_status_mission_uses_only_status_schema_and_keeps_owner_policy(tmp_path: Path):
    router = CapturingRouter()
    router.schemas = []

    def tool_calling(messages, schemas, **_kwargs):
        router.messages = list(messages)
        router.schemas = list(schemas)
        return {"tool_calls": [{"name": "status", "arguments": {}, "id": "status-call"}]}

    router.tool_calling = tool_calling
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))

    class EmptyMemory:
        def available(self):
            return False

        def retrieve_relevant(self, *_args, **_kwargs):
            return []

    plan = core._plan(
        "Return the current system status using the status tool.",
        policy_context="CAPTURED OWNER POLICY SNAPSHOT: active policy",
        conversation_id="owner-status-budget-test",
        memory_provider=EmptyMemory(),
    )

    assert [step.action for step in plan.steps] == ["status"]
    assert [item["function"]["name"] for item in router.schemas] == ["status"]
    serialized = "\n".join(str(item.get("content", "")) for item in router.messages)
    assert "CAPTURED OWNER POLICY SNAPSHOT: active policy" in serialized
    assert "Return the current system status" in serialized


def test_intent_tool_selection_is_intersected_with_owner_scope_and_supports_multiple_intents(tmp_path: Path):
    core = AgentCore(CapturingRouter(), store=MissionStore(tmp_path / "missions.sqlite3"))

    assert core._eligible_planning_tools(
        "Check system status, local TCP listeners, and run the project tests.", None
    ) == {"status", "local_security_check", "run_project_tests"}
    assert core._eligible_planning_tools(
        "Run the authorized local project tests and verify their result", None
    ) == {"status", "run_project_tests"}
    assert core._eligible_planning_tools(
        "Use exactly these two tools: status and latest_intel. Read current status and the latest locally available intelligence snapshot.",
        None,
    ) == {"status", "latest_intel"}
    assert core._eligible_planning_tools(
        "Read the latest locally available intelligence snapshot.", None
    ) == {"latest_intel"}
    assert core._eligible_planning_tools("Return the current status.", {"search"}) == set()
    assert core._eligible_planning_tools("Analyze this project.", {"search"}) == {"search"}


def test_initial_planning_sends_and_budgets_only_scope_permitted_tools(tmp_path: Path, monkeypatch):
    import agent.agent_core as agent_core_module
    from tools.registry import model_tool_definitions

    router = CapturingRouter()
    router.schemas = []

    def tool_calling(messages, schemas, **_kwargs):
        router.messages = list(messages)
        router.schemas = list(schemas)
        return {"content": "bounded proposal"}

    router.tool_calling = tool_calling
    core = AgentCore(router, store=MissionStore(tmp_path / "missions.sqlite3"))
    all_names = {item["function"]["name"] for item in model_tool_definitions()}
    scope_context = {"forbidden_actions": sorted(all_names - {"status"})}
    available = core._planning_tool_allowlist(scope_context)
    captured = {}
    original_build = agent_core_module.ContextEngine.build

    def capture_build(cls, **kwargs):
        context = original_build(**kwargs)
        captured["tool_schema_names"] = kwargs["tool_schema_names"]
        captured["context"] = context
        return context

    monkeypatch.setattr(agent_core_module.ContextEngine, "build", classmethod(capture_build))
    response = core._ask(
        "Observe the current read-only status.",
        policy_context="authenticated owner policy",
        conversation_id="scope-budget-test",
        available_tool_names=available,
    )

    assert response["content"] == "bounded proposal"
    assert available == {"status"}
    assert captured["tool_schema_names"] == {"status"}
    assert [item["function"]["name"] for item in router.schemas] == ["status"]
    assert captured["context"].budget.total_tokens < captured["context"].budget.limits.max_context_tokens


def test_malformed_scope_tool_lists_fail_closed(tmp_path: Path):
    import pytest

    core = AgentCore(CapturingRouter(), store=MissionStore(tmp_path / "missions.sqlite3"))
    with pytest.raises(ValueError, match="invalid_forbidden_actions"):
        core._planning_tool_allowlist({"forbidden_actions": "status"})
    with pytest.raises(ValueError, match="invalid_allowed_tools"):
        core._planning_tool_allowlist({"allowed_tools": ["status", 7]})


def test_mission_dispatch_filters_schemas_by_persisted_authorization():
    from types import SimpleNamespace
    from security.mission_authorization import MissionAuthorizationSnapshot
    from tools.registry import model_tool_definitions

    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner-ref",
        mission_id="authorized-mission",
        target_identity="local-status",
        scope=("workspace",),
        allowed_actions=("status",),
        forbidden_actions=(),
        allowed_tools=("status",),
        time_window={"timezone": "UTC"},
        max_duration=60,
        rate_limits={"status": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("local-status",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/tmp"},
        policy_version="owner-policy",
        owner_approval="owner-approval-proof",
    )
    mission = SimpleNamespace(authorization_snapshot=snapshot.to_dict())

    selected = AgentCore._schemas_for_mission_authorization(mission, model_tool_definitions())

    assert [item["function"]["name"] for item in selected] == ["status"]
