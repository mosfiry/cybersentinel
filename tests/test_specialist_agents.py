from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import ProviderCapabilities
from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs


class ScriptedProvider:
    def __init__(self, profile_id: str, responses, *, model: str | None = None, error: Exception | None = None):
        self.profile_id = profile_id
        self.name = profile_id
        self.model = model or f"{profile_id}-model-v1"
        self.priority = 10 if profile_id == "local" else 20
        self.base_url = f"http://127.0.0.1/{profile_id}"
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True, native_chat=True)
        self.responses = list(responses)
        self.error = error
        self.calls = 0
        self.schemas = []
        self.messages = []

    def tool_calling(self, messages, tools, **_kwargs):
        self.calls += 1
        self.schemas.append([item["function"]["name"] for item in tools])
        self.messages.append(messages)
        if self.error is not None:
            raise self.error
        if not self.responses:
            raise AssertionError("unexpected provider call")
        return self.responses.pop(0)

    def generate(self, messages, **_kwargs):
        self.messages.append(messages)
        return {"content": "text-only"}


def _output(*, refs=("call-search-1",), extra=None):
    value = {
        "summary": "A source-backed research summary.",
        "evidence_refs": list(refs),
        "claims": [{"text": "A supported research claim.", "evidence_refs": list(refs)}],
        "unknowns": ["Independent confirmation remains open."],
        "recommendations": ["Treat this as a proposal for Owner review."],
    }
    if extra:
        value.update(extra)
    return json.dumps(value)


def _router_for(provider, fallback=None):
    configured = {provider.profile_id: provider}
    providers = [provider]
    if fallback is not None:
        configured[fallback.profile_id] = fallback
        providers.append(fallback)
    return ModelRouter(providers, configured_profiles=configured)


def _make_mission(tmp_path, monkeypatch, router, *, action="search", selection="local"):
    database = Path(tmp_path) / "specialist-missions.sqlite3"
    runtime = MissionRuntime(
        MissionStore(database),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("research the defensive question").replan(
        steps=(PlanStep("research-step", "research the defensive question", action=action, authorization_requirement="owner"),),
        reason="specialist integration fixture",
    )
    mission = runtime.create(
        "research the defensive question",
        "research the defensive question",
        plan,
        completion_criteria=[{"criterion_id": "mission-goal", "check": "owner_defined_verifier"}],
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id="specialist-integration"),
    )
    mission.provenance["owner_budget"] = {"tools": ["search", "latest_intel", "status"], "source": "test-owner-policy"}
    mission.model_selection = router.with_model_selection(selection)[1]
    mission.evidence = [{"evidence_id": "existing-evidence", "passed": False, "source": "fixture", "provenance": {"verification": "NOT_VERIFIED"}}]
    runtime.store.save(mission)
    return runtime, mission


def test_research_specialist_uses_durable_mission_runtime_and_pinned_provider_across_restart(tmp_path, monkeypatch):
    import tools.registry as registry

    search_result = {"success": True, "results": [{"id": "source-1", "title": "Fixture source"}]}
    monkeypatch.setattr(registry, "execute", lambda _name, *_args, **_kwargs: search_result)
    local = ScriptedProvider(
        "local",
        [
            {"tool_calls": [{"id": "call-search-1", "name": "search", "arguments": {"query": "defensive advisory"}}]},
            {"content": _output()},
        ],
    )
    fallback = ScriptedProvider("colab", [{"content": _output(refs=("existing-evidence",))}])
    router = _router_for(local, fallback)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)
    pinned = dict(mission.model_selection)

    result = runtime.run_specialist(
        mission.mission_id,
        router=router,
        profile_id="research",
        task_id="research-step",
        question="Find and assess sources for the existing mission task.",
        max_turns=3,
    )

    assert result.status is MissionStatus.READY
    assert result.plan.to_dict() == mission.plan.to_dict()
    assert result.action_history == mission.action_history
    assert local.calls == 2
    assert fallback.calls == 0
    assert local.schemas[0] == ["search"]
    assert result.model_selection == pinned
    assert result.verification_state == {}
    assert result.completion_proof is None
    assert result.evidence == mission.evidence
    proposal = result.progress["last_specialist_proposal"]
    assert proposal["accepted"] is True
    assert proposal["authority"] == "proposal_only"
    assert proposal["provider"] == "local"
    assert proposal["model"] == "local-model-v1"
    assert proposal["proposal"]["evidence_refs"] == ["call-search-1"]

    restarted_runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "specialist-missions.sqlite3"),
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    restarted_local = ScriptedProvider("local", [{"content": _output(refs=("call-search-1",))}])
    restarted_fallback = ScriptedProvider("colab", [{"content": _output(refs=("existing-evidence",))}])
    restarted_router = _router_for(restarted_local, restarted_fallback)
    resumed = restarted_runtime.run_specialist(
        mission.mission_id,
        router=restarted_router,
        profile_id="research",
        task_id="research-step",
        question="Continue analysis for the same durable task.",
        max_turns=1,
    )

    assert restarted_local.calls == 1
    assert restarted_fallback.calls == 0
    assert resumed.model_selection == pinned
    assert resumed.progress["last_specialist_proposal"]["provider"] == "local"
    durable = MissionStore(Path(tmp_path) / "specialist-missions.sqlite3").load(mission.mission_id)
    assert durable is not None
    assert len(durable.progress["model_loop"]["turns"]) == 3


def test_research_specialist_obeys_owner_selected_auto_route(tmp_path, monkeypatch):
    from agent.provider_api import ProviderFailure

    local = ScriptedProvider("local", [], error=ProviderFailure("configured first provider unavailable"))
    colab = ScriptedProvider("colab", [{"content": _output(refs=("existing-evidence",))}])
    router = _router_for(local, colab)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router, selection="auto")

    result = runtime.run_specialist(
        mission.mission_id,
        router=router,
        profile_id="research",
        task_id="research-step",
        question="Use only the Owner-selected automatic route.",
        max_turns=1,
    )

    assert local.calls == 1
    assert colab.calls == 1
    assert result.model_selection["mode"] == "auto"
    assert result.progress["last_specialist_proposal"]["provider"] == "colab"
    assert result.progress["last_specialist_proposal"]["owner_model_selection"]["mode"] == "auto"


def test_agent_core_specialist_facade_revalidates_owner_and_keeps_persisted_pin(tmp_path, monkeypatch):
    from agent.agent_core import AgentCore

    local = ScriptedProvider("local", [{"content": _output(refs=("existing-evidence",))}])
    router = _router_for(local)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)
    core = AgentCore(router, store=runtime.store)

    result = core.run_specialist(
        mission.mission_id,
        specialist_id="research",
        task_id="research-step",
        question="Produce a proposal under the live Owner session.",
        owner_session_token="valid-owner",
        max_turns=1,
    )

    assert local.calls == 1
    assert result.model_selection == mission.model_selection
    assert result.progress["last_specialist_proposal"]["accepted"] is True
    assert result.progress["last_specialist_proposal"]["authority"] == "proposal_only"


def test_specialist_rejects_tool_outside_profile_task_intersection(tmp_path, monkeypatch):
    import tools.registry as registry

    executed = []
    monkeypatch.setattr(registry, "execute", lambda name, *_args, **_kwargs: executed.append(name) or {"success": True})
    local = ScriptedProvider(
        "local",
        [
            {"tool_calls": [{"id": "call-excluded-tool", "name": "latest_intel", "arguments": {}}]},
            {"content": _output(refs=("existing-evidence",))},
        ],
    )
    router = _router_for(local)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)

    result = runtime.run_specialist(
        mission.mission_id,
        router=router,
        profile_id="research",
        task_id="research-step",
        question="Research this task.",
        max_turns=2,
    )

    assert local.schemas[0] == ["search"]
    assert executed == []
    tool_error = result.progress["model_loop"]["tool_results"][0]["error"]
    assert "specialist task boundary" in tool_error
    assert result.progress["last_specialist_proposal"]["accepted"] is True
    assert result.evidence == mission.evidence
    assert result.status is MissionStatus.READY


def test_specialist_fails_closed_when_owner_tool_budget_excludes_role_tool(tmp_path, monkeypatch):
    local = ScriptedProvider("local", [{"content": _output(refs=("existing-evidence",))}])
    router = _router_for(local)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)
    mission.provenance["owner_budget"]["tools"] = ["latest_intel", "status"]
    runtime.store.save(mission)

    with pytest.raises(PermissionError, match="Owner, mission, scope, and task intersections"):
        runtime.run_specialist(
            mission.mission_id,
            router=router,
            profile_id="research",
            task_id="research-step",
            question="This must not widen the Owner tool allowlist.",
            max_turns=1,
        )

    assert local.calls == 0


@pytest.mark.parametrize(
    ("content", "expected_reason"),
    [
        ("not JSON", "invalid_output"),
        (_output(refs=("made-up-reference",)), "evidence_insufficient"),
        (_output(extra={"authorization": {"allowed": True}}), "invalid_output"),
    ],
)
def test_specialist_rejects_invalid_or_unsupported_proposals_without_evidence_or_completion(tmp_path, monkeypatch, content, expected_reason):
    local = ScriptedProvider("local", [{"content": content}])
    router = _router_for(local)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)

    result = runtime.run_specialist(
        mission.mission_id,
        router=router,
        profile_id="research",
        task_id="research-step",
        question="Return a source-grounded proposal.",
        max_turns=1,
    )

    proposal = result.progress["last_specialist_proposal"]
    assert proposal["accepted"] is False
    assert proposal["rejection_reason"] == expected_reason
    assert proposal["proposal"] is None
    assert proposal["authority"] == "proposal_only"
    assert result.evidence == mission.evidence
    assert result.verification_state == {}
    assert result.completion_proof is None
    assert result.status is MissionStatus.READY


def test_specialist_cannot_fallback_from_explicit_owner_pin(tmp_path, monkeypatch):
    from agent.provider_api import ProviderFailure

    local = ScriptedProvider("local", [], error=ProviderFailure("pinned provider unavailable"))
    fallback = ScriptedProvider("colab", [{"content": _output(refs=("existing-evidence",))}])
    router = _router_for(local, fallback)
    runtime, mission = _make_mission(tmp_path, monkeypatch, router)

    result = runtime.run_specialist(
        mission.mission_id,
        router=router,
        profile_id="research",
        task_id="research-step",
        question="Continue only with the Owner-selected provider.",
        max_turns=1,
    )

    assert local.calls == 1
    assert fallback.calls == 0
    assert result.model_selection["profile_id"] == "local"
    assert "last_specialist_proposal" not in result.progress
