from __future__ import annotations

from pathlib import Path

import pytest

from owner_session_testutils import allow_owner_sessions
from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall


class PlanningProvider:
    name = "planner-contract-test"
    model = "planner-contract-fixture"

    def __init__(self, responses):
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.responses = list(responses)
        self.calls = 0
        self.requests = []

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        self.requests.append({"messages": messages, "tools": tools})
        return self.responses.pop(0)

    def generate(self, messages, **kwargs):
        self.calls += 1
        return {"content": "unused"}


def make_core(tmp_path, responses):
    provider = PlanningProvider(responses)
    core = AgentCore(
        ModelRouter([provider]),
        store=MissionStore(Path(tmp_path) / "missions.sqlite3"),
    )
    return core, provider


def failure_code(plan):
    assert plan.steps and plan.steps[0].action == "__planning_failure__"
    return plan.steps[0].retry_policy["reason_code"]


def test_valid_plan_uses_registered_schemas_and_includes_required_actions(tmp_path):
    server_id = "mcp_" + "a" * 32
    required = (
        "status", "latest_intel", "browser", "mcp.discover", "mcp.invoke", "run_project_tests",
    )
    response = ProviderResponse(tool_calls=[
        ToolCall("status", {}, "status-1"),
        ToolCall("latest_intel", {}, "intel-1"),
        ToolCall("browser", {"operation": "open", "url": "https://example.test/research"}, "browser-1"),
        ToolCall("mcp.discover", {"server_id": server_id, "tool_name": "read_acceptance_record"}, "discover-1"),
        ToolCall("mcp.invoke", {
            "server_id": server_id,
            "tool_name": "read_acceptance_record",
            "arguments": {"query": "bounded acceptance"},
        }, "invoke-1"),
        ToolCall("run_project_tests", {"query": "bounded-test-project"}, "tests-1"),
    ])
    core, provider = make_core(tmp_path, [response])

    plan = core._plan(
        "Review status, intelligence, scoped browser evidence, approved MCP, and project tests",
        planning_requirements=required,
    )

    assert [step.action for step in plan.steps] == list(required)
    assert all(isinstance(step.retry_policy["arguments"], dict) for step in plan.steps)
    prompt = str(provider.requests[0]["messages"])
    assert "Planning contract (not additional authority)" in prompt
    assert "run_project_tests" in prompt


def test_missing_required_actions_fail_instead_of_becoming_a_successful_plan(tmp_path):
    core, _provider = make_core(tmp_path, [
        ProviderResponse(tool_calls=[ToolCall("status", {}, "status-only")]),
    ])

    plan = core._plan(
        "Check status and latest intelligence",
        available_tool_names={"status", "latest_intel"},
        planning_requirements=("status", "latest_intel"),
    )

    assert failure_code(plan) == "MISSING_REQUIRED_TOOLS"
    assert plan.steps[0].retry_policy["missing_required_tools"] == ["latest_intel"]


@pytest.mark.parametrize(
    ("tool_calls", "available_tools", "expected_code"),
    [
        ([ToolCall("not_registered", {}, "unknown")], {"status"}, "UNSUPPORTED_TOOL"),
        ([ToolCall("browser", {"operation": "open", "url": "bad"}, "bad-url")], {"browser"}, "INVALID_ARGUMENTS"),
        ([ToolCall("status", {}, "status-1"), ToolCall("status", {}, "status-2")], {"status"}, "DUPLICATE_TOOL_CALL"),
        ([ToolCall("watch", {"query": "critical"}, "watch"), ToolCall("unwatch", {"query": "critical"}, "unwatch")], {"watch", "unwatch"}, "CONTRADICTORY_ACTIONS"),
        ([
            ToolCall("mcp.invoke", {
                "server_id": "mcp_" + "b" * 32,
                "tool_name": "read_acceptance_record",
                "arguments": {"query": "bounded acceptance"},
            }, "invoke-first"),
            ToolCall("mcp.discover", {"server_id": "mcp_" + "b" * 32, "tool_name": "read_acceptance_record"}, "discover-later"),
        ], {"mcp.discover", "mcp.invoke"}, "INVALID_MCP_SEQUENCE"),
        ([ToolCall("status", {}, "out-of-scope")], {"browser"}, "UNAUTHORIZED_TOOL"),
    ],
)
def test_invalid_or_unauthorized_proposals_are_rejected(tool_calls, available_tools, expected_code, tmp_path):
    core, _provider = make_core(tmp_path, [ProviderResponse(tool_calls=tool_calls)])

    plan = core._plan("Review the local acceptance fixture", available_tool_names=available_tools)

    assert failure_code(plan) == expected_code


def test_required_tools_cannot_expand_the_existing_owner_scope(tmp_path):
    core, provider = make_core(tmp_path, [ProviderResponse(tool_calls=[])])

    with pytest.raises(PermissionError, match="required_planning_tool_outside_owner_scope"):
        core._normalize_planning_requirements(["run_project_tests"], {"status"})

    assert provider.calls == 0


def test_one_incomplete_plan_gets_one_feedback_repair_and_preserves_attempts(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    core, provider = make_core(tmp_path, [
        ProviderResponse(tool_calls=[ToolCall("status", {}, "first-status")]),
        ProviderResponse(tool_calls=[
            ToolCall("status", {}, "repaired-status"),
            ToolCall("latest_intel", {}, "repaired-intel"),
        ]),
    ])

    mission = core.run_owner_mission(
        "Check status and latest intelligence",
        owner_session_token="valid-owner",
        planning_requirements=("status", "latest_intel"),
        run=False,
    )

    assert mission.status is MissionStatus.READY
    assert [step.action for step in mission.plan.steps] == ["status", "latest_intel"]
    assert provider.calls == 2
    assert mission.progress["initial_model_response"]["tool_calls"][0]["name"] == "status"
    assert mission.progress["planning_requirements"] == ["status", "latest_intel"]
    attempts = mission.progress["planning_attempts"]
    assert len(attempts) == 2
    assert attempts[0]["failure_code"] == "MISSING_REQUIRED_TOOLS"
    assert attempts[0]["repair_requested"] is True
    assert attempts[1]["plan_valid"] is True
    assert "missing required tools=latest_intel" in str(provider.requests[1]["messages"])
    assert mission.failures[0]["reason_code"] == "MISSING_REQUIRED_TOOLS"
    assert mission.action_history == []
    assert mission.evidence == []


def test_explicit_required_actions_get_a_second_bounded_repair(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    core, provider = make_core(tmp_path, [
        ProviderResponse(tool_calls=[ToolCall("status", {}, "first-status")]),
        ProviderResponse(tool_calls=[ToolCall("status", {}, "second-status")]),
        ProviderResponse(tool_calls=[
            ToolCall("status", {}, "repaired-status"),
            ToolCall("latest_intel", {}, "repaired-intel"),
        ]),
    ])

    mission = core.run_owner_mission(
        "Check status and latest intelligence",
        owner_session_token="valid-owner",
        planning_requirements=("status", "latest_intel"),
        run=False,
    )

    assert mission.status is MissionStatus.READY
    assert [step.action for step in mission.plan.steps] == ["status", "latest_intel"]
    assert provider.calls == 3
    attempts = mission.progress["planning_attempts"]
    assert len(attempts) == 3
    assert attempts[0]["repair_requested"] is True
    assert attempts[1]["repair_requested"] is True
    assert attempts[2]["plan_valid"] is True
    assert "missing required tools=latest_intel" in str(provider.requests[1]["messages"])
    assert "missing required tools=latest_intel" in str(provider.requests[2]["messages"])


def test_required_action_omission_after_bounded_repair_is_terminal_not_success(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    core, provider = make_core(tmp_path, [
        ProviderResponse(text="Everything is done."),
        ProviderResponse(text="Still done."),
        ProviderResponse(text="No action was taken."),
    ])

    mission = core.run_owner_mission(
        "Check status",
        owner_session_token="valid-owner",
        planning_requirements=("status",),
        run=False,
    )

    assert provider.calls == 3
    assert mission.status is MissionStatus.FAILED_RETRY_EXHAUSTED
    assert mission.error == "model planning failure: INVALID_MODEL_PLAN (MISSING_REQUIRED_TOOLS)"
    assert mission.progress["planning_attempts"][0]["missing_required_tools"] == ["status"]
    attempts = mission.progress["planning_attempts"]
    assert len(attempts) == 3
    assert attempts[0]["repair_requested"] is True
    assert attempts[1]["repair_requested"] is True
    assert attempts[2]["plan_valid"] is False
    assert mission.failures[-1]["retry_policy"]["retry_scheduled"] is False
    assert mission.failures[-1]["retry_policy"]["max_retries"] == 2
    assert mission.action_history == []
    assert mission.evidence == []
