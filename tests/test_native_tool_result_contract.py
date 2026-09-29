from __future__ import annotations

from pathlib import Path

import pytest

from runtime_authorization import make_test_snapshot, signed_test_owner_kwargs
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.planning import Plan, PlanStep


class _NativeToolModel:
    def __init__(self, tool_name: str, *, parallel: bool, arguments: dict | None = None):
        self.tool_name = tool_name
        self.parallel = parallel
        self.arguments = arguments or {}
        self.turn_count = 0

    def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
        self.turn_count += 1
        if self.turn_count > 1:
            return ModelTurn(turn_id, content="Tool observations received.")

        names = [self.tool_name]
        if self.parallel:
            names.append("latest_intel" if self.tool_name == "status" else "status")
        calls = tuple(
            ToolCallProposal.create(
                name,
                self.arguments if name == self.tool_name else {},
                mission_id=mission_id,
                run_id=run_id,
                turn_id=turn_id,
                action_id=f"action-{index}-{name}",
                tool_call_id=f"call-{index}-{name}",
                plan_version=plan_version,
                step_id="primary-step" if name == self.tool_name else "",
            )
            for index, name in enumerate(names)
        )
        return ModelTurn(turn_id, tool_calls=calls)


def _run_native_tool(tool_name, payload, *, parallel, tmp_path, monkeypatch, arguments=None):
    import tools.registry

    companion = "latest_intel" if tool_name == "status" else "status"
    outputs = {tool_name: payload, companion: {"companion_data": True}}
    monkeypatch.setattr(tools.registry, "execute", lambda name, *_args, **_kwargs: outputs[name])

    runtime = MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=lambda *_: {},
        authorization_snapshot_factory=make_test_snapshot,
    )
    plan = Plan.initial("observe native tool output").replan(
        steps=(PlanStep("primary-step", "observe native tool output", action=tool_name),),
        reason="native tool output contract regression",
    )
    mission = runtime.create(
        "observe native tool output",
        "observe native tool output",
        plan,
        **signed_test_owner_kwargs(monkeypatch, tmp_path, request_id=f"native-result-{tool_name}-{parallel}"),
    )
    names = [tool_name, companion] if parallel else [tool_name]
    result = runtime.run_model_loop(
        mission.mission_id,
        _NativeToolModel(tool_name, parallel=parallel, arguments=arguments),
        tools=[{"name": name} for name in names],
        max_turns=2,
    )
    tool_result = next(item for item in result.progress["model_loop"]["tool_results"] if item["name"] == tool_name)
    return result, tool_result


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_latest_intel_list_output_is_successful_and_preserved(parallel, tmp_path, monkeypatch):
    latest = [{"id": "intel-1", "title": "Example indicator"}]

    mission, tool_result = _run_native_tool(
        "latest_intel", latest, parallel=parallel, tmp_path=tmp_path, monkeypatch=monkeypatch
    )

    assert tool_result["ok"] is True
    assert tool_result["result"]["success"] is True
    assert tool_result["result"]["result"] == latest
    action = next(item for item in mission.action_history if item["action_id"] == "action-0-latest_intel")
    assert action["status"] == "completed"
    assert action["observation"]["result"] == latest


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
@pytest.mark.parametrize(
    ("tool_name", "payload", "arguments"),
    [
        ("status", {"service": "CyberSentinel", "version": "test", "online": True}, {}),
        ("local_system_info", {"hostname": "test-host", "platform": "test-os"}, {}),
        ("watch", {"keyword": "critical", "watches": ["critical"]}, {"query": "critical"}),
    ],
    ids=["status-data", "local-info-data", "watch-data"],
)
def test_data_only_dictionary_is_successful_and_preserved(
    parallel, tool_name, payload, arguments, tmp_path, monkeypatch
):
    mission, tool_result = _run_native_tool(
        tool_name,
        payload,
        parallel=parallel,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        arguments=arguments,
    )

    assert tool_result["ok"] is True
    assert tool_result["result"]["success"] is True
    for key, value in payload.items():
        assert tool_result["result"][key] == value
    action = next(item for item in mission.action_history if item["action_id"] == f"action-0-{tool_name}")
    assert action["status"] == "completed"


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_explicit_failure_remains_failed(parallel, tmp_path, monkeypatch):
    payload = {"success": False, "error": "provider unavailable", "error_type": "provider_unavailable"}

    mission, tool_result = _run_native_tool(
        "search",
        payload,
        parallel=parallel,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        arguments={"query": "local:example"},
    )

    assert tool_result["ok"] is False
    assert tool_result["result"]["success"] is False
    assert tool_result["result"]["error"] == payload["error"]
    action = next(item for item in mission.action_history if item["action_id"] == "action-0-search")
    assert action["status"] == "failed"


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_error_only_provider_envelope_is_failed_and_visible(parallel, tmp_path, monkeypatch):
    payload = {
        "query": "example",
        "total_results": 0,
        "results": [],
        "error": "all search providers unavailable",
        "error_type": "provider_unavailable",
    }

    _mission, tool_result = _run_native_tool(
        "search",
        payload,
        parallel=parallel,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        arguments={"query": "local:example"},
    )

    assert tool_result["ok"] is False
    assert tool_result["result"]["success"] is False
    assert tool_result["result"]["error"] == payload["error"]
    assert tool_result["result"]["results"] == []


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
def test_search_results_with_provider_errors_are_visible_partial_success(
    parallel, tmp_path, monkeypatch
):
    payload = {
        "query": "example",
        "total_results": 1,
        "results": [{"id": "local-1", "title": "Local result"}],
        "error": "web provider timed out; local results are available",
        "error_type": "provider_errors",
    }

    _mission, tool_result = _run_native_tool(
        "search",
        payload,
        parallel=parallel,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        arguments={"query": "example"},
    )

    assert tool_result["ok"] is True
    assert tool_result["result"]["success"] is True
    assert tool_result["result"]["partial_success"] is True
    assert tool_result["result"]["results"] == payload["results"]
    assert tool_result["result"]["error"] == payload["error"]
    assert tool_result["result"]["error_type"] == "provider_errors"
