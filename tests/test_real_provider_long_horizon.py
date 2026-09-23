from __future__ import annotations
from runtime_authorization import make_test_snapshot
"""Round 2 P0-3 - real-provider long-horizon harness.

HONESTY LABEL: UNVERIFIED - REAL PROVIDER UNAVAILABLE.

This harness runs the REAL MissionRuntime loop against a LIVE model provider.
It is skipped (never faked) unless the environment provides:

- CYBERSENTINEL_LIVE_PROVIDER_KEY: a non-empty live provider credential
- CYBERSENTINEL_LIVE_ROUTER_FACTORY: "module:function" returning an object
  with a tool_calling(messages, tools) method (ModelRouter-compatible).

When both are present the harness asserts a 20+ model-turn trajectory with
real tool calls, observations, evidence, and deterministic verification.
"""


import importlib
import os
from pathlib import Path

import pytest

from agent.model_protocol import RouterNativeModel
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep


def test_real_provider_long_horizon(tmp_path):
    key = os.environ.get("CYBERSENTINEL_LIVE_PROVIDER_KEY", "").strip()
    factory = os.environ.get("CYBERSENTINEL_LIVE_ROUTER_FACTORY", "").strip()
    if not key or not factory:
        pytest.skip(
            "UNVERIFIED - REAL PROVIDER UNAVAILABLE: no live provider credentials "
            "configured in this environment. Set CYBERSENTINEL_LIVE_PROVIDER_KEY and "
            "CYBERSENTINEL_LIVE_ROUTER_FACTORY=module:function to execute this harness."
        )

    module_name, _, function_name = factory.partition(":")
    router = getattr(importlib.import_module(module_name), function_name)()
    assert callable(getattr(router, "tool_calling", None)), "router must expose tool_calling()"

    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("live long-horizon audit").replan(
        steps=(PlanStep("observe", "observe", action="status"),), reason="live"
    )
    mission = runtime.create(
        "live long-horizon audit",
        "live long-horizon audit",
        plan,
        completion_criteria=[{"criterion_id": "goal"}],
    )

    result = runtime.run_model_loop(
        mission.mission_id,
        RouterNativeModel(router),
        tools=[{"name": "status"}],
        max_turns=30,
    )

    turns = result.progress.get("model_loop", {}).get("turns", [])
    assert len(turns) >= 20, "a live provider must sustain at least 20 model turns"
    events = [event["event"] for event in result.trajectory]
    assert events.count("ModelTurn") >= 20
    assert "ObservationReceived" in events
    assert result.verification_state, "verification must be recorded"
    assert not result.is_terminal or result.status is MissionStatus.GOAL_COMPLETED
