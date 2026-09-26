"""B3-C5-H: final hardening — registry-level execution_run_id wiring.

Defense-in-depth closure found by the C5 final source audit: the runtime
serial/parallel model-loop call sites and the AgentCore slice executor called
tools.registry.execute WITHOUT execution_run_id, so the registry's own
cross-run proof check (RUN_MISMATCH) was silently skipped and run binding
relied solely on ExecutionAuthorizationProof.validate_against_mission in the
runtime. This battery proves the wiring is now explicit at every call site
and keeps failing closed:

- the serial and parallel model loops pass the LIVE run id to the registry;
- the AgentCore slice executor passes the live execution run id;
- a proof replayed to the registry under a rotated run dies with
  RUN_MISMATCH and no tool handler runs;
- the registered-only Owner budget reconstruction stays pure narrowing
  (snapshot allowlist intersect KNOWN_TOOLS; malformed snapshots fail
  closed; empty intersection never grants);
- legacy per-step canonical conversion keeps failing closed for
  out-of-budget, unregistered, and authority-shaped steps, and repeated
  same-tool steps keep deriving distinct canonical identities;
- a stale in-flight checkpoint requires recovery instead of executing.

Every rejection case asserts that NO TOOL HANDLER EXECUTED.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import security.owner_policy as owner_policy
import tools.registry
from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from security.execution_plan_runtime import (
    legacy_step_execution_plan,
    registered_owner_budget_from_snapshot,
)
from security.execution_proof import RejectionCode
from security.owner_budget import OwnerAuthorizedToolBudget
from tools.registry import KNOWN_TOOLS
from tools.registry import execute as registry_execute


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, actions=("status",), **kwargs):
    steps = tuple(PlanStep(f"s{index + 1}", "objective", action=action) for index, action in enumerate(actions))
    plan = Plan.initial("objective").replan(steps=steps, reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}], **kwargs)


def _snapshot(mission):
    from security.mission_authorization import MissionAuthorizationSnapshot

    return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))


class OneTurnModel:
    def __init__(self, proposals):
        self.proposals = tuple(proposals)
        self.done = False

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        if self.done:
            return ModelTurn(turn_id, content="done")
        self.done = True
        return ModelTurn(turn_id, tool_calls=self.proposals)


class CountingStatus:
    def __init__(self):
        self.calls = 0

    def handler(self, argument=None, **kwargs):
        self.calls += 1
        return {"ok": True, "criterion_id": "goal", "source": "status"}


@pytest.fixture
def counting_status(monkeypatch):
    from dataclasses import replace as dataclass_replace

    counter = CountingStatus()
    spec = tools.registry.get_tool("status")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "status", dataclass_replace(spec, handler=counter.handler))
    return counter


def _wiring_mission(tmp_path, request_id, actions=("status",)):
    runtime = _runtime(tmp_path)
    mission = _mission(
        runtime,
        actions=actions,
        request_id=request_id,
        authorization_context=make_test_authorization_context(request_id, tmp_path).to_dict(),
    )
    return runtime, mission


def test_serial_model_loop_passes_live_execution_run_id_to_registry(tmp_path, monkeypatch):
    captured = []

    def fake_execute(name, argument=None, **kwargs):
        captured.append({"name": name, "execution_run_id": kwargs.get("execution_run_id")})
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime, mission = _wiring_mission(tmp_path, "req-hw-serial")
    proposal = ToolCallProposal.create("status", None, mission_id=mission.mission_id, run_id="run-1", turn_id="run-1:turn:1", action_id="a1", tool_call_id="call_001")
    runtime.run_model_loop(mission.mission_id, OneTurnModel([proposal]), tools=[], run_id="run-1", max_turns=2)
    assert captured, "the serial loop must reach the registry boundary"
    assert all(item["name"] == "status" for item in captured)
    assert all(item["execution_run_id"] == "run-1" for item in captured), "the registry must receive the LIVE run id (defense-in-depth wiring)"


def test_parallel_model_loop_passes_live_execution_run_id_to_registry(tmp_path, monkeypatch):
    captured = []

    def fake_execute(name, argument=None, **kwargs):
        captured.append({"name": name, "execution_run_id": kwargs.get("execution_run_id")})
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime, mission = _wiring_mission(tmp_path, "req-hw-parallel", actions=("status", "search"))
    proposals = (
        ToolCallProposal.create("status", None, mission_id=mission.mission_id, run_id="run-p", turn_id="run-p:turn:1", action_id="a1", tool_call_id="call_p1"),
        ToolCallProposal.create("search", {"query": "probe"}, mission_id=mission.mission_id, run_id="run-p", turn_id="run-p:turn:1", action_id="a2", tool_call_id="call_p2"),
    )
    runtime.run_model_loop(mission.mission_id, OneTurnModel(proposals), tools=[], run_id="run-p", max_turns=2)
    assert {item["name"] for item in captured} == {"status", "search"}, "both parallel proposals must reach the registry boundary"
    assert all(item["execution_run_id"] == "run-p" for item in captured), "the parallel fold must pass the LIVE run id for every executed proposal"


def test_replayed_proof_rejected_at_registry_under_rotated_run_without_handler(tmp_path, monkeypatch, counting_status):
    proof_box = {}

    def fake_execute(name, argument=None, **kwargs):
        proof_box["proof"] = kwargs.get("execution_proof")
        return {"ok": True, "criterion_id": "goal", "source": name}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime, mission = _wiring_mission(tmp_path, "req-hw-replay")
    proposal = ToolCallProposal.create("status", None, mission_id=mission.mission_id, run_id="run-1", turn_id="run-1:turn:1", action_id="a1", tool_call_id="call_001")
    result = runtime.run_model_loop(mission.mission_id, OneTurnModel([proposal]), tools=[], run_id="run-1", max_turns=2)
    proof = proof_box["proof"]
    assert proof is not None and proof.run_id == "run-1"
    # Replay the captured proof under a rotated run: the registry boundary
    # itself must reject it (RUN_MISMATCH) with no tool handler executed.
    with pytest.raises(PermissionError, match=RejectionCode.RUN_MISMATCH.value):
        registry_execute(
            "status",
            None,
            mission_id=result.mission_id,
            request_id=result.request_id,
            mission_authorization=_snapshot(result),
            execution_proof=proof,
            execution_class="MISSION_BOUND",
            execution_run_id="run-2",
        )
    assert counting_status.calls == 0


@pytest.fixture
def mission_env(tmp_path, monkeypatch):
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "valid-owner")
    return tmp_path


class MissionProvider:
    name = "mission-test"
    model = "mission-test-1"

    def __init__(self, responses):
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.responses = list(responses)
        self.calls = 0

    def tool_calling(self, messages, tools, **kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, messages, **kwargs):
        self.calls += 1
        return {"content": "final"}


def test_agent_core_slice_executor_passes_live_execution_run_id_to_registry(mission_env, monkeypatch):
    import agent.agent_core as agent_core_module

    captured = {}

    def fake_execute(name, argument=None, **kwargs):
        captured["name"] = name
        captured["execution_run_id"] = kwargs.get("execution_run_id")
        return {"ok": True, "criterion_id": "mission-goal", "source": name}

    monkeypatch.setattr(agent_core_module, "execute_tool", fake_execute)
    provider = MissionProvider([ProviderResponse(tool_calls=[ToolCall("status", {}, "c1")])])
    core = AgentCore(ModelRouter([provider]), store=MissionStore(Path(mission_env) / "missions.sqlite3"))
    result = core.run_owner_mission("Investigate system status", owner_token="valid-owner", run=True)
    assert captured.get("name") == "status", "the slice executor must reach the registry boundary"
    live_run = str(result.progress.get("execution_run_id") or "")
    assert live_run, "run_to_completion must stamp a live execution run id"
    assert captured["execution_run_id"] == live_run, "the AgentCore slice executor must pass the live execution run id to the registry"


def test_registered_owner_budget_from_snapshot_narrows_to_registered_tools(tmp_path):
    runtime = _runtime(tmp_path)
    # "write" is not a registered tool: a compatibility-era snapshot naming
    # it must be narrowed to the registered subset, never widen or fail open.
    mission = _mission(runtime, actions=("status", "write"))
    budget = registered_owner_budget_from_snapshot(mission)
    assert "write" not in budget.tools
    assert budget.tools <= KNOWN_TOOLS
    assert "status" in budget.tools
    assert budget.source == "mission_snapshot+registered"


def test_registered_owner_budget_from_snapshot_malformed_fails_closed(tmp_path):
    from security.mission_authorization import MissionAuthorizationError

    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.authorization_snapshot = {"garbage": True}
    with pytest.raises((MissionAuthorizationError, PermissionError, ValueError, TypeError, KeyError)):
        registered_owner_budget_from_snapshot(mission)


def test_empty_registered_budget_fails_step_conversion_closed():
    # Empty intersection is an empty budget, never a fallback grant: even a
    # registered in-snapshot step cannot convert to a canonical plan.
    budget = OwnerAuthorizedToolBudget(frozenset())
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="status"),), reason="test")
    assert legacy_step_execution_plan(budget, plan, plan.steps[0]) is None


def test_legacy_step_conversion_rejects_out_of_budget_registered_tool():
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="search"),), reason="test")
    assert legacy_step_execution_plan(budget, plan, plan.steps[0]) is None


def test_legacy_step_conversion_rejects_unregistered_tool():
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="build"),), reason="test")
    assert legacy_step_execution_plan(budget, plan, plan.steps[0]) is None


def test_legacy_step_conversion_rejects_authority_shaped_arguments():
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    step = PlanStep("s1", "objective", action="status", retry_policy={"arguments": {"owner_budget": ["watch"]}})
    plan = Plan.initial("objective").replan(steps=(step,), reason="test")
    assert legacy_step_execution_plan(budget, plan, step) is None


def test_repeated_same_tool_steps_derive_distinct_canonical_identities():
    budget = OwnerAuthorizedToolBudget(frozenset({"status"}))
    first = PlanStep("s1", "objective", action="status")
    second = PlanStep("s2", "objective", action="status")
    plan = Plan.initial("objective").replan(steps=(first, second), reason="test")
    plan_one = legacy_step_execution_plan(budget, plan, first)
    plan_two = legacy_step_execution_plan(budget, plan, second)
    assert plan_one is not None and plan_two is not None
    assert plan_one.plan_fingerprint != plan_two.plan_fingerprint


def test_stale_in_flight_checkpoint_requires_recovery_without_execution(tmp_path):
    class RecordingExecutor:
        def __init__(self):
            self.calls = []

        def __call__(self, mission, step, action_id):
            self.calls.append((step.step_id, step.action, action_id))
            return {"success": True, "criterion_id": "goal", "source": step.action}

    executor = RecordingExecutor()
    runtime = MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=executor, authorization_snapshot_factory=make_test_snapshot)
    mission = _mission(runtime, actions=("status",))
    runtime.run_slice(mission.mission_id)
    assert [call[1] for call in executor.calls] == ["status"]
    # A stale in-flight checkpoint (crash between checkpoint and completion)
    # must force RECOVERY_REQUIRED; the executor must not run again.
    stale = runtime._load(mission.mission_id)
    stale.checkpoint = {"step_id": "s1", "action_id": "s1", "status": "in_flight", "plan_version": stale.plan.version}
    runtime.store.save(stale)
    result = runtime.run_to_completion(mission.mission_id, max_slices=4)
    assert result.status is MissionStatus.RECOVERY_REQUIRED
    assert [call[1] for call in executor.calls] == ["status"], "no handler may run for a stale in-flight checkpoint"
