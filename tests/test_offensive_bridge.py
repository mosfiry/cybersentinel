"""Offensive Capability Layer — live reachability and adversarial battery.

P0 of the Offensive Capability Activation mission. These tests PROVE the
offensive path is not dead code: a real owner-authenticated mission flows
through MissionRuntime → OffensiveActionBridge (typed proposal → scope
firewall → existing proof chain → ToolAdapter → tools.registry.execute →
handler) → evidence → OffensiveMind feedback.

Negative battery: every unauthorized / out-of-scope / tampered / cross-mission
/ cross-run / scope-expansion attempt is rejected BEFORE any execution
(execute spy and handler spy both stay empty).

If any layer of this path becomes isolated again, these tests fail.
"""

from __future__ import annotations

from dataclasses import replace as dataclass_replace
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_snapshot

import security.owner_policy as owner_policy
import security.scope_store as scope_store
from security.scope_store import init_scope_store, save_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.offensive_bridge import (
    LOCAL_PROCESS_INFO_ADAPTER,
    OffensiveActionBridge,
    OffensiveActionProposal,
    OffensiveActionRejected,
    ScopedHttpProbeAdapter,
)
from agent.offensive_mind import Engagement, OffensiveMind
from agent.planning import Plan, PlanStep
from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="local_process_info"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, tool="local_process_info", **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id=tool,
        plan_hash=mission.plan.fingerprint,
        target_kind="local",
        risk_class="read_only",
        hypothesis_id="h-1",
        required_evidence=("process listing",),
        source_step_id="s-01",
        rationale="observe local processes",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


def _program(in_scope, out_of_scope=(), methods=("GET", "HEAD")):
    return ProgramAuthorization(
        program_id="prog-1",
        platform="test-platform",
        scope_version="v1",
        retrieved_at="2026-09-26T00:00:00+00:00",
        in_scope_assets=tuple(in_scope),
        out_of_scope_assets=tuple(out_of_scope),
        allowed_methods=tuple(methods),
    )


def _web_asset(host):
    return {"host": host, "schemes": ["http", "https"]}


def _target(host, tid="t1"):
    return TargetIdentity(target_id=tid, program_id="prog-1", host=host)


def _scope_snapshot():
    auth = _program([_web_asset("target.example")])
    return make_snapshot("snap-1", auth, [_target("target.example")])


@pytest.fixture
def execute_spy(monkeypatch):
    real_execute = tools.registry.execute
    calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    return calls


@pytest.fixture
def saved_scope_snapshot(tmp_path, monkeypatch):
    """Build AND persist the typed ScopeSnapshot through the REAL owner store.

    The registry re-resolves scope_required tools against the scope snapshot
    store; the persisted snapshot must be the SAME object the bridge's
    ScopeGuard evaluates (one scope, two deterministic checks).
    """
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "bridge-owner")
    init_scope_store()
    snapshot = _scope_snapshot()
    return save_snapshot(snapshot, owner_token="bridge-owner")


@pytest.fixture
def counting_handler(monkeypatch):
    class Counter:
        def __init__(self):
            self.calls = 0

        def __call__(self, argument=None, **kwargs):
            self.calls += 1
            return {"ok": True, "operation": "scoped_http_probe", "url": argument, "status_code": 200, "note": "observation"}

    counter = Counter()
    spec = tools.registry.get_tool("scoped_http_probe")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "scoped_http_probe", dataclass_replace(spec, handler=counter))
    return counter


# ---------------------------------------------------------------------------
# LIVE REACHABILITY (positive): every layer must actually be wired
# ---------------------------------------------------------------------------


def test_live_local_reachability_full_chain(tmp_path, execute_spy):
    """Owner-authenticated mission → bridge → registry → REAL handler → evidence."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_process_info")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1")
    bridge = OffensiveActionBridge()
    record = bridge.run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["local_process_info"]
    result = record.result
    assert result.status == "SUCCESS"
    assert isinstance(result.normalized_output, dict)
    assert result.normalized_output["count"] >= 1
    # Evidence flows through the existing chain (no second evidence system).
    assert result.evidence["tool"] == "local_process_info"
    assert result.evidence["mission_id"] == mission.mission_id
    assert result.evidence["proof_fingerprint"] == record.proof_fingerprint


def test_live_network_reachability_scope_authorized(tmp_path, execute_spy, counting_handler, saved_scope_snapshot):
    """Network action: scope firewall allows, canonical url executes, evidence binds."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="scoped_http_probe")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(
        mission,
        tool="scoped_http_probe",
        target_kind="network",
        target_url="https://target.example/",
        target_id="t1",
        risk_class="network_read",
    )
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=saved_scope_snapshot)
    assert record.status == "EXECUTED", record.result.error_state
    assert counting_handler.calls == 1
    assert execute_spy == ["scoped_http_probe"]
    # The GUARD's canonical url is the executed argument (never the raw text).
    assert record.result.normalized_output["url"] == "https://target.example/"
    assert record.guard_decision["allowed"] is True
    assert record.result.evidence["tool"] == "scoped_http_probe"


def test_live_feedback_loop_feeds_offensive_mind(tmp_path):
    """Execution record → feedback event → OffensiveMind.adapt actually adapts."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_process_info")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, source_step_id="s-01")
    bridge = OffensiveActionBridge()
    record = bridge.run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    event = bridge.feedback_event(record)
    assert event["type"] == "STEP_RESULT"
    assert event["outcome"] == "COMPLETED"
    mind = OffensiveMind(Engagement(engagement_id="e1", authorized_scope=("local",), rules_of_engagement_accepted=True))
    campaign = mind.plan("inspect the exposed web surface", ("web-exposed-surface",))
    assert campaign.steps, "campaign must have steps to adapt"
    event["step_id"] = campaign.steps[0].step_id  # bind to the live campaign step
    adapted = mind.adapt(campaign, event)
    assert adapted.steps[0].status.value == "COMPLETED"
    assert adapted.version >= campaign.version


def test_live_dry_run_never_executes(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="local_process_info")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-1")
    record = OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER, dry_run=True)
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []


# ---------------------------------------------------------------------------
# NEGATIVE REACHABILITY: every rejection happens BEFORE execution
# ---------------------------------------------------------------------------


def test_network_action_without_scope_snapshot_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="scoped_http_probe")
    proposal = _proposal(mission, tool="scoped_http_probe", target_kind="network", target_url="https://target.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=None)
    assert execute_spy == []


def test_out_of_scope_host_is_rejected_before_execution(tmp_path, execute_spy, counting_handler, saved_scope_snapshot):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="scoped_http_probe")
    proposal = _proposal(mission, tool="scoped_http_probe", target_kind="network", target_url="https://other.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=saved_scope_snapshot)
    assert counting_handler.calls == 0
    assert execute_spy == []


def test_scope_expansion_via_target_id_smuggling_is_rejected(tmp_path, execute_spy, counting_handler, saved_scope_snapshot):
    """Claiming the in-scope target id while pointing at another host grants nothing."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="scoped_http_probe")
    proposal = _proposal(mission, tool="scoped_http_probe", target_kind="network", target_url="https://evil.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []


def test_cross_mission_proposal_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission_a = _mission(runtime)
    mission_b = _mission(runtime)
    proposal = _proposal(mission_b)  # proposal describes ANOTHER mission
    with pytest.raises(OffensiveActionRejected, match="mission"):
        OffensiveActionBridge().run(proposal, mission=mission_a, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="0" * 64)  # stale/tampered plan binding
    with pytest.raises(OffensiveActionRejected, match="plan hash"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_wrong_execution_run_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, execution_run_id="run-999")
    with pytest.raises(OffensiveActionRejected, match="execution run"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool_id="nmap")  # catalog-only tool: definition != execution
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_adapter_tool_mismatch_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission)  # local_process_info proposal ...
    with pytest.raises(OffensiveActionRejected, match="adapter"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter())  # ... behind the probe adapter
    assert execute_spy == []


def test_local_proposal_cannot_smuggle_network_target(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_kind="local", target_url="https://target.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="local proposals"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_malformed_proposals_fail_closed(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    base = _proposal(mission)
    bad_cases = [
        dataclass_replace(base, proposal_id=""),
        dataclass_replace(base, risk_class=""),
        dataclass_replace(base, target_kind="carrier_pigeon"),
        dataclass_replace(base, target_kind="network", target_url="", target_id="t1"),
        dataclass_replace(base, target_kind="network", target_url="https://target.example/", target_id=""),
    ]
    for bad in bad_cases:
        with pytest.raises(OffensiveActionRejected):
            OffensiveActionBridge().run(bad, mission=mission, adapter=LOCAL_PROCESS_INFO_ADAPTER)
    assert execute_spy == []


def test_tool_output_is_observation_not_authority(tmp_path, execute_spy, counting_handler, saved_scope_snapshot):
    """The probe's output stays untrusted data; it can never widen scope."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime, action="scoped_http_probe")
    mission.progress["model_run_id"] = "run-1"
    proposal = _proposal(mission, tool="scoped_http_probe", target_kind="network", target_url="https://target.example/", target_id="t1")
    bridge = OffensiveActionBridge()
    record = bridge.run(proposal, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=saved_scope_snapshot)
    assert record.status == "EXECUTED", record.result.error_state
    # A second action pointing at an endpoint the OBSERVED output mentions
    # is refused: observation is never authorization (INV-OFF-2/INV-OFF-5).
    smuggled = _proposal(
        mission,
        tool="scoped_http_probe",
        target_kind="network",
        target_url="https://mentioned-in-output.example/",
        target_id="t1",
        proposal_id="prop-2",
    )
    with pytest.raises(OffensiveActionRejected, match="scope"):
        bridge.run(smuggled, mission=mission, adapter=ScopedHttpProbeAdapter(), scope_snapshot=saved_scope_snapshot)
    assert counting_handler.calls == 1
