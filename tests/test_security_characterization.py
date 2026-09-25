from __future__ import annotations

"""CHARACTERIZATION TESTS - Commit 1 of the security hardening plan.

These tests DOCUMENT the current runtime behavior of the four security
findings from the PRE-IMPLEMENTATION SECURITY GATE report.  They are
security characterization / regression tests, NOT fixes:

- A-1  one successful tool observation satisfies the default
       ``mission-goal`` criterion and completes the mission
       (agent/agent_core.py ``_executor`` hard-codes
       ``criterion_id="mission-goal"`` in every success result;
       ``run_owner_mission`` defaults ``completion_criteria`` to the same
       id).
- A-2  a tool observation that does not carry ``criterion_id`` falls back
       to ``completion_criteria[0]`` and is recorded with ``passed=True``
       (agent/mission_runtime.py run_model_loop evidence writers).
- A-3  the observation interpreter (model-output-driven component) can
       mint mission evidence with ``passed=True`` by default, with no
       authority provenance, and that evidence alone completes the goal
       (agent/mission_runtime.py ``_interpret_observation``).
- C    the owner decision at ``MissionRuntime.provide_owner_decision``
       is an unsigned, untyped, replayable plain dict.
- D    client-supplied ``scope_context`` / ``completion_criteria`` flow
       unchanged from api/chat.py into ``run_owner_mission`` and become
       the mission's scope boundaries and completion authority
       (api/chat.py -> agent/agent_core.py ``run_owner_mission`` ->
       ``MissionRuntime.create_from_owner_instruction``).

Classification: none of these tests modify production behavior.  The fix
commits (Finding A/B/C/D hardening) are expected to INVERT these
expectations; each test lists the exact invariant that the fix must
enforce.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib

import pytest

from runtime_authorization import make_test_authorization_context, make_test_snapshot

from agent.agent_core import AgentCore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.model_protocol import ModelTurn, ToolCallProposal
from agent.observation_intelligence import ObservationInterpretationProposal
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot


def _plan(action="status"):
    return Plan.initial("objective").replan(
        steps=(PlanStep("s1", "objective", action=action),),
        reason="characterization",
    )


def _runtime(tmp_path, executor, interpreter=None, factory=make_test_snapshot):
    return MissionRuntime(
        MissionStore(Path(tmp_path) / "missions.sqlite3"),
        executor=executor,
        interpreter=interpreter,
        authorization_snapshot_factory=factory,
    )


def _mission(runtime, criteria, **kwargs):
    return runtime.create(
        "request",
        "objective",
        _plan(),
        completion_criteria=criteria,
        **kwargs,
    )


def _run_id(mission):
    return hashlib.sha256((mission.mission_id + mission.request_id).encode()).hexdigest()[:20]


def _proposal(mission, name="status", *, arguments=None, tool_call_id="call_001"):
    return ToolCallProposal.create(
        name,
        arguments,
        mission_id=mission.mission_id,
        run_id=_run_id(mission),
        turn_id=_run_id(mission) + ":turn:1",
        action_id="a1",
        tool_call_id=tool_call_id,
    )


class OneTurnModel:
    def __init__(self, proposals):
        self.proposals = tuple(proposals)
        self.done = False

    def complete(self, messages, tools, *, mission_id, run_id, turn_id, plan_version):
        if self.done:
            return ModelTurn(turn_id, content="done")
        self.done = True
        return ModelTurn(turn_id, tool_calls=self.proposals)


# ---------------------------------------------------------------------------
# Finding A-1: a single successful tool completes the mission
# ---------------------------------------------------------------------------


def test_a1_single_tool_success_completes_mission_with_default_criteria(tmp_path):
    """CURRENT BEHAVIOR: one successful tool observation reaches GOAL_COMPLETED.

    The executor replicates the exact success shape returned by
    agent/agent_core.py ``AgentCore._executor`` ({"success": True,
    "source": <action>, "criterion_id": "mission-goal", "result": ...,
    "execution_id": ...}) and the completion criteria are the exact
    defaults installed by ``AgentCore.run_owner_mission``.  The result:
    a single tool success is recorded as evidence for "mission-goal" and
    the mission completes on the next verification slice.

    Invariant that the fix must enforce: GOAL_COMPLETED requires a
    verifier-issued attestation bound to canonical execution evidence;
    a hard-coded criterion_id in a tool result is not verification.
    """
    from agent.agent_core import AgentCore  # noqa: F401  (source of the shape)

    def executor(mission, step, action_id):
        # Byte-for-byte the success shape of AgentCore._executor.
        return {
            "success": True,
            "source": step.action,
            "criterion_id": "mission-goal",
            "result": {"status": "ok"},
            "execution_id": action_id,
        }

    runtime = _runtime(tmp_path, executor)
    mission = _mission(
        runtime,
        [
            {
                "criterion_id": "mission-goal",
                "description": "Owner objective has a verified successful observation",
                "check": "tool observation",
                "required": True,
            }
        ],
    )
    mission = runtime.run_slice(mission.mission_id)
    assert mission.status is not MissionStatus.GOAL_COMPLETED
    assert mission.evidence and mission.evidence[0]["criterion_id"] == "mission-goal"
    assert mission.evidence[0]["passed"] is True

    for _ in range(5):
        if mission.status is MissionStatus.GOAL_COMPLETED:
            break
        mission = runtime.run_slice(mission.mission_id)
    assert mission.status is MissionStatus.GOAL_COMPLETED
    assert mission.verification_state["verified"] is True


# ---------------------------------------------------------------------------
# Finding A-2: criterion fallback to completion_criteria[0]
# ---------------------------------------------------------------------------


def test_a2_observation_without_criterion_falls_back_to_first_criterion(tmp_path, monkeypatch):
    """CURRENT BEHAVIOR: a tool observation that says nothing about any
    criterion is still recorded as passed evidence for
    ``completion_criteria[0]`` and completes the mission.

    Invariant that the fix must enforce: evidence can only be minted by
    the canonical execution path with explicit, verified criterion
    identity; fallback heuristics are not verification.
    """
    import tools.registry

    def fake_execute(name, argument=None, **kwargs):
        # Successful observation that carries NO criterion identity.
        return {"ok": True}

    monkeypatch.setattr(tools.registry, "execute", fake_execute)
    runtime = _runtime(tmp_path, lambda mission, step, action_id: {})
    mission = _mission(runtime, [{"criterion_id": "first-criterion"}], request_id="req-a2", authorization_context=make_test_authorization_context("req-a2", tmp_path).to_dict())

    mission = runtime.run_model_loop(
        mission.mission_id, OneTurnModel([_proposal(mission)]), tools=[], max_turns=2
    )

    assert mission.status is MissionStatus.GOAL_COMPLETED
    criteria_evidence = [item for item in mission.evidence if item["criterion_id"] == "first-criterion"]
    assert criteria_evidence and criteria_evidence[0]["passed"] is True


# ---------------------------------------------------------------------------
# Finding A-3: model interpreter mints passed=True evidence (W3)
# ---------------------------------------------------------------------------


class _ClaimingInterpreter:
    """Stands in for the model-output-driven observation interpreter."""

    def interpret(self, **kwargs):
        return ObservationInterpretationProposal(
            observation_id="obs-model-claim",
            summary="model claims the goal is met",
            new_evidence=(
                {
                    "criterion_id": "owner-strict-goal",
                    "result": {"claim": "model says done"},
                },
            ),
        )


def test_a3_model_interpreter_mints_passed_true_evidence(tmp_path):
    """CURRENT BEHAVIOR: interpreter (model-output-driven) proposals become
    mission evidence with ``passed=True`` by default and authority=None
    provenance, even though the tool observation itself never referenced
    the completion criterion.

    Invariant that the fix must enforce: model output is an annotation /
    claim only; EvidenceRecorder evidence must originate from the
    canonical execution path and be hash-bound to it.
    """
    def executor(mission, step, action_id):
        # Successful observation that does NOT reference the strict goal.
        return {"success": True, "source": step.action}

    runtime = _runtime(tmp_path, executor, interpreter=_ClaimingInterpreter())
    mission = _mission(runtime, [{"criterion_id": "owner-strict-goal"}])

    mission = runtime.run_slice(mission.mission_id)

    minted = [
        item
        for item in mission.evidence
        if item.get("criterion_id") == "owner-strict-goal"
    ]
    assert minted, "interpreter-minted evidence expected"
    assert minted[0]["passed"] is True
    assert minted[0].get("source") == "observation_interpreter"
    assert minted[0].get("provenance", {}).get("authority") is None

    # The model-minted evidence alone completes the mission.
    for _ in range(5):
        if mission.status is MissionStatus.GOAL_COMPLETED:
            break
        mission = runtime.run_slice(mission.mission_id)
    assert mission.status is MissionStatus.GOAL_COMPLETED


# ---------------------------------------------------------------------------
# Finding C: owner decision is unsigned / untyped / replayable
# ---------------------------------------------------------------------------


def test_c_owner_decision_is_unsigned_untyped_and_replayable(tmp_path):
    """CURRENT BEHAVIOR: ``MissionRuntime.provide_owner_decision`` stores a
    plain dict ({"owner_decision": "allow"}) as the mission authorization
    context.  It is not typed, not authenticated, not bound to a tool set
    or request identity, and an identical dict is accepted verbatim on a
    different mission (replay across missions).

    Invariant that the fix must enforce: owner approval must be typed,
    authenticated, anti-replay, bound to the exact requested capability
    set, and applied via snapshot amendment only.
    """
    runtime = _runtime(tmp_path, lambda mission, step, action_id: {"success": True})

    first = _mission(runtime, [{"criterion_id": "goal"}])
    first.transition(MissionStatus.OWNER_INPUT_REQUIRED, "characterization gate")
    runtime.store.save(first)

    first = runtime.provide_owner_decision(first.mission_id, allow=True)
    assert first.status is MissionStatus.READY
    assert first.authorization_context == {"owner_decision": "allow"}
    assert isinstance(first.authorization_context, dict)

    # The same unsigned decision is accepted verbatim on another mission.
    second = _mission(runtime, [{"criterion_id": "goal"}])
    second.transition(MissionStatus.OWNER_INPUT_REQUIRED, "characterization gate")
    runtime.store.save(second)
    second = runtime.provide_owner_decision(
        second.mission_id, allow=True, authorization_context=dict(first.authorization_context)
    )
    assert second.status is MissionStatus.READY
    assert second.authorization_context == first.authorization_context

    # Denial stays fail-closed (documented existing behavior).
    third = _mission(runtime, [{"criterion_id": "goal"}])
    third.transition(MissionStatus.OWNER_INPUT_REQUIRED, "characterization gate")
    runtime.store.save(third)
    third = runtime.provide_owner_decision(third.mission_id, allow=False)
    assert third.status is MissionStatus.AUTHORIZATION_BLOCKED


# ---------------------------------------------------------------------------
# Finding D: client-supplied scope/criteria become mission authority
# ---------------------------------------------------------------------------


def _owner_context(tmp_path, monkeypatch, request_id="req-d"):
    import security.owner_policy as owner_policy
    from security.authorization_context import AuthorizationContext

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    policy = owner_policy.capture_policy_snapshot(request_id, evidence)
    return AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=policy)


def _client_scope_factory(mission):
    """Snapshot factory mirroring AgentCore.run_owner_mission's factory:
    client ``scope_context`` values become snapshot boundaries."""
    scope = dict(mission.scope_snapshot or {})
    target = str(scope.get("target_id", "test-target"))
    now = datetime.now(timezone.utc)
    actions = tuple(dict.fromkeys(tuple(step.action for step in mission.plan.steps if step.action != "__planning_failure__") + ("status",)))
    return MissionAuthorizationSnapshot.create(
        owner_identity=str(mission.owner_identity_ref or "test-owner"),
        mission_id=mission.mission_id,
        target_identity=target,
        scope=("workspace",),
        allowed_actions=actions,
        forbidden_actions=(),
        allowed_tools=actions,
        time_window={"timezone": "UTC"},
        max_duration=300,
        rate_limits={action: 10 for action in actions},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": (target,)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(scope.get("workspace_root", "/workspace/test"))},
        policy_version="test-policy-v1",
        owner_approval="test-owner-approval",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )


def _client_mission(tmp_path, monkeypatch, runtime, scope, criteria):
    from security.authorization_context import AuthorizationContext  # noqa: F401

    context = _owner_context(tmp_path, monkeypatch)
    return runtime.create_from_owner_instruction(
        "client supplied objective",
        _plan(),
        authorization_context=context,
        scope_snapshot=scope,
        completion_criteria=criteria,
    )


def test_d_client_scope_and_criteria_become_mission_authority(tmp_path, monkeypatch):
    """CURRENT BEHAVIOR: the runtime seam fed by api/chat.py ->
    AgentCore.run_owner_mission (``create_from_owner_instruction``)
    persists client-supplied ``scope_snapshot`` and ``completion_criteria``
    verbatim, and client completion criteria act as the completion
    authority: a tool observation satisfying the client criterion
    completes the mission with no owner-policy linkage to the criteria.

    Invariant that the fix must enforce: completion criteria and scope
    boundaries must originate from Owner Policy / Owner Policy Snapshot or
    be rejected; API-client payloads carry no authority.
    """

    def executor(mission, step, action_id):
        return {
            "success": True,
            "source": step.action,
            "criterion_id": "client-criterion",
            "target": "client-target",
        }

    runtime = _runtime(tmp_path, executor, factory=_client_scope_factory)
    client_scope = {"target_id": "client-target", "allowed_targets": ["client-target"]}
    client_criteria = [{"criterion_id": "client-criterion", "required": True}]
    mission = _client_mission(tmp_path, monkeypatch, runtime, client_scope, client_criteria)

    assert mission.scope_snapshot == client_scope
    assert mission.completion_criteria == client_criteria
    assert mission.owner_instruction == "client supplied objective"

    mission = runtime.run_slice(mission.mission_id)
    for _ in range(5):
        if mission.status is MissionStatus.GOAL_COMPLETED:
            break
        mission = runtime.run_slice(mission.mission_id)
    assert mission.status is MissionStatus.GOAL_COMPLETED


def test_d_client_allowed_targets_govern_scope_boundary(tmp_path, monkeypatch):
    """CURRENT BEHAVIOR: the client-supplied ``allowed_targets`` list is the
    enforced scope boundary at observation time: an observation targeting
    anything outside the client list blocks the mission.

    Invariant that the fix must enforce: scope boundaries must derive
    from Owner authority, not from the API payload.
    """

    def executor(mission, step, action_id):
        return {
            "success": True,
            "source": step.action,
            "criterion_id": "client-criterion",
            "target": "outside-target",
        }

    runtime = _runtime(tmp_path, executor, factory=_client_scope_factory)
    client_scope = {"target_id": "client-target", "allowed_targets": ["client-target"]}
    mission = _client_mission(tmp_path, monkeypatch, runtime, client_scope, [{"criterion_id": "client-criterion"}])

    mission = runtime.run_slice(mission.mission_id)
    assert mission.status is MissionStatus.SCOPE_BLOCKED
    assert "scope" in mission.error


def test_d_agentcore_snapshot_factory_mirrors_client_scope_context(tmp_path, monkeypatch):
    """CURRENT BEHAVIOR: ``AgentCore.run_owner_mission`` builds the mission
    authorization snapshot directly from the client ``scope_context``:
    workspace root, target identity, scope tuple, network and credential
    boundaries all mirror the client payload, and the client
    ``completion_criteria`` are installed unchanged.  (The tool allowlist
    itself comes from the model-planned steps - the Finding B overlap.)

    Invariant that the fix must enforce: the capability budget must
    originate from Owner Policy; client input may narrow it at most.
    """
    plan = _plan()
    core = AgentCore(router=object(), store=MissionStore(Path(tmp_path) / "missions-core.sqlite3"))
    context = _owner_context(tmp_path, monkeypatch)
    core._auth = lambda instruction, owner_token, request_id, owner_session_id, owner_challenge: (context, "policy-context")
    core._plan = lambda objective, observation=None, **kwargs: plan

    client_scope = {
        "workspace_root": "/client/chosen/root",
        "target_id": "client-target",
        "scope": ["workspace"],
        "allowed_networks": ["client.example"],
        "allowed_credentials": [],
    }
    client_criteria = [{"criterion_id": "client-criterion", "required": True}]

    mission = core.run_owner_mission(
        "check the workspace",
        owner_token="stubbed-auth",
        scope_context=client_scope,
        completion_criteria=client_criteria,
        run=False,
    )

    snapshot = mission.authorization_snapshot
    assert snapshot["workspace_boundary"]["root"] == "/client/chosen/root"
    assert snapshot["target_identity"] == "client-target"
    assert tuple(snapshot["scope"]) == ("workspace",)
    assert set(snapshot["network_boundary"]["allowed"]) == {"client.example"}
    assert snapshot["credential_boundary"]["allowed"] in ([], ())
    assert not list(snapshot["credential_boundary"]["allowed"])
    assert tuple(snapshot["allowed_tools"]) == ("status",)
    assert mission.completion_criteria == client_criteria
    assert mission.scope_snapshot == client_scope
    assert snapshot["owner_approval"] == context.owner_evidence.proof_fingerprint
