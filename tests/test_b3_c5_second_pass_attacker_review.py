"""B3-C5 second-pass attacker review battery (deep B3-scope security review).

Source of this battery: the post-completion second-pass attacker review of
the B3 four-layer intent + canonical execution boundary (execution paths,
registry boundary, authorization/proof, recovery, stale state).

REVIEW FINDING (fixed and proven here): the tool registry did not require
the typed AuthorizationDecision for OWNER_DIRECT-class executions. The
decision-binding checks in tools/registry.execute only ran when a decision
was supplied, and the decision was only mandatory for owner_only /
scope_required tools, so a captured owner-direct ExecutionAuthorizationProof
for a non-sensitive tool could be replayed at the registry boundary with NO
AuthorizationDecision at all. That contradicts the documented OWNER_DIRECT
contract ("the typed AuthorizationDecision that authorized the execution ...
are mandatory"). The registry now fails closed: an OWNER_DIRECT execution
without its typed decision is rejected with PROOF_INCOMPLETE before any
handler runs. This is pure tightening: no authority widening, and the
single-RUN (not single-USE) TTL replay semantics remain the documented
architecture decision (Case 15 in test_execution_proof_boundary.py).

Every rejection case asserts that NO TOOL HANDLER EXECUTED.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.execution_boundary import OwnerDirectBoundary
from security.execution_proof import (
    ExecutionAuthorizationProof,
    ExecutionClass,
    RejectionCode,
)
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import ToolSpec, execute as registry_execute


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime, action="status"):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action=action),), reason="test")
    return runtime.create("request", "objective", plan, completion_criteria=[{"criterion_id": "goal"}])


def _snapshot(mission):
    return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))


def _mission_proof(mission, *, run_id="run-1", tool="status", argument=None, **overrides):
    kwargs = dict(
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool=tool,
        argument=argument,
        snapshot=_snapshot(mission),
        tool_call_id="call_m1",
        run_id=run_id,
        plan_hash=mission.plan.fingerprint,
        scope=mission.scope_snapshot,
        mission_status=mission.status.value,
        lifecycle_revision=len(mission.transitions))
    )
    kwargs.update(overrides)
    return ExecutionAuthorizationProof.derive(**kwargs)


def _owner_decision(tmp_path, monkeypatch, *, tool="status", argument=None, request_id="req-owner"):
    import security.owner_policy as owner_policy

    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", request_id, "proof")
    context = AuthorizationContext(request_id=request_id, owner_evidence=evidence, policy_snapshot=owner_policy.capture_policy_snapshot(request_id, evidence))
    return authorize_tool([tool, argument], context=context)


class CountingStatus:
    def __init__(self):
        self.calls = 0

    def handler(self, argument=None, **kwargs):
        self.calls += 1
        return {"ok": True, "source": "status", "seen": argument}


@pytest.fixture
def counting_status(monkeypatch):
    counter = CountingStatus()
    monkeypatch.setitem(tools.registry.REGISTRY, "status", ToolSpec("status", "counting status test tool", "read", False, None, counter.handler))
    return counter


# ---------------------------------------------------------------------------
# REVIEW FINDING: OWNER_DIRECT execution without its typed decision
# ----------------------------------------------------------------------------
