from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from agent.intelligence_layer.events import (
    EventBus,
    EventStore,
    HookDecision,
    HookPhase,
    HookRegistry,
    IntelligenceEventType as E,
)
from agent.intelligence_layer.models import DelegationScope
from runtime_authorization import make_test_snapshot
from security.mission_authorization import MissionAuthorizationError
from tools.registry import REGISTRY, ToolSpec, build_registry, execute, get_tool


class _Fence:
    def __init__(self):
        self.dispatch_checks = 0

    def assert_dispatch(self, **_kwargs):
        self.dispatch_checks += 1


def _snapshot():
    mission = SimpleNamespace(
        owner_identity_ref="owner:1",
        mission_id="mission:hooks",
        plan=SimpleNamespace(steps=(SimpleNamespace(action="status"), SimpleNamespace(action="latest_intel"))),
        max_iterations=2,
    )
    return make_test_snapshot(mission)


def _dispatch(*, snapshot, bus, hooks, execution_fence):
    return execute(
        "status",
        None,
        request_id="request:1",
        mission_authorization=snapshot,
        mission_id=snapshot.mission_id,
        target_identity=snapshot.target_identity,
        execution_fence=execution_fence,
        execution_id="action:1",
        event_bus=bus,
        hook_registry=hooks,
    )


def test_registry_executes_authorized_before_hook_and_persists_minimal_events(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "events.sqlite")
    bus = EventBus(store)
    hooks = HookRegistry(store)
    snapshot = _snapshot()
    fence = _Fence()
    invocations = []
    handler_calls = []
    monkeypatch.setitem(
        REGISTRY,
        "status",
        replace(get_tool("status"), handler=lambda _argument: handler_calls.append(True) or {"success": True, "result": "private tool output"}),
    )
    hooks.register(
        hook_id="deny-sensitive-status",
        owner_identity_ref=snapshot.owner_identity,
        mission_id=snapshot.mission_id,
        phase=HookPhase.BEFORE_TOOL,
        handler=lambda invocation: invocations.append(invocation) or HookDecision(True),
        authorization_check=lambda owner, mission, phase: (owner, mission, phase) == (snapshot.owner_identity, snapshot.mission_id, HookPhase.BEFORE_TOOL),
    )

    result = _dispatch(snapshot=snapshot, bus=bus, hooks=hooks, execution_fence=fence)

    assert result == {"success": True, "result": "private tool output"}
    assert handler_calls == [True]
    assert len(invocations) == 1
    assert invocations[0].data["tool_id"] == "status"
    assert len(invocations[0].data["argument_sha256"]) == 64
    events = store.list(owner_identity_ref=snapshot.owner_identity, mission_id=snapshot.mission_id)
    assert [event.event_type for event in events] == [E.HOOK_INVOKED, E.TASK_STARTED, E.TOOL_CALLED, E.TASK_COMPLETED]
    assert events[1].payload["phase"] == "pre-dispatch"
    assert events[2].payload["phase"] == "pre-dispatch"
    assert "private tool output" not in repr([event.payload for event in events])
    assert fence.dispatch_checks >= 3


def test_blocked_or_unauthorized_hook_prevents_tool_effect_and_call_event(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "events.sqlite")
    bus = EventBus(store)
    hooks = HookRegistry(store)
    snapshot = _snapshot()
    handler_calls = []
    monkeypatch.setitem(REGISTRY, "status", replace(get_tool("status"), handler=lambda _argument: handler_calls.append(True) or {"success": True}))
    hooks.register(
        hook_id="veto",
        owner_identity_ref=snapshot.owner_identity,
        mission_id=snapshot.mission_id,
        phase=HookPhase.BEFORE_TOOL,
        handler=lambda _invocation: HookDecision(False, "Owner policy veto"),
        authorization_check=lambda *_args: True,
    )

    with pytest.raises(PermissionError, match="blocked by current mission policy hook"):
        _dispatch(snapshot=snapshot, bus=bus, hooks=hooks, execution_fence=_Fence())

    assert handler_calls == []
    events = store.list(owner_identity_ref=snapshot.owner_identity, mission_id=snapshot.mission_id)
    assert [event.event_type for event in events] == [E.HOOK_BLOCKED]


def test_event_journal_failure_blocks_dispatch_before_handler(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "events.sqlite")
    bus = EventBus(store)
    snapshot = _snapshot()
    handler_calls = []
    monkeypatch.setitem(REGISTRY, "status", replace(get_tool("status"), handler=lambda _argument: handler_calls.append(True) or {"success": True}))

    def fail_publish(**_kwargs):
        raise RuntimeError("journal unavailable")

    monkeypatch.setattr(bus, "publish", fail_publish)
    with pytest.raises(RuntimeError, match="journal unavailable"):
        _dispatch(snapshot=snapshot, bus=bus, hooks=None, execution_fence=_Fence())
    assert handler_calls == []


def test_canonical_registry_revalidates_task_scope_before_handler(monkeypatch):
    snapshot = _snapshot()
    parent = DelegationScope.from_snapshot(snapshot)
    child = parent.narrow(
        target_identity=snapshot.target_identity,
        scope=("workspace",),
        allowed_tools=("status",),
        allowed_actions=("status",),
        workspace_root=None,
    )
    handler_calls = []
    monkeypatch.setitem(
        REGISTRY,
        "status",
        replace(get_tool("status"), handler=lambda _argument: handler_calls.append("status") or {"ok": True}),
    )

    result = execute(
        "status",
        None,
        request_id="request:1",
        mission_authorization=snapshot,
        mission_id=snapshot.mission_id,
        target_identity=snapshot.target_identity,
        execution_fence=_Fence(),
        execution_id="action:1",
        delegation_scope=child,
        scope_ref="workspace",
    )

    assert result == {"ok": True}
    assert handler_calls == ["status"]
    with pytest.raises(PermissionError, match="exceeds task delegation"):
        execute(
            "latest_intel",
            None,
            request_id="request:1",
            mission_authorization=snapshot,
            mission_id=snapshot.mission_id,
            target_identity=snapshot.target_identity,
            execution_fence=_Fence(),
            execution_id="action:2",
            delegation_scope=child,
            scope_ref="workspace",
        )
    with pytest.raises(MissionAuthorizationError, match="target identity outside authorization snapshot"):
        execute(
            "status",
            None,
            request_id="request:1",
            mission_authorization=snapshot,
            mission_id=snapshot.mission_id,
            target_identity="different-target",
            execution_fence=_Fence(),
            execution_id="action:3",
            delegation_scope=child,
            scope_ref="workspace",
        )
    assert handler_calls == ["status"]


@pytest.mark.parametrize(
    "spec",
    [
        ToolSpec(
            "unsafe_parallel_network",
            "test-only unsafe parallel declaration",
            "read",
            False,
            None,
            lambda _argument: {"ok": True},
            network_access="bounded",
            parallel_execution_safe=True,
        ),
        ToolSpec(
            "nonboolean_parallel_declaration",
            "test-only malformed parallel declaration",
            "read",
            False,
            None,
            lambda _argument: {"ok": True},
            parallel_execution_safe="yes",
        ),
    ],
)
def test_registry_rejects_invalid_parallel_safety_attestation(spec):
    with pytest.raises(ValueError, match="invalid registry metadata"):
        build_registry([spec])
