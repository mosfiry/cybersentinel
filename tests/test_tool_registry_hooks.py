from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
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
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
from tools.registry import REGISTRY, ToolSpec, _delegated_resource_access_allowed, build_registry, execute, get_tool


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


def _network_snapshot():
    now = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner:1",
        mission_id="mission:delegated-network",
        target_identity="target:delegated-network",
        scope=("host:allowed.example", "host:other.example"),
        allowed_actions=("browser",),
        forbidden_actions=(),
        allowed_tools=("browser",),
        time_window={"timezone": "UTC"},
        max_duration=3600,
        rate_limits={"browser": 10},
        network_boundary={"allowed": ("allowed.example", "other.example")},
        data_boundary={"allowed": ("target:delegated-network",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": ""},
        policy_version="test-v1",
        owner_approval="owner-approved bounded network test",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )


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


def test_delegated_scope_allows_only_owner_workspace_sandbox_resources(tmp_path):
    now = datetime.now(timezone.utc)
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:1",
        mission_id="mission:workspace-skill",
        target_identity="target:workspace",
        scope=("workspace",),
        allowed_actions=("run_project_tests",),
        forbidden_actions=(),
        allowed_tools=("run_project_tests",),
        time_window={"timezone": "UTC"},
        max_duration=3600,
        rate_limits={"run_project_tests": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("target:workspace",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version="test-v1",
        owner_approval="owner-approved bounded workspace tool",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
    )
    parent = DelegationScope.from_snapshot(snapshot)
    child = parent.narrow(
        target_identity=snapshot.target_identity,
        scope=("workspace",),
        allowed_tools=("run_project_tests",),
        allowed_actions=("run_project_tests",),
        workspace_root=str(tmp_path),
    )
    workspace = SimpleNamespace(root=str(tmp_path))
    fenced_evidence = SimpleNamespace(require_execution_fence=True)
    spec = get_tool("run_project_tests")

    assert spec is not None
    assert _delegated_resource_access_allowed(spec, snapshot, child, workspace, fenced_evidence)
    assert not _delegated_resource_access_allowed(spec, snapshot, child, SimpleNamespace(root=str(tmp_path / "outside")), fenced_evidence)
    assert not _delegated_resource_access_allowed(spec, snapshot, child, workspace, SimpleNamespace(require_execution_fence=False))

    unsafe_host_process = SimpleNamespace(**{
        **spec.__dict__,
        "filesystem_access": "host_fs_via_process",
        "process_access": "workspace_process_unisolated",
    })
    assert not _delegated_resource_access_allowed(unsafe_host_process, snapshot, child, workspace, fenced_evidence)

    credentialed = SimpleNamespace(**{**spec.__dict__, "credential_access": "host_user_credentials_possible"})
    assert not _delegated_resource_access_allowed(credentialed, snapshot, child, workspace, fenced_evidence)
    assert not _delegated_resource_access_allowed(get_tool("status"), snapshot, child, workspace, fenced_evidence)


def test_delegated_network_tool_is_bound_to_each_child_granted_host():
    snapshot = _network_snapshot()
    parent = DelegationScope.from_snapshot(snapshot)
    child = parent.narrow(
        target_identity=snapshot.target_identity,
        scope=("host:allowed.example",),
        allowed_tools=("browser",),
        allowed_actions=("browser",),
        allowed_networks=("allowed.example",),
    )
    from tools.browser import _delegated_network_host_allowed

    browser_context = SimpleNamespace(delegation_scope=child)
    assert _delegated_network_host_allowed(browser_context, "https://allowed.example/page")
    assert not _delegated_network_host_allowed(browser_context, "https://other.example/redirect")
    forged = DelegationScope.from_dict({
        **child.to_dict(),
        "allowed_networks": ["outside-owner.example"],
    })
    assert not forged.is_within_owner_authorization(snapshot)
    browser = get_tool("browser")
    assert browser is not None
    fenced_evidence = SimpleNamespace(require_execution_fence=True)
    scope_context = {
        "program_id": "program:delegated-network",
        "target_id": snapshot.target_identity,
        "scope_snapshot_id": "scope:delegated-network",
        "url": "https://allowed.example/",
    }

    assert _delegated_resource_access_allowed(
        browser, snapshot, child, evidence_store=fenced_evidence,
        argument={"operation": "open", "url": "https://allowed.example/page"},
        scope_context=scope_context,
    )
    assert not _delegated_resource_access_allowed(
        browser, snapshot, child, evidence_store=fenced_evidence,
        argument={"operation": "open", "url": "https://other.example/page"},
        scope_context=scope_context,
    )
    assert not _delegated_resource_access_allowed(
        browser, snapshot, child, evidence_store=fenced_evidence,
        argument={"operation": "open", "url": "https://allowed.example/page"},
        scope_context={**scope_context, "redirect_chain": ["https://other.example/redirect"]},
    )

    no_network_child = parent.narrow(
        target_identity=snapshot.target_identity,
        scope=("host:allowed.example",),
        allowed_tools=("browser",),
        allowed_actions=("browser",),
        allowed_networks=(),
    )
    assert not _delegated_resource_access_allowed(
        browser, snapshot, no_network_child, evidence_store=fenced_evidence,
        argument={"operation": "open", "url": "https://allowed.example/page"},
        scope_context=scope_context,
    )
