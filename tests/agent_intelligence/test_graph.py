from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3

import pytest

from security.mission_authorization import MissionAuthorizationSnapshot
from agent.intelligence_layer import (
    AgentGraphPolicy,
    AgentLifecycle,
    AgentRecord,
    DelegationDenied,
    DelegationScope,
    InvalidTransition,
    TaskGraph,
    TaskGraphConflict,
    TaskGraphError,
    TaskGraphIntegrityError,
    TaskGraphStore,
    TaskLifecycle,
    TaskRecord,
)


def authorization(*, expires_delta: int = 3600, allowed_tools=("status", "search", "evidence"), allowed_actions=("read", "research", "validate"), scope=("host:example.test",), workspace_root=""):
    created = datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity="owner-1",
        mission_id="mission-1",
        target_identity="host:example.test",
        scope=scope,
        allowed_actions=allowed_actions,
        forbidden_actions=("delete", "credential_export"),
        allowed_tools=allowed_tools,
        time_window={},
        max_duration=max(1, expires_delta),
        rate_limits={"tools": 20},
        network_boundary={"allowed": []},
        data_boundary={"allowed": []},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": workspace_root} if workspace_root else {},
        policy_version="test-policy-v1",
        owner_approval="owner-approved-test-fixture",
        created_at=created.isoformat(),
        expires_at=(created + timedelta(seconds=expires_delta)).isoformat(),
    )


def setup_graph(tmp_path, *, policy=None, snapshot=None):
    snapshot = snapshot or authorization()
    graph = TaskGraph.create(snapshot, policy=policy)
    root_scope = graph.root_scope(snapshot)
    root = AgentRecord.create(
        mission_id=graph.mission_id,
        owner_identity_ref=graph.owner_identity_ref,
        role="coordinator",
        capabilities=("plan", "delegate"),
        permission_scope=root_scope,
        agent_id="agent-root",
    )
    graph.add_agent(root)
    graph.activate_agent(root.agent_id)
    child_scope = root_scope.narrow(
        target_identity=graph.target_identity,
        scope=("host:example.test",),
        allowed_tools=("status",),
        allowed_actions=("read",),
    )
    child = AgentRecord.create(
        mission_id=graph.mission_id,
        owner_identity_ref=graph.owner_identity_ref,
        role="analyst",
        capabilities=("inspect",),
        permission_scope=child_scope,
        parent_agent_id=root.agent_id,
        agent_id="agent-child",
    )
    graph.add_agent(child)
    graph.activate_agent(child.agent_id)
    return snapshot, graph


def test_lifecycle_transitions_are_deterministic_and_terminal_states_cannot_restart():
    auth = authorization()
    root_scope = DelegationScope.from_snapshot(auth)
    agent = AgentRecord.create(mission_id=auth.mission_id, owner_identity_ref=auth.owner_identity, role="worker", capabilities=(), permission_scope=root_scope, agent_id="a")
    agent.transition(AgentLifecycle.READY)
    agent.transition(AgentLifecycle.RUNNING)
    agent.transition(AgentLifecycle.COMPLETED)
    with pytest.raises(InvalidTransition):
        agent.transition(AgentLifecycle.READY)
    task = TaskRecord.create(mission_id=auth.mission_id, assigned_agent_id="a", objective="review", task_id="t")
    task.transition(TaskLifecycle.READY)
    task.transition(TaskLifecycle.RUNNING)
    task.transition(TaskLifecycle.COMPLETED)
    with pytest.raises(InvalidTransition):
        task.transition(TaskLifecycle.RUNNING)


def test_legacy_task_record_without_memory_refs_remains_loadable():
    task = TaskRecord.create(mission_id="mission-1", assigned_agent_id="agent-1", objective="legacy task", task_id="legacy-task")
    payload = task.to_dict()
    payload.pop("memory_refs")

    restored = TaskRecord.from_dict(payload)

    assert restored.memory_refs == ()


def test_root_scope_canonicalizes_redundant_owner_grants():
    snapshot = authorization(
        allowed_tools=("status", "status", "search"),
        allowed_actions=("read", "read"),
        scope=("host:example.test", "host:example.test"),
    )
    root_scope = DelegationScope.from_snapshot(snapshot)
    assert root_scope.allowed_tools == ("status", "search")
    assert root_scope.allowed_actions == ("read",)
    assert root_scope.scope == ("host:example.test",)


def test_child_scope_is_explicitly_narrowed_and_bound_to_parent():
    snapshot = authorization(workspace_root="/tmp/cs-workspace")
    parent = DelegationScope.from_snapshot(snapshot)
    child = parent.narrow(
        target_identity=snapshot.target_identity,
        scope=("host:example.test",),
        allowed_tools=("status",),
        allowed_actions=("read",),
        workspace_root="/tmp/cs-workspace/reports",
    )
    assert child.is_subset_of(parent)
    assert child.parent_grant_hash == parent.fingerprint
    assert child.permits(tool="status", action="read", scope_ref="host:example.test", target_identity=snapshot.target_identity)
    assert not child.permits(tool="search", action="read", scope_ref="host:example.test", target_identity=snapshot.target_identity)
    assert not child.permits(tool="status", action="read", scope_ref="host:example.test", target_identity=snapshot.target_identity, network="internet")
    assert not child.permits(tool="status", action="read", scope_ref="host:example.test", target_identity=snapshot.target_identity, workspace_path="/tmp/cs-workspace/private/file.txt")


@pytest.mark.parametrize("overrides", [
    {"target_identity": "host:other.test"},
    {"allowed_tools": ("search", "red_team_assess")},
    {"allowed_actions": ("read", "delete")},
    {"scope": ("host:other.test",)},
    {"workspace_root": "/tmp/outside"},
])
def test_scope_expansion_is_rejected(overrides):
    snapshot = authorization(workspace_root="/tmp/cs-workspace")
    parent = DelegationScope.from_snapshot(snapshot)
    request = dict(
        target_identity=snapshot.target_identity,
        scope=("host:example.test",),
        allowed_tools=("status",),
        allowed_actions=("read",),
        workspace_root="/tmp/cs-workspace/reports",
    )
    request.update(overrides)
    with pytest.raises(DelegationDenied):
        parent.narrow(**request)


@pytest.mark.parametrize(("parent_overrides", "child_override"), [
    ({"scope": ()}, {"scope": ("host:example.test",)}),
    ({"allowed_tools": ()}, {"allowed_tools": ("status",)}),
    ({"allowed_actions": ()}, {"allowed_actions": ("read",)}),
    ({}, {"allowed_networks": ("internet",)}),
    ({}, {"allowed_credentials": ("credential-store",)}),
])
def test_empty_parent_grant_cannot_be_widened(parent_overrides, child_override):
    snapshot = authorization(**parent_overrides)
    parent = DelegationScope.from_snapshot(snapshot)
    request = {
        "target_identity": parent.target_identity,
        "scope": ("host:example.test",),
        "allowed_tools": ("status",),
        "allowed_actions": ("read",),
    }
    request.update(child_override)

    with pytest.raises(DelegationDenied):
        parent.narrow(**request)

    forged_child = DelegationScope(
        owner_identity_ref=parent.owner_identity_ref,
        mission_id=parent.mission_id,
        target_identity=parent.target_identity,
        root_authorization_hash=parent.root_authorization_hash,
        parent_grant_hash=parent.fingerprint,
        scope=tuple(request["scope"]),
        allowed_tools=tuple(request["allowed_tools"]),
        allowed_actions=tuple(request["allowed_actions"]),
        allowed_networks=tuple(request.get("allowed_networks", ())),
        allowed_credentials=tuple(request.get("allowed_credentials", ())),
    )
    assert not forged_child.is_subset_of(parent)


def test_delegation_requires_explicit_tool_action_and_scope():
    parent = DelegationScope.from_snapshot(authorization())
    with pytest.raises(ValueError):
        parent.narrow(target_identity=parent.target_identity, scope=(), allowed_tools=("status",), allowed_actions=("read",))
    with pytest.raises(ValueError):
        parent.narrow(target_identity=parent.target_identity, scope=("host:example.test",), allowed_tools=(), allowed_actions=("read",))


def test_graph_rejects_owner_reference_that_differs_from_authorized_owner():
    with pytest.raises(DelegationDenied, match="owner identity reference"):
        TaskGraph.create(authorization(), owner_identity_ref="another-owner")


def test_dependency_graph_promotes_only_ready_tasks_and_respects_concurrency(tmp_path):
    snapshot, graph = setup_graph(tmp_path, policy=AgentGraphPolicy(max_parallel_tasks=1))
    graph.add_tasks((
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="first", task_id="t1"),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="second", task_id="t2", dependencies=("t1",)),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="independent", task_id="t3"),
    ))
    assert graph.refresh_ready_tasks() == ("t1", "t3")
    assert graph.ready_task_ids() == ("t1",)
    graph.claim_task("t1", snapshot)
    assert graph.ready_task_ids() == ()
    graph.complete_task("t1", {"summary": "done"}, evidence_refs=("evidence-1",))
    assert graph.tasks["t1"].result_validation_state == "PENDING_VALIDATION"
    assert graph.tasks["t2"].lifecycle is TaskLifecycle.READY


def test_unverified_task_result_is_never_promoted_to_validated_evidence(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="work", task_id="task"),))
    graph.refresh_ready_tasks()
    graph.claim_task("task", snapshot)
    task = graph.complete_task("task", {"claim": "unsupported"})
    assert task.lifecycle is TaskLifecycle.COMPLETED
    assert task.result_validation_state == "UNVERIFIED"
    assert task.evidence_refs == ()


def test_unknown_dependency_and_cycle_are_rejected_atomically(tmp_path):
    _, graph = setup_graph(tmp_path)
    with pytest.raises(TaskGraphError, match="unknown task dependency"):
        graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="orphan", task_id="orphan", dependencies=("missing",)),))
    assert not graph.tasks
    with pytest.raises(TaskGraphError, match="cycle"):
        graph.add_tasks((
            TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="a", task_id="a", dependencies=("b",)),
            TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="b", task_id="b", dependencies=("a",)),
        ))
    assert not graph.tasks


def test_task_agent_mission_and_parent_scope_bindings_are_enforced(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    with pytest.raises(ValueError, match="binding mismatch"):
        graph.add_agent(AgentRecord.create(mission_id="another", owner_identity_ref=graph.owner_identity_ref, role="bad", capabilities=(), permission_scope=DelegationScope.from_snapshot(snapshot), agent_id="bad"))
    with pytest.raises(TaskGraphError, match="not registered"):
        graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="unknown", objective="work", task_id="task"),))


def test_claim_revalidates_owner_mission_scope_and_snapshot_expiry(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="work", task_id="task"),))
    graph.refresh_ready_tasks()
    with pytest.raises(DelegationDenied, match="snapshot changed"):
        graph.claim_task("task", authorization(allowed_tools=("status", "search", "evidence", "extra")))
    with pytest.raises(DelegationDenied, match="expired"):
        graph.claim_task("task", snapshot, at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    assert graph.tasks["task"].lifecycle is TaskLifecycle.READY


def test_failed_dependency_blocks_descendants_and_cannot_be_retried_past_policy(tmp_path):
    snapshot, graph = setup_graph(tmp_path, policy=AgentGraphPolicy(max_retries=0))
    graph.add_tasks((
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="first", task_id="t1"),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="second", task_id="t2", dependencies=("t1",)),
    ))
    graph.refresh_ready_tasks()
    graph.claim_task("t1", snapshot)
    graph.fail_task("t1", "provider unavailable")
    assert graph.tasks["t1"].lifecycle is TaskLifecycle.FAILED
    assert graph.tasks["t2"].lifecycle is TaskLifecycle.BLOCKED
    with pytest.raises(TaskGraphError, match="retry limit"):
        graph.retry_task("t1")


def test_retry_reopens_only_after_explicit_budgeted_retry(tmp_path):
    snapshot, graph = setup_graph(tmp_path, policy=AgentGraphPolicy(max_retries=1))
    graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="retryable", task_id="task"),))
    graph.refresh_ready_tasks()
    graph.claim_task("task", snapshot)
    graph.fail_task("task", "transient provider failure")
    assert graph.retry_task("task").lifecycle is TaskLifecycle.READY
    graph.claim_task("task", snapshot)
    graph.fail_task("task", "second failure")
    with pytest.raises(TaskGraphError, match="retry limit"):
        graph.retry_task("task")


def test_dependents_unblock_in_order_after_dependency_retry_succeeds(tmp_path):
    snapshot, graph = setup_graph(tmp_path, policy=AgentGraphPolicy(max_retries=1))
    graph.add_tasks((
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="first", task_id="t1"),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="second", task_id="t2", dependencies=("t1",)),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="third", task_id="t3", dependencies=("t2",)),
    ))
    graph.refresh_ready_tasks()
    graph.claim_task("t1", snapshot)
    graph.fail_task("t1", "transient")
    assert graph.tasks["t2"].lifecycle is TaskLifecycle.BLOCKED
    assert graph.tasks["t3"].lifecycle is TaskLifecycle.BLOCKED
    graph.retry_task("t1")
    graph.claim_task("t1", snapshot)
    graph.complete_task("t1", {"ok": True})
    assert graph.tasks["t2"].lifecycle is TaskLifecycle.READY
    assert graph.tasks["t3"].lifecycle is TaskLifecycle.BLOCKED
    graph.claim_task("t2", snapshot)
    graph.complete_task("t2", {"ok": True})
    assert graph.tasks["t3"].lifecycle is TaskLifecycle.READY


def test_cancellation_propagates_but_does_not_claim_running_work_stopped(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    graph.add_tasks((
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="first", task_id="t1"),
        TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="second", task_id="t2", dependencies=("t1",)),
    ))
    graph.refresh_ready_tasks()
    graph.claim_task("t1", snapshot)
    affected = graph.cancel_task("t1")
    assert affected == ("t1", "t2")
    assert graph.tasks["t1"].lifecycle is TaskLifecycle.RUNNING
    assert graph.tasks["t1"].cancel_requested is True
    assert graph.tasks["t2"].lifecycle is TaskLifecycle.CANCELLED


def test_owner_scoped_store_round_trip_and_optimistic_revision(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="persist", task_id="task"),))
    store = TaskGraphStore(tmp_path / "agent-graphs.sqlite3")
    store.save(graph, expected_revision=0)
    assert graph.revision == 1
    restored = store.load(graph.owner_identity_ref, graph.mission_id)
    assert restored is not None
    assert restored.revision == 1
    assert restored.to_dict() == graph.to_dict()
    assert store.load("another-owner", graph.mission_id) is None
    assert store.list_for_owner("another-owner") == []
    with pytest.raises(TaskGraphConflict):
        store.save(graph, expected_revision=0)


def test_stale_concurrent_graph_copy_cannot_overwrite_newer_revision(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    store = TaskGraphStore(tmp_path / "agent-graphs.sqlite3")
    store.save(graph)
    stale_copy = TaskGraph.from_dict(graph.to_dict())
    graph.tasks.clear()
    store.save(graph, expected_revision=1)
    with pytest.raises(TaskGraphConflict):
        store.save(stale_copy, expected_revision=1)


def test_persisted_graph_payload_tampering_is_detected(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    store = TaskGraphStore(tmp_path / "agent-graphs.sqlite3")
    store.save(graph)
    with sqlite3.connect(store.db_path) as db:
        payload = db.execute("SELECT payload FROM agent_task_graphs").fetchone()[0]
        modified = payload.replace("coordinator", "attacker____")
        assert modified != payload
        db.execute("UPDATE agent_task_graphs SET payload=?", (modified,))
    with pytest.raises(TaskGraphIntegrityError, match="digest mismatch"):
        store.load(graph.owner_identity_ref, graph.mission_id)


def test_unsupported_persisted_schema_version_fails_closed(tmp_path):
    snapshot, graph = setup_graph(tmp_path)
    store = TaskGraphStore(tmp_path / "agent-graphs.sqlite3")
    store.save(graph)
    with sqlite3.connect(store.db_path) as db:
        db.execute("UPDATE agent_task_graphs SET schema_version=99")
    with pytest.raises(TaskGraphIntegrityError, match="schema version"):
        store.load(graph.owner_identity_ref, graph.mission_id)


def test_resource_limits_bound_agents_tasks_and_result_payloads(tmp_path):
    snapshot, graph = setup_graph(tmp_path, policy=AgentGraphPolicy(max_tasks=1, max_task_result_bytes=16))
    graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="work", task_id="task"),))
    with pytest.raises(TaskGraphError, match="task count"):
        graph.add_tasks((TaskRecord.create(mission_id=graph.mission_id, assigned_agent_id="agent-child", objective="work", task_id="task-2"),))
    graph.refresh_ready_tasks()
    graph.claim_task("task", snapshot)
    with pytest.raises(TaskGraphError, match="result exceeds"):
        graph.complete_task("task", {"too_long": "x" * 64})
    assert graph.tasks["task"].lifecycle is TaskLifecycle.RUNNING


def test_graph_schema_and_scope_round_trip_are_versioned():
    snapshot, graph = setup_graph(__import__("pathlib").Path("/tmp"))
    data = graph.to_dict()
    assert data["schema_version"] == TaskGraph.SCHEMA_VERSION
    restored = TaskGraph.from_dict(data)
    assert restored.to_dict() == data
    with pytest.raises(TaskGraphError, match="schema version"):
        TaskGraph.from_dict({**data, "schema_version": 99})
