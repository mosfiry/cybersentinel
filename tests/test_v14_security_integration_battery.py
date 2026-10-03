from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import agent.agent_core as agent_core_module
import security.owner_policy as owner_policy
import security.scope_store as scope_store
from agent.agent_core import AgentCore
from agent.evidence import EvidenceChainStore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from api.missions import MissionService
from owner_session_testutils import allow_owner_sessions
from security.scope_store import init_scope_store


class _StaticMissionProvider:
    name = "v14-fixture"
    model = "v14-fixture-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def __init__(self, response: ProviderResponse):
        self.response = response
        self.calls = 0

    def tool_calling(self, _messages, _tools, **_kwargs):
        self.calls += 1
        return self.response

    def generate(self, *_args, **_kwargs):
        raise AssertionError("the V14 fixture does not require an additional provider call")


class _NativeWorkspaceProvider:
    name = "native-workspace-fixture"
    model = "native-workspace-fixture-1"
    capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=True,
    )

    def __init__(self, tool_calls: list[ToolCall]):
        self.responses = [
            ProviderResponse(tool_calls=tool_calls),
            ProviderResponse(
                tool_calls=[
                    ToolCall(call.name, dict(call.arguments), f"native-{call.call_id}")
                    for call in tool_calls
                ]
            ),
            ProviderResponse(text="The authorized workspace checks are complete."),
        ]
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        if not self.responses:
            raise AssertionError("unexpected additional native model turn")
        return self.responses.pop(0)

    def generate(self, *_args, **_kwargs):
        raise AssertionError("native tool calling should not use generate")


class _EmptyKnowledge:
    def retrieve_relevant(self, *_args, **_kwargs):
        return []

    def retrieve_adaptive(self, *_args, **_kwargs):
        return {"results": []}


def _core(tmp_path: Path, monkeypatch, *, response: ProviderResponse):
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    monkeypatch.setattr(agent_core_module, "DB_PATH", tmp_path / "application.sqlite3")
    provider = _StaticMissionProvider(response)
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    return core, store, provider


def _run_project_tests_proposal() -> ProviderResponse:
    return ProviderResponse(
        tool_calls=[ToolCall("run_project_tests", {"query": "."}, "v14-test-project")]
    )


def test_owner_queue_worker_and_evidence_boundaries_compose_end_to_end(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    project_root = tmp_path / "authorized-project"
    project_root.mkdir()
    (project_root / "test_smoke.py").write_text(
        "def test_smoke():\n    assert 2 + 2 == 4\n",
        encoding="utf-8",
    )
    core, store, provider = _core(
        tmp_path, monkeypatch, response=_run_project_tests_proposal()
    )

    mission = core.run_owner_mission(
        "Run the local project tests and verify their result",
        owner_session_token="owner-session",
        request_id="v14-owner-worker-request",
        scope_context={"workspace_root": str(project_root)},
        run=False,
    )

    assert provider.calls == 1
    assert mission.status is MissionStatus.READY
    assert mission.authorization_snapshot["owner_approval"]
    assert mission.authorization_context["request_id"] == mission.request_id

    queue = MissionQueue(
        tmp_path / "queue.sqlite3",
        require_execution_fence=True,
        mission_store=store,
    )
    runtime = MissionRuntime(store, executor=core._executor)
    service = MissionService(
        runtime,
        queue,
        owner_revalidator=core.prepare_mission_for_queue,
    )
    worker = MissionWorker(
        queue,
        lambda: MissionRuntime(store, executor=core._executor),
        worker_id="v14-worker",
        lease_seconds=60,
    )
    worker.recover_after_restart()
    service.start_mission(mission.mission_id, owner_session_token="owner-session")

    queued = queue.get(mission.mission_id)
    assert queued.state is WorkerMissionState.QUEUED
    renewed = store.load(mission.mission_id)
    assert renewed.authorization_snapshot["owner_approval"] == renewed.policy_snapshot[
        "authentication"
    ]["proof_fingerprint"]
    assert any(item.get("event") == "owner_revalidated" for item in renewed.recovery_events)

    completed = worker.run_once(max_slices=5)

    assert completed is not None
    assert completed.state is WorkerMissionState.COMPLETED
    persisted = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    assert persisted.status is MissionStatus.GOAL_COMPLETED
    assert persisted.action_history[0]["status"] == "completed"
    assert persisted.evidence
    assert queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED

    evidence_store = EvidenceChainStore(
        tmp_path / "evidence_chain.db",
        mission_store=store,
    )
    records = evidence_store.list(request_id=mission.request_id)
    assert records
    assert evidence_store.verify()
    provenance = records[0]["evidence"]["provenance"]
    assert provenance["mission_id"] == mission.mission_id
    assert provenance["request_id"] == mission.request_id
    assert provenance["tool_id"] == "run_project_tests"
    assert provenance["authorization_snapshot_hash"] == persisted.authorization_snapshot[
        "authorization_hash"
    ]


@pytest.mark.parametrize("parallel", [False, True])
def test_native_model_workspace_dispatch_binds_authorized_root_and_evidence(tmp_path, monkeypatch, parallel):
    allow_owner_sessions(monkeypatch, "native-owner-session")
    authorized_root = tmp_path / "authorized-native-project"
    authorized_root.mkdir()
    (authorized_root / "test_ok.py").write_text(
        "def test_ok():\n    assert 4 == 2 + 2\n",
        encoding="utf-8",
    )
    decoy_root = tmp_path / "decoy-project"
    decoy_root.mkdir()
    (decoy_root / "test_fail.py").write_text(
        "def test_fail():\n    assert False\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(decoy_root))
    tool_calls = [ToolCall("run_project_tests", {"query": "."}, "native-workspace-call")]
    if parallel:
        tool_calls.append(ToolCall("status", {}, "native-status-call"))
    provider = _NativeWorkspaceProvider(tool_calls)
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )

    mission = core.run_owner_mission(
        "Run the authorized local project tests and verify their result",
        owner_session_token="native-owner-session",
        request_id=f"native-workspace-{parallel}",
        scope_context={"workspace_root": str(authorized_root)},
    )

    assert provider.calls == 3
    assert mission.status is MissionStatus.GOAL_COMPLETED
    goal_criterion = mission.completion_criteria[0]["criterion_id"]
    goal_evidence = [item for item in mission.evidence if item.get("criterion_id") == goal_criterion]
    assert len(goal_evidence) == 1
    assert goal_evidence[0]["source"] == "run_project_tests"
    assert goal_evidence[0]["provenance"]["tool_call_id"].endswith("native-workspace-call")
    assert not goal_evidence[0]["provenance"]["tool_call_id"].endswith("native-status-call")
    evidence_store = EvidenceChainStore(
        tmp_path / "evidence_chain.db",
        mission_store=store,
    )
    records = evidence_store.list(request_id=mission.request_id)
    assert len(records) == 1
    assert evidence_store.verify()
    assert records[0]["task_id"]
    assert records[0]["execution_id"]
    assert records[0]["evidence"]["result"] == "success"
    assert records[0]["evidence"]["provenance"]["workspace"] == str(authorized_root.resolve())
    assert any(
        receipt["evidence_id"] == records[0]["evidence_id"]
        for receipt in store.load(mission.mission_id).progress["execution_evidence_refs"]
    )


def test_stale_owner_cannot_enqueue_or_reach_worker_effect_boundary(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner-session")
    core, store, provider = _core(
        tmp_path, monkeypatch, response=_run_project_tests_proposal()
    )
    mission = core.run_owner_mission(
        "Run the local project tests",
        owner_session_token="owner-session",
        request_id="v14-stale-owner-request",
        scope_context={"workspace_root": str(tmp_path)},
        run=False,
    )
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    service = MissionService(
        MissionRuntime(store, executor=core._executor),
        queue,
        owner_revalidator=core.prepare_mission_for_queue,
    )

    with pytest.raises(PermissionError):
        service.start_mission(mission.mission_id, owner_session_token="expired-session")

    persisted = store.load(mission.mission_id)
    assert persisted.status is MissionStatus.READY
    assert not any(item.get("event") == "owner_revalidation_failed" for item in persisted.recovery_events)
    assert queue.list() == []

    executions = []
    worker = MissionWorker(
        queue,
        lambda: executions.append("runtime-created") or MissionRuntime(
            store, executor=lambda *_args: executions.append("tool-executed")
        ),
        worker_id="v14-stale-owner-worker",
        lease_seconds=60,
    )
    assert worker.run_once() is None
    assert executions == []
    assert provider.calls == 1
    assert EvidenceChainStore(tmp_path / "evidence_chain.db").list() == []


def test_missing_scope_snapshot_is_rejected_before_model_planning_or_persistence(
    tmp_path, monkeypatch
):
    allow_owner_sessions(monkeypatch, "owner-session")
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", tmp_path / "scope.sqlite3")
    init_scope_store()
    core, store, provider = _core(
        tmp_path, monkeypatch, response=_run_project_tests_proposal()
    )

    with pytest.raises(PermissionError, match="invalid_scope_context"):
        core.run_owner_mission(
            "Run a scoped mission",
            owner_session_token="owner-session",
            request_id="v14-missing-scope-request",
            scope_context={"scope_snapshot_id": "missing-scope-snapshot"},
            run=False,
        )

    assert provider.calls == 0
    with sqlite3.connect(store.db_path) as db:
        persisted_count = db.execute("SELECT COUNT(*) FROM missions").fetchone()[0]
    assert persisted_count == 0
