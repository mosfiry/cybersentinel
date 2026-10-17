from __future__ import annotations

import secrets
import sys

import pytest

import agent.agent_core as agent_core_module
import core.db as core_db
import security.owner_password as owner_password
import security.owner_policy as owner_policy
import workspace.environment as environment
from agent.agent_core import AgentCore
from agent.evidence import EvidenceChainStore
from agent.external_effects import ExternalEffectLedger
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from api.missions import MissionService
from owner_session_testutils import persist_canonical_scope, workspace_scope_context
from security.owner_password import OWNER_USERNAME
from security.scope_store import init_scope_store
from workspace.process_sandbox import get_process_sandbox_backend


class _LocalTestsProposal:
    name = "windows-refusal-fixture"
    model = "windows-refusal-fixture-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def __init__(self):
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        return ProviderResponse(
            tool_calls=[ToolCall("run_project_tests", {"query": "."}, f"windows-tests-{self.calls}")]
        )

    def generate(self, *_args, **_kwargs):
        raise AssertionError("test proposal requires no inference beyond tool calling")


class _EmptyKnowledge:
    def retrieve_relevant(self, *_args, **_kwargs):
        return []

    def retrieve_adaptive(self, *_args, **_kwargs):
        return {"results": []}


def _governed_windows_refusal(tmp_path, monkeypatch, *, contract_route: bool):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "core.sqlite3")
    monkeypatch.setattr(agent_core_module, "DB_PATH", tmp_path / "core.sqlite3")
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    scope_store = __import__("security.scope_store", fromlist=["SCOPE_DB_PATH"])
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", tmp_path / "scope.sqlite3")
    init_scope_store()

    password = secrets.token_urlsafe(24)
    owner_password.create_owner_account(OWNER_USERNAME, password)
    session = owner_password.login(OWNER_USERNAME, password)
    session_token = session["session_id"]
    project_root = tmp_path / "authorized-project"
    project_root.mkdir()
    scope = persist_canonical_scope(
        monkeypatch, tmp_path, owner_session_token=session_token, target_id="windows-local-workspace"
    )

    if contract_route:
        monkeypatch.setattr(
            environment,
            "get_process_sandbox_backend",
            lambda platform=None: get_process_sandbox_backend("win32"),
        )

    selected = environment.get_process_sandbox_backend()
    availability = selected.availability()
    expected_detail = (
        "windows_appcontainer_backend_unimplemented"
        if sys.platform == "win32"
        else "windows_only"
    )
    assert selected.backend_id == "windows-appcontainer-job"
    assert not availability.available
    assert availability.reason_code == "backend_unavailable"
    assert availability.detail_code == expected_detail

    from workspace.environment import Workspace

    def forbid_process_start(*_args, **_kwargs):
        pytest.fail("a blocked governed mission must not attempt process start")

    monkeypatch.setattr(Workspace, "_sandbox_popen", forbid_process_start)
    provider = _LocalTestsProposal()
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]), store=store, max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    scope_context = workspace_scope_context(scope, project_root)
    mission = core.run_owner_mission(
        "Run the authorized local project tests and verify their result",
        owner_session_token=session_token,
        request_id="windows-governed-refusal",
        scope_context=scope_context,
        run=False,
    )
    assert mission.status is MissionStatus.READY
    assert provider.calls == 1
    second = core.run_owner_mission(
        "Run the authorized local project tests and verify their result",
        owner_session_token=session_token,
        request_id="windows-revoked-owner-start",
        scope_context=scope_context,
        run=False,
    )
    assert second.status is MissionStatus.READY

    queue = MissionQueue(
        tmp_path / "queue.sqlite3", require_execution_fence=True, mission_store=store
    )
    # Pre-create the real stores so an absent table cannot masquerade as proof.
    assert ExternalEffectLedger(queue.db_path).list_effects() == []
    evidence_path = tmp_path / "evidence_chain.db"
    assert EvidenceChainStore(evidence_path, mission_store=store).list() == []
    runtime = MissionRuntime(store, executor=core._executor)
    service = MissionService(runtime, queue, owner_revalidator=core.prepare_mission_for_queue)
    worker = MissionWorker(
        queue, lambda: MissionRuntime(store, executor=core._executor),
        worker_id="windows-refusal-worker", lease_seconds=60,
    )
    worker.recover_after_restart()
    service.start_mission(mission.mission_id, owner_session_token=session_token)
    assert queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    completed = worker.run_once(max_slices=5)
    assert completed is not None
    assert completed.state is WorkerMissionState.FAILED

    reopened_store = MissionStore(tmp_path / "missions.sqlite3")
    persisted = reopened_store.load(mission.mission_id)
    assert persisted is not None and persisted.verify_integrity()
    assert persisted.status is MissionStatus.RESOURCE_BLOCKED
    assert persisted.checkpoint["status"] == "not_dispatched"
    assert persisted.checkpoint["reason_code"] == "backend_unavailable"
    assert persisted.checkpoint["detail_code"] == expected_detail
    assert persisted.checkpoint["dispatch_attempted"] is False
    assert persisted.checkpoint["process_started"] is False
    assert persisted.checkpoint["process_start_confirmed"] is False
    failure = persisted.failures[-1]
    assert failure["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert failure["reason_code"] == "backend_unavailable"
    assert failure["detail_code"] == expected_detail
    assert failure["dispatch_attempted"] is False
    assert failure["process_started"] is False
    assert failure["process_start_confirmed"] is False
    assert persisted.action_history[-1]["status"] != "completed"
    assert not persisted.evidence
    assert not persisted.progress.get("execution_evidence_refs")
    assert queue.get(mission.mission_id).state is WorkerMissionState.FAILED
    reopened_ledger = ExternalEffectLedger(queue.db_path)
    assert reopened_ledger.list_effects(mission_id=mission.mission_id) == []
    reopened_evidence = EvidenceChainStore(evidence_path, mission_store=reopened_store)
    assert reopened_evidence.list() == []
    assert reopened_evidence.verify()

    assert owner_password.revoke_session(session_token)
    with pytest.raises(PermissionError):
        service.start_mission(second.mission_id, owner_session_token=session_token)
    with pytest.raises(KeyError, match="unknown queued mission"):
        queue.get(second.mission_id)
    assert reopened_ledger.list_effects(mission_id=second.mission_id) == []
    assert reopened_evidence.list() == []


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows backend evidence only")
def test_native_windows_governed_refusal_is_durable(tmp_path, monkeypatch):
    _governed_windows_refusal(tmp_path, monkeypatch, contract_route=False)


@pytest.mark.skipif(sys.platform == "win32", reason="runs only as a Windows-backend contract check")
def test_windows_backend_governed_refusal_contract_on_non_windows(tmp_path, monkeypatch):
    _governed_windows_refusal(tmp_path, monkeypatch, contract_route=True)
