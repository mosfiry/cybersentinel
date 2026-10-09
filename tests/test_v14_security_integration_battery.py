from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent.context import RuntimeLimits
import agent.agent_core as agent_core_module
import agent.mission_runtime as mission_runtime_module
import security.owner_policy as owner_policy
import security.scope_store as scope_store
from agent.agent_core import AgentCore
from agent.evidence import EvidenceChainStore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.model_router import ModelRouter
from agent.planning import Plan, PlanStep
from agent.provider_api import ProviderCapabilities, ProviderFailure, ProviderResponse, ToolCall
from api.missions import MissionService
from owner_session_testutils import allow_owner_sessions, persist_canonical_scope, workspace_scope_context
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


class _AlwaysFailingPlanningProvider:
    name = "owner-retry-cap-fixture"
    model = "owner-retry-cap-fixture-1"
    capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def __init__(self):
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        raise ProviderFailure("private planning failure", provider=self.name, model=self.model)

    def generate(self, *_args, **_kwargs):
        raise AssertionError("planning retry-cap test must use tool calling")


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


def _external_effect_count(db_path: str | Path) -> int:
    connection = sqlite3.connect(str(db_path))
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "external_effects" not in tables:
            return 0
        return int(connection.execute("SELECT COUNT(*) FROM external_effects").fetchone()[0])
    finally:
        connection.close()


def _process_sandbox_unavailable_reason() -> str | None:
    from workspace import Workspace

    return Workspace.process_sandbox_unavailable_reason()


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
    scope_snapshot = persist_canonical_scope(
        monkeypatch, tmp_path, owner_session_token="owner-session",
        target_id="v14-local-workspace", bind_session=False,
    )
    core, store, provider = _core(
        tmp_path, monkeypatch, response=_run_project_tests_proposal()
    )

    mission = core.run_owner_mission(
        "Run the local project tests and verify their result",
        owner_session_token="owner-session",
        request_id="v14-owner-worker-request",
        scope_context=workspace_scope_context(scope_snapshot, project_root),
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
    persisted = MissionStore(tmp_path / "missions.sqlite3").load(mission.mission_id)
    sandbox_unavailable = _process_sandbox_unavailable_reason()
    if sandbox_unavailable:
        assert completed.state is WorkerMissionState.FAILED
        assert persisted.status is MissionStatus.RESOURCE_BLOCKED
        assert persisted.checkpoint["status"] == "not_dispatched"
        assert persisted.checkpoint["reason_code"] == "process_sandbox_unavailable"
        assert persisted.failures[-1]["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
        assert persisted.failures[-1]["dispatch_attempted"] is False
        assert persisted.action_history == []
        assert queue.get(mission.mission_id).state is WorkerMissionState.FAILED
        assert _external_effect_count(store.db_path) == 0
        return
    from security.owner_password import authenticated_owner
    persisted_session = (persisted.authorization_context or {}).get("session_id")
    persisted_evidence = (persisted.authorization_context or {}).get("owner_evidence", {})
    assert completed.state is WorkerMissionState.COMPLETED, {
        "queue_error": completed.last_error,
        "mission_status": persisted.status.value,
        "mission_error": persisted.error,
        "owner_context_session_active": bool(authenticated_owner(str(persisted_session or ""))),
        "owner_evidence_session_matches": persisted_evidence.get("session_id") == persisted_session,
        "last_action_error": (
            persisted.action_history[-1].get("observation", {}).get("error")
            if persisted.action_history else None
        ),
    }
    assert persisted.status is MissionStatus.GOAL_COMPLETED
    assert persisted.action_history[0]["status"] == "completed"
    assert persisted.evidence
    assert queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED

    evidence_store = EvidenceChainStore(
        tmp_path / "evidence_chain.db",
        mission_store=store,
    )
    records = evidence_store.list(request_id=mission.request_id)
    assert len(records) >= 2
    assert evidence_store.verify()
    process_records = [record for record in records if record.get("source") == "sandboxed-process:run_project_tests"]
    workspace_events = [
        record for record in records
        if record.get("source") == "workspace:run_project_tests"
        and record.get("evidence", {}).get("operation") == "process"
    ]
    assert len(process_records) == 1 and len(workspace_events) == 1
    provenance = workspace_events[0]["evidence"]["provenance"]
    assert provenance["mission_id"] == mission.mission_id
    assert provenance["request_id"] == mission.request_id
    assert provenance["tool_id"] == "run_project_tests"
    assert provenance["authorization_snapshot_hash"] == persisted.authorization_snapshot[
        "authorization_hash"
    ]


def test_planned_run_project_tests_sandbox_denial_is_not_recorded_as_execution(tmp_path, monkeypatch):
    from agent.trajectory import EventType
    from workspace import Workspace

    owner_session = "planned-sandbox-denial-owner"
    allow_owner_sessions(monkeypatch, owner_session)
    project_root = tmp_path / "authorized-denial-project"
    project_root.mkdir()
    sentinel = project_root / "test_was_dispatched.txt"
    (project_root / "test_side_effect.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('unexpected dispatch', encoding='utf-8')\n"
        "def test_should_not_run_without_isolation():\n    assert True\n",
        encoding="utf-8",
    )
    scope_snapshot = persist_canonical_scope(
        monkeypatch,
        tmp_path,
        owner_session_token=owner_session,
        target_id="planned-sandbox-denial",
    )
    monkeypatch.setattr(
        Workspace,
        "process_sandbox_unavailable_reason",
        staticmethod(lambda: "required rootless Linux process sandbox is unavailable"),
    )
    core, store, provider = _core(
        tmp_path,
        monkeypatch,
        response=_run_project_tests_proposal(),
    )

    mission = core.run_owner_mission(
        "Run one bounded local project test and report its observed result",
        owner_session_token=owner_session,
        request_id="planned-sandbox-denial-request",
        scope_context=workspace_scope_context(scope_snapshot, project_root),
        run=True,
    )
    persisted = store.load(mission.mission_id)

    assert provider.calls >= 1
    assert persisted is not None and persisted.verify_integrity()
    assert persisted.status is MissionStatus.RESOURCE_BLOCKED
    assert persisted.checkpoint["status"] == "not_dispatched"
    assert persisted.checkpoint["reason_code"] == "process_sandbox_unavailable"
    assert persisted.checkpoint["stage"] == "pre_dispatch_sandbox_check"
    assert persisted.checkpoint["dispatch_attempted"] is False
    failure = persisted.failures[-1]
    assert failure["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
    assert failure["reason_code"] == "process_sandbox_unavailable"
    assert failure["stage"] == "pre_dispatch_sandbox_check"
    assert failure["error_type"] == "ProcessSandboxUnavailable"
    assert failure["mission_id"] == persisted.mission_id
    assert failure["dispatch_attempted"] is False
    assert persisted.action_history == []
    assert all(
        event.get("event") != EventType.TOOL_EXECUTED.value
        for event in persisted.trajectory
    )
    assert persisted.evidence == []
    assert _external_effect_count(store.db_path) == 0
    assert not sentinel.exists()


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
    target_id = f"native-workspace-{parallel}"
    scope_snapshot = persist_canonical_scope(
        monkeypatch, tmp_path, owner_session_token="native-owner-session",
        target_id=target_id,
    )
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
        scope_context=workspace_scope_context(scope_snapshot, authorized_root),
    )

    sandbox_unavailable = _process_sandbox_unavailable_reason()
    if sandbox_unavailable:
        expected_calls = 2 if parallel else 1
        assert provider.calls == 2
        assert mission.status is MissionStatus.RESOURCE_BLOCKED
        assert mission.checkpoint["status"] == "not_dispatched"
        assert mission.checkpoint["reason_code"] == "process_sandbox_unavailable"
        assert mission.failures[-1]["kind"] == "PROCESS_SANDBOX_UNAVAILABLE"
        assert mission.failures[-1]["dispatch_attempted"] is False
        results = mission.progress["model_loop"]["tool_results"]
        assert len(results) == expected_calls
        assert all(result.get("ok") is False for result in results)
        assert _external_effect_count(store.db_path) == 0
        return

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
    assert len(records) == (4 if parallel else 3)
    assert evidence_store.verify()
    native_tool_records = [record for record in records if str(record.get("source", "")).startswith("native-tool:")]
    assert len(native_tool_records) == (2 if parallel else 1)
    expected_native_call_ids = {("run_project_tests", "native-native-workspace-call")}
    if parallel:
        expected_native_call_ids.add(("status", "native-native-status-call"))
    assert {
        (record["evidence"]["tool_name"], record["evidence"]["tool_call_id"])
        for record in native_tool_records
    } == expected_native_call_ids
    process_records = [record for record in records if record.get("source") == "sandboxed-process:run_project_tests"]
    workspace_events = [
        record for record in records
        if record.get("source") == "workspace:run_project_tests"
        and record.get("evidence", {}).get("operation") == "process"
    ]
    assert len(process_records) == 1 and len(workspace_events) == 1
    process_record = process_records[0]
    assert process_record["task_id"]
    assert process_record["execution_id"]
    assert process_record["evidence"]["record_type"] == "UNTRUSTED_SANDBOX_PROCESS_RESULT"
    assert process_record["evidence"]["exit_code"] == 0
    assert process_record["evidence"]["trust"] == "untrusted_data"
    assert workspace_events[0]["evidence"]["provenance"]["workspace"] == str(authorized_root.resolve())
    assert any(
        receipt["evidence_id"] == process_record["evidence_id"]
        for receipt in store.load(mission.mission_id).progress["execution_evidence_refs"]
    )


def test_native_model_serializes_tool_calls_when_provider_disables_parallel_calls(tmp_path, monkeypatch):
    allow_owner_sessions(monkeypatch, "native-serial-owner-session")
    authorized_root = tmp_path / "authorized-serial-project"
    authorized_root.mkdir()
    (authorized_root / "test_ok.py").write_text(
        "def test_ok():\n    assert 2 + 2 == 4\n",
        encoding="utf-8",
    )
    scope_snapshot = persist_canonical_scope(
        monkeypatch, tmp_path, owner_session_token="native-serial-owner-session",
        target_id="native-serial-workspace",
    )
    provider = _NativeWorkspaceProvider([
        ToolCall("run_project_tests", {"query": "."}, "native-serial-tests"),
        ToolCall("status", {}, "native-serial-status"),
    ])
    provider.capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=False,
    )
    observed_worker_limits = []
    real_execute_bounded_parallel = mission_runtime_module.execute_bounded_parallel

    def record_worker_limit(proposals, execute_one, *, max_workers=4):
        observed_worker_limits.append(max_workers)
        return real_execute_bounded_parallel(proposals, execute_one, max_workers=max_workers)

    monkeypatch.setattr(
        mission_runtime_module, "execute_bounded_parallel", record_worker_limit
    )
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )

    mission = core.run_owner_mission(
        "Run the authorized local project tests and read system status, then verify the results",
        owner_session_token="native-serial-owner-session",
        request_id="native-serial-workspace-request",
        scope_context=workspace_scope_context(scope_snapshot, authorized_root),
    )

    if _process_sandbox_unavailable_reason():
        assert provider.calls == 2
        assert observed_worker_limits == []
        assert mission.status is MissionStatus.RESOURCE_BLOCKED
        assert mission.checkpoint["status"] == "not_dispatched"
        assert mission.checkpoint["reason_code"] == "process_sandbox_unavailable"
        assert mission.failures[-1]["dispatch_attempted"] is False
        assert all(
            result.get("ok") is False
            for result in mission.progress["model_loop"]["tool_results"]
        )
        assert _external_effect_count(store.db_path) == 0
        return

    assert provider.calls == 3
    assert observed_worker_limits == [1]
    assert mission.status is MissionStatus.GOAL_COMPLETED
    completed_tools = {
        item.get("name")
        for item in mission.progress["model_loop"]["tool_results"]
        if item.get("ok") is True
    }
    assert {"run_project_tests", "status"}.issubset(completed_tools)


def test_native_owner_mission_preserves_latest_intel_list_result(tmp_path, monkeypatch):
    import json
    import core.db as core_db

    session = "native-latest-intel-owner-session"
    marker = "V52_LOCAL_INTEL_FIXTURE_CVE"
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "core.sqlite3")
    monkeypatch.setattr(agent_core_module, "DB_PATH", tmp_path / "application.sqlite3")
    with core_db.connect():
        pass
    assert core_db.add_intel(
        marker, "acceptance-fixture", "Local test advisory",
        "Read-only synthetic record; no network request.", "high", {"fixture": True},
    )
    allow_owner_sessions(monkeypatch, session)
    provider = _NativeWorkspaceProvider([
        ToolCall("status", {}, "native-latest-intel-status"),
        ToolCall("latest_intel", {}, "native-latest-intel-list"),
    ])
    provider.capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=False,
    )
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )

    mission = core.run_owner_mission(
        "Read current local system status and latest locally available intelligence, then report only observed facts.",
        owner_session_token=session,
        request_id="native-latest-intel-list-request",
    )

    assert mission.status is MissionStatus.GOAL_COMPLETED
    successful_tools = {
        item.get("name"): item
        for item in mission.progress["model_loop"]["tool_results"]
        if item.get("ok") is True
    }
    assert {"status", "latest_intel"}.issubset(successful_tools)
    intel_result = successful_tools["latest_intel"].get("result")
    assert isinstance(intel_result, dict)
    assert isinstance(intel_result.get("items"), list)
    assert marker in json.dumps(intel_result, ensure_ascii=False)
    assert mission.checkpoint.get("status") != "in_flight_parallel"
    evidence_store = EvidenceChainStore(
        Path(store.db_path).with_name("evidence_chain.db"),
        mission_store=store,
    )
    records = evidence_store.list(request_id=mission.request_id)
    native_records = [record for record in records if str(record.get("source", "")).startswith("native-tool:")]
    assert evidence_store.verify()
    assert {record["evidence"]["tool_name"] for record in native_records} == {"status", "latest_intel"}
    assert {
        (record["evidence"]["tool_name"], record["evidence"]["tool_call_id"])
        for record in native_records
    } == {
        ("status", "native-native-latest-intel-status"),
        ("latest_intel", "native-native-latest-intel-list"),
    }
    assert all(record.get("fence_id") and record.get("authorization_hash") for record in native_records)
    assert all(record["evidence"]["trust_classification"] == "untrusted_data" for record in native_records)
    assert all(record["evidence"]["authority"] == "none" for record in native_records)
    assert all(record["evidence"]["authorized_tool"] is True for record in native_records)
    assert all(len(record["evidence"]["result_sha256"]) == 64 for record in native_records)
    assert all(len(record["evidence"]["scope_sha256"]) == 64 for record in native_records)
    evidence_refs = store.load(mission.mission_id).progress["execution_evidence_refs"]
    assert all(any(receipt["evidence_id"] == record["evidence_id"] for receipt in evidence_refs) for record in native_records)


def test_model_planner_cannot_self_authorize_tool_outside_owner_scope(tmp_path, monkeypatch):
    session = "owner-plan-scope-session"
    allow_owner_sessions(monkeypatch, session)
    core, _store, provider = _core(
        tmp_path,
        monkeypatch,
        response=ProviderResponse(text="provider should not be called"),
    )
    unauthorized_plan = Plan.initial("Read current status").replan(
        steps=(PlanStep("unauthorized-step", "run outside the Owner allowlist", action="run_project_tests"),),
        reason="hostile-model-proposal",
    )
    monkeypatch.setattr(core, "_plan", lambda *_args, **_kwargs: unauthorized_plan)

    with pytest.raises(PermissionError, match="model_plan_exceeds_owner_tool_scope"):
        core.run_owner_mission(
            "Read current status.",
            owner_session_token=session,
            request_id="owner-plan-scope-rejection",
            scope_context={"scope": ["workspace"], "target_id": "owner-scope", "allowed_tools": ["status"]},
            run=False,
        )

    assert provider.calls == 0


def test_initial_planning_retry_count_uses_owner_runtime_limit(tmp_path, monkeypatch):
    session = "owner-planning-retry-cap-session"
    allow_owner_sessions(monkeypatch, session)
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    monkeypatch.setattr(agent_core_module, "DB_PATH", tmp_path / "application.sqlite3")
    provider = _AlwaysFailingPlanningProvider()
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    monkeypatch.setattr(core, "_context_runtime_limits", lambda: RuntimeLimits(max_retries=0))

    mission = core.run_owner_mission(
        "Read current status and report observed facts.",
        owner_session_token=session,
        request_id="owner-planning-retry-cap",
        run=False,
    )

    assert provider.calls == 1
    assert mission.failures[0]["retry_policy"]["max_retries"] == 0
    assert mission.failures[0]["retry_policy"]["retry_scheduled"] is False


class _ReadOnlyToolCycleProvider:
    name = "read-only-cycle-fixture"
    model = "read-only-cycle-fixture-1"
    capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=True,
    )

    def __init__(self):
        self.responses = [
            ProviderResponse(tool_calls=[
                ToolCall("status", {}, "cycle-planning-status"),
                ToolCall("latest_intel", {}, "cycle-planning-intel"),
            ]),
            ProviderResponse(tool_calls=[
                ToolCall("status", {}, "cycle-first-status"),
                ToolCall("latest_intel", {}, "cycle-first-intel"),
            ]),
            ProviderResponse(tool_calls=[
                ToolCall("status", {}, "cycle-repeat-status"),
                ToolCall("latest_intel", {}, "cycle-repeat-intel"),
            ]),
        ]
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, *_args, **_kwargs):
        raise AssertionError("native repeat guard test must use real tool calling")


class _RepeatedSingleReadOnlyToolProvider:
    name = "repeated-single-read-only-fixture"
    model = "repeated-single-read-only-fixture-1"
    capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=True,
    )

    def __init__(self):
        self.responses = [
            ProviderResponse(tool_calls=[
                ToolCall("status", {}, "single-repeat-planning-status"),
                ToolCall("latest_intel", {}, "single-repeat-planning-intel"),
            ]),
            ProviderResponse(tool_calls=[ToolCall("latest_intel", {}, "single-first-intel")]),
            ProviderResponse(tool_calls=[ToolCall("latest_intel", {}, "single-repeat-intel")]),
        ]
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, *_args, **_kwargs):
        raise AssertionError("single read-tool repeat guard test must use real tool calling")


class _ReadOnlyAbaCycleProvider:
    name = "read-only-aba-cycle-fixture"
    model = "read-only-aba-cycle-fixture-1"
    capabilities = ProviderCapabilities(
        generate=True,
        tool_calling=True,
        native_chat=True,
        parallel_tool_calls=True,
    )

    def __init__(self):
        first_batch = [
            ToolCall("status", {}, "cycle-first-status-a"),
            ToolCall("latest_intel", {}, "cycle-first-intel"),
            ToolCall("status", {}, "cycle-first-status-b"),
        ]
        repeated_batch = [
            ToolCall("status", {}, "cycle-repeat-status-a"),
            ToolCall("latest_intel", {}, "cycle-repeat-intel"),
            ToolCall("status", {}, "cycle-repeat-status-b"),
        ]
        self.responses = [
            ProviderResponse(tool_calls=[
                ToolCall("status", {}, "cycle-planning-status"),
                ToolCall("latest_intel", {}, "cycle-planning-intel"),
            ]),
            ProviderResponse(tool_calls=first_batch),
            ProviderResponse(tool_calls=repeated_batch),
        ]
        self.calls = 0

    def tool_calling(self, *_args, **_kwargs):
        self.calls += 1
        return self.responses.pop(0)

    def generate(self, *_args, **_kwargs):
        raise AssertionError("native A,B,A repeat guard test must use real tool calling")


def test_native_model_blocks_repeated_read_only_tool_cycle_before_dispatch(tmp_path, monkeypatch):
    session = "native-cycle-owner-session"
    allow_owner_sessions(monkeypatch, session)
    provider = _ReadOnlyToolCycleProvider()
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    monkeypatch.setattr(core, "_context_runtime_limits", lambda: RuntimeLimits(max_same_tool_calls=10))

    mission = core.run_owner_mission(
        "Read current local system status and latest locally available intelligence, then report only observed facts.",
        owner_session_token=session,
        request_id="native-read-only-cycle-request",
    )

    assert provider.calls == 3
    assert mission.status is MissionStatus.RESOURCE_BLOCKED
    assert mission.is_terminal
    loop = mission.progress["model_loop"]
    assert len(loop["turns"]) == 2
    assert len(loop["tool_results"]) == 4
    assert [(item["name"], item["ok"]) for item in loop["tool_results"]] == [
        ("status", True),
        ("latest_intel", True),
        ("status", False),
        ("latest_intel", False),
    ]
    cycle_guard = loop["semantic_read_only_cycle_guard"]
    assert cycle_guard["tool_name"] == "status"
    assert cycle_guard["blocked_tool_call_id"].endswith("cycle-repeat-status")
    assert cycle_guard["duplicate_of_tool_call_id"].endswith("cycle-first-status")
    assert cycle_guard["duplicate_kind"] == "repeated_read_only_tool_cycle"
    assert cycle_guard["cycle_length"] == 2
    assert [call_id.rsplit("-", 1)[-1] for call_id in cycle_guard["cycle_tool_call_ids"]] == [
        "status",
        "intel",
    ]
    assert cycle_guard["arguments_sha256"].startswith("44136fa355b3")
    assert len(cycle_guard["arguments_sha256"]) == 64
    assert cycle_guard["dispatch_attempted"] is False
    assert mission.checkpoint["status"] == "not_dispatched"
    assert mission.failures[-1]["budget"] == "repeated_read_only_tool_cycle"
    assert mission.failures[-1]["details"]["dispatch_attempted"] is False

    evidence_store = EvidenceChainStore(tmp_path / "evidence_chain.db", mission_store=store)
    records = evidence_store.list(request_id=mission.request_id)
    native_records = [record for record in records if str(record.get("source", "")).startswith("native-tool:")]
    assert evidence_store.verify()
    assert len(native_records) == 2
    assert {record["evidence"]["tool_name"] for record in native_records} == {"status", "latest_intel"}
    assert {record["evidence"]["tool_call_id"].rsplit("-", 1)[-1] for record in native_records} == {
        "status",
        "intel",
    }
    assert all("cycle-repeat" not in record["evidence"]["tool_call_id"] for record in native_records)


def test_native_model_blocks_repeated_identical_single_read_tool_before_dispatch(tmp_path, monkeypatch):
    from tools.registry import get_tool

    assert get_tool("latest_intel").block_identical_read_repeats is True
    assert get_tool("status").block_identical_read_repeats is False
    session = "native-single-read-repeat-owner-session"
    allow_owner_sessions(monkeypatch, session)
    provider = _RepeatedSingleReadOnlyToolProvider()
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    monkeypatch.setattr(
        core,
        "_context_runtime_limits",
        lambda: RuntimeLimits(max_tool_calls=10, max_same_tool_calls=10),
    )

    mission = core.run_owner_mission(
        "Read the latest locally available intelligence once and report observed facts.",
        owner_session_token=session,
        request_id="native-single-read-repeat-request",
    )

    assert provider.calls == 3
    assert mission.status is MissionStatus.RESOURCE_BLOCKED
    assert mission.is_terminal
    loop = mission.progress["model_loop"]
    assert len(loop["turns"]) == 2
    assert [(item["name"], item["ok"]) for item in loop["tool_results"]] == [
        ("latest_intel", True),
        ("latest_intel", False),
    ]
    repeat_guard = loop["semantic_read_only_cycle_guard"]
    assert repeat_guard["tool_name"] == "latest_intel"
    assert repeat_guard["blocked_tool_call_id"] == "single-repeat-intel"
    assert repeat_guard["duplicate_of_tool_call_id"] == "single-first-intel"
    assert repeat_guard["duplicate_kind"] == "repeated_read_only_tool_call"
    assert repeat_guard["cycle_length"] == 1
    assert repeat_guard["dispatch_attempted"] is False
    assert mission.checkpoint["status"] == "not_dispatched"
    assert mission.failures[-1]["budget"] == "repeated_read_only_tool_call"

    evidence_store = EvidenceChainStore(tmp_path / "evidence_chain.db", mission_store=store)
    records = evidence_store.list(request_id=mission.request_id)
    native_records = [record for record in records if str(record.get("source", "")).startswith("native-tool:")]
    assert evidence_store.verify()
    assert len(native_records) == 1
    assert native_records[0]["evidence"]["tool_call_id"] == "single-first-intel"
    assert all(record["evidence"]["tool_call_id"] != "single-repeat-intel" for record in native_records)


def test_native_read_only_cycle_guard_allows_first_aba_batch_and_blocks_its_repeat(tmp_path, monkeypatch):
    session = "native-aba-cycle-owner-session"
    allow_owner_sessions(monkeypatch, session)
    provider = _ReadOnlyAbaCycleProvider()
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(
        ModelRouter([provider]),
        store=store,
        max_iterations=5,
        knowledge_retriever=_EmptyKnowledge(),
    )
    monkeypatch.setattr(
        core,
        "_context_runtime_limits",
        lambda: RuntimeLimits(max_tool_calls=10, max_same_tool_calls=10),
    )

    mission = core.run_owner_mission(
        "Read current local system status and latest locally available intelligence, then report only observed facts.",
        owner_session_token=session,
        request_id="native-read-only-aba-cycle-request",
    )

    assert provider.calls == 3
    assert mission.status is MissionStatus.RESOURCE_BLOCKED
    assert mission.is_terminal
    loop = mission.progress["model_loop"]
    assert len(loop["turns"]) == 2
    assert [(item["name"], item["ok"]) for item in loop["tool_results"]] == [
        ("status", True),
        ("latest_intel", True),
        ("status", True),
        ("status", False),
        ("latest_intel", False),
        ("status", False),
    ]
    cycle_guard = loop["semantic_read_only_cycle_guard"]
    assert cycle_guard["tool_name"] == "status"
    assert cycle_guard["blocked_tool_call_id"] == "cycle-repeat-status-a"
    assert cycle_guard["duplicate_of_tool_call_id"] == "cycle-first-status-a"
    assert cycle_guard["cycle_length"] == 3
    assert cycle_guard["dispatch_attempted"] is False
    assert mission.checkpoint["status"] == "not_dispatched"

    evidence_store = EvidenceChainStore(tmp_path / "evidence_chain.db", mission_store=store)
    records = evidence_store.list(request_id=mission.request_id)
    native_records = [record for record in records if str(record.get("source", "")).startswith("native-tool:")]
    assert evidence_store.verify()
    assert {
        record["evidence"]["tool_call_id"] for record in native_records
    } == {"cycle-first-status-a", "cycle-first-intel", "cycle-first-status-b"}
    assert all("cycle-repeat" not in record["evidence"]["tool_call_id"] for record in native_records)


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
