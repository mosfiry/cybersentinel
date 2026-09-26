from __future__ import annotations
from runtime_authorization import make_test_snapshot

from pathlib import Path
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Event, Thread
import json
import time

import pytest

from agent.evidence import EvidenceChainStore
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.self_repair import BoundedSelfRepair
from agent.filesystem_verification import FilesystemVerifier
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import execute
from workspace import Workspace, WorkspaceBoundaryError, WorkspacePolicyError


def auth(root: str, *, mission_id: str = "m1", owner: str = "owner-proof", actions=None, tools=None, forbidden=None, expiry=None):
    created = (expiry - timedelta(minutes=1)) if expiry is not None and expiry <= datetime.now(timezone.utc) else datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity=owner,
        mission_id=mission_id,
        target_identity="target-1",
        scope=["workspace"],
        allowed_actions=list(actions if actions is not None else ["run_project_tests", "read", "write", "process", "development"]),
        forbidden_actions=list(forbidden if forbidden is not None else []),
        allowed_tools=list(tools if tools is not None else ["run_project_tests"]),
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={"run_project_tests": 1},
        network_boundary={"allowed": []},
        data_boundary={"allowed": ["target-1"]},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": root},
        policy_version="policy-v1",
        owner_approval="approval",
        created_at=(created - timedelta(seconds=1)).isoformat(),
        expires_at=(expiry or created + timedelta(minutes=10)).isoformat(),
    )


def test_run_project_tests_uses_workspace_and_persists_evidence(tmp_path, monkeypatch):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert 2 + 2 == 4\n")
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    snapshot = auth(str(tmp_path))
    workspace = Workspace(tmp_path)
    import security.owner_policy as owner_policy
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", "req-1", "proof")
    context = AuthorizationContext(request_id="req-1", owner_evidence=evidence, policy_snapshot=owner_policy.capture_policy_snapshot("req-1", evidence))
    decision = authorize_tool(["run_project_tests", "."], context=context)
    assert decision.allowed and decision.decision is not None
    result = execute("run_project_tests", ".", authorization_decision=decision.decision, request_id="req-1", mission_authorization=snapshot, workspace=workspace, evidence_store=store, mission_id="m1")
    assert result["ok"] is True
    assert result["returncode"] == 0
    records = store.list(request_id="req-1")
    assert records and store.verify()
    provenance = records[0]["evidence"]["provenance"]
    assert provenance["mission_id"] == "m1"
    assert provenance["request_id"] == "req-1"
    assert provenance["tool_id"] == "run_project_tests"
    assert provenance["authorization_snapshot_hash"] == snapshot.authorization_hash


def test_workspace_requires_snapshot_and_blocks_boundary_and_symlink(tmp_path):
    workspace = Workspace(tmp_path)
    with pytest.raises(WorkspacePolicyError, match="snapshot"):
        workspace.read("x")
    snapshot = auth(str(tmp_path), actions=["read", "write"] , tools=[])
    workspace = Workspace(tmp_path, authorization_snapshot=snapshot)
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret")
    with pytest.raises(WorkspaceBoundaryError):
        workspace.read("../outside.txt")
    link = tmp_path / "escape"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(WorkspaceBoundaryError):
        workspace.read("escape")


def test_snapshot_tamper_expiry_wrong_mission_target_and_forbidden_tool_are_blocked(tmp_path):
    snapshot = auth(str(tmp_path), mission_id="m1")
    assert snapshot.validate_for_mission(mission_id="m1", owner_identity="owner-proof", target_identity="target-1")[0]
    assert not snapshot.validate_for_mission(mission_id="m2", owner_identity="owner-proof", target_identity="target-1")[0]
    assert not snapshot.validate_for_mission(mission_id="m1", owner_identity="other", target_identity="target-1")[0]
    assert not snapshot.check(action="other-tool", tool_id="other-tool", target_identity="target-1")[0]
    expired = auth(str(tmp_path), expiry=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not expired.is_active()
    tampered = snapshot.to_dict()
    tampered["allowed_tools"] = ["other-tool"]
    with pytest.raises(Exception):
        MissionAuthorizationSnapshot.from_dict(tampered)


def test_worker_lease_prevents_duplicate_and_recovers_expired(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m1", available_at="2026-01-01T00:00:00+00:00")
    first = queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id="a", lease_seconds=10)
    assert first and first.lease_owner == "a"
    assert queue.claim_next(now="2026-01-01T00:00:01+00:00", worker_id="b", lease_seconds=10) is None
    with pytest.raises(PermissionError):
        queue.heartbeat("m1", worker_id="b", now="2026-01-01T00:00:01+00:00")
    recovered = queue.recover_expired(now="2026-01-01T00:00:11+00:00")
    assert recovered[0].state is WorkerMissionState.QUEUED
    second = queue.claim_next(now="2026-01-01T00:00:11+00:00", worker_id="b", lease_seconds=10)
    assert second and second.lease_owner == "b"


def test_successful_command_without_goal_evidence_is_unknown_and_repair_requires_auth(tmp_path):
    from agent.verification import FindingClaim, VerificationEngine, VerificationPlan, VerificationResult
    claim = FindingClaim("file created", "target-1")
    report = VerificationEngine().verify(claim, VerificationPlan("filesystem-validator", required_evidence=("filesystem",)), [{"source": "command", "type": "process", "exit_code": 0}])
    assert report.result is VerificationResult.UNKNOWN
    repaired = BoundedSelfRepair(max_retries=1).run(lambda: (_ for _ in ()).throw(RuntimeError("fail")), lambda exc: str(exc), lambda _d, _a: pytest.fail("unauthorized repair executed"), lambda _v: True, authorize_repair=lambda _d: False)
    assert not repaired.success
    assert repaired.reason == "repair authorization denied"
    assert any(item.phase == "authorization" for item in repaired.records)


def test_expired_snapshot_blocks_mission_runtime_execution(tmp_path):
    expired = auth(str(tmp_path), expiry=datetime.now(timezone.utc) - timedelta(seconds=1))
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda *_args: pytest.fail("expired mission executed"), require_authorization_snapshot=True, authorization_snapshot_factory=make_test_snapshot)
    mission = runtime.create("request", "objective", Plan.initial("objective"), owner_identity_ref="owner-proof", authorization_snapshot=expired.to_dict(), max_iterations=1)
    result = runtime.run_slice(mission.mission_id)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED


@pytest.mark.parametrize("mutation", [
    "missing", "expired", "tampered", "wrong_mission", "wrong_owner", "wrong_target",
    "wrong_action", "wrong_tool", "wrong_workspace", "wrong_network", "wrong_credential", "wrong_version",
])
def test_every_snapshot_negative_path_blocks_before_executor(tmp_path, mutation):
    store = MissionStore(tmp_path / f"{mutation}.sqlite3")
    called = []
    runtime = MissionRuntime(store, executor=lambda *_args: called.append(True) or {"success": True}, authorization_snapshot_factory=make_test_snapshot)
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "status", action="status"),), reason="test")
    mission = runtime.create("request", "objective", plan, owner_identity_ref="test-owner", scope_snapshot={"workspace_root": "/workspace/test", "allowed_networks": [], "allowed_credentials": []})
    snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    if mutation == "missing":
        mission.authorization_snapshot = None
    elif mutation == "expired":
        mission.authorization_snapshot = auth(str(tmp_path), expiry=datetime.now(timezone.utc) - timedelta(seconds=1), actions=["status"], tools=["status"]).to_dict()
    elif mutation == "tampered":
        raw = snapshot.to_dict(); raw["allowed_actions"] = ["other"]; raw["authorization_hash"] = snapshot.authorization_hash; mission.authorization_snapshot = raw
    elif mutation == "wrong_mission":
        mission.authorization_snapshot = auth(str(tmp_path), mission_id="other", actions=["status"], tools=["status"]).to_dict()
    elif mutation == "wrong_owner":
        mission.owner_identity_ref = "other-owner"
    elif mutation == "wrong_target":
        mission.scope_snapshot["target_id"] = "other-target"
    elif mutation == "wrong_action":
        raw = snapshot.to_dict(); raw["allowed_actions"] = ["other"]; raw.pop("authorization_hash"); mission.authorization_snapshot = MissionAuthorizationSnapshot.from_dict(raw).to_dict()
    elif mutation == "wrong_tool":
        raw = snapshot.to_dict(); raw["allowed_tools"] = ["other"]; raw.pop("authorization_hash"); mission.authorization_snapshot = MissionAuthorizationSnapshot.from_dict(raw).to_dict()
    elif mutation == "wrong_workspace":
        mission.scope_snapshot["workspace_root"] = "/workspace/other"
    elif mutation == "wrong_network":
        mission.scope_snapshot["allowed_networks"] = ["network-a"]
    elif mutation == "wrong_credential":
        mission.scope_snapshot["allowed_credentials"] = ["credential-a"]
    elif mutation == "wrong_version":
        raw = snapshot.to_dict(); raw["version"] = 99; raw.pop("authorization_hash"); mission.authorization_snapshot = MissionAuthorizationSnapshot.from_dict(raw).to_dict()
    store.save(mission)
    result = runtime.run_slice(mission.mission_id)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert called == []


def test_mission_runtime_default_requires_snapshot_and_has_no_bypass(tmp_path):
    called = []
    runtime = MissionRuntime(MissionStore(tmp_path / "strict.sqlite3"), executor=lambda *_: called.append(True))
    plan = Plan.initial("strict objective").replan(steps=(PlanStep("s1", "status", action="status"),), reason="test")
    mission = runtime.create("strict objective", "strict objective", plan, owner_identity_ref="test-owner")
    result = runtime.run_slice(mission.mission_id)
    assert runtime.require_authorization_snapshot is True
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert called == []


def test_filesystem_verifier_reads_actual_state_not_operation_result(tmp_path):
    target = tmp_path / "artifact.txt"
    target.write_text("verified")
    verifier = FilesystemVerifier(tmp_path)
    observed = verifier.verify_created("artifact.txt", expected_size=8)
    assert observed["verification"] == "VERIFIED"
    assert observed["observation"]["type"] == "file"
    target.unlink()
    missing = verifier.verify_created("artifact.txt")
    assert missing["verification"] == "OBSERVED"
    assert missing["passed"] is False


def test_worker_heartbeat_during_execution_and_stale_update_rejected(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m1", available_at="2026-01-01T00:00:00+00:00")
    item = queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id="a", lease_seconds=1)
    assert item is not None
    renewed = queue.heartbeat("m1", worker_id="a", now="2026-01-01T00:00:00.500000+00:00", lease_seconds=10)
    assert renewed.lease_owner == "a"
    with pytest.raises(PermissionError):
        queue.update("m1", WorkerMissionState.COMPLETED, worker_id="stale")
    queue.recover_expired(now="2026-01-01T00:00:11+00:00")
    queue.claim_next(now="2026-01-01T00:00:11+00:00", worker_id="b", lease_seconds=10)
    with pytest.raises(PermissionError):
        queue.update("m1", WorkerMissionState.COMPLETED, worker_id="a")


def test_mission_http_api_routes_use_bridge_auth_and_mission_service(tmp_path, monkeypatch):
    import bridge
    import security.owner_policy as owner_policy
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "owner-test")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "api.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, payload=None, token="owner-test", bridge_token="bridge-test"):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {"X-CyberSentinel-Token": bridge_token, "X-CyberSentinel-Owner-Token": token}
        raw = None
        if payload is not None:
            raw = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        body = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, body

    plan = {"version": 1, "objective": "Check status for api mission", "steps": [{"step_id": "s1", "objective": "status", "action": "status"}]}
    try:
        status, created = request("POST", "/api/missions", {"objective": "Check status for api mission", "plan": plan})
        assert status == 201
        mission_id = created["mission_id"]
        assert created["mission"]["progress"]["execution_mode"] == "dag"
        assert created["mission"]["owner_instruction"] == "Check status for api mission"
        for suffix in ("", "/status", "/timeline", "/evidence", "/artifacts", "/logs"):
            code, body = request("GET", f"/api/missions/{mission_id}{suffix}")
            assert code == 200 and body["ok"] is True
        code, _ = request("POST", f"/api/missions/{mission_id}/start")
        assert code == 200
        code, _ = request("POST", f"/api/missions/{mission_id}/pause")
        assert code == 200
        code, _ = request("POST", f"/api/missions/{mission_id}/resume")
        assert code == 200
        code, _ = request("POST", f"/api/missions/{mission_id}/schedule", {"run_at": "2099-01-01T00:00:00+00:00"})
        assert code == 201
        code, _ = request("POST", f"/api/missions/{mission_id}/cancel")
        assert code == 200
        assert request("GET", f"/api/missions/{mission_id}", bridge_token="wrong")[0] == 401
        assert request("GET", f"/api/missions/{mission_id}", token="wrong")[0] == 403
    finally:
        server.shutdown()
        server.server_close()


def test_bridge_worker_executes_owner_graph_end_to_end(tmp_path, monkeypatch):
    import bridge
    import security.owner_policy as owner_policy
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "owner-test")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "api.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    http_thread = Thread(target=server.serve_forever, daemon=True)
    stop = Event()
    worker_thread = Thread(target=bridge.mission_worker_supervisor, args=(stop,), kwargs={"poll_seconds": 0.02}, daemon=True)
    http_thread.start()
    worker_thread.start()

    def request(method, path, payload=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {"X-CyberSentinel-Token": "bridge-test", "X-CyberSentinel-Owner-Token": "owner-test"}
        raw = None
        if payload is not None:
            raw = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        body = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, body

    instruction = "Check status for durable worker integration"
    plan = {"version": 1, "objective": instruction, "steps": [{"step_id": "status-1", "objective": "read current status", "action": "status"}]}
    try:
        code, created = request("POST", "/api/missions", {"text": instruction, "plan": plan})
        assert code == 201
        mission_id = created["mission_id"]
        code, queued = request("POST", f"/api/missions/{mission_id}/start")
        assert code == 200 and queued["mission"]["state"] == "queued"
        deadline = time.monotonic() + 5
        result = None
        while time.monotonic() < deadline:
            time.sleep(0.05)
            code, state = request("GET", f"/api/missions/{mission_id}/status")
            assert code == 200
            result = state["status"]
            if result["status"] in {MissionStatus.GOAL_COMPLETED.value, MissionStatus.AUTHORIZATION_BLOCKED.value, MissionStatus.FAILED_RETRY_EXHAUSTED.value}:
                break
        assert result is not None
        assert result["status"] == MissionStatus.GOAL_COMPLETED.value
        assert result["observations"]
        assert result["checkpoint"]["orchestration"]["completed_nodes"]
        queue = MissionQueue(tmp_path / "mission_queue.sqlite3")
        assert queue.get(mission_id).state is WorkerMissionState.COMPLETED
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        worker_thread.join(timeout=2)
        http_thread.join(timeout=2)


def test_http_chat_reaches_agent_core_and_deterministic_scheduler(tmp_path, monkeypatch):
    import bridge
    import api.chat as chat_module
    import security.owner_policy as owner_policy
    from agent.agent_core import AgentCore
    from agent.model_router import ModelRouter
    from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall

    class Provider:
        name = "http-e2e-test"
        model = "deterministic"
        capabilities = ProviderCapabilities(generate=True, tool_calling=True)

        def tool_calling(self, messages, tools, **kwargs):
            return ProviderResponse(tool_calls=[ToolCall("status", {}, "http-status")])

        def generate(self, messages, **kwargs):
            return {"content": json.dumps({"type": "final", "content": "verified"})}

    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "owner-test")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "api.sqlite3")
    core = AgentCore(ModelRouter([Provider()]), store=MissionStore(tmp_path / "chat-missions.sqlite3"))
    monkeypatch.setattr(chat_module, "_agent_core", lambda: core)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    instruction = "Check status and verify the HTTP chat route"
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        body = json.dumps({"text": instruction, "conversation_id": "http-dag-e2e"}).encode()
        connection.request("POST", "/api/chat", body=body, headers={"Content-Type": "application/json", "X-CyberSentinel-Token": "bridge-test", "X-CyberSentinel-Owner-Token": "owner-test"})
        response = connection.getresponse()
        payload = json.loads(response.read() or b"{}")
        connection.close()
        assert response.status == 200 and payload["ok"] is True
        mission = payload["mission"]
        assert mission["owner_instruction"] == instruction
        assert mission["progress"]["execution_mode"] == "dag"
        assert mission["checkpoint"]["orchestration"]["completed_nodes"]
        assert mission["status"] == MissionStatus.GOAL_COMPLETED.value
        assert mission["observations"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_restart_e2e_persists_mission_worker_evidence_and_revalidates(tmp_path):
    mission_db = tmp_path / "missions.sqlite3"
    queue_db = tmp_path / "queue.sqlite3"
    evidence_db = tmp_path / "evidence.sqlite3"
    plan = Plan.initial("restart objective").replan(steps=(PlanStep("s1", "write", action="write"),), reason="test")
    evidence_store = EvidenceChainStore(evidence_db)

    def execute(mission, _step, _action):
        snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
        workspace = Workspace(tmp_path, authorization_snapshot=snapshot).bind(mission_id=mission.mission_id, request_id=mission.request_id, tool_id="write", authorization_snapshot=snapshot, evidence_store=evidence_store)
        workspace.write("artifact.txt", "persisted")
        return {"success": True, "criterion_id": "write", "source": "workspace"}

    first = MissionRuntime(MissionStore(mission_db), executor=execute, authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)))
    mission = first.create("restart objective", "restart objective", plan, owner_identity_ref="test-owner", request_id="restart-request")
    queue = MissionQueue(queue_db)
    queue.enqueue(mission.mission_id)
    worker_item = queue.claim_next(worker_id="worker-a", lease_seconds=60)
    assert worker_item is not None
    result = first.run_to_completion(mission.mission_id, max_slices=3, heartbeat=lambda: queue.heartbeat(mission.mission_id, worker_id="worker-a"))
    assert result.status is MissionStatus.GOAL_COMPLETED
    queue.update(mission.mission_id, WorkerMissionState.COMPLETED, worker_id="worker-a")
    assert (tmp_path / "artifact.txt").read_text() == "persisted"
    assert evidence_store.verify() and evidence_store.list(request_id="restart-request")

    restarted_store = MissionStore(mission_db)
    restarted_queue = MissionQueue(queue_db)
    restarted_evidence = EvidenceChainStore(evidence_db)
    assert restarted_store.load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert restarted_evidence.verify()
    assert restarted_queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED


def test_expiry_after_restart_blocks_before_workspace(tmp_path):
    mission_db = tmp_path / "expiry.sqlite3"
    called = []
    expired_at = datetime.now(timezone.utc) + timedelta(milliseconds=50)
    plan = Plan.initial("expiry objective").replan(steps=(PlanStep("s1", "status", action="status"),), reason="test")
    snapshot = auth(str(tmp_path), expiry=expired_at, actions=["status"], tools=["status"])
    first = MissionRuntime(MissionStore(mission_db), executor=lambda *_: called.append(True), authorization_snapshot_factory=lambda _mission: snapshot)
    mission = first.create("expiry objective", "expiry objective", plan, owner_identity_ref="owner-proof")
    time.sleep(0.08)
    restarted = MissionRuntime(MissionStore(mission_db), executor=lambda *_: called.append(True))
    result = restarted.run_slice(mission.mission_id)
    assert result.status is MissionStatus.AUTHORIZATION_BLOCKED
    assert called == []


def test_authorized_self_repair_runs_only_after_authorization():
    repaired = []
    attempts = iter((RuntimeError("fail"), "fixed"))
    def action():
        value = next(attempts)
        if isinstance(value, Exception):
            raise value
        return value
    result = BoundedSelfRepair(max_retries=1).run(action, lambda exc: str(exc), lambda detail, attempt: repaired.append((detail, attempt)), lambda _value: True, authorize_repair=lambda _detail: True)
    assert result.success is True
    assert repaired == [("fail", 1)]
