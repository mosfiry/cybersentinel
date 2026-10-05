from __future__ import annotations
from runtime_authorization import make_test_snapshot
from owner_session_testutils import allow_owner_sessions

from pathlib import Path
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
import json
import time

import pytest

from agent.evidence import EvidenceChainStore
from agent.execution_fence import ExecutionFence
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.mission import Mission, MissionStatus, MissionStore
from agent.planning import Plan, PlanStep
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.self_repair import BoundedSelfRepair
from agent.filesystem_verification import FilesystemVerifier
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationSnapshot
from security.session_reference import session_reference
from tools.registry import execute
from workspace import ProcessManager, Workspace, WorkspaceBoundaryError, WorkspacePolicy, WorkspacePolicyError


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
    import hashlib
    import socket
    from owner_session_testutils import allow_owner_sessions
    from security.authorization_context import AuthorizationContext
    from security.mission_authorization import MissionAuthorizationSnapshot
    from security.owner_policy import OwnerPolicySnapshot, _issue_evidence
    from security.scope import ProgramAuthorization, ScopeSnapshot, TargetIdentity

    request_id, session_id = "req-sandbox-test", "session-sandbox-test"
    mission_id, target_id = "mission-sandbox-test", "target-sandbox-test"
    scope_id, program_id = "scope-sandbox-test", "program-sandbox-test"
    allow_owner_sessions(monkeypatch, session_id)
    import security.owner_policy as owner_policy
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    monkeypatch.setenv("CYBERSENTINEL_SYNTHETIC_HOST_SECRET", "synthetic-test-only-value")

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    network_port = listener.getsockname()[1]
    outside_file = tmp_path.parent / f"{tmp_path.name}-host-only.txt"
    outside_file.write_text("host-only-test-data", encoding="utf-8")
    test_source = f'''\
import errno, os, resource, socket, subprocess, sys
from pathlib import Path
import pytest

HOST_ONLY_PATH = {str(outside_file)!r}
HOST_SERVICE_PORT = {network_port}

def test_host_environment_is_not_inherited():
    assert os.environ.get("CYBERSENTINEL_SYNTHETIC_HOST_SECRET") is None
    assert os.environ.get("OPENAI_API_KEY") is None

def test_workspace_is_read_only_and_host_files_are_absent():
    with pytest.raises(OSError):
        (Path(__file__).parent / "write-outside-workspace.txt").write_text("blocked")
    with pytest.raises(OSError):
        Path(HOST_ONLY_PATH).read_text(encoding="utf-8")
    with pytest.raises(OSError):
        Path(HOST_ONLY_PATH).write_text("blocked", encoding="utf-8")

def test_path_traversal_cannot_leave_workspace_or_reach_host_files():
    traversed_workspace_file = Path("../../workspace/project/test_sandbox_contract.py")
    assert traversed_workspace_file.read_text(encoding="utf-8")
    with pytest.raises(OSError):
        traversed_workspace_file.write_text("blocked", encoding="utf-8")
    relative_host_path = os.path.relpath(HOST_ONLY_PATH, os.getcwd())
    with pytest.raises(OSError):
        Path(relative_host_path).read_text(encoding="utf-8")

def test_host_network_is_unreachable():
    assert {{name for _, name in socket.if_nameindex()}} <= {{"lo"}}
    probe = socket.socket()
    probe.settimeout(0.2)
    try:
        with pytest.raises(OSError):
            probe.connect(("127.0.0.1", HOST_SERVICE_PORT))
    finally:
        probe.close()

def test_kernel_resource_limits_and_tmpfs_quotas_are_applied():
    assert resource.getrlimit(resource.RLIMIT_CPU)[0] <= 60
    assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 1_073_741_824
    assert resource.getrlimit(resource.RLIMIT_FSIZE)[0] <= 4_194_304
    assert resource.getrlimit(resource.RLIMIT_NOFILE)[0] <= 128
    assert resource.getrlimit(resource.RLIMIT_NPROC)[0] <= 32
    tmp = os.statvfs("/tmp")
    artifacts = os.statvfs("/artifacts")
    assert tmp.f_blocks * tmp.f_frsize <= 67_108_864 + tmp.f_frsize
    assert artifacts.f_blocks * artifacts.f_frsize <= 4_194_304 + artifacts.f_frsize

def test_file_descriptor_abuse_hits_the_kernel_limit():
    opened = []
    try:
        while True:
            opened.append(os.open("/dev/null", os.O_RDONLY))
    except OSError as exc:
        assert exc.errno == errno.EMFILE
    finally:
        for fd in opened:
            os.close(fd)
    assert len(opened) <= resource.getrlimit(resource.RLIMIT_NOFILE)[0]

def test_child_process_abuse_hits_the_kernel_limit():
    children = []
    refused = False
    try:
        for _ in range(40):
            try:
                child = os.fork()
            except OSError as exc:
                assert exc.errno == errno.EAGAIN
                refused = True
                break
            if child == 0:
                os._exit(0)
            children.append(child)
    finally:
        for child in children:
            os.waitpid(child, 0)
    assert refused and len(children) < 40

def test_file_size_abuse_hits_the_kernel_limit():
    path = f"/tmp/file-size-limit-{{os.getpid()}}"
    code = (
        "import os,signal,sys; signal.signal(signal.SIGXFSZ, signal.SIG_IGN); "
        "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600); "
        "block=b'x'*1048576; total=0\\n"
        "try:\\n"
        " while total < 6291456:\\n"
        "  try: total += os.write(fd, block)\\n"
        "  except OSError: break\\n"
        " else: raise AssertionError('file size limit not applied')\\n"
        "finally: os.close(fd)\\n"
    )
    completed = subprocess.run([sys.executable, "-c", code, path], capture_output=True, timeout=5)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert 0 < Path(path).stat().st_size <= resource.getrlimit(resource.RLIMIT_FSIZE)[0]
    Path(path).unlink()
'''
    test_contract = tmp_path / "test_sandbox_contract.py"
    test_contract.write_text(test_source, encoding="utf-8")

    now = datetime.now(timezone.utc)
    created, expires = now.isoformat(), (now + timedelta(minutes=30)).isoformat()
    owner_evidence = _issue_evidence("username_password", request_id, session_id, session_id)
    owner_policy = OwnerPolicySnapshot(
        request_id=request_id,
        owner_instruction="Owner-approved isolated workspace test",
        owner_instruction_fingerprint=hashlib.sha256(b"Owner-approved isolated workspace test").hexdigest(),
        owner_policy_fingerprint="sandbox-test-policy",
        authority_snapshot={}, authentication={}, captured_at=created,
    )
    program = ProgramAuthorization(
        program_id=program_id, platform="test", scope_version="1", retrieved_at=created,
        in_scope_assets=({"host": "127.0.0.1", "schemes": ["http"], "ports": [network_port], "paths": ["/"]},),
        owner_session_id=session_id,
    )
    target = TargetIdentity(target_id, program_id, "127.0.0.1", allowed_ports=(network_port,), allowed_paths=("/",))
    canonical_scope = ScopeSnapshot(scope_id, program, (target,), created_at=created, expires_at=expires)
    owner_auth = AuthorizationContext(request_id, owner_evidence, owner_policy, canonical_scope, session_id=session_id)
    scope_context = {
        "program_id": program_id, "target_id": target_id,
        "scope_snapshot_id": scope_id, "url": f"http://127.0.0.1:{network_port}/", "method": "GET",
    }
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:1", mission_id=mission_id, target_identity=target_id,
        scope=(scope_id,), allowed_actions=("run_project_tests",), forbidden_actions=(),
        allowed_tools=("run_project_tests",), time_window={"timezone": "UTC"}, max_duration=60,
        rate_limits={"run_project_tests": 5}, network_boundary={"allowed": ()},
        data_boundary={"allowed": (target_id,)}, credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path.resolve())}, policy_version="sandbox-test-v1",
        owner_approval="explicit-sandbox-test-approval", created_at=created, expires_at=expires,
    )
    decision = authorize_tool(["run_project_tests", "."], context=owner_auth)
    assert decision.allowed and decision.decision is not None

    mission_store = MissionStore(tmp_path / "missions.sqlite3")
    queue = MissionQueue(tmp_path / "mission-queue.sqlite3", require_execution_fence=True, mission_store=mission_store)
    queue.enqueue(mission_id)
    identity = queue.register_worker("governed-test-worker")
    identity_fence = ExecutionFence.for_worker(queue, identity)
    claim = queue.claim_next(
        now=datetime.now(timezone.utc).isoformat(), worker_id=identity.worker_id,
        worker_instance_id=identity.worker_instance_id,
        runtime_generation=identity.runtime_generation, execution_fence=identity_fence,
    )
    assert claim is not None
    mission_record = Mission.create(
        "workspace test", "workspace test",
        Plan(version=1, objective="workspace test", steps=(PlanStep("workspace-step", "run tests", action="run_project_tests"),)),
        mission_id=mission_id, request_id=request_id, owner_identity_ref=snapshot.owner_identity,
        authorization_snapshot=snapshot.to_dict(),
    )
    mission_record.scope_snapshot = scope_context
    mission_record.authorization_context = owner_auth.to_dict()
    mission_record.transition(MissionStatus.READY, "test mission ready")
    mission_store.save(mission_record)
    fence = identity_fence.with_lease(claim).for_mission(
        mission_record, task_id="workspace-step", execution_id="workspace-execution-1"
    )
    binding = mission_store.bind_execution_claim(mission_id, fence)
    assert binding.terminal_status is None and binding.lease_binding_id is not None
    mission_record = mission_store.load(mission_id)
    mission_record.checkpoint = {
        "status": "in_flight", "step_id": fence.task_id,
        "action_id": fence.execution_id, "plan_version": mission_record.plan.version,
    }
    mission_store.save(mission_record, execution_fence=fence)
    store = EvidenceChainStore(
        tmp_path / "evidence.sqlite3", execution_fence=fence,
        mission_store=mission_store, mission=mission_record, require_execution_fence=True,
    )
    workspace = Workspace(
        tmp_path, authorization_snapshot=snapshot, mission_id=mission_id,
        request_id=request_id, tool_id="run_project_tests", evidence_store=store,
    )
    try:
        with pytest.raises(WorkspaceBoundaryError):
            workspace.resolve("../")

        dispatch_args = dict(
            request_id=request_id, owner_authorization=owner_auth,
            owner_authorization_record=owner_auth.to_dict(), scope_context=scope_context,
            workspace=workspace, evidence_store=store, mission_id=mission_id,
            target_identity=target_id, execution_fence=fence,
            execution_id="workspace-execution-1",
        )
        with pytest.raises(PermissionError, match="current persisted Mission authorization version"):
            execute(
                "run_project_tests", ".", authorization_decision=decision.decision,
                mission_authorization=snapshot, **dispatch_args,
            )
        with pytest.raises(PermissionError, match="current persisted Mission authorization version"):
            execute(
                "run_project_tests", ".", authorization_decision=decision.decision,
                mission_authorization=snapshot,
                mission_authorization_version=snapshot.version + 1,
                **dispatch_args,
            )

        result = execute(
            "run_project_tests", ".", authorization_decision=decision.decision,
            request_id=request_id, mission_authorization=snapshot,
            mission_authorization_version=int(mission_record.provenance.get("authorization_snapshot_version", 1)),
            owner_authorization=owner_auth,
            owner_authorization_record=owner_auth.to_dict(), scope_context=scope_context,
            workspace=workspace, evidence_store=store, mission_id=mission_id,
            target_identity=target_id, execution_fence=fence,
            execution_id="workspace-execution-1",
        )
        assert result["ok"] is True, {key: result.get(key) for key in ("returncode", "output", "artifact_refs")}
        assert result["returncode"] == 0
        assert "8 passed" in result["output"]
        assert result["sandbox_backend"] == "bubblewrap+prlimit"
        assert result["artifact_refs"]
        assert not (tmp_path / "write-outside-workspace.txt").exists()
        records = store.list(request_id=request_id)
        assert records and store.verify()
        process_records = [record for record in records if record.get("source") == "sandboxed-process:run_project_tests"]
        assert len(process_records) == 1
        process_record = process_records[0]
        evidence_payload = process_record["evidence"]
        assert evidence_payload["record_type"] == "UNTRUSTED_SANDBOX_PROCESS_RESULT"
        assert evidence_payload["trust"] == "untrusted_data"
        assert evidence_payload["authority"] == "none"
        assert evidence_payload["network"] == "disabled"
        assert result["artifact_refs"][0]["validation"] == "unvalidated"
        assert "synthetic-test-only-value" not in repr(workspace.audit)
        assert process_record["mission_id"] == mission_id
        assert process_record["request_id"] == request_id
        assert process_record["task_id"] == "workspace-step"
        assert process_record["execution_id"] == "workspace-execution-1"
        assert process_record["authorization_hash"] == fence.authorization_hash
        assert process_record["fence_id"] == fence.fence_id
        assert outside_file.read_text(encoding="utf-8") == "host-only-test-data"

        timeout_root = tmp_path / "timeout-workspace"
        timeout_root.mkdir()
        timeout_marker = f"cybersentinel-sandbox-child-{tmp_path.name}"
        timeout_source = f'''\
import subprocess, sys, time

def test_detached_child_cannot_outlive_tool_cancellation():
    subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", {timeout_marker!r}],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    while True:
        time.sleep(0.1)
'''
        (timeout_root / "test_timeout.py").write_text(timeout_source, encoding="utf-8")
        timeout_mission_id = "mission-sandbox-timeout-test"
        timeout_snapshot_data = snapshot.to_dict()
        timeout_snapshot_data["mission_id"] = timeout_mission_id
        timeout_snapshot_data["workspace_boundary"] = {"root": str(timeout_root.resolve())}
        timeout_snapshot_data.pop("authorization_hash", None)
        timeout_snapshot = MissionAuthorizationSnapshot.from_dict(timeout_snapshot_data)
        timeout_mission = Mission.create(
            "timeout sandbox test", "timeout sandbox test",
            Plan(version=1, objective="timeout sandbox test", steps=(
                PlanStep("timeout-step", "cancel a detached child", action="run_project_tests"),
            )),
            mission_id=timeout_mission_id, request_id=request_id,
            owner_identity_ref=timeout_snapshot.owner_identity,
            authorization_snapshot=timeout_snapshot.to_dict(),
        )
        timeout_mission.scope_snapshot = scope_context
        timeout_mission.authorization_context = owner_auth.to_dict()
        timeout_mission.transition(MissionStatus.READY, "authorized timeout test")
        mission_store.save(timeout_mission)
        queue.enqueue(timeout_mission_id)
        timeout_identity = queue.register_worker("governed-timeout-test-worker")
        timeout_identity_fence = ExecutionFence.for_worker(queue, timeout_identity)
        timeout_claim = queue.claim_next(
            now=datetime.now(timezone.utc).isoformat(), worker_id=timeout_identity.worker_id,
            worker_instance_id=timeout_identity.worker_instance_id,
            runtime_generation=timeout_identity.runtime_generation,
            execution_fence=timeout_identity_fence,
        )
        assert timeout_claim is not None
        timeout_fence = timeout_identity_fence.with_lease(timeout_claim).for_mission(
            timeout_mission, task_id="timeout-step", execution_id="timeout-execution",
        )
        timeout_binding = mission_store.bind_execution_claim(timeout_mission_id, timeout_fence)
        assert timeout_binding.terminal_status is None and timeout_binding.lease_binding_id is not None
        timeout_mission = mission_store.load(timeout_mission_id)
        timeout_mission.checkpoint = {
            "status": "in_flight", "step_id": timeout_fence.task_id,
            "action_id": timeout_fence.execution_id, "plan_version": timeout_mission.plan.version,
        }
        mission_store.save(timeout_mission, execution_fence=timeout_fence)
        timeout_store = EvidenceChainStore(
            tmp_path / "timeout-evidence.sqlite3", execution_fence=timeout_fence,
            mission_store=mission_store, mission=timeout_mission, require_execution_fence=True,
        )
        timeout_workspace = Workspace(
            timeout_root, authorization_snapshot=timeout_snapshot,
            mission_id=timeout_mission_id, request_id=request_id,
            tool_id="run_project_tests", evidence_store=timeout_store,
        )
        try:
            from agent.external_effects import EffectRecoveryRequired

            with pytest.raises(EffectRecoveryRequired) as timed_out:
                execute(
                    "run_project_tests", ".", timeout=3.0,
                    authorization_decision=decision.decision,
                    request_id=request_id, mission_authorization=timeout_snapshot,
                    mission_authorization_version=int(timeout_mission.provenance.get("authorization_snapshot_version", 1)),
                    owner_authorization=owner_auth,
                    owner_authorization_record=owner_auth.to_dict(), scope_context=scope_context,
                    workspace=timeout_workspace, evidence_store=timeout_store,
                    mission_id=timeout_mission_id, target_identity=target_id,
                    execution_fence=timeout_fence, execution_id="timeout-execution",
                )
            assert timed_out.value.reason_code == "TOOL_TIMEOUT"
            assert timed_out.value.state == "RECOVERY_REQUIRED"
            deadline = time.monotonic() + 8
            process_events = []
            while time.monotonic() < deadline:
                process_events = [event for event in timeout_workspace.audit if event.operation == "process"]
                if process_events:
                    break
                time.sleep(0.05)
            assert process_events
            assert process_events[-1].result == "failure"
            assert process_events[-1].exit_code is None
            assert timeout_store.verify()
            time.sleep(0.2)
            marker_bytes = timeout_marker.encode("utf-8")
            marker_process_alive = False
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    if marker_bytes in (entry / "cmdline").read_bytes():
                        marker_process_alive = True
                        break
                except OSError:
                    continue
            assert not marker_process_alive
        finally:
            timeout_workspace.close()
    finally:
        listener.close()
        outside_file.unlink(missing_ok=True)
        workspace.close()


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


def test_workspace_rejects_symlink_swapped_after_authorization(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("do-not-read")
    entry = tmp_path / "entry"
    entry.mkdir()
    workspace = Workspace(
        tmp_path,
        authorization_snapshot=auth(str(tmp_path), actions=["read"], tools=[]),
    )
    original_authorize = workspace._authorize

    def authorize_then_swap(operation, **kwargs):
        original_authorize(operation, **kwargs)
        if operation == "read" and kwargs.get("path") == "entry/secret.txt":
            entry.rmdir()
            entry.symlink_to(outside, target_is_directory=True)

    workspace._authorize = authorize_then_swap
    with pytest.raises(WorkspaceBoundaryError):
        workspace.read("entry/secret.txt")
    assert (outside / "secret.txt").read_text() == "do-not-read"


def test_process_manager_requires_registry_execution_context_before_launch(tmp_path):
    workspace = Workspace(
        tmp_path,
        authorization_snapshot=auth(str(tmp_path), actions=["process"], tools=[]),
    )
    with pytest.raises(WorkspacePolicyError, match="ExecutionContext"):
        ProcessManager(workspace).start(("python", "-c", "raise SystemExit(0)"), cwd=".")
    assert workspace.audit == []


def test_process_output_is_bounded_while_captured(tmp_path):
    import io
    from workspace.environment import _drain_tail
    tail = bytearray()
    _drain_tail(io.BytesIO(b"x" * 1_000_000), tail, 128)
    assert len(tail) == 128
    assert bytes(tail) == b"x" * 128


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
        queue.heartbeat("m1", worker_id="b", lease_epoch=first.lease_epoch, now="2026-01-01T00:00:01+00:00")
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
    renewed = queue.heartbeat("m1", worker_id="a", lease_epoch=item.lease_epoch, now="2026-01-01T00:00:00.500000+00:00", lease_seconds=10)
    assert renewed.lease_owner == "a"
    with pytest.raises(PermissionError):
        queue.update("m1", WorkerMissionState.COMPLETED, worker_id="stale", lease_epoch=item.lease_epoch, now="2026-01-01T00:00:00.500000+00:00")
    queue.recover_expired(now="2026-01-01T00:00:11+00:00")
    replacement = queue.claim_next(now="2026-01-01T00:00:11+00:00", worker_id="b", lease_seconds=10)
    assert replacement is not None
    with pytest.raises(PermissionError):
        queue.update("m1", WorkerMissionState.COMPLETED, worker_id="a", lease_epoch=item.lease_epoch, now="2026-01-01T00:00:11+00:00")


def test_mission_http_api_routes_use_bridge_auth_and_mission_service(tmp_path, monkeypatch):
    import bridge
    import core.db as core_db
    import agent.task_manager as task_db
    from core.lifecycle import bind_owner, begin as begin_execution, get as get_execution
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test")
    allow_owner_sessions(monkeypatch, "owner-test", "other-owner")
    monkeypatch.setattr(bridge, "DB_PATH", tmp_path / "api.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "owner_auth.sqlite3")
    monkeypatch.setattr(task_db, "DB_PATH", tmp_path / "tasks.sqlite3")
    task_db._init_db()
    now = datetime.now(timezone.utc).isoformat()
    with core_db.connect() as auth_db:
        auth_db.execute(
            "INSERT INTO owner_accounts(username,password_hash,kdf_algorithm,kdf_params_json,status) "
            "VALUES(?,?,?,?,?)",
            ("owner-test-user", "test-verifier", "scrypt", "{}", "active"),
        )
        auth_db.execute(
            "INSERT INTO owner_sessions(session_id,owner_id,created_at,authenticated_at,expires_at,status,auth_method) "
            "VALUES(?,?,?,?,?,?,?)",
            (session_reference("owner-test"), 1, now, now, "2999-01-01T00:00:00+00:00", "active", "username_password"),
        )
    # Exercise the same startup migration that converts legacy raw references.
    with core_db.connect():
        pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, payload=None, token="owner-test", bridge_token="bridge-test"):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {"X-CyberSentinel-Token": bridge_token, "X-CyberSentinel-Owner-Session": token}
        raw = None
        if payload is not None:
            raw = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        body = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, body

    plan = {"version": 1, "objective": "api mission", "steps": [{"step_id": "s1", "objective": "status", "action": "status"}]}
    try:
        status, created = request(
            "POST",
            "/api/missions",
            {
                "objective": "api mission",
                "plan": plan,
                "scope_context": {
                    "scope": ["workspace"],
                    "target_id": "api-target",
                    "workspace_root": str(Path.cwd().resolve()),
                    "allowed_networks": [],
                    "allowed_credentials": [],
                    "forbidden_actions": [],
                },
            },
        )
        assert status == 201
        mission_id = created["mission_id"]
        report_chain = tmp_path / "evidence_chain.db"
        if not report_chain.exists():
            EvidenceChainStore(report_chain)
        for suffix in ("", "/status", "/timeline", "/evidence", "/artifacts", "/logs", "/report"):
            chain_before = report_chain.read_bytes() if suffix == "/report" else None
            code, body = request("GET", f"/api/missions/{mission_id}{suffix}")
            assert code == 200 and body["ok"] is True
            if suffix == "/report":
                assert body["report"]["schema_version"] == "cybersentinel.mission-report.v1"
                assert body["report"]["mission_summary"]["outcome"] == "UNKNOWN"
                assert report_chain.read_bytes() == chain_before
        code, start_result = request("POST", f"/api/missions/{mission_id}/start")
        assert code == 200, start_result
        code, _ = request("POST", f"/api/missions/{mission_id}/pause")
        assert code == 200
        code, _ = request("POST", f"/api/missions/{mission_id}/resume")
        assert code == 200
        code, schedule_result = request(
            "POST",
            f"/api/missions/{mission_id}/schedule",
            {"run_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()},
        )
        assert code == 201, schedule_result
        code, _ = request("POST", f"/api/missions/{mission_id}/cancel")
        assert code == 200
        assert request("GET", f"/api/missions/{mission_id}", bridge_token="wrong")[0] == 401
        assert request("GET", f"/api/missions/{mission_id}", token="wrong")[0] == 403
        assert request("GET", f"/api/missions/{mission_id}/report", token="wrong")[0] == 403

        core_db.ensure_conversation("owner-conversation", "owner-test")
        core_db.add_conversation_message("owner-conversation", "user", "owner-private")
        core_db.ensure_conversation("foreign-conversation", "other-owner")
        core_db.add_conversation_message("foreign-conversation", "user", "foreign-private")
        code, owner_session = request("GET", "/api/session/owner-conversation")
        assert code == 200 and owner_session["session"]["owner_session_id"]
        assert owner_session["session"]["messages"][0]["content"] == "owner-private"
        code, _ = request("GET", "/api/session/foreign-conversation")
        assert code == 404
        code, foreign_session = request("GET", "/api/session/foreign-conversation", token="other-owner")
        assert code == 200 and foreign_session["session"]["messages"][0]["content"] == "foreign-private"
        missing_status, missing = request("GET", "/api/session/not-found")
        assert missing_status == 404 and missing == {"ok": False, "error": "unknown_session"}
        assert request("GET", "/api/session/foreign-conversation")[1] == missing

        begin_execution("cancel-owned", "http-test")
        bind_owner("cancel-owned", "owner-test")
        assert request("POST", "/api/cancel", {"request_id": "cancel-owned"}, bridge_token="wrong")[0] == 401
        assert request("POST", "/api/cancel", {"request_id": "cancel-owned"}, token="")[0] == 403
        assert request("POST", "/api/cancel", {"request_id": "cancel-owned"}, token="other-owner")[0] == 404
        assert get_execution("cancel-owned").cancel_requested is False
        code, cancelled = request("POST", "/api/cancel", {"request_id": "cancel-owned"})
        assert code == 200 and cancelled["cancel_requested"] is True
        assert get_execution("cancel-owned").cancel_requested is True
    finally:
        server.shutdown()
        server.server_close()


def test_restart_e2e_persists_mission_worker_evidence_and_revalidates(tmp_path):
    mission_db = tmp_path / "missions.sqlite3"
    queue_db = tmp_path / "queue.sqlite3"
    evidence_db = tmp_path / "evidence.sqlite3"
    plan = Plan.initial("restart objective run project tests").replan(
        steps=(
            PlanStep("s1", "write artifact", action="write"),
            PlanStep("s2", "run project tests", action="run_project_tests"),
        ),
        reason="test",
    )
    evidence_store = EvidenceChainStore(evidence_db)

    def execute(mission, step, _action):
        if step.action == "run_project_tests":
            return {"success": True, "source": "run_project_tests", "result": {"ok": True, "returncode": 0, "timed_out": False}}
        snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
        workspace = Workspace(tmp_path, authorization_snapshot=snapshot).bind(mission_id=mission.mission_id, request_id=mission.request_id, tool_id="write", authorization_snapshot=snapshot, evidence_store=evidence_store)
        workspace.write("artifact.txt", "persisted")
        return {"success": True, "source": "workspace"}

    first = MissionRuntime(MissionStore(mission_db), executor=execute, authorization_snapshot_factory=lambda mission: make_test_snapshot(mission, root=str(tmp_path)))
    mission = first.create("restart objective", "restart objective run project tests", plan, owner_identity_ref="test-owner", request_id="restart-request", completion_criteria=[{"criterion_id": "tests", "check": "pytest_success"}])
    queue = MissionQueue(queue_db)
    queue.enqueue(mission.mission_id)
    worker_item = queue.claim_next(worker_id="worker-a", lease_seconds=60)
    assert worker_item is not None
    result = first.run_to_completion(mission.mission_id, max_slices=3, heartbeat=lambda: queue.heartbeat(mission.mission_id, worker_id="worker-a", lease_epoch=worker_item.lease_epoch))
    assert result.status is MissionStatus.GOAL_COMPLETED
    queue.update(mission.mission_id, WorkerMissionState.COMPLETED, worker_id="worker-a", lease_epoch=worker_item.lease_epoch)
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
