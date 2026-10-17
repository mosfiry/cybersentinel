from __future__ import annotations

import io
import os
import signal
import sys
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from security.mission_authorization import MissionAuthorizationSnapshot
from workspace.environment import ProcessHandle, ProcessResult, Workspace, WorkspacePolicyError


def _result(exit_code, *, timed_out=False, cancelled=False):
    return ProcessResult(
        command=("python", "-c", "pass"),
        stdout="",
        stderr="",
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=0.01,
        cancelled=cancelled,
    )


def test_process_result_has_distinct_success_failure_timeout_and_cancellation_outcomes():
    assert (_result(0).outcome, _result(0).reason_code) == (
        "SUCCEEDED",
        "process_exit_zero",
    )
    assert (_result(1).outcome, _result(1).reason_code) == (
        "COMMAND_FAILED",
        "command_nonzero_exit",
    )
    assert (_result(None, timed_out=True).outcome, _result(None, timed_out=True).reason_code) == (
        "TIMED_OUT",
        "process_timeout",
    )
    assert (_result(None, cancelled=True).outcome, _result(None, cancelled=True).reason_code) == (
        "CANCELLED",
        "process_cancelled",
    )
    assert _result(0).sandbox_backend == "bubblewrap+prlimit+cgroup-v2"


def test_process_result_preserves_cgroup_resource_limit_reason():
    result = replace(_result(-9), resource_limit_reason="memory_max")

    assert result.outcome == "RESOURCE_LIMIT_EXCEEDED"
    assert result.reason_code == "memory_max"
    assert result.to_dict()["resource_limit_reason"] == "memory_max"


@pytest.mark.skipif(not hasattr(signal, "SIGXCPU"), reason="SIGXCPU is not available on this platform")
def test_process_result_distinguishes_cpu_resource_limit_signal():
    result = _result(-int(signal.SIGXCPU))
    assert result.outcome == "RESOURCE_LIMIT_EXCEEDED"
    assert result.reason_code == "resource_limit_signal"


def test_invalid_monitor_timeout_terminates_the_active_process(monkeypatch):
    from workspace import environment

    class FakeProcess:
        pid = 12345
        returncode = None
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def poll(self):
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        environment,
        "_stop_process_tree",
        lambda proc, *, grace_seconds=1.0: setattr(proc, "returncode", -int(signal.SIGTERM)),
    )
    handle = ProcessHandle(process, ("python", "-c", "pass"), 1024, max_timeout_seconds=5)

    with pytest.raises(WorkspacePolicyError, match="monitor timeout is outside"):
        handle.monitor(timeout=10)

    assert process.returncode == -int(signal.SIGTERM)
    assert handle._cleaned is True


def test_sandbox_availability_is_explicit_for_the_current_native_platform():
    availability = Workspace.process_sandbox_availability()
    assert isinstance(availability.available, bool)
    assert availability.backend
    if availability.available:
        assert availability.reason_code is None
        assert availability.detail_code is None
    else:
        assert availability.reason_code in {"backend_unavailable", "sandbox_setup_failed"}
        assert availability.detail_code
        assert availability.reason


@pytest.mark.skipif(sys.platform != "linux", reason="requires the Linux sandbox backend")
def test_pre_spawn_dispatch_failure_never_creates_a_child(tmp_path, monkeypatch):
    from workspace import process_sandbox

    backend = process_sandbox.LinuxBubblewrapBackend()
    availability = backend.availability()
    if not availability.available:
        pytest.skip(availability.reason or "native Linux sandbox backend unavailable")

    class FakeWorkspace:
        policy = SimpleNamespace(
            max_temp_bytes=1024 * 1024,
            max_total_artifact_bytes=1024 * 1024,
            max_memory_bytes=128 * 1024 * 1024,
            max_cpu_seconds=10,
            max_file_bytes=1024 * 1024,
            max_open_files=32,
            max_child_processes=8,
        )

        @staticmethod
        def _open_dir_fd(relative):
            path = tmp_path if str(relative) == "." else tmp_path / str(relative)
            return os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

    popen_calls = []
    monkeypatch.setattr(process_sandbox.subprocess, "Popen", lambda *args, **kwargs: popen_calls.append(args))
    artifact_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        with pytest.raises(RuntimeError, match="fence refused dispatch"):
            backend.spawn(
                FakeWorkspace(),
                (sys.executable, "-c", "raise SystemExit(99)"),
                cwd=".",
                artifact_fd=artifact_fd,
                start_marker_fd=artifact_fd,
                timeout=5,
                before_spawn=lambda _backend: (_ for _ in ()).throw(RuntimeError("fence refused dispatch")),
            )
    finally:
        os.close(artifact_fd)

    assert popen_calls == []


def test_workspace_spawn_holds_cross_process_start_gate_through_backend_spawn(tmp_path, monkeypatch):
    from security.dispatch_gate import MissionDispatchGate
    from workspace import environment

    store_path = tmp_path / "mission-store.sqlite3"
    mission_id = "mission-process-start-boundary"
    gate = MissionDispatchGate(store_path, mission_id)
    peer_gate = MissionDispatchGate(store_path, mission_id)
    authorized = []
    spawn_observations = []
    sentinel = object()
    context = SimpleNamespace(
        dispatch_gate=gate,
        tool_dispatch_lock=None,
        process_dispatch_lock=None,
        authorize_process_dispatch=lambda *, backend: authorized.append(backend),
    )

    class FakeBackend:
        backend_id = "contract-test-backend"

        def spawn(self, _workspace, _command, **kwargs):
            kwargs["before_spawn"](self.backend_id)
            with pytest.raises(TimeoutError):
                with peer_gate.process_start_guard(timeout=0.03):
                    pytest.fail("peer process start crossed the active Workspace spawn gate")
            spawn_observations.append("spawned-under-gate")
            return sentinel

    workspace = Workspace(
        tmp_path / "workspace",
        mission_id=mission_id,
        request_id="request-process-start-boundary",
        tool_id="run_project_tests",
        execution_context=context,
    )
    monkeypatch.setattr(workspace, "_require_process_authority", lambda: None)
    monkeypatch.setattr(environment, "get_process_sandbox_backend", lambda: FakeBackend())
    try:
        result = workspace._sandbox_popen(
            (sys.executable, "-c", "pass"),
            cwd=".",
            artifact_fd=1,
            start_marker_fd=2,
            timeout=1,
        )
        assert result is sentinel
        assert authorized == ["contract-test-backend"]
        assert spawn_observations == ["spawned-under-gate"]
        with peer_gate.process_start_guard(timeout=0.1):
            pass
    finally:
        workspace.close()


@pytest.mark.skipif(sys.platform != "linux", reason="requires the Linux sandbox backend contract")
def test_post_popen_missing_start_marker_is_ambiguous_not_no_effect(tmp_path, monkeypatch):
    from workspace import process_sandbox
    from workspace.cgroup_v2 import CgroupV2Manager
    from workspace.environment import ProcessSandboxSetupError

    backend = process_sandbox.LinuxBubblewrapBackend()
    monkeypatch.setattr(
        backend,
        "availability",
        lambda: process_sandbox.SandboxAvailability(True, backend.backend_id),
    )
    monkeypatch.setattr(
        process_sandbox.shutil,
        "which",
        lambda name, path=None: f"/usr/bin/{name}",
    )

    scope_state = {"killed": False, "cleaned": False}

    class FakeScope:
        path = tmp_path / "fake-cgroup"
        cgroup_procs = path / "cgroup.procs"

        def kill(self):
            scope_state["killed"] = True

        def cleanup(self, **_kwargs):
            scope_state["cleaned"] = True

    scope = FakeScope()

    class FakeManager:
        def create_scope(self, **_kwargs):
            return scope

    monkeypatch.setattr(
        CgroupV2Manager,
        "from_environment",
        classmethod(lambda _cls: FakeManager()),
    )

    class FakeWorkspace:
        policy = SimpleNamespace(
            max_temp_bytes=1024 * 1024,
            max_total_artifact_bytes=1024 * 1024,
            max_memory_bytes=128 * 1024 * 1024,
            max_cpu_seconds=10,
            max_file_bytes=1024 * 1024,
            max_open_files=32,
            max_child_processes=8,
        )

        @staticmethod
        def _open_dir_fd(_relative):
            return os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

    class FakeProcess:
        pid = 4242
        returncode = 0
        command_was_started = True

        def poll(self):
            return self.returncode

    process = FakeProcess()
    popen_calls = []
    monkeypatch.setattr(
        process_sandbox.subprocess,
        "Popen",
        lambda *args, **kwargs: popen_calls.append((args, kwargs)) or process,
    )
    artifact_fd = os.open(tmp_path / "artifact", os.O_CREAT | os.O_RDWR, 0o600)
    marker_fd = os.open(tmp_path / "start-marker", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with pytest.raises(ProcessSandboxSetupError) as caught:
            backend.spawn(
                FakeWorkspace(),
                (sys.executable, "-c", "pass"),
                cwd=".",
                artifact_fd=artifact_fd,
                start_marker_fd=marker_fd,
                timeout=5,
                before_spawn=lambda _backend: None,
            )
    finally:
        os.close(marker_fd)
        os.close(artifact_fd)

    assert len(popen_calls) == 1
    assert process.command_was_started is True
    assert scope_state == {"killed": True, "cleaned": True}
    assert caught.value.detail_code == "sandbox_command_start_unconfirmed"
    assert caught.value.no_effect_proof is None


def test_cgroup_attribution_failure_still_cleans_tree_without_no_effect_proof():
    from types import SimpleNamespace

    from workspace.environment import ProcessSandboxSetupError, _cleanup_sandbox_scope

    state = {"cleaned": False}

    class BrokenScope:
        def resource_limit_reason(self):
            raise OSError("synthetic event file failure")

        def cleanup(self, *, kill_if_populated=True):
            assert kill_if_populated is True
            state["cleaned"] = True

    process = SimpleNamespace(
        _cybersentinel_cgroup_scope=BrokenScope(),
        _cybersentinel_backend="linux-cgroup-v2",
    )
    with pytest.raises(ProcessSandboxSetupError) as caught:
        _cleanup_sandbox_scope(process)

    assert state["cleaned"] is True
    assert process._cybersentinel_cgroup_scope is None
    assert caught.value.detail_code == "cgroup_resource_event_attribution_unavailable"
    assert caught.value.no_effect_proof is None


def test_owner_cancel_commit_waits_for_active_process_dispatch_lock():
    from tools.registry import (
        _register_active_tool_cancellation,
        _unregister_active_tool_cancellation,
        cancel_active_mission_tool_executions,
    )

    mission_id = "mission-dispatch-cancel-race"
    cancellation_event = threading.Event()
    dispatch_lock = threading.Lock()
    cancel_started = threading.Event()
    marker_committed = threading.Event()
    _register_active_tool_cancellation(mission_id, cancellation_event, dispatch_lock)
    dispatch_lock.acquire()

    def request_cancel():
        cancel_started.set()
        cancel_active_mission_tool_executions(
            mission_id,
            before_signal=marker_committed.set,
        )

    worker = threading.Thread(target=request_cancel, daemon=True)
    try:
        worker.start()
        assert cancel_started.wait(timeout=2)
        assert not marker_committed.wait(timeout=0.1)
        assert worker.is_alive()
        dispatch_lock.release()
        assert marker_committed.wait(timeout=2)
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert cancellation_event.is_set()
        assert not dispatch_lock.locked()
    finally:
        if dispatch_lock.locked():
            dispatch_lock.release()
        worker.join(timeout=2)
        _unregister_active_tool_cancellation(mission_id, cancellation_event)


def test_owner_cancel_marker_serializes_late_tool_registration():
    from tools.registry import (
        _register_active_tool_cancellation,
        _unregister_active_tool_cancellation,
        cancel_active_mission_tool_executions,
    )

    mission_id = "mission-late-registration-cancel-race"
    active_event = threading.Event()
    active_lock = threading.Lock()
    late_event = threading.Event()
    late_lock = threading.Lock()
    marker_commit_started = threading.Event()
    allow_marker_commit = threading.Event()
    marker_committed = threading.Event()
    late_registration_started = threading.Event()
    late_registration_finished = threading.Event()
    late_registration_saw_marker = []
    _register_active_tool_cancellation(mission_id, active_event, active_lock)

    def commit_marker():
        marker_commit_started.set()
        assert allow_marker_commit.wait(timeout=2)
        marker_committed.set()

    def request_cancel():
        cancel_active_mission_tool_executions(mission_id, before_signal=commit_marker)

    def register_late_tool():
        late_registration_started.set()
        _register_active_tool_cancellation(mission_id, late_event, late_lock)
        late_registration_saw_marker.append(marker_committed.is_set())
        late_registration_finished.set()

    cancel_thread = threading.Thread(target=request_cancel, daemon=True)
    register_thread = threading.Thread(target=register_late_tool, daemon=True)
    try:
        cancel_thread.start()
        assert marker_commit_started.wait(timeout=2)
        register_thread.start()
        assert late_registration_started.wait(timeout=2)
        assert not late_registration_finished.wait(timeout=0.05)
        allow_marker_commit.set()
        assert marker_committed.wait(timeout=2)
        assert late_registration_finished.wait(timeout=2)
        assert late_registration_saw_marker == [True]
        assert active_event.is_set()
        assert not late_event.is_set()
    finally:
        allow_marker_commit.set()
        cancel_thread.join(timeout=2)
        register_thread.join(timeout=2)
        _unregister_active_tool_cancellation(mission_id, active_event)
        _unregister_active_tool_cancellation(mission_id, late_event)


def test_owner_cancel_commits_promptly_during_local_state_handler(tmp_path, monkeypatch):
    from agent import external_effects
    from tools import registry

    mission_id = "mission-local-state-cancel-race"
    request_id = "request-local-state-cancel-race"
    target_identity = "target-local-state-cancel-race"
    marker_committed = threading.Event()
    handler_entered = threading.Event()
    release_handler = threading.Event()
    ordering = []
    effect_events = []

    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:local-state-cancel-race",
        mission_id=mission_id,
        target_identity=target_identity,
        scope=("local-state",),
        allowed_actions=("watch",),
        forbidden_actions=(),
        allowed_tools=("watch",),
        time_window={"timezone": "UTC"},
        max_duration=60,
        rate_limits={"watch": 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": (target_identity,)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": ""},
        policy_version="test-local-state-cancel",
        owner_approval="owner-approved local watch",
    )

    class FakeLedger:
        def __init__(self, _db_path):
            pass

        def reserve(self, *_args, **_kwargs):
            return SimpleNamespace(effect_id="effect:watch", idempotency_key=None)

        def mark_dispatched(self, *_args, **_kwargs):
            effect_events.append("dispatched")

        def mark_succeeded(self, *_args, **_kwargs):
            effect_events.append("succeeded")

        def mark_failed(self, *_args, **_kwargs):
            effect_events.append("failed")

    monkeypatch.setattr(external_effects, "ExternalEffectLedger", FakeLedger)

    def local_watch(_argument):
        handler_entered.set()
        assert release_handler.wait(timeout=3)
        ordering.append("local-state-effect")
        return {"success": True, "result": "watch registered"}

    monkeypatch.setitem(
        registry.REGISTRY,
        "watch",
        replace(registry.REGISTRY["watch"], handler=local_watch),
    )

    class FakeFence:
        queue = SimpleNamespace(
            db_path=tmp_path / "mission-queue.sqlite3",
            owner_cancellation_requested=lambda _mission_id: marker_committed.is_set(),
        )

        @staticmethod
        def assert_dispatch(**_kwargs):
            return None

    result = []
    failures = []

    def invoke_watch():
        try:
            result.append(
                registry.execute(
                    "watch",
                    "critical",
                    request_id=request_id,
                    mission_authorization=snapshot,
                    mission_id=mission_id,
                    target_identity=target_identity,
                    execution_fence=FakeFence(),
                    execution_id="action-local-state-cancel-race",
                )
            )
        except BaseException as exc:  # preserve worker-thread failures for assertions
            failures.append(exc)

    worker = threading.Thread(target=invoke_watch, daemon=True)

    def commit_marker():
        ordering.append("owner-cancel-marker")
        marker_committed.set()

    cancel_thread = threading.Thread(
        target=lambda: registry.cancel_active_mission_tool_executions(
            mission_id,
            before_signal=commit_marker,
        ),
        daemon=True,
    )

    try:
        worker.start()
        assert handler_entered.wait(timeout=2)
        cancel_thread.start()
        assert marker_committed.wait(timeout=2)
        assert ordering == ["owner-cancel-marker"]

        release_handler.set()
        worker.join(timeout=2)
        cancel_thread.join(timeout=2)

        assert not worker.is_alive()
        assert not cancel_thread.is_alive()
        assert failures == []
        assert result == [{"success": True, "result": "watch registered"}]
        assert ordering == ["owner-cancel-marker", "local-state-effect"]
        assert effect_events == ["dispatched", "succeeded"]

        with pytest.raises(PermissionError, match="Owner cancellation requested"):
            registry.execute(
                "watch",
                "late",
                request_id="request-after-local-state-cancel",
                mission_authorization=snapshot,
                mission_id=mission_id,
                target_identity=target_identity,
                execution_fence=FakeFence(),
                execution_id="action-after-local-state-cancel",
            )
        assert effect_events == ["dispatched", "succeeded"]
    finally:
        release_handler.set()
        worker.join(timeout=2)
        cancel_thread.join(timeout=2)


@pytest.mark.skipif(os.name != "posix", reason="requires a native POSIX process backend")
def test_real_linux_sandbox_process_is_killed_after_cancellation(tmp_path):
    availability = Workspace.process_sandbox_availability()
    if not availability.available:
        pytest.skip(availability.reason or "native sandbox backend unavailable")
    (tmp_path / "test_slow.py").write_text(
        "import time\n\ndef test_slow():\n    time.sleep(30)\n",
        encoding="utf-8",
    )
    mission_id = "mission-process-cancel-test"
    request_id = "request-process-cancel-test"
    tool_id = "run_project_tests"
    cancellation_event = threading.Event()
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:process-cancel-test",
        mission_id=mission_id,
        target_identity="process-cancel-test-target",
        scope=("workspace",),
        allowed_actions=(tool_id,),
        forbidden_actions=(),
        allowed_tools=(tool_id,),
        time_window={"timezone": "UTC"},
        max_duration=60,
        rate_limits={tool_id: 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("process-cancel-test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path.resolve())},
        policy_version="test-process-cancellation",
        owner_approval="owner:process-cancel-test",
    )
    started_process_ids = []
    execution_context = SimpleNamespace(
        mission_id=mission_id,
        request_id=request_id,
        tool_id=tool_id,
        mission_authorization=snapshot,
        evidence_store=None,
        cancellation_event=cancellation_event,
        assert_active=lambda **_kwargs: None,
        notify_process_started=lambda *, backend, process_id, started_at_utc: started_process_ids.append(
            (process_id, started_at_utc)
        ),
    )
    workspace = Workspace(
        tmp_path,
        mission_id=mission_id,
        request_id=request_id,
        tool_id=tool_id,
        authorization_snapshot=snapshot,
        execution_context=execution_context,
    )
    result_holder = []
    worker = threading.Thread(
        target=lambda: result_holder.append(
            workspace.develop(
                ("python3", "-m", "pytest", "-q", "--junitxml=/artifacts/pytest.xml"),
                cwd=".",
                timeout=20,
                cancellation_event=cancellation_event,
            )
        ),
        daemon=True,
    )
    try:
        worker.start()
        deadline = time.monotonic() + 10
        while not started_process_ids and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert started_process_ids, "sandbox backend did not report a started process"
        process_id, started_at_utc = started_process_ids[0]
        assert process_id is not None
        assert started_at_utc and started_at_utc.endswith("+00:00")
        time.sleep(0.2)
        assert worker.is_alive(), "test process exited before cancellation was requested"
        cancellation_event.set()
        worker.join(timeout=10)
        assert not worker.is_alive(), "sandbox process did not stop after cancellation"
        assert len(result_holder) == 1
        result = result_holder[0]
        assert result.cancelled is True
        assert result.timed_out is False
        assert result.outcome == "CANCELLED"
        assert result.reason_code == "process_cancelled"
        assert result.process_id == process_id
        assert result.process_started_at_utc == started_at_utc
        with pytest.raises(ProcessLookupError):
            os.kill(process_id, 0)
    finally:
        cancellation_event.set()
        worker.join(timeout=10)
        workspace.close()


@pytest.mark.skipif(sys.platform != "win32", reason="requires a native Windows runner")
def test_native_windows_process_execution_fails_closed_until_appcontainer_backend_exists():
    availability = Workspace.process_sandbox_availability()
    assert availability.available is False
    assert availability.backend == "windows-appcontainer-job"
    assert availability.reason_code == "backend_unavailable"
    assert availability.detail_code == "windows_appcontainer_backend_unimplemented"
