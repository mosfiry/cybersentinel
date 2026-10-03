from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import queue as thread_queue
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import uuid

import pytest

from agent.agent_core import AgentCore
from agent.evidence import EvidenceChainStore
from agent.external_effects import EffectState, ExternalEffectLedger
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue, MissionScheduler, WorkerMissionState
from agent.planning import Plan, PlanStep
from api.missions import MissionService
from core import db as core_db
from security.owner_password import OWNER_USERNAME, create_owner_account, login, revoke_session
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import REGISTRY


ROOT = Path(__file__).resolve().parents[1]
CHILD = Path(__file__).with_name("mission_worker_child.py")
TEST_PASSWORD = "V10-only-ephemeral-test-password"


class _NoModelRouter:
    providers: tuple[()] = ()


@dataclass
class V10Environment:
    db_path: Path
    mission_db: Path
    queue_db: Path
    scheduler_db: Path
    evidence_db: Path
    workspace: Path
    owner_id: int
    owner_session_id: str
    core: AgentCore
    runtime: MissionRuntime
    queue: MissionQueue
    scheduler: MissionScheduler
    service: MissionService

    def create_mission(self, *, action: str = "watch", keyword: str | None = None):
        request_id = "v10-" + uuid.uuid4().hex
        objective = f"V10 process durability fixture {request_id}"
        context, _policy_context = self.core._auth(
            objective, self.owner_session_id, request_id
        )
        query = "." if action == "run_project_tests" else keyword or f"v10-{uuid.uuid4().hex}"
        step = PlanStep(
            step_id="v10-step-1",
            objective=objective,
            action=action,
            retry_policy={"arguments": {"query": query}} if action in {"watch", "run_project_tests"} else {},
        )
        plan = Plan.initial(objective).replan(
            steps=(step,),
            reason="V10 real process-death fixture",
        )

        def snapshot_factory(mission):
            base = MissionAuthorizationSnapshot.create(
                owner_identity=mission.owner_identity_ref,
                mission_id=mission.mission_id,
                target_identity="v10-local-target",
                scope=("local-test",),
                allowed_actions=(action, "status"),
                forbidden_actions=(),
                allowed_tools=(action, "status"),
                time_window={"timezone": "UTC"},
                max_duration=3600,
                rate_limits={action: 10, "status": 10},
                network_boundary={"allowed": ()},
                data_boundary={"allowed": ("v10-local-target",)},
                credential_boundary={"allowed": ()},
                workspace_boundary={"root": str(self.workspace.resolve())},
                policy_version="v10-process-test-v1",
                owner_approval=context.owner_evidence.proof_fingerprint,
            )
            return base

        mission = self.runtime.create_from_owner_instruction(
            instruction=objective,
            plan=plan,
            authorization_context=context,
            scope_snapshot={
                "target_id": "v10-local-target",
                "workspace_root": str(self.workspace.resolve()),
                "allowed_targets": ["v10-local-target"],
                "allowed_networks": [],
                "allowed_credentials": [],
            },
            completion_criteria=[
                {
                    "criterion_id": "mission-goal",
                    "description": "the one-step local action completed",
                    "check": "runtime",
                    "required": True,
                }
            ],
            authorization_snapshot_factory=snapshot_factory,
        )
        return mission, query

    def enqueue(self, mission) -> None:
        self.service.start_mission(
            mission.mission_id,
            owner_session_token=self.owner_session_id,
        )


@pytest.fixture
def v10_env(tmp_path, monkeypatch) -> V10Environment:
    db_path = tmp_path / "intel.sqlite3"
    monkeypatch.setattr(core_db, "DB_PATH", db_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    owner_id = create_owner_account(OWNER_USERNAME, TEST_PASSWORD)
    session = login(OWNER_USERNAME, TEST_PASSWORD)
    core = AgentCore(
        _NoModelRouter(),
        db_path=db_path.with_name("missions.sqlite3"),
    )
    queue = MissionQueue(
        db_path.with_name("mission_queue.sqlite3"),
        require_execution_fence=True,
        mission_store=core.store,
    )
    scheduler = MissionScheduler(
        db_path.with_name("mission_scheduler.sqlite3"),
        queue,
        mission_store=core.store,
    )
    runtime = MissionRuntime(
        core.store,
        executor=core._executor,
        require_authorization_snapshot=True,
        require_execution_fence=True,
    )
    service = MissionService(
        runtime,
        queue,
        scheduler,
        owner_revalidator=core.prepare_mission_for_queue,
    )
    return V10Environment(
        db_path=db_path,
        mission_db=db_path.with_name("missions.sqlite3"),
        queue_db=db_path.with_name("mission_queue.sqlite3"),
        scheduler_db=db_path.with_name("mission_scheduler.sqlite3"),
        evidence_db=db_path.with_name("evidence_chain.db"),
        workspace=workspace,
        owner_id=owner_id,
        owner_session_id=session["session_id"],
        core=core,
        runtime=runtime,
        queue=queue,
        scheduler=scheduler,
        service=service,
    )


class WorkerProcess:
    def __init__(
        self,
        process: subprocess.Popen[str],
        *,
        child_script: Path,
        db_path: Path,
        temp_root: Path,
    ):
        self.process = process
        self.child_script = child_script.resolve()
        self.db_path = db_path.resolve()
        self.temp_root = temp_root.resolve()
        self._verify_disposable_target()
        self.events: thread_queue.Queue[dict | None] = thread_queue.Queue()
        self.pending: list[dict] = []
        self.stderr: list[str] = []
        self._out_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._err_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._out_thread.start()
        self._err_thread.start()

    def _verify_disposable_target(self) -> None:
        try:
            self.db_path.relative_to(self.temp_root)
        except ValueError as exc:
            raise AssertionError("V10 child DB_PATH must be inside its pytest temporary directory") from exc
        if self.process.poll() is not None:
            raise AssertionError("V10 child exited before its PID could be verified")
        args = self.process.args
        if (
            not isinstance(args, (list, tuple))
            or len(args) < 2
            or Path(args[1]).resolve() != self.child_script
        ):
            raise AssertionError("refusing to signal a process that is not the V10 child harness")
        proc_dir = Path("/proc") / str(self.process.pid)
        try:
            live_args = [os.fsdecode(item) for item in (proc_dir / "cmdline").read_bytes().split(b"\0") if item]
            raw_env = (proc_dir / "environ").read_bytes().split(b"\0")
        except OSError as exc:
            raise AssertionError("unable to verify the live V10 child process identity") from exc
        if (
            len(live_args) < 2
            or Path(live_args[1]).resolve() != self.child_script
            or Path(live_args[0]).resolve() != Path(args[0]).resolve()
        ):
            raise AssertionError("live PID does not belong to the expected V10 child harness")
        live_env = {}
        for item in raw_env:
            key, separator, value = item.partition(b"=")
            if separator:
                live_env[os.fsdecode(key)] = os.fsdecode(value)
        if (
            live_env.get("DB_PATH") != str(self.db_path)
            or live_env.get("PYTHON_DOTENV_DISABLED") != "1"
            or not Path(live_env.get("DB_PATH", "/")).resolve().is_relative_to(self.temp_root)
        ):
            raise AssertionError("refusing to signal a child without a verified temporary-only database")

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            text = line.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                value = {"event": "non_json_output", "text": text[:240]}
            self.events.put(value)
        self.events.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line.rstrip()[:500])

    def send(self, command: str) -> None:
        if self.process.stdin is None or self.process.poll() is not None:
            raise AssertionError("cannot send a control line to an exited V10 child")
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def expect_any(self, names: set[str], timeout: float = 20.0) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self.pending):
                if event.get("event") in names:
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"timed out waiting for {sorted(names)}; child={self.process.poll()}, "
                    f"stderr={self.stderr[-10:]}, pending={self.pending[-10:]}"
                )
            try:
                event = self.events.get(timeout=remaining)
            except thread_queue.Empty as exc:
                raise AssertionError(
                    f"timed out waiting for {sorted(names)}; child={self.process.poll()}, "
                    f"stderr={self.stderr[-10:]}, pending={self.pending[-10:]}"
                ) from exc
            if event is None:
                raise AssertionError(
                    f"child exited before {sorted(names)}; returncode={self.process.poll()}, "
                    f"stderr={self.stderr[-10:]}, pending={self.pending[-10:]}"
                )
            if event.get("event") == "child_error":
                raise AssertionError(f"V10 child error: {event}; stderr={self.stderr[-10:]}")
            if event.get("event") in names:
                return event
            self.pending.append(event)

    def expect(self, name: str, timeout: float = 20.0) -> dict:
        return self.expect_any({name}, timeout=timeout)

    def signal(self, signum: int) -> None:
        self._verify_disposable_target()
        self.process.send_signal(signum)

    def wait(self, timeout: float = 20.0) -> int:
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.signal(signal.SIGKILL)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired as wait_exc:
                raise AssertionError("V10 child was not reaped after guarded SIGKILL") from wait_exc
            if self.process.poll() is None:
                raise AssertionError("V10 child remained live after guarded SIGKILL")
            raise AssertionError(
                f"V10 child did not exit within {timeout}s; stderr={self.stderr[-10:]}"
            ) from exc

    def cleanup(self) -> None:
        try:
            if self.process.poll() is None:
                self.signal(signal.SIGKILL)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise AssertionError("V10 child was not reaped during cleanup") from exc
            if self.process.poll() is None:
                raise AssertionError("V10 child remained live after cleanup")
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()


@pytest.mark.parametrize(
    ("args", "db_path", "expected_error"),
    [
        ([sys.executable, str(ROOT / "bridge.py")], "temporary", "not the V10 child harness"),
        ([sys.executable, str(CHILD)], "outside", "inside its pytest temporary directory"),
    ],
)
def test_v10_signal_guard_never_signals_wrong_process_or_runtime_database(
    tmp_path, args, db_path, expected_error
):
    signaled: list[int] = []

    class FakeProcess:
        pid = 1
        returncode = None

        def __init__(self):
            self.args = args

        def poll(self):
            return None

        def send_signal(self, signum):
            signaled.append(signum)

    worker = WorkerProcess.__new__(WorkerProcess)
    worker.process = FakeProcess()
    worker.child_script = CHILD.resolve()
    worker.temp_root = tmp_path.resolve()
    worker.db_path = (
        tmp_path / "disposable.sqlite3"
        if db_path == "temporary"
        else tmp_path.parent / "must-not-be-opened.sqlite3"
    )

    with pytest.raises(AssertionError, match=expected_error):
        worker.signal(signal.SIGKILL)
    assert signaled == []


def test_v10_cleanup_fails_if_guarded_child_cannot_be_reaped():
    signaled: list[int] = []

    class TimedOutProcess:
        pid = 1
        args = [sys.executable, str(CHILD)]
        returncode = None
        stdin = stdout = stderr = None

        def poll(self):
            return None

        def wait(self, *, timeout):
            raise subprocess.TimeoutExpired(cmd="v10-child", timeout=timeout)

    worker = WorkerProcess.__new__(WorkerProcess)
    worker.process = TimedOutProcess()
    worker.signal = lambda signum: signaled.append(signum)

    with pytest.raises(AssertionError, match="was not reaped during cleanup"):
        worker.cleanup()
    assert signaled == [signal.SIGKILL]


@pytest.fixture
def children(v10_env):
    running: list[WorkerProcess] = []
    yield running
    for child in reversed(running):
        child.cleanup()
    for path in (
        v10_env.db_path,
        v10_env.mission_db,
        v10_env.queue_db,
        v10_env.scheduler_db,
        v10_env.evidence_db,
    ):
        if not path.exists():
            continue
        with sqlite3.connect(path, timeout=5, isolation_level=None) as connection:
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            assert journal_mode in {"delete", "truncate", "persist"}, (
                f"{path.name} must remain reopenable in rollback-journal mode, got {journal_mode}"
            )
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
            connection.execute("SELECT name FROM sqlite_master").fetchall()


def _spawn(
    children: list[WorkerProcess],
    tmp_path: Path,
    env: V10Environment,
    *,
    worker_id: str,
    mission_id: str,
    mode: str = "count_only",
) -> WorkerProcess:
    child_home = tmp_path / ("home-" + uuid.uuid4().hex)
    child_home.mkdir()
    child_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(child_home),
        "DB_PATH": str(env.db_path),
        "PYTHONPATH": str(ROOT),
        "PYTHON_DOTENV_DISABLED": "1",
        "PYTHONUNBUFFERED": "1",
        "LANG": "C.UTF-8",
    }
    process = subprocess.Popen(
        [
            sys.executable,
            str(CHILD),
            "--worker-id",
            worker_id,
            "--mission-id",
            mission_id,
            "--mode",
            mode,
        ],
        cwd=ROOT,
        env=child_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    wrapped = WorkerProcess(
        process,
        child_script=CHILD,
        db_path=env.db_path,
        temp_root=tmp_path,
    )
    children.append(wrapped)
    return wrapped


def _one_poll(child: WorkerProcess) -> dict:
    child.send("poll")
    result = child.expect("poll_result")
    stopped = child.expect("stopped")
    assert stopped["state"] in {"STOPPED", "FAILED"}
    assert child.wait() == 0
    return result


def _expire_claim(env: V10Environment, mission_id: str) -> None:
    expired = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    with sqlite3.connect(env.queue_db) as db:
        changed = db.execute(
            "UPDATE mission_queue SET lease_expires_at=? WHERE mission_id=? AND state=?",
            (expired, mission_id, WorkerMissionState.EXECUTING.value),
        ).rowcount
    assert changed == 1


def _counter(env: V10Environment, tool_name: str) -> int:
    with sqlite3.connect(env.db_path) as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='v10_test_dispatch_counts'"
        ).fetchone()
        if exists is None:
            return 0
        row = db.execute(
            "SELECT call_count FROM v10_test_dispatch_counts WHERE tool_name=?",
            (tool_name,),
        ).fetchone()
    return 0 if row is None else int(row[0])


def _watch_count(env: V10Environment, keyword: str) -> int:
    with sqlite3.connect(env.db_path) as db:
        row = db.execute(
            "SELECT COUNT(*) FROM watches WHERE keyword=?",
            (keyword,),
        ).fetchone()
    return int(row[0])


def _effect_states(env: V10Environment, mission_id: str) -> list[str]:
    effects = ExternalEffectLedger(env.queue_db).list_effects(mission_id=mission_id)
    return [item.state.value if hasattr(item.state, "value") else str(item.state) for item in effects]


def _recover_child(children, tmp_path, env, mission_id: str, *, worker_id: str | None = None, mode: str = "count_only"):
    child = _spawn(
        children,
        tmp_path,
        env,
        worker_id=worker_id or ("recovery-" + uuid.uuid4().hex[:12]),
        mission_id=mission_id,
        mode=mode,
    )
    child.expect("ready")
    result = _one_poll(child)
    return child, result


@pytest.mark.parametrize(
    ("argv", "expected_worker_id"),
    [([], "worker"), (["--worker-id", "worker-green"], "worker-green")],
)
def test_supervised_cli_preserves_default_and_accepts_distinct_worker_identity(
    monkeypatch, capsys, argv, expected_worker_id
):
    import scripts.run_mission_worker as cli

    captured: list[str] = []

    class FakeSupervisor:
        def __init__(self, worker, *, poll_interval_seconds):
            assert poll_interval_seconds == 1.0
            self.worker = worker
            self.state = cli.SupervisorState.STARTING

        @contextmanager
        def install_signal_handlers(self):
            yield self

        def health(self):
            return {"state": self.state.value}

        def start(self):
            self.state = cli.SupervisorState.RUNNING
            return self.health()

        def serve_forever(self, *, max_iterations=None):
            assert max_iterations is None
            self.state = cli.SupervisorState.STOPPED
            return self.health()

    def build(*, worker_id="worker"):
        captured.append(worker_id)
        return SimpleNamespace(worker_id=worker_id)

    monkeypatch.setattr(cli, "build_mission_worker", build)
    monkeypatch.setattr(cli, "RuntimeSupervisor", FakeSupervisor)
    assert cli.main(argv) == 0
    assert captured == [expected_worker_id]
    assert "worker_state" in capsys.readouterr().out


def test_sigterm_before_claim_does_not_dispatch_and_restart_quarantines_owner_work(
    tmp_path, v10_env, children
):
    mission, keyword = v10_env.create_mission()
    child = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-before-claim",
        mission_id=mission.mission_id,
        mode="before_poll",
    )
    child.expect("ready")
    v10_env.enqueue(mission)
    child.send("poll")
    assert child.expect("barrier")["point"] == "before_claim"
    child.signal(signal.SIGTERM)
    child.send("continue")
    result = child.expect("poll_result")
    assert result["claimed"] is False
    assert child.expect("stopped")["state"] == "STOPPED"
    assert child.wait() == 0
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.QUEUED
    assert _counter(v10_env, "watch") == 0
    assert _watch_count(v10_env, keyword) == 0

    replacement, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert _counter(v10_env, "watch") == 0


def test_sigkill_after_claim_before_mission_binding_is_quarantined(tmp_path, v10_env, children):
    mission, keyword = v10_env.create_mission()
    first = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-claim-before-bind",
        mission_id=mission.mission_id,
        mode="after_claim",
    )
    first.expect("ready")
    v10_env.enqueue(mission)
    first.send("poll")
    event = first.expect("barrier")
    assert event["point"] == "after_claim_before_bind"
    claimed = v10_env.queue.get(mission.mission_id)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.claim_phase == "CLAIMED"
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.READY
    first.signal(signal.SIGKILL)
    assert first.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    parked = v10_env.queue.get(mission.mission_id)
    assert parked.state is WorkerMissionState.NEEDS_INPUT
    assert parked.lease_owner is None
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert _counter(v10_env, "watch") == 0
    assert _watch_count(v10_env, keyword) == 0


def test_sigkill_during_readonly_tool_after_inflight_checkpoint_is_not_replayed(
    tmp_path, v10_env, children
):
    mission, _keyword = v10_env.create_mission(action="status")
    child = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-readonly-execution",
        mission_id=mission.mission_id,
        mode="before_handler",
    )
    child.expect("ready")
    v10_env.enqueue(mission)
    child.send("poll")
    assert child.expect("barrier")["point"] == "before_handler"
    current = v10_env.core.store.load(mission.mission_id)
    assert current.checkpoint["status"] == "in_flight"
    assert v10_env.queue.get(mission.mission_id).claim_phase == "BOUND"
    child.signal(signal.SIGKILL)
    assert child.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(
        children,
        tmp_path,
        v10_env,
        mission.mission_id,
        mode="count_status",
    )
    assert result["claimed"] is False
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert _effect_states(v10_env, mission.mission_id) == []
    assert _counter(v10_env, "status") == 0


def test_sigkill_after_effect_dispatch_before_handler_outcome_preserves_ambiguity(
    tmp_path, v10_env, children
):
    mission, keyword = v10_env.create_mission()
    child = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-dispatched-before-handler",
        mission_id=mission.mission_id,
        mode="before_watch_handler",
    )
    child.expect("ready")
    v10_env.enqueue(mission)
    child.send("poll")
    assert child.expect("barrier")["point"] == "before_handler"
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    assert _counter(v10_env, "watch") == 0
    assert _watch_count(v10_env, keyword) == 0
    child.signal(signal.SIGKILL)
    assert child.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    assert _counter(v10_env, "watch") == 0
    assert _watch_count(v10_env, keyword) == 0


def test_sigkill_after_evidence_commit_keeps_chain_and_does_not_replay(
    tmp_path, v10_env, children
):
    (v10_env.workspace / "test_v10_process_evidence.py").write_text(
        "def test_v10_process_evidence():\n    assert 2 + 2 == 4\n",
        encoding="utf-8",
    )
    mission, _query = v10_env.create_mission(action="run_project_tests")
    child = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-evidence-boundary",
        mission_id=mission.mission_id,
        mode="after_evidence",
    )
    child.expect("ready")
    v10_env.enqueue(mission)
    child.send("poll")
    barrier = child.expect("barrier")
    assert barrier["point"] == "after_evidence_commit"
    chain = EvidenceChainStore(v10_env.evidence_db, mission_store=v10_env.core.store)
    records = chain.list()
    assert len(records) == 1
    assert chain.verify() is True
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    assert _counter(v10_env, "run_project_tests") == 0
    child.signal(signal.SIGKILL)
    assert child.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    recovered_chain = EvidenceChainStore(v10_env.evidence_db, mission_store=v10_env.core.store)
    assert recovered_chain.verify()
    assert len(recovered_chain.list()) == 1
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    assert _counter(v10_env, "run_project_tests") == 0


def test_sigkill_after_terminal_mission_save_recovers_queue_ack_without_reexecution(
    tmp_path, v10_env, children
):
    mission, keyword = v10_env.create_mission()
    child = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-terminal-before-ack",
        mission_id=mission.mission_id,
        mode="after_terminal_save",
    )
    child.expect("ready")
    v10_env.enqueue(mission)
    child.send("poll")
    assert child.expect("barrier")["point"] == "after_terminal_mission_commit"
    saved = v10_env.core.store.load(mission.mission_id)
    assert saved.status is MissionStatus.GOAL_COMPLETED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.EXECUTING
    child.signal(signal.SIGKILL)
    assert child.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED
    assert _counter(v10_env, "watch") == 1
    assert _watch_count(v10_env, keyword) == 1


def test_two_supervised_processes_racing_for_one_mission_claim_once(tmp_path, v10_env, children):
    mission, keyword = v10_env.create_mission()
    workers = [
        _spawn(
            children,
            tmp_path,
            v10_env,
            worker_id=f"v10-racer-{index}",
            mission_id=mission.mission_id,
            mode="race_claim",
        )
        for index in range(2)
    ]
    for child in workers:
        child.expect("ready")
    v10_env.enqueue(mission)
    for child in workers:
        child.send("poll")
    outcomes = [child.expect_any({"barrier", "poll_result"}) for child in workers]
    winners = [index for index, event in enumerate(outcomes) if event["event"] == "barrier"]
    losers = [index for index, event in enumerate(outcomes) if event["event"] == "poll_result"]
    assert len(winners) == len(losers) == 1
    winner_index = winners[0]
    assert outcomes[winner_index]["point"] == "after_claim_before_bind"
    assert outcomes[losers[0]]["claimed"] is False
    loser = workers[losers[0]]
    assert loser.expect("stopped")["state"] == "STOPPED"
    assert loser.wait() == 0
    claimed = v10_env.queue.get(mission.mission_id)
    assert claimed.state is WorkerMissionState.EXECUTING
    assert claimed.claim_phase == "CLAIMED"
    assert claimed.worker_instance_id == outcomes[winner_index]["worker_instance_id"]
    assert _counter(v10_env, "watch") == 0
    workers[winner_index].signal(signal.SIGKILL)
    assert workers[winner_index].wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(children, tmp_path, v10_env, mission.mission_id)
    assert result["claimed"] is False
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert _counter(v10_env, "watch") == 0
    assert _watch_count(v10_env, keyword) == 0


def test_old_worker_return_cannot_overwrite_a_new_generation_claim(tmp_path, v10_env, children):
    old_mission, old_keyword = v10_env.create_mission()
    old = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-stale-generation",
        mission_id=old_mission.mission_id,
        mode="after_handler",
    )
    old_ready = old.expect("ready")
    v10_env.enqueue(old_mission)
    old.send("poll")
    assert old.expect("barrier")["point"] == "after_handler"
    assert _watch_count(v10_env, old_keyword) == 1
    assert _effect_states(v10_env, old_mission.mission_id) == [EffectState.DISPATCHED.value]
    _expire_claim(v10_env, old_mission.mission_id)

    new_mission, new_keyword = v10_env.create_mission()
    new = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-stale-generation",
        mission_id=new_mission.mission_id,
        mode="after_claim",
    )
    new_ready = new.expect("ready")
    assert new_ready["runtime_generation"] == old_ready["runtime_generation"] + 1
    assert v10_env.core.store.load(old_mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert v10_env.queue.get(old_mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    v10_env.enqueue(new_mission)
    new.send("poll")
    claim_event = new.expect("barrier")
    assert claim_event["point"] == "after_claim_before_bind"
    new_claim_before = v10_env.queue.get(new_mission.mission_id)
    assert new_claim_before.state is WorkerMissionState.EXECUTING
    assert new_claim_before.claim_phase == "CLAIMED"
    assert new_claim_before.worker_instance_id == new_ready["worker_instance_id"]

    old.send("continue")
    old_result = old.expect("poll_result")
    assert old_result["claimed"] is True
    assert old.wait() == 0
    old_after = v10_env.queue.get(old_mission.mission_id)
    new_claim_after = v10_env.queue.get(new_mission.mission_id)
    assert v10_env.core.store.load(old_mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert old_after.state is WorkerMissionState.WAITING_FOR_TOOL
    assert new_claim_after == new_claim_before
    assert v10_env.core.store.load(new_mission.mission_id).status is MissionStatus.READY
    assert _watch_count(v10_env, old_keyword) == 1
    assert _watch_count(v10_env, new_keyword) == 0
    new.signal(signal.SIGKILL)
    assert new.wait() == -signal.SIGKILL


def test_applied_but_ambiguous_local_effect_is_not_replayed_after_restart(tmp_path, v10_env, children):
    mission, keyword = v10_env.create_mission()
    first = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-applied-ambiguous",
        mission_id=mission.mission_id,
        mode="after_handler",
    )
    first.expect("ready")
    v10_env.enqueue(mission)
    first.send("poll")
    assert first.expect("barrier")["point"] == "after_handler"
    assert _watch_count(v10_env, keyword) == 1
    assert _counter(v10_env, "watch") == 1
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    first.signal(signal.SIGKILL)
    assert first.wait() == -signal.SIGKILL
    _expire_claim(v10_env, mission.mission_id)

    _restart, result = _recover_child(
        children,
        tmp_path,
        v10_env,
        mission.mission_id,
        worker_id="v10-applied-ambiguous",
        mode="count_only",
    )
    assert result["claimed"] is False
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.RECOVERY_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.WAITING_FOR_TOOL
    assert _effect_states(v10_env, mission.mission_id) == [EffectState.DISPATCHED.value]
    assert _watch_count(v10_env, keyword) == 1
    assert _counter(v10_env, "watch") == 1


def test_restart_requires_new_owner_session_before_requeue(tmp_path, v10_env, children):
    mission, keyword = v10_env.create_mission()
    initial_snapshot = MissionAuthorizationSnapshot.from_dict(mission.authorization_snapshot)
    first = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-owner-reauth",
        mission_id=mission.mission_id,
        mode="count_only",
    )
    first.expect("ready")
    v10_env.enqueue(mission)
    first.signal(signal.SIGKILL)
    assert first.wait() == -signal.SIGKILL
    assert revoke_session(v10_env.owner_session_id) is True

    restarted = _spawn(
        children,
        tmp_path,
        v10_env,
        worker_id="v10-owner-reauth",
        mission_id=mission.mission_id,
        mode="count_only",
    )
    restarted.expect("ready")
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT
    with pytest.raises(PermissionError):
        v10_env.service.start_mission(
            mission.mission_id,
            owner_session_token=v10_env.owner_session_id,
        )
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.OWNER_REAUTH_REQUIRED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.NEEDS_INPUT

    fresh_session = login(OWNER_USERNAME, TEST_PASSWORD)
    v10_env.owner_session_id = fresh_session["session_id"]
    v10_env.service.start_mission(
        mission.mission_id,
        owner_session_token=fresh_session["session_id"],
    )
    renewed = v10_env.core.store.load(mission.mission_id)
    renewed_snapshot = MissionAuthorizationSnapshot.from_dict(renewed.authorization_snapshot)
    assert renewed.status is MissionStatus.READY
    assert renewed_snapshot.owner_identity == initial_snapshot.owner_identity
    assert renewed_snapshot.mission_id == mission.mission_id
    assert renewed_snapshot.version > initial_snapshot.version
    assert renewed_snapshot.authorization_hash != initial_snapshot.authorization_hash
    assert renewed_snapshot.owner_approval
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.QUEUED

    result = _one_poll_after_ready(restarted)
    assert result["claimed"] is True
    assert v10_env.core.store.load(mission.mission_id).status is MissionStatus.GOAL_COMPLETED
    assert v10_env.queue.get(mission.mission_id).state is WorkerMissionState.COMPLETED
    assert _counter(v10_env, "watch") == 1
    assert _watch_count(v10_env, keyword) == 1


def _one_poll_after_ready(child: WorkerProcess) -> dict:
    return _one_poll(child)
