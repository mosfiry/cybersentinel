from __future__ import annotations

import json
import multiprocessing
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from owner_session_testutils import allow_owner_sessions

import agent.memory as memory
import agent.task_manager as task_db
import core.db as core_db
from agent.model_router import ModelRouter
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.provider_api import ProviderCapabilities, ProviderResponse
from agent.task import TaskStatus
from agent.task_manager import TaskManager, TaskVersionConflictError
from agent.task_runtime import AgentTaskRuntime


BASE = "2026-01-01T00:00:00+00:00"


@pytest.fixture
def isolated_dbs(tmp_path, monkeypatch):
    task_path = Path(tmp_path) / "tasks.sqlite3"
    monkeypatch.setattr(task_db, "DB_PATH", task_path)
    monkeypatch.setattr(memory, "MEMORY_DB_PATH", Path(tmp_path) / "memory.sqlite3")
    monkeypatch.setattr(core_db, "DB_PATH", Path(tmp_path) / "core.sqlite3")
    task_db._init_db()
    memory._init_memory_db()
    core_db.connect().close()
    return Path(tmp_path)


def _claim_task_in_child(db_path: str, task_id: str, owner_session_id: str, gate, results) -> None:
    task_db.DB_PATH = Path(db_path)
    gate.wait(timeout=15)
    try:
        task = TaskManager.claim_task(task_id, owner_session_id)
        results.put(None if task is None else (task.status.value, task.task_version))
    except BaseException as exc:  # propagate child failures to the parent assertion
        results.put(("error", type(exc).__name__, str(exc)))


def test_competing_processes_claim_one_task_once(isolated_dbs):
    task = TaskManager.create_task("conv-multi", "req-multi", "owner", "serialized objective")
    ctx = multiprocessing.get_context("fork")
    gate = ctx.Barrier(3)
    results = ctx.Queue()
    workers = [
        ctx.Process(target=_claim_task_in_child, args=(str(task_db.DB_PATH), task.task_id, "owner", gate, results))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    gate.wait(timeout=15)
    outcomes = [results.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    assert all(not (isinstance(result, tuple) and result and result[0] == "error") for result in outcomes)
    assert sum(result is not None for result in outcomes) == 1
    persisted = TaskManager.get_task(task.task_id)
    assert persisted is not None
    assert persisted.status is TaskStatus.EXECUTING
    assert persisted.task_version == 1


def test_stale_task_snapshot_cannot_overwrite_a_newer_writer(isolated_dbs):
    task = TaskManager.create_task("conv-version", "req-version", "owner", "versioned objective")
    newer = TaskManager.get_task(task.task_id)
    stale = TaskManager.get_task(task.task_id)
    assert newer is not None and stale is not None
    assert newer.task_version == stale.task_version == 0

    newer.error = "newer writer"
    TaskManager.update_task(newer)
    assert newer.task_version == 1

    stale.error = "stale writer"
    with pytest.raises(TaskVersionConflictError, match="stale task version"):
        TaskManager.update_task(stale)

    persisted = TaskManager.get_task(task.task_id)
    assert persisted is not None
    assert persisted.error == "newer writer"
    assert persisted.task_version == 1


def test_deleted_version_zero_snapshot_cannot_resurrect_task(isolated_dbs):
    task = TaskManager.create_task("conv-delete", "req-delete", "owner", "delete fencing objective")
    stale = TaskManager.get_task(task.task_id)
    assert stale is not None and stale.task_version == 0

    assert TaskManager.delete_task(task.task_id) is True
    with pytest.raises(TaskVersionConflictError, match="row disappeared"):
        TaskManager.update_task(stale)
    assert TaskManager.get_task(task.task_id) is None


def test_legacy_task_table_migrates_with_zero_version(tmp_path, monkeypatch):
    db_path = Path(tmp_path) / "legacy-tasks.sqlite3"
    monkeypatch.setattr(task_db, "DB_PATH", db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("""CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, request_id TEXT NOT NULL,
            owner_session_id TEXT NOT NULL, authentication_method TEXT NOT NULL DEFAULT 'username_password',
            status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            started_at TEXT, finished_at TEXT, current_step INTEGER DEFAULT 0,
            tool_calls TEXT DEFAULT '[]', retry_count INTEGER DEFAULT 0, provider TEXT DEFAULT '', model TEXT DEFAULT '',
            objective TEXT DEFAULT '', execution_state TEXT DEFAULT '{}', result TEXT, error TEXT,
            cancel_requested INTEGER DEFAULT 0, pause_requested INTEGER DEFAULT 0, resume_state TEXT)""")
        db.execute(
            "INSERT INTO tasks(task_id,conversation_id,request_id,owner_session_id,status,created_at,updated_at,objective) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("legacy", "conv", "req", "owner", "queued", BASE, BASE, "legacy objective"),
        )

    task_db._init_db()
    migrated = TaskManager.get_task("legacy")
    assert migrated is not None
    assert migrated.task_version == 0
    with sqlite3.connect(db_path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(tasks)")}
    assert "task_version" in columns


def test_competing_queue_workers_claim_distinct_rows_once(tmp_path):
    db_path = tmp_path / "mission-queue.sqlite3"
    setup = MissionQueue(db_path)
    for index in range(6):
        setup.enqueue(f"mission-{index}", available_at=BASE)
    worker_queues = [MissionQueue(db_path) for _ in range(10)]
    gate = threading.Barrier(len(worker_queues) + 1)

    def claim(index: int):
        gate.wait(timeout=10)
        return worker_queues[index].claim_next(now=BASE, worker_id=f"worker-{index}", lease_seconds=60)

    with ThreadPoolExecutor(max_workers=len(worker_queues)) as pool:
        futures = [pool.submit(claim, index) for index in range(len(worker_queues))]
        gate.wait(timeout=10)
        claims = [future.result(timeout=15) for future in futures]

    winners = [item for item in claims if item is not None]
    assert len(winners) == 6
    assert len({item.mission_id for item in winners}) == 6
    assert len({item.lease_owner for item in winners}) == 6
    assert all(item.state is WorkerMissionState.EXECUTING and item.lease_epoch == 1 for item in winners)
    assert all(queue.claim_next(now=BASE, worker_id="late-worker") is None for queue in worker_queues)


def test_second_runtime_cannot_claim_while_first_model_slice_is_active(isolated_dbs, monkeypatch):
    allow_owner_sessions(monkeypatch, "owner")

    class BlockingProvider:
        name = "blocking"
        model = "blocking-1"
        capabilities = ProviderCapabilities(generate=True, stream=False, tool_calling=True, structured_output=True)

        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()
            self.started = threading.Event()
            self.release = threading.Event()

        def tool_calling(self, messages, tools, temperature=0, **kwargs):
            with self.lock:
                self.calls += 1
            self.started.set()
            if not self.release.wait(10):
                raise TimeoutError("test provider release was not signalled")
            return ProviderResponse(text=json.dumps({"type": "final", "content": "done"}), finish_reason="stop")

        def generate(self, messages, temperature=0, **kwargs):
            return self.tool_calling(messages, [], temperature, **kwargs)

    provider = BlockingProvider()
    runtime_a = AgentTaskRuntime(ModelRouter([provider]))
    runtime_b = AgentTaskRuntime(ModelRouter([provider]))
    task = runtime_a.create_task("conv-active", "keep one worker", owner_session_id="owner")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(runtime_a.run_slice, task.task_id, owner_session_token="owner")
        assert provider.started.wait(10)
        while_active = runtime_b.run_slice(task.task_id, owner_session_token="owner")
        assert provider.calls == 1
        assert while_active.status is TaskStatus.EXECUTING
        provider.release.set()
        completed = first.result(timeout=15)

    assert completed.status is TaskStatus.COMPLETED
    assert provider.calls == 1
    final = TaskManager.get_task(task.task_id)
    assert final is not None and final.status is TaskStatus.COMPLETED

@pytest.mark.parametrize(
    ("control_name", "expected_status"),
    [("request_pause", TaskStatus.PAUSED), ("request_cancel", TaskStatus.CANCELLED)],
)
def test_control_request_during_active_slice_never_makes_task_claimable(isolated_dbs, monkeypatch, control_name, expected_status):
    allow_owner_sessions(monkeypatch, "owner")

    class BlockingProvider:
        name = "blocking-control"
        model = "blocking-control-1"
        capabilities = ProviderCapabilities(generate=True, stream=False, tool_calling=True, structured_output=True)

        def __init__(self):
            self.calls = 0
            self.started = threading.Event()
            self.release = threading.Event()

        def tool_calling(self, messages, tools, temperature=0, **kwargs):
            self.calls += 1
            self.started.set()
            if not self.release.wait(10):
                raise TimeoutError("test provider release was not signalled")
            return ProviderResponse(text=json.dumps({"type": "final", "content": "done"}), finish_reason="stop")

        def generate(self, messages, temperature=0, **kwargs):
            return self.tool_calling(messages, [], temperature, **kwargs)

    provider = BlockingProvider()
    runtime_a = AgentTaskRuntime(ModelRouter([provider]))
    runtime_b = AgentTaskRuntime(ModelRouter([provider]))
    task = runtime_a.create_task("conv-active-control", "honor a concurrent control request", owner_session_id="owner")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(runtime_a.run_slice, task.task_id, owner_session_token="owner")
        assert provider.started.wait(10)
        requested = getattr(TaskManager, control_name)(task.task_id, "owner")
        assert requested is not None
        assert requested.status is TaskStatus.EXECUTING
        assert requested.pause_requested is (control_name == "request_pause")
        assert requested.cancel_requested is (control_name == "request_cancel")

        while_active = runtime_b.run_slice(task.task_id, owner_session_token="owner")
        assert while_active.status is TaskStatus.EXECUTING
        assert provider.calls == 1
        provider.release.set()
        yielded = first.result(timeout=15)

    assert yielded.status is expected_status
    persisted = TaskManager.get_task(task.task_id)
    assert persisted is not None and persisted.status is expected_status
    assert provider.calls == 1


def test_control_requests_preserve_owner_boundary_and_fence_stale_snapshot(isolated_dbs):
    task = TaskManager.create_task("conv-control", "req-control", "owner", "control objective")
    stale = TaskManager.get_task(task.task_id)
    assert stale is not None

    paused = TaskManager.request_pause(task.task_id, "owner")
    assert paused is not None
    assert paused.status is TaskStatus.PAUSED
    assert paused.pause_requested is True
    assert paused.task_version == 1

    stale.error = "stale overwrite attempt"
    with pytest.raises(TaskVersionConflictError):
        TaskManager.update_task(stale)
    assert TaskManager.request_cancel(task.task_id, "different-owner") is None

    cancelled = TaskManager.request_cancel(task.task_id, "owner")
    assert cancelled is not None
    assert cancelled.status is TaskStatus.PAUSED
    assert cancelled.cancel_requested is True
    assert cancelled.task_version == 2
