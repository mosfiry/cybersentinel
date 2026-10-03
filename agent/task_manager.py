"""SQLite-backed persistent task manager."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .state import TaskState
from .task import TERMINAL_STATUSES, Task, TaskStatus
from security.session_reference import normalize_persisted_session_fields, session_reference


class TaskVersionConflictError(RuntimeError):
    """Raised when a stale Task snapshot attempts to overwrite a newer row."""

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv("TASK_DB_PATH", str(ROOT / "tasks.sqlite3"))).expanduser()
_db_lock = threading.RLock()


@contextmanager
def _get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, request_id TEXT NOT NULL,
            owner_session_id TEXT NOT NULL, authentication_method TEXT NOT NULL DEFAULT 'username_password',
            status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            started_at TEXT, finished_at TEXT, current_step INTEGER DEFAULT 0,
            tool_calls TEXT DEFAULT '[]', retry_count INTEGER DEFAULT 0, provider TEXT DEFAULT '', model TEXT DEFAULT '',
            objective TEXT DEFAULT '', execution_state TEXT DEFAULT '{}', result TEXT, error TEXT,
            cancel_requested INTEGER DEFAULT 0, pause_requested INTEGER DEFAULT 0, resume_state TEXT)""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()}
        if "authentication_method" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN authentication_method TEXT NOT NULL DEFAULT 'username_password'")
        if "task_version" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN task_version INTEGER NOT NULL DEFAULT 0")
        rows = conn.execute(
            "SELECT task_id, owner_session_id, tool_calls, execution_state, result, resume_state FROM tasks"
        ).fetchall()
        for row in rows:
            owner_ref = session_reference(row["owner_session_id"] or "")
            updates: dict[str, str | None] = {}
            for column in ("tool_calls", "execution_state", "result", "resume_state"):
                raw = row[column]
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    continue
                normalized = normalize_persisted_session_fields(payload)
                encoded = json.dumps(normalized, ensure_ascii=False)
                if encoded != raw:
                    updates[column] = encoded
            if owner_ref != (row["owner_session_id"] or "") or updates:
                assignments = ["owner_session_id=?"]
                values: list[Any] = [owner_ref]
                for column, value in updates.items():
                    assignments.append(f"{column}=?")
                    values.append(value)
                values.append(row["task_id"])
                conn.execute(
                    f"UPDATE tasks SET {', '.join(assignments)} WHERE task_id=?",
                    values,
                )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_conversation ON tasks(conversation_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_owner_session ON tasks(owner_session_id)")


_init_db()


def _from_row(row: sqlite3.Row) -> Task:
    return Task(
        task_id=row["task_id"], conversation_id=row["conversation_id"], request_id=row["request_id"],
        owner_session_id=row["owner_session_id"], authentication_method=row["authentication_method"],
        status=TaskStatus(row["status"]), created_at=row["created_at"], updated_at=row["updated_at"],
        started_at=row["started_at"], finished_at=row["finished_at"], current_step=row["current_step"],
        tool_calls=json.loads(row["tool_calls"] or "[]"), retry_count=row["retry_count"], provider=row["provider"], model=row["model"],
        objective=row["objective"], execution_state=json.loads(row["execution_state"] or "{}"),
        result=json.loads(row["result"]) if row["result"] else None, error=row["error"],
        cancel_requested=bool(row["cancel_requested"]), pause_requested=bool(row["pause_requested"]),
        resume_state=json.loads(row["resume_state"]) if row["resume_state"] else None,
        task_version=int(row["task_version"]),
    )


class TaskManager:
    @staticmethod
    def create_task(conversation_id: str, request_id: str, owner_session_id: str, objective: str, provider: str = "", model: str = "", authentication_method: str = "username_password") -> Task:
        task = Task.create(conversation_id, request_id, session_reference(owner_session_id), objective, provider, model, authentication_method)
        TaskManager._save_task(task, allow_insert=True)
        return task

    @staticmethod
    def _save_task(task: Task, *, allow_insert: bool = False) -> None:
        task.owner_session_id = session_reference(task.owner_session_id)
        values = (
            task.conversation_id, task.request_id, task.owner_session_id, task.authentication_method,
            task.status.value, task.created_at, task.updated_at, task.started_at, task.finished_at,
            task.current_step, json.dumps(normalize_persisted_session_fields(task.tool_calls), ensure_ascii=False), task.retry_count,
            task.provider, task.model, task.objective,
            json.dumps(normalize_persisted_session_fields(task.execution_state), ensure_ascii=False),
            json.dumps(normalize_persisted_session_fields(task.result), ensure_ascii=False) if task.result is not None else None,
            task.error, int(task.cancel_requested), int(task.pause_requested),
            json.dumps(normalize_persisted_session_fields(task.resume_state), ensure_ascii=False) if task.resume_state is not None else None,
        )
        next_version = task.task_version
        with _db_lock, _get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT task_version FROM tasks WHERE task_id=?", (task.task_id,)).fetchone()
            if current is None:
                if not allow_insert:
                    raise TaskVersionConflictError("task row disappeared before save")
                if task.task_version != 0:
                    raise TaskVersionConflictError("task row disappeared before save")
                conn.execute("""INSERT INTO tasks (
                    task_id, conversation_id, request_id, owner_session_id, authentication_method, status,
                    created_at, updated_at, started_at, finished_at, current_step, tool_calls, retry_count,
                    provider, model, objective, execution_state, result, error, cancel_requested, pause_requested,
                    resume_state, task_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                    (task.task_id, *values))
            else:
                if allow_insert:
                    raise TaskVersionConflictError("task row already exists")
                actual_version = int(current["task_version"])
                if actual_version != task.task_version:
                    raise TaskVersionConflictError(
                        f"stale task version: expected {task.task_version}, current {actual_version}"
                    )
                updated = conn.execute("""UPDATE tasks SET
                    conversation_id=?, request_id=?, owner_session_id=?, authentication_method=?, status=?,
                    created_at=?, updated_at=?, started_at=?, finished_at=?, current_step=?, tool_calls=?, retry_count=?,
                    provider=?, model=?, objective=?, execution_state=?, result=?, error=?, cancel_requested=?,
                    pause_requested=?, resume_state=?, task_version=task_version+1
                    WHERE task_id=? AND task_version=?""",
                    (*values, task.task_id, task.task_version))
                if updated.rowcount != 1:
                    raise TaskVersionConflictError("task row changed before save")
                next_version = task.task_version + 1
        task.task_version = next_version

    update_task = _save_task

    @staticmethod
    def get_task(task_id: str) -> Task | None:
        with _get_db() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        return _from_row(row) if row else None

    @staticmethod
    def claim_task(task_id: str, owner_session_id: str, *, allow_paused: bool = True) -> Task | None:
        owner_session_id = session_reference(owner_session_id)
        allowed = [TaskStatus.QUEUED.value, TaskStatus.WAITING_FOR_MODEL.value, TaskStatus.WAITING_FOR_TOOL.value]
        if allow_paused:
            allowed.append(TaskStatus.PAUSED.value)
        placeholders = ",".join("?" for _ in allowed)
        with _db_lock, _get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(f"SELECT * FROM tasks WHERE task_id = ? AND owner_session_id = ? AND status IN ({placeholders})", (task_id, owner_session_id, *allowed)).fetchone()
            if row is None:
                return None
            updated = conn.execute(
                "UPDATE tasks SET status=?,pause_requested=0,updated_at=?,task_version=task_version+1 "
                "WHERE task_id=? AND owner_session_id=? AND status=? AND task_version=?",
                (TaskStatus.EXECUTING.value, datetime.now(timezone.utc).isoformat(), task_id,
                 owner_session_id, row["status"], int(row["task_version"])),
            )
            if updated.rowcount != 1:
                raise TaskVersionConflictError("task claim changed before commit")
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        return _from_row(row)

    @staticmethod
    def _update_control_request(task_id: str, owner_session_id: str, *, pause: bool = False, cancel: bool = False) -> Task | None:
        if not pause and not cancel:
            raise ValueError("at least one task control request is required")
        owner_session_id = session_reference(owner_session_id)
        now = datetime.now(timezone.utc).isoformat()
        with _db_lock, _get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if row is None or (row["owner_session_id"] and row["owner_session_id"] != owner_session_id):
                return None
            current_status = TaskStatus(row["status"])
            if current_status in TERMINAL_STATUSES:
                return _from_row(row)
            status = row["status"]
            if pause and current_status is not TaskStatus.EXECUTING:
                status = TaskStatus.PAUSED.value
            pause_requested = 1 if pause else int(row["pause_requested"])
            cancel_requested = 1 if cancel else int(row["cancel_requested"])
            updated = conn.execute(
                "UPDATE tasks SET status=?,updated_at=?,pause_requested=?,cancel_requested=?,task_version=task_version+1 "
                "WHERE task_id=? AND task_version=?",
                (status, now, pause_requested, cancel_requested, task_id, int(row["task_version"])),
            )
            if updated.rowcount != 1:
                raise TaskVersionConflictError("task control request changed before commit")
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return _from_row(row)

    @staticmethod
    def request_pause(task_id: str, owner_session_id: str) -> Task | None:
        return TaskManager._update_control_request(task_id, owner_session_id, pause=True)

    @staticmethod
    def request_cancel(task_id: str, owner_session_id: str) -> Task | None:
        return TaskManager._update_control_request(task_id, owner_session_id, cancel=True)

    @staticmethod
    def get_tasks_by_conversation(conversation_id: str, owner_session_id: str | None = None) -> list[Task]:
        sql = "SELECT * FROM tasks WHERE conversation_id = ?"
        params: list[Any] = [conversation_id]
        if owner_session_id is not None:
            owner_session_id = session_reference(owner_session_id)
            sql += " AND owner_session_id = ?"
            params.append(owner_session_id)
        sql += " ORDER BY created_at DESC"
        with _get_db() as conn:
            return [_from_row(row) for row in conn.execute(sql, params).fetchall()]

    @staticmethod
    def get_active_tasks(owner_session_id: str | None = None) -> list[Task]:
        terminal = tuple(status.value for status in TERMINAL_STATUSES)
        placeholders = ",".join("?" for _ in terminal)
        sql = f"SELECT * FROM tasks WHERE status NOT IN ({placeholders})"
        params: list[Any] = list(terminal)
        if owner_session_id:
            owner_session_id = session_reference(owner_session_id)
            sql += " AND owner_session_id = ?"
            params.append(owner_session_id)
        sql += " ORDER BY created_at DESC"
        with _get_db() as conn:
            return [_from_row(row) for row in conn.execute(sql, params).fetchall()]

    @staticmethod
    def get_task_state(task_id: str) -> TaskState | None:
        task = TaskManager.get_task(task_id)
        return TaskState.from_task(task) if task else None

    @staticmethod
    def delete_task(task_id: str) -> bool:
        with _get_db() as conn:
            return conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,)).rowcount > 0

    @staticmethod
    def cleanup_completed_tasks(max_age_days: int = 30) -> int:
        terminal = tuple(status.value for status in TERMINAL_STATUSES)
        placeholders = ",".join("?" for _ in terminal)
        with _get_db() as conn:
            return conn.execute(f"DELETE FROM tasks WHERE status IN ({placeholders}) AND finished_at < datetime('now', ?)", (*terminal, f'-{max_age_days} days')).rowcount

    @staticmethod
    def get_stats() -> dict[str, int]:
        with _get_db() as conn:
            rows = conn.execute("SELECT status, COUNT(*) AS count FROM tasks GROUP BY status").fetchall()
        stats = {"total": sum(row["count"] for row in rows), "active": 0, "completed": 0, "partial_success": 0, "needs_input": 0, "failed": 0, "cancelled": 0}
        for row in rows:
            key = row["status"]
            stats[key] = row["count"]
            if key not in {status.value for status in TERMINAL_STATUSES}:
                stats["active"] += row["count"]
        return stats
