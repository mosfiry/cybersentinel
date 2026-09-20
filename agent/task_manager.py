"""
CyberSentinel X - Phase 5B: Task Manager

Persistent task management for long-horizon conversational execution.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .task import Task, TaskStatus
from .state import TaskState


# Database setup
ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "tasks.sqlite3"

# Ensure database directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Lock for thread-safe database operations
_db_lock = threading.Lock()


@contextmanager
def _get_db():
    """Get database connection context manager."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
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
    """Initialize task database."""
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                owner_session_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                current_step INTEGER DEFAULT 0,
                tool_calls TEXT DEFAULT '[]',
                retry_count INTEGER DEFAULT 0,
                provider TEXT DEFAULT '',
                model TEXT DEFAULT '',
                objective TEXT DEFAULT '',
                execution_state TEXT DEFAULT '{}',
                result TEXT,
                error TEXT,
                cancel_requested INTEGER DEFAULT 0,
                pause_requested INTEGER DEFAULT 0,
                resume_state TEXT
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tasks_conversation 
            ON tasks(conversation_id)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tasks_status 
            ON tasks(status)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_tasks_owner_session 
            ON tasks(owner_session_id)
        """)


# Initialize database on module load
_init_db()


class TaskManager:
    """Manages persistent tasks for long-horizon execution."""
    
    @staticmethod
    def create_task(
        conversation_id: str,
        request_id: str,
        owner_session_id: str,
        objective: str,
        provider: str = "",
        model: str = "",
    ) -> Task:
        """Create a new task and persist it."""
        task = Task.create(
            conversation_id=conversation_id,
            request_id=request_id,
            owner_session_id=owner_session_id,
            objective=objective,
            provider=provider,
            model=model,
        )
        TaskManager._save_task(task)
        return task
    
    @staticmethod
    def _save_task(task: Task) -> None:
        """Save task to database."""
        with _db_lock:
            with _get_db() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO tasks (
                        task_id, conversation_id, request_id, owner_session_id,
                        status, created_at, updated_at, started_at, finished_at,
                        current_step, tool_calls, retry_count, provider, model,
                        objective, execution_state, result, error,
                        cancel_requested, pause_requested, resume_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    task.task_id,
                    task.conversation_id,
                    task.request_id,
                    task.owner_session_id,
                    task.status.value,
                    task.created_at,
                    task.updated_at,
                    task.started_at,
                    task.finished_at,
                    task.current_step,
                    json.dumps(task.tool_calls),
                    task.retry_count,
                    task.provider,
                    task.model,
                    task.objective,
                    json.dumps(task.execution_state),
                    json.dumps(task.result) if task.result else None,
                    task.error,
                    1 if task.cancel_requested else 0,
                    1 if task.pause_requested else 0,
                    json.dumps(task.resume_state) if task.resume_state else None,
                ))
    
    @staticmethod
    def get_task(task_id: str) -> Task | None:
        """Get task by ID."""
        with _get_db() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            
            if row is None:
                return None
            
            return Task(
                task_id=row["task_id"],
                conversation_id=row["conversation_id"],
                request_id=row["request_id"],
                owner_session_id=row["owner_session_id"],
                status=TaskStatus(row["status"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                current_step=row["current_step"],
                tool_calls=json.loads(row["tool_calls"]),
                retry_count=row["retry_count"],
                provider=row["provider"],
                model=row["model"],
                objective=row["objective"],
                execution_state=json.loads(row["execution_state"]),
                result=json.loads(row["result"]) if row["result"] else None,
                error=row["error"],
                cancel_requested=bool(row["cancel_requested"]),
                pause_requested=bool(row["pause_requested"]),
                resume_state=json.loads(row["resume_state"]) if row["resume_state"] else None,
            )
    
    @staticmethod
    def update_task(task: Task) -> None:
        """Update existing task in database."""
        TaskManager._save_task(task)
    
    @staticmethod
    def delete_task(task_id: str) -> bool:
        """Delete task by ID."""
        with _get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM tasks WHERE task_id = ?", (task_id,)
            )
            return cursor.rowcount > 0
    
    @staticmethod
    def get_tasks_by_conversation(conversation_id: str) -> list[Task]:
        """Get all tasks for a conversation."""
        with _get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE conversation_id = ? ORDER BY created_at DESC",
                (conversation_id,)
            ).fetchall()
            
            return [
                Task(
                    task_id=row["task_id"],
                    conversation_id=row["conversation_id"],
                    request_id=row["request_id"],
                    owner_session_id=row["owner_session_id"],
                    status=TaskStatus(row["status"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    current_step=row["current_step"],
                    tool_calls=json.loads(row["tool_calls"]),
                    retry_count=row["retry_count"],
                    provider=row["provider"],
                    model=row["model"],
                    objective=row["objective"],
                    execution_state=json.loads(row["execution_state"]),
                    result=json.loads(row["result"]) if row["result"] else None,
                    error=row["error"],
                    cancel_requested=bool(row["cancel_requested"]),
                    pause_requested=bool(row["pause_requested"]),
                    resume_state=json.loads(row["resume_state"]) if row["resume_state"] else None,
                )
                for row in rows
            ]
    
    @staticmethod
    def get_active_tasks(owner_session_id: str | None = None) -> list[Task]:
        """Get all active tasks."""
        with _get_db() as conn:
            if owner_session_id:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE status NOT IN ('completed', 'failed', 'cancelled') "
                    "AND owner_session_id = ? ORDER BY created_at DESC",
                    (owner_session_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE status NOT IN ('completed', 'failed', 'cancelled') "
                    "ORDER BY created_at DESC"
                ).fetchall()
            
            return [
                Task(
                    task_id=row["task_id"],
                    conversation_id=row["conversation_id"],
                    request_id=row["request_id"],
                    owner_session_id=row["owner_session_id"],
                    status=TaskStatus(row["status"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    current_step=row["current_step"],
                    tool_calls=json.loads(row["tool_calls"]),
                    retry_count=row["retry_count"],
                    provider=row["provider"],
                    model=row["model"],
                    objective=row["objective"],
                    execution_state=json.loads(row["execution_state"]),
                    result=json.loads(row["result"]) if row["result"] else None,
                    error=row["error"],
                    cancel_requested=bool(row["cancel_requested"]),
                    pause_requested=bool(row["pause_requested"]),
                    resume_state=json.loads(row["resume_state"]) if row["resume_state"] else None,
                )
                for row in rows
            ]
    
    @staticmethod
    def get_task_state(task_id: str) -> TaskState | None:
        """Get immutable task state snapshot."""
        task = TaskManager.get_task(task_id)
        if task is None:
            return None
        return TaskState.from_task(task)
    
    @staticmethod
    def cleanup_completed_tasks(max_age_days: int = 30) -> int:
        """Clean up old completed tasks."""
        with _get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM tasks WHERE status IN ('completed', 'failed', 'cancelled') "
                "AND finished_at < datetime('now', ?)",
                (f"-{max_age_days} days",)
            )
            return cursor.rowcount
    
    @staticmethod
    def get_stats() -> dict[str, Any]:
        """Get task statistics."""
        with _get_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status NOT IN ('completed', 'failed', 'cancelled')"
            ).fetchone()[0]
            completed = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status = 'completed'"
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status = 'failed'"
            ).fetchone()[0]
            cancelled = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status = 'cancelled'"
            ).fetchone()[0]
            
            return {
                "total": total,
                "active": active,
                "completed": completed,
                "failed": failed,
                "cancelled": cancelled,
            }
