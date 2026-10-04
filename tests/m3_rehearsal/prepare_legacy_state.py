from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat

from agent.mission_worker import WorkerMissionState


STATE = Path(os.environ.get("CYBERSENTINEL_STATE_DIR", "/var/lib/cybersentinel"))


def _database(path: Path) -> sqlite3.Connection:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    os.close(fd)
    return sqlite3.connect(path)


def main() -> int:
    info = STATE.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit("legacy_fixture_state_root_invalid")

    with _database(STATE / "intel.db") as db:
        db.execute(
            "CREATE TABLE executions ("
            "request_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, source TEXT NOT NULL, "
            "status TEXT NOT NULL, plan_hash TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '', "
            "model TEXT NOT NULL DEFAULT '', attempt INTEGER NOT NULL DEFAULT 1, "
            "final_result_json TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '')"
        )
        db.execute(
            "INSERT INTO executions(request_id, source, status, error) VALUES(?,?,?,?)",
            ("v12-legacy-execution", "v12-legacy-fixture", "completed", "preserve-me"),
        )

    with _database(STATE / "tasks.sqlite3") as db:
        db.execute(
            "CREATE TABLE tasks ("
            "task_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, request_id TEXT NOT NULL, "
            "owner_session_id TEXT NOT NULL, authentication_method TEXT NOT NULL DEFAULT 'username_password', "
            "status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, "
            "finished_at TEXT, current_step INTEGER DEFAULT 0, tool_calls TEXT DEFAULT '[]', "
            "retry_count INTEGER DEFAULT 0, provider TEXT DEFAULT '', model TEXT DEFAULT '', objective TEXT DEFAULT '', "
            "execution_state TEXT DEFAULT '{}', result TEXT, error TEXT, cancel_requested INTEGER DEFAULT 0, "
            "pause_requested INTEGER DEFAULT 0, resume_state TEXT)"
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO tasks(task_id,conversation_id,request_id,owner_session_id,status,created_at,updated_at,objective) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("v12-legacy-task", "v12-legacy-conversation", "v12-legacy-request", "", "completed", timestamp, timestamp, "preserve legacy task"),
        )

    with _database(STATE / "mission_queue.sqlite3") as db:
        db.execute(
            "CREATE TABLE mission_queue ("
            "mission_id TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
            "available_at TEXT NOT NULL, claimed_at TEXT, last_error TEXT NOT NULL DEFAULT '', "
            "lease_owner TEXT, lease_expires_at TEXT)"
        )
        db.execute(
            "INSERT INTO mission_queue(mission_id,state,attempts,available_at,last_error) VALUES(?,?,?,?,?)",
            (
                "v12-legacy-queue",
                WorkerMissionState.COMPLETED.value,
                4,
                datetime.now(timezone.utc).isoformat(),
                "preserve legacy queue row",
            ),
        )

    print(
        json.dumps(
            {
                "legacy_schemas_seeded": ["executions", "tasks", "mission_queue"],
                "legacy_rows_seeded": 3,
                "state_root_is_directory": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
