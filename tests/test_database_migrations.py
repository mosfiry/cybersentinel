from __future__ import annotations

import sqlite3

from core import db as app_db


def test_legacy_execution_schema_migrates_cancel_flag_idempotently(tmp_path, monkeypatch):
    database = tmp_path / "legacy-app.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE executions (request_id TEXT PRIMARY KEY, status TEXT NOT NULL)")
    monkeypatch.setattr(app_db, "DB_PATH", database)

    for _ in range(2):
        connection = app_db.connect()
        try:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(executions)")}
            assert "cancel_requested" in columns
        finally:
            connection.close()
