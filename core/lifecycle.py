from __future__ import annotations

from dataclasses import dataclass, replace
import json
import sqlite3
from typing import Any

from .db import connect

STATES = frozenset({"created", "planned", "validated", "authorized", "executing", "succeeded", "failed", "completed"})
TRANSITIONS = {
    "created": {"planned", "failed"},
    "planned": {"validated", "failed"},
    "validated": {"authorized", "failed"},
    "authorized": {"executing", "failed"},
    "executing": {"succeeded", "failed"},
    "succeeded": {"completed"},
    "failed": {"completed"},
    "completed": set(),
}


@dataclass(frozen=True)
class LifecycleRecord:
    request_id: str
    status: str
    source: str
    plan_hash: str
    provider: str
    model: str
    attempt: int
    cancel_requested: bool
    final_result: dict[str, Any] | None
    error: str
    claimed: bool = False


def _decode(row) -> LifecycleRecord | None:
    if row is None:
        return None
    return LifecycleRecord(row["request_id"], row["status"], row["source"], row["plan_hash"], row["provider"], row["model"], row["attempt"], bool(row["cancel_requested"]), json.loads(row["final_result_json"]) if row["final_result_json"] else None, row["error"])


def request_cancel(request_id: str) -> LifecycleRecord:
    with connect() as con:
        con.execute("UPDATE executions SET cancel_requested=1,updated_at=CURRENT_TIMESTAMP WHERE request_id=? AND status != 'completed'", (request_id,))
    record = get(request_id)
    if record is None:
        raise ValueError("unknown request_id")
    return record


def is_cancelled(request_id: str) -> bool:
    record = get(request_id)
    return bool(record and record.cancel_requested)


def get(request_id: str) -> LifecycleRecord | None:
    with connect() as con:
        return _decode(con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone())


def begin(request_id: str, source: str) -> LifecycleRecord:
    """Atomically create a request; an existing request is never executed twice."""
    with connect() as con:
        try:
            con.execute("INSERT INTO executions(request_id,source,status) VALUES(?,?,?)", (request_id, source, "created"))
            row = con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone()
            return replace(_decode(row), claimed=True)
        except sqlite3.IntegrityError:
            row = con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone()
            return replace(_decode(row), claimed=False)


def transition(request_id: str, target: str, *, plan_hash: str = "", provider: str = "", model: str = "", error: str = "") -> LifecycleRecord:
    if target not in STATES:
        raise ValueError("unknown lifecycle state")
    with connect() as con:
        row = con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone()
        current = _decode(row)
        if current is None:
            raise ValueError("unknown request_id")
        if current.status == target:
            return current
        if target not in TRANSITIONS[current.status]:
            raise ValueError(f"invalid lifecycle transition {current.status}->{target}")
        con.execute(
            "UPDATE executions SET status=?,updated_at=CURRENT_TIMESTAMP,plan_hash=COALESCE(NULLIF(?,''),plan_hash),provider=COALESCE(NULLIF(?,''),provider),model=COALESCE(NULLIF(?,''),model),error=? WHERE request_id=? AND status=?",
            (target, plan_hash, provider, model, error, request_id, current.status),
        )
        return _decode(con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone())


def complete(request_id: str, result: dict[str, Any], *, success: bool, error: str = "") -> LifecycleRecord:
    current = get(request_id)
    if current is None:
        raise ValueError("unknown request_id")
    if current.status == "completed":
        return current
    terminal = "succeeded" if success else "failed"
    if current.status != terminal:
        transition(request_id, terminal, error=error)
    with connect() as con:
        con.execute("UPDATE executions SET status='completed',updated_at=CURRENT_TIMESTAMP,final_result_json=?,error=? WHERE request_id=?", (json.dumps(result, ensure_ascii=False), error, request_id))
        return _decode(con.execute("SELECT * FROM executions WHERE request_id = ?", (request_id,)).fetchone())


def recover_incomplete() -> list[LifecycleRecord]:
    """Mark records left in active states by a crash as failed and completed."""
    with connect() as con:
        rows = con.execute("SELECT * FROM executions WHERE status != 'completed'").fetchall()
        ids = [row["request_id"] for row in rows]
    recovered = []
    for request_id in ids:
        try:
            current = get(request_id)
            if current.status not in {"succeeded", "failed"}:
                transition(request_id, "failed", error="recovered after interrupted execution")
            recovered.append(complete(request_id, {"ok": False, "recovered": True, "error": "interrupted execution; no final response was persisted"}, success=False, error="recovered after interrupted execution"))
        except ValueError:
            pass
    return recovered
