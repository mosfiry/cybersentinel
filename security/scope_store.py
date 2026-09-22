from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .scope import ProgramAuthorization, ScopeSnapshot, TargetIdentity, make_snapshot

SCOPE_DB_PATH = Path(__import__("os").environ.get("SCOPE_DB_PATH", "~/.cybersentinel-x/scope.sqlite3")).expanduser()
_LOCK = threading.RLock()


def _connect() -> sqlite3.Connection:
    SCOPE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SCOPE_DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_scope_store() -> None:
    with _LOCK, _connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scope_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL,
            scope_version TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scope_rate_events (
            rate_key TEXT NOT NULL,
            occurred_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scope_rate_events ON scope_rate_events(rate_key, occurred_at);
        """)


init_scope_store()


def save_snapshot(snapshot: ScopeSnapshot, *, owner_token: str | None = None) -> ScopeSnapshot:
    from .owner_policy import verify_owner
    owner_ok, reason = verify_owner("Owner approve scope snapshot", owner_token)
    if not owner_ok:
        raise PermissionError(reason)
    payload = json.dumps(snapshot.to_dict(), ensure_ascii=False, sort_keys=True)
    with _LOCK, _connect() as conn:
        try:
            conn.execute("INSERT INTO scope_snapshots(snapshot_id,program_id,scope_version,evidence_hash,snapshot_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", (snapshot.snapshot_id, snapshot.authorization.program_id, snapshot.authorization.scope_version, snapshot.authorization.evidence_hash, payload, snapshot.created_at, snapshot.expires_at))
        except sqlite3.IntegrityError as exc:
            raise ValueError("scope_snapshot_id_already_exists") from exc
    return snapshot


def get_snapshot(snapshot_id: str) -> ScopeSnapshot | None:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT snapshot_json FROM scope_snapshots WHERE snapshot_id = ?", (snapshot_id,)).fetchone()
    if row is None:
        return None
    data = json.loads(row["snapshot_json"])
    auth_data = data["authorization"]
    stored_hash = auth_data.get("evidence_hash", "")
    auth = ProgramAuthorization(**{**auth_data, "evidence_hash": "", "in_scope_assets": tuple(auth_data["in_scope_assets"]), "out_of_scope_assets": tuple(auth_data.get("out_of_scope_assets", [])), "allowed_methods": tuple(auth_data.get("allowed_methods", [])), "prohibited_methods": tuple(auth_data.get("prohibited_methods", []))})
    if stored_hash and stored_hash != auth.evidence_hash:
        raise ValueError("scope_evidence_hash_mismatch")
    targets = tuple(TargetIdentity(**{**item, "allowed_ports": tuple(item.get("allowed_ports", [])), "allowed_paths": tuple(item.get("allowed_paths", [])), "excluded_paths": tuple(item.get("excluded_paths", []))}) for item in data["targets"])
    return make_snapshot(data["snapshot_id"], auth, list(targets), expires_at=data.get("expires_at"), created_at=data.get("created_at"))


def delete_snapshot(snapshot_id: str) -> bool:
    with _LOCK, _connect() as conn:
        return conn.execute("DELETE FROM scope_snapshots WHERE snapshot_id = ?", (snapshot_id,)).rowcount > 0


def record_rate_event(rate_key: str, occurred_at: float) -> None:
    with _LOCK, _connect() as conn:
        conn.execute("INSERT INTO scope_rate_events(rate_key, occurred_at) VALUES(?, ?)", (rate_key, occurred_at))


def count_rate_events(rate_key: str, since: float) -> int:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM scope_rate_events WHERE occurred_at < ?", (since - 86400,))
        return int(conn.execute("SELECT COUNT(*) FROM scope_rate_events WHERE rate_key = ? AND occurred_at >= ?", (rate_key, since)).fetchone()[0])
