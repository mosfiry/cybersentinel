from __future__ import annotations
import sqlite3
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    source TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS watches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT NOT NULL UNIQUE,
    collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_intel_collected ON intel(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_severity ON intel(severity);
"""

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con

def add_event(kind, title, body, source, severity="info", trusted=False, metadata=None):
    payload = metadata if isinstance(metadata, str) else __import__("json").dumps(metadata or {}, ensure_ascii=False)
    with connect() as con:
        cur = con.execute(
            """INSERT INTO events
               (kind,severity,title,body,source,trusted,metadata_json)
               VALUES(?,?,?,?,?,?,?)""",
            (kind, severity, title, body, source, int(trusted), payload),
        )
        return cur.lastrowid

def recent(limit=50):
    with connect() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (int(limit),)
        )]

def counts():
    with connect() as con:
        return {r["severity"]: r["n"] for r in con.execute(
            "SELECT severity,COUNT(*) n FROM events GROUP BY severity"
        )}

def search_all(query, limit=50):
    q = f"%{query.lower()}%"
    with connect() as con:
        events = [dict(r) for r in con.execute(
            """SELECT * FROM events
               WHERE lower(title) LIKE ? OR lower(body) LIKE ? OR lower(source) LIKE ?
               ORDER BY id DESC LIMIT ?""", (q,q,q,int(limit))
        )]
        intel = [dict(r) for r in con.execute(
            """SELECT * FROM intel
               WHERE lower(external_id) LIKE ? OR lower(title) LIKE ? OR lower(body) LIKE ?
                  OR lower(source) LIKE ?
               ORDER BY id DESC LIMIT ?""", (q,q,q,q,int(limit))
        )]
    return {"events": events, "intel": intel}

def add_intel(external_id, source, title, body, severity="info", metadata=None):
    payload = __import__("json").dumps(metadata or {}, ensure_ascii=False)
    with connect() as con:
        cur = con.execute(
            """INSERT OR IGNORE INTO intel
               (external_id,source,title,body,severity,metadata_json)
               VALUES(?,?,?,?,?,?)""",
            (external_id, source, title, body, severity, payload),
        )
        return cur.rowcount == 1

def intel_recent(limit=100):
    with connect() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM intel ORDER BY id DESC LIMIT ?", (int(limit),)
        )]

def add_watch(keyword):
    with connect() as con:
        con.execute("INSERT OR IGNORE INTO watches(keyword) VALUES(?)", (keyword.strip(),))

def remove_watch(keyword):
    with connect() as con:
        con.execute("DELETE FROM watches WHERE lower(keyword)=lower(?)", (keyword.strip(),))

def watches():
    with connect() as con:
        return [r["keyword"] for r in con.execute("SELECT keyword FROM watches ORDER BY keyword")]

def clear_database():
    with connect() as con:
        con.execute("DELETE FROM events")
        con.execute("DELETE FROM intel")
        con.execute("DELETE FROM watches")
