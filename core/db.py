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

CREATE TABLE IF NOT EXISTS executions (
    request_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    plan_hash TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 1,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    final_result_json TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);

CREATE TABLE IF NOT EXISTS reasoning_memory (
    request_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    case_json TEXT NOT NULL,
    critic_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_reasoning_memory_created ON reasoning_memory(created_at DESC);

CREATE TABLE IF NOT EXISTS conversations (
    conversation_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_session_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS conversation_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id)
);
CREATE INDEX IF NOT EXISTS idx_conversation_messages ON conversation_messages(conversation_id, id);
"""

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    try:
        con.execute("ALTER TABLE executions ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
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

def events_for_request(request_id, limit=500):
    needle = f'"request_id": "{request_id}"'
    with connect() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM events WHERE metadata_json LIKE ? ORDER BY id ASC LIMIT ?", (f"%{needle}%", int(limit))
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

def save_reasoning_memory(request_id, case, critic):
    import json
    with connect() as con:
        con.execute(
            "INSERT OR REPLACE INTO reasoning_memory(request_id,case_json,critic_json) VALUES(?,?,?)",
            (request_id, json.dumps(case, ensure_ascii=False), json.dumps(critic, ensure_ascii=False)),
        )

def reasoning_for_request(request_id):
    import json
    with connect() as con:
        row = con.execute("SELECT * FROM reasoning_memory WHERE request_id=?", (request_id,)).fetchone()
    if row is None:
        return None
    value = dict(row)
    value["case"] = json.loads(value.pop("case_json"))
    value["critic"] = json.loads(value.pop("critic_json"))
    return value

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

def ensure_conversation(conversation_id, owner_session_id=""):
    with connect() as con:
        con.execute(
            "INSERT OR IGNORE INTO conversations(conversation_id,owner_session_id) VALUES(?,?)",
            (str(conversation_id), str(owner_session_id or "")),
        )
        con.execute("UPDATE conversations SET updated_at=CURRENT_TIMESTAMP WHERE conversation_id=?", (str(conversation_id),))

def add_conversation_message(conversation_id, role, content, metadata=None):
    import json
    ensure_conversation(conversation_id)
    with connect() as con:
        cur = con.execute(
            "INSERT INTO conversation_messages(conversation_id,role,content,metadata_json) VALUES(?,?,?,?)",
            (str(conversation_id), str(role), str(content), json.dumps(metadata or {}, ensure_ascii=False)),
        )
        con.execute("UPDATE conversations SET updated_at=CURRENT_TIMESTAMP WHERE conversation_id=?", (str(conversation_id),))
        return cur.lastrowid

def conversation_messages(conversation_id, limit=40):
    import json
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM conversation_messages WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
            (str(conversation_id), int(limit)),
        ).fetchall()
    result = []
    for row in reversed(rows):
        item = dict(row)
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        result.append(item)
    return result

def conversation_info(conversation_id):
    with connect() as con:
        row = con.execute("SELECT * FROM conversations WHERE conversation_id=?", (str(conversation_id),)).fetchone()
    return dict(row) if row else None
