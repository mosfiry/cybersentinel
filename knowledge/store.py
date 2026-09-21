from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from typing import Iterator

from .foundation import IntegrityError, KnowledgeError, KnowledgeKind, KnowledgeObject, TransformationPolicy


DEFAULT_PATH = Path(__file__).resolve().parents[1] / "knowledge.sqlite3"
DB_PATH = Path(os.getenv("KNOWLEDGE_DB_PATH", str(DEFAULT_PATH))).expanduser()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge_objects (
 object_id TEXT PRIMARY KEY,
 kind TEXT NOT NULL,
 title TEXT NOT NULL,
 language TEXT NOT NULL,
 source_id TEXT NOT NULL,
 source_url TEXT NOT NULL,
 edition TEXT NOT NULL,
 author TEXT NOT NULL,
 trust_class TEXT NOT NULL,
 transformation_policy TEXT NOT NULL,
 content TEXT NOT NULL,
 content_hash TEXT NOT NULL,
 created_at TEXT NOT NULL,
 metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_kind ON knowledge_objects(kind);
CREATE INDEX IF NOT EXISTS idx_knowledge_hash ON knowledge_objects(content_hash);
CREATE TRIGGER IF NOT EXISTS knowledge_objects_no_update
BEFORE UPDATE ON knowledge_objects BEGIN SELECT RAISE(ABORT, 'knowledge objects are append-only'); END;
CREATE TRIGGER IF NOT EXISTS knowledge_objects_no_delete
BEFORE DELETE ON knowledge_objects BEGIN SELECT RAISE(ABORT, 'knowledge objects are append-only'); END;
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        con.executescript(_SCHEMA)
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_store() -> None:
    with connect():
        pass


def add(obj: KnowledgeObject) -> str:
    obj.verify_integrity()
    record = obj.to_record()
    with connect() as con:
        existing = con.execute("SELECT * FROM knowledge_objects WHERE object_id=?", (obj.object_id,)).fetchone()
        if existing is not None:
            old = KnowledgeObject.from_record(dict(existing))
            if old.content_hash != obj.content_hash or old.content != obj.content:
                raise KnowledgeError("immutable object_id already exists with different exact content")
            raise KnowledgeError("object_id already exists; no silent duplicate revision")
        con.execute("""INSERT INTO knowledge_objects
          (object_id,kind,title,language,source_id,source_url,edition,author,trust_class,transformation_policy,content,content_hash,created_at,metadata_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            record["object_id"], record["kind"], record["title"], record["language"], record["source_id"],
            record["source_url"], record["edition"], record["author"], record["trust_class"],
            record["transformation_policy"], record["content"], record["content_hash"], record["created_at"],
            json.dumps(record["metadata"], ensure_ascii=False),
        ))
    return obj.object_id


def get(object_id: str) -> KnowledgeObject | None:
    with connect() as con:
        row = con.execute("SELECT * FROM knowledge_objects WHERE object_id=?", (object_id,)).fetchone()
    if row is None:
        return None
    return KnowledgeObject.from_record(dict(row))


def verify_integrity(object_id: str) -> bool:
    obj = get(object_id)
    if obj is None:
        raise KeyError(object_id)
    return obj.verify_integrity()


def search(query: str, *, kind: KnowledgeKind | None = None, limit: int = 20) -> list[KnowledgeObject]:
    # Retrieval is data access only; no authority or execution permission is returned.
    needle = f"%{query.lower()}%"
    with connect() as con:
        if kind is None:
            rows = con.execute("SELECT * FROM knowledge_objects WHERE lower(title) LIKE ? OR lower(content) LIKE ? ORDER BY created_at DESC LIMIT ?", (needle, needle, int(limit))).fetchall()
        else:
            rows = con.execute("SELECT * FROM knowledge_objects WHERE kind=? AND (lower(title) LIKE ? OR lower(content) LIKE ?) ORDER BY created_at DESC LIMIT ?", (kind.value, needle, needle, int(limit))).fetchall()
    return [KnowledgeObject.from_record(dict(row)) for row in rows]
