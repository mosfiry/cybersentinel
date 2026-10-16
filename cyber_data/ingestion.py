from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from cyber_knowledge.models import KnowledgeObject, normalize


def load_jsonl(path: str | Path, *, source: str, source_type: str) -> list[KnowledgeObject]:
    objects = []
    seen: set[str] = set()
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read knowledge file: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            obj = normalize(raw, source=source, source_type=source_type)
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            raise ValueError(f"invalid knowledge record at line {line_number}: {exc}") from exc
        if len(obj.observation) < 12 or obj.content_hash in seen:
            continue
        seen.add(obj.content_hash)
        objects.append(obj)
    return objects


def quality_filter(objects: Iterable[KnowledgeObject], *, min_confidence: float = 0.2) -> list[KnowledgeObject]:
    return [obj for obj in objects if obj.confidence >= min_confidence and obj.source and obj.content_hash]
