from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(frozen=True)
class CompactionResult:
    state: dict[str, Any]
    removed_items: int
    provenance: dict[str, Any]
    context_hash: str


REQUIRED = ("owner", "mission", "authorization", "scope", "plan", "current_step", "critical_evidence", "counter_evidence", "hypotheses", "unknowns", "strategy", "verification")


def compact_state(state: dict[str, Any], *, max_items: int = 32) -> CompactionResult:
    preserved = dict(state)
    for key in REQUIRED:
        preserved.setdefault(key, state.get(key, {} if key in {"owner", "mission", "authorization", "scope", "plan", "current_step", "strategy", "verification"} else []))
    conversation = list(preserved.get("conversation", ()))
    removed = max(0, len(conversation) - max_items)
    if removed:
        preserved["conversation"] = conversation[-max_items:]
    provenance = {"preserved": list(REQUIRED), "removed_conversation_items": removed, "method": "deterministic_tail_with_authority_pinning"}
    payload = json.dumps(preserved, ensure_ascii=False, sort_keys=True, default=str)
    return CompactionResult(preserved, removed, provenance, sha256(payload.encode()).hexdigest())


__all__ = ["CompactionResult", "REQUIRED", "compact_state"]
