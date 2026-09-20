from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ExecutionContext:
    request_id: str
    owner_authenticated: bool
    owner_identity: str
    policy_snapshot: str
    provider: str = "local"
    model: str = "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
