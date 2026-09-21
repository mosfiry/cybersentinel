from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Observation:
    tool_id: str
    execution_id: str
    status: str
    normalized_data: dict[str, Any] = field(default_factory=dict)
    raw_reference: str = ""
    reliability: float = 0.0
    provenance: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] | None = None
    request_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_result(cls, tool_id: str, execution_id: str, result: dict[str, Any], *, request_id: str = "", scope: dict[str, Any] | None = None) -> "Observation":
        success = bool(result.get("success", result.get("ok", False)))
        normalized = {key: value for key, value in result.items() if key not in {"token", "secret", "password", "authorization"}}
        return cls(tool_id, execution_id, "success" if success else "failure", normalized_data=normalized, reliability=1.0 if success else 0.0, provenance={"source": "tool_runtime", "tool_id": tool_id}, scope=scope, request_id=request_id)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


__all__ = ["Observation"]
