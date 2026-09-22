from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InternalDiagnostic:
    code: str
    message: str
    provider_available: bool | None = None
    provider: str = ""
    model: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "provider_available": self.provider_available, "provider": self.provider, "model": self.model, "details": dict(self.details)}


@dataclass(frozen=True)
class UserFacingResponse:
    answer: str
    mode: str
    capability_limited: bool = False
    diagnostics_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"answer": self.answer, "mode": self.mode, "capability_limited": self.capability_limited, "diagnostics_ref": self.diagnostics_ref}


__all__ = ["InternalDiagnostic", "UserFacingResponse"]
