from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ExecutionContext:
    request_id: str
    owner_authenticated: bool
    owner_identity: str
    policy_snapshot: str
    provider: str = "local"
    model: str = "deterministic"
    authority: dict[str, Any] = field(default_factory=dict)
    owner_session_id: str | None = None
    authentication_method: str = "owner_token"
    authenticated_at: str | None = None
    owner_instruction_snapshot: str = ""
    owner_instruction_fingerprint: str = ""
    policy_snapshot_details: dict[str, Any] = field(default_factory=dict)
    scope_snapshot: dict[str, Any] = field(default_factory=dict)
    authorization_context: dict[str, Any] = field(default_factory=dict)
    authorization_decisions: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
