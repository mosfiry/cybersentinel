from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
import json


class MissionAuthorizationError(PermissionError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class MissionAuthorizationSnapshot:
    """Owner-approved, immutable authority for one mission execution."""

    owner_identity: str
    mission_id: str
    target_identity: str
    scope: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    time_window: dict[str, Any]
    max_duration: int
    rate_limits: dict[str, int]
    network_boundary: dict[str, Any]
    data_boundary: dict[str, Any]
    credential_boundary: dict[str, Any]
    workspace_boundary: dict[str, Any]
    policy_version: str
    owner_approval: str
    created_at: str
    expires_at: str
    authorization_hash: str = ""
    version: int = 1

    def __post_init__(self) -> None:
        required = (self.owner_identity, self.mission_id, self.target_identity, self.policy_version, self.owner_approval, self.created_at, self.expires_at)
        if not all(str(item).strip() for item in required):
            raise MissionAuthorizationError("authorization snapshot has missing identity or time fields")
        if self.max_duration <= 0 or self.version <= 0:
            raise MissionAuthorizationError("authorization snapshot bounds must be positive")
        if _parse(self.expires_at) <= _parse(self.created_at):
            raise MissionAuthorizationError("authorization snapshot expiry must be after creation")
        computed = self.compute_hash()
        if self.authorization_hash and self.authorization_hash != computed:
            raise MissionAuthorizationError("authorization snapshot hash mismatch")
        if not self.authorization_hash:
            object.__setattr__(self, "authorization_hash", computed)

    def _unsigned(self) -> dict[str, Any]:
        return {
            "owner_identity": self.owner_identity,
            "mission_id": self.mission_id,
            "target_identity": self.target_identity,
            "scope": list(self.scope),
            "allowed_actions": list(self.allowed_actions),
            "forbidden_actions": list(self.forbidden_actions),
            "allowed_tools": list(self.allowed_tools),
            "time_window": self.time_window,
            "max_duration": self.max_duration,
            "rate_limits": self.rate_limits,
            "network_boundary": self.network_boundary,
            "data_boundary": self.data_boundary,
            "credential_boundary": self.credential_boundary,
            "workspace_boundary": self.workspace_boundary,
            "policy_version": self.policy_version,
            "owner_approval": self.owner_approval,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "version": self.version,
        }

    def compute_hash(self) -> str:
        return sha256(_canonical(self._unsigned()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned(), "authorization_hash": self.authorization_hash}

    @classmethod
    def create(cls, *, owner_identity: str, mission_id: str, target_identity: str, scope: tuple[str, ...] | list[str], allowed_actions: tuple[str, ...] | list[str], forbidden_actions: tuple[str, ...] | list[str], allowed_tools: tuple[str, ...] | list[str], time_window: dict[str, Any], max_duration: int, rate_limits: dict[str, int], network_boundary: dict[str, Any], data_boundary: dict[str, Any], credential_boundary: dict[str, Any], workspace_boundary: dict[str, Any], policy_version: str, owner_approval: str, created_at: str | None = None, expires_at: str | None = None) -> "MissionAuthorizationSnapshot":
        created = created_at or _now()
        expiry = expires_at or datetime.fromtimestamp(_parse(created).timestamp() + max_duration, timezone.utc).isoformat()
        return cls(owner_identity, mission_id, target_identity, tuple(scope), tuple(allowed_actions), tuple(forbidden_actions), tuple(allowed_tools), dict(time_window), int(max_duration), dict(rate_limits), dict(network_boundary), dict(data_boundary), dict(credential_boundary), dict(workspace_boundary), policy_version, owner_approval, created, expiry)

    def is_active(self, *, at: str | None = None) -> bool:
        moment = _parse(at or _now())
        return _parse(self.created_at) <= moment < _parse(self.expires_at)

    def check(self, *, action: str, tool_id: str, target_identity: str, at: str | None = None, network: str | None = None, credential: str | None = None, workspace_path: str | None = None) -> tuple[bool, str]:
        if not self.is_active(at=at):
            return False, "authorization snapshot expired or not active"
        if target_identity != self.target_identity:
            return False, "target identity outside authorization snapshot"
        if action in self.forbidden_actions or (self.allowed_actions and action not in self.allowed_actions):
            return False, "action outside authorization snapshot"
        if self.allowed_tools and tool_id not in self.allowed_tools:
            return False, "tool outside authorization snapshot"
        if network and network not in set(self.network_boundary.get("allowed", ())) and self.network_boundary.get("allowed"):
            return False, "network boundary violation"
        if credential and credential not in set(self.credential_boundary.get("allowed", ())) and self.credential_boundary.get("allowed"):
            return False, "credential boundary violation"
        if workspace_path and self.workspace_boundary.get("root") and not str(workspace_path).startswith(str(self.workspace_boundary["root"]).rstrip("/") + "/") and str(workspace_path) != str(self.workspace_boundary["root"]):
            return False, "workspace boundary violation"
        return True, "authorized"

    def amend(self, *, owner_approval: str, changes: dict[str, Any], created_at: str | None = None, expires_at: str | None = None) -> "MissionAuthorizationSnapshot":
        if not owner_approval.strip():
            raise MissionAuthorizationError("Owner-approved amendment is required")
        allowed = set(self._unsigned())
        unknown = set(changes) - allowed
        if unknown:
            raise MissionAuthorizationError("unknown authorization amendment fields: " + ", ".join(sorted(unknown)))
        payload = self._unsigned()
        payload.update(changes)
        payload["owner_approval"] = owner_approval
        payload["created_at"] = created_at or _now()
        if expires_at is not None:
            payload["expires_at"] = expires_at
        payload["version"] = self.version + 1
        payload.pop("authorization_hash", None)
        for key in ("scope", "allowed_actions", "forbidden_actions", "allowed_tools"):
            payload[key] = tuple(payload[key])
        return MissionAuthorizationSnapshot(**payload)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MissionAuthorizationSnapshot":
        values = dict(data)
        for key in ("scope", "allowed_actions", "forbidden_actions", "allowed_tools"):
            values[key] = tuple(values.get(key, ()))
        return cls(**values)


__all__ = ["MissionAuthorizationError", "MissionAuthorizationSnapshot"]
