from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import hmac
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_host(value: str) -> str:
    raw = str(value or "").strip().rstrip(".").lower()
    if not raw or any(ch.isspace() for ch in raw) or "/" in raw or "@" in raw:
        raise ScopeError("invalid_host")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        try:
            return raw.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError("invalid_host") from exc


def canonical_url(value: str, *, allowed_schemes: tuple[str, ...] = ("http", "https")) -> str:
    parts = urlsplit(str(value or "").strip())
    if parts.scheme.lower() not in allowed_schemes or not parts.hostname:
        raise ScopeError("invalid_url")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("userinfo_not_allowed")
    host = canonical_host(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise ScopeError("invalid_port") from exc
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not ((parts.scheme.lower() == "http" and port == 80) or (parts.scheme.lower() == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _asset_matches(asset: dict[str, Any], host: str, scheme: str, port: int | None, path: str) -> bool:
    asset_host = str(asset.get("host") or asset.get("hostname") or "").strip().lower()
    if not asset_host:
        return False
    wildcard = asset_host.startswith("*.")
    expected = canonical_host(asset_host[2:] if wildcard else asset_host)
    if wildcard:
        if host == expected or not host.endswith("." + expected):
            return False
    elif host != expected:
        return False
    schemes = tuple(str(item).lower() for item in asset.get("schemes", asset.get("allowed_schemes", ["http", "https"])))
    if scheme not in schemes:
        return False
    ports = asset.get("ports") or asset.get("allowed_ports")
    if ports and port not in {int(item) for item in ports}:
        return False
    prefixes = asset.get("paths") or asset.get("allowed_paths")
    if prefixes and not any(path == str(prefix) or path.startswith(str(prefix).rstrip("/") + "/") for prefix in prefixes):
        return False
    return True


@dataclass(frozen=True)
class TargetIdentity:
    target_id: str
    program_id: str
    host: str
    asset_type: str = "web"
    environment: str = "production"
    allowed_ports: tuple[int, ...] = ()
    allowed_paths: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "host", canonical_host(self.host))
        if not self.target_id or not self.program_id:
            raise ScopeError("target_id_and_program_id_required")

    def to_dict(self) -> dict[str, Any]:
        return {"target_id": self.target_id, "program_id": self.program_id, "host": self.host, "asset_type": self.asset_type, "environment": self.environment, "allowed_ports": list(self.allowed_ports), "allowed_paths": list(self.allowed_paths), "excluded_paths": list(self.excluded_paths)}


@dataclass(frozen=True)
class ProgramAuthorization:
    program_id: str
    platform: str
    scope_version: str
    retrieved_at: str
    in_scope_assets: tuple[dict[str, Any], ...]
    out_of_scope_assets: tuple[dict[str, Any], ...] = ()
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")
    prohibited_methods: tuple[str, ...] = ("DELETE", "PATCH", "PUT")
    rate_limits: dict[str, int] = field(default_factory=dict)
    testing_window: dict[str, Any] = field(default_factory=dict)
    disclosure_policy: dict[str, Any] = field(default_factory=dict)
    evidence_hash: str = ""
    owner_session_id: str = ""
    source: str = "owner"

    def __post_init__(self) -> None:
        if not self.program_id or not self.platform or not self.scope_version or not self.in_scope_assets:
            raise ScopeError("incomplete_program_authorization")
        computed = self.computed_evidence_hash()
        if not self.evidence_hash:
            object.__setattr__(self, "evidence_hash", computed)
        elif not hmac.compare_digest(str(self.evidence_hash), computed):
            raise ScopeError("scope_evidence_hash_mismatch")

    def computed_evidence_hash(self) -> str:
        payload = {"program_id": self.program_id, "platform": self.platform, "scope_version": self.scope_version, "in_scope_assets": self.in_scope_assets, "out_of_scope_assets": self.out_of_scope_assets, "allowed_methods": self.allowed_methods, "prohibited_methods": self.prohibited_methods, "rate_limits": self.rate_limits, "testing_window": self.testing_window, "disclosure_policy": self.disclosure_policy}
        return sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {"program_id": self.program_id, "platform": self.platform, "scope_version": self.scope_version, "retrieved_at": self.retrieved_at, "in_scope_assets": list(self.in_scope_assets), "out_of_scope_assets": list(self.out_of_scope_assets), "allowed_methods": list(self.allowed_methods), "prohibited_methods": list(self.prohibited_methods), "rate_limits": self.rate_limits, "testing_window": self.testing_window, "disclosure_policy": self.disclosure_policy, "evidence_hash": self.evidence_hash, "owner_session_id": self.owner_session_id, "source": self.source}


@dataclass(frozen=True)
class ScopeSnapshot:
    snapshot_id: str
    authorization: ProgramAuthorization
    targets: tuple[TargetIdentity, ...]
    created_at: str = field(default_factory=_utc)
    expires_at: str | None = None

    def target(self, target_id: str) -> TargetIdentity | None:
        return next((item for item in self.targets if item.target_id == target_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {"snapshot_id": self.snapshot_id, "authorization": self.authorization.to_dict(), "targets": [target.to_dict() for target in self.targets], "created_at": self.created_at, "expires_at": self.expires_at}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    program_id: str | None = None
    target_id: str | None = None
    snapshot_id: str | None = None
    canonical_url: str | None = None
    rate_limit_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def make_snapshot(snapshot_id: str, authorization: ProgramAuthorization, targets: list[TargetIdentity], *, expires_at: str | None = None, created_at: str | None = None) -> ScopeSnapshot:
    if any(target.program_id != authorization.program_id for target in targets):
        raise ScopeError("target_program_mismatch")
    return ScopeSnapshot(snapshot_id, authorization, tuple(targets), created_at=created_at or _utc(), expires_at=expires_at)
