from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import uuid
from typing import Any

from security.scope import ProgramAuthorization, ScopeError, ScopeSnapshot, TargetIdentity, _asset_matches, canonical_host, make_snapshot


_MAX_ASSETS = 32
_MAX_TARGETS = 32
_MAX_PORTS = 20
_MAX_PATHS = 32
_MAX_METHODS = 9
_MAX_RATE_PER_MINUTE = 1_000
_MAX_EXPIRATION_DAYS = 365
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
_TOP_LEVEL_FIELDS = frozenset({
    "program_id",
    "platform",
    "scope_version",
    "in_scope_assets",
    "out_of_scope_assets",
    "targets",
    "allowed_methods",
    "prohibited_methods",
    "rate_limits",
    "expires_at",
})
_ASSET_FIELDS = frozenset({"host", "schemes", "ports", "paths"})
_TARGET_FIELDS = frozenset({"target_id", "host", "asset_type", "environment", "allowed_ports", "allowed_paths", "excluded_paths"})
_OUT_OF_SCOPE_FIELDS = frozenset({"host", "paths"})


def _object(value: Any, *, allowed: frozenset[str], required: frozenset[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"invalid_{field}")
    keys = set(value)
    if keys - allowed:
        raise ValueError(f"unknown_{field}_field")
    if required - keys:
        raise ValueError(f"missing_{field}_field")
    return value


def _list(value: Any, *, field: str, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"invalid_{field}")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid_{field}")
    return value


def _host(value: Any, *, field: str, allow_wildcard: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 253:
        raise ValueError(f"invalid_{field}")
    if "://" in value or "/" in value or "@" in value:
        raise ValueError(f"invalid_{field}")
    wildcard = value.startswith("*.")
    if "*" in value and (not allow_wildcard or not wildcard or value.count("*") != 1):
        raise ValueError(f"invalid_{field}")
    try:
        canonical = canonical_host(value[2:] if wildcard else value)
    except ScopeError as exc:
        raise ValueError(f"invalid_{field}") from exc
    return f"*.{canonical}" if wildcard else canonical


def _path(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or not value.startswith("/")
        or value.startswith("//")
        or any(char in value for char in ("?", "#", "\\"))
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(segment in {".", ".."} for segment in value.split("/"))
        or re.search(r"%(?:2e|2f|5c)", value, flags=re.IGNORECASE)
    ):
        raise ValueError(f"invalid_{field}")
    return value


def _paths(value: Any, *, field: str, minimum: int, maximum: int) -> tuple[str, ...]:
    items = _list(value, field=field, minimum=minimum, maximum=maximum)
    parsed = tuple(_path(item, field) for item in items)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"duplicate_{field}")
    return parsed


def _ports(value: Any, field: str) -> tuple[int, ...]:
    items = _list(value, field=field, minimum=1, maximum=_MAX_PORTS)
    if any(type(item) is not int or not 1 <= item <= 65535 for item in items):
        raise ValueError(f"invalid_{field}")
    parsed = tuple(items)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"duplicate_{field}")
    return parsed


def _assets(value: Any, *, field: str, out_of_scope: bool = False) -> tuple[dict[str, Any], ...]:
    items = _list(value, field=field, minimum=0 if out_of_scope else 1, maximum=_MAX_ASSETS)
    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in items:
        if out_of_scope:
            raw = _object(item, allowed=_OUT_OF_SCOPE_FIELDS, required=frozenset({"host"}), field="out_of_scope_asset")
            asset: dict[str, Any] = {"host": _host(raw["host"], field="out_of_scope_host", allow_wildcard=True)}
            if "paths" in raw:
                asset["paths"] = list(_paths(raw["paths"], field="out_of_scope_paths", minimum=0, maximum=_MAX_PATHS))
            identity = (asset["host"], tuple(asset.get("paths", ())))
        else:
            raw = _object(item, allowed=_ASSET_FIELDS, required=_ASSET_FIELDS, field="in_scope_asset")
            schemes = _list(raw["schemes"], field="asset_schemes", minimum=1, maximum=2)
            if any(not isinstance(scheme, str) or scheme not in {"http", "https"} for scheme in schemes) or len(set(schemes)) != len(schemes):
                raise ValueError("invalid_asset_schemes")
            asset = {
                "host": _host(raw["host"], field="in_scope_host", allow_wildcard=True),
                "schemes": list(schemes),
                "ports": list(_ports(raw["ports"], "asset_ports")),
                "paths": list(_paths(raw["paths"], field="asset_paths", minimum=1, maximum=_MAX_PATHS)),
            }
            identity = (asset["host"], tuple(asset["schemes"]), tuple(asset["ports"]), tuple(asset["paths"]))
        if identity in seen:
            raise ValueError(f"duplicate_{field}")
        seen.add(identity)
        result.append(asset)
    return tuple(result)


def _methods(value: Any, *, field: str, minimum: int) -> tuple[str, ...]:
    items = _list(value, field=field, minimum=minimum, maximum=_MAX_METHODS)
    if any(not isinstance(item, str) or item not in _HTTP_METHODS for item in items):
        raise ValueError(f"invalid_{field}")
    parsed = tuple(items)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"duplicate_{field}")
    return parsed


def _rate_limits(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) - {"requests_per_minute"}:
        raise ValueError("invalid_rate_limits")
    if not value:
        return {}
    limit = value["requests_per_minute"]
    if type(limit) is not int or not 1 <= limit <= _MAX_RATE_PER_MINUTE:
        raise ValueError("invalid_requests_per_minute")
    return {"requests_per_minute": limit}


def _expiration(value: Any, *, now: datetime) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 64:
        raise ValueError("invalid_expires_at")
    try:
        expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid_expires_at") from exc
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("expires_at_timezone_required")
    expires_at = expires_at.astimezone(timezone.utc)
    if expires_at <= now:
        raise ValueError("expires_at_must_be_future")
    if expires_at > now + timedelta(days=_MAX_EXPIRATION_DAYS):
        raise ValueError("expires_at_too_far")
    return expires_at.isoformat()


def _target_is_within_assets(target: TargetIdentity, assets: tuple[dict[str, Any], ...]) -> bool:
    for port in target.allowed_ports:
        for path in target.allowed_paths:
            if not any(
                _asset_matches(asset, target.host, scheme, port, path)
                for asset in assets
                for scheme in asset["schemes"]
            ):
                return False
    return True


def build_manual_scope_snapshot(payload: Any) -> ScopeSnapshot:
    """Validate an explicit Owner-submitted scope declaration and build its snapshot."""
    raw = _object(
        payload,
        allowed=_TOP_LEVEL_FIELDS,
        required=_TOP_LEVEL_FIELDS - {"rate_limits"},
        field="request",
    )
    program_id = _identifier(raw["program_id"], "program_id")
    platform = _identifier(raw["platform"], "platform")
    scope_version = _identifier(raw["scope_version"], "scope_version")
    in_scope_assets = _assets(raw["in_scope_assets"], field="in_scope_assets")
    out_of_scope_assets = _assets(raw["out_of_scope_assets"], field="out_of_scope_assets", out_of_scope=True)
    allowed_methods = _methods(raw["allowed_methods"], field="allowed_methods", minimum=1)
    prohibited_methods = _methods(raw["prohibited_methods"], field="prohibited_methods", minimum=0)
    if set(allowed_methods) & set(prohibited_methods):
        raise ValueError("allowed_and_prohibited_methods_overlap")
    rate_limits = _rate_limits(raw.get("rate_limits", {}))
    if not isinstance(raw["targets"], list) or not 1 <= len(raw["targets"]) <= _MAX_TARGETS:
        raise ValueError("invalid_targets")
    targets: list[TargetIdentity] = []
    target_ids: set[str] = set()
    for item in raw["targets"]:
        target_data = _object(
            item,
            allowed=_TARGET_FIELDS,
            required=frozenset({"target_id", "host", "allowed_ports", "allowed_paths"}),
            field="target",
        )
        target_id = _identifier(target_data["target_id"], "target_id")
        if target_id in target_ids:
            raise ValueError("duplicate_target_id")
        target_ids.add(target_id)
        host = _host(target_data["host"], field="target_host")
        allowed_ports = _ports(target_data["allowed_ports"], "target_ports")
        allowed_paths = _paths(target_data["allowed_paths"], field="target_paths", minimum=1, maximum=_MAX_PATHS)
        excluded_paths = _paths(target_data.get("excluded_paths", []), field="target_excluded_paths", minimum=0, maximum=_MAX_PATHS)
        asset_type = target_data.get("asset_type", "web")
        environment = target_data.get("environment", "production")
        if not isinstance(asset_type, str) or not _IDENTIFIER.fullmatch(asset_type):
            raise ValueError("invalid_asset_type")
        if not isinstance(environment, str) or not _IDENTIFIER.fullmatch(environment):
            raise ValueError("invalid_environment")
        try:
            target = TargetIdentity(
                target_id=target_id,
                program_id=program_id,
                host=host,
                asset_type=asset_type,
                environment=environment,
                allowed_ports=allowed_ports,
                allowed_paths=allowed_paths,
                excluded_paths=excluded_paths,
            )
        except ScopeError as exc:
            raise ValueError("invalid_target") from exc
        if not _target_is_within_assets(target, in_scope_assets):
            raise ValueError("target_outside_in_scope_assets")
        targets.append(target)

    now = datetime.now(timezone.utc)
    expires_at = _expiration(raw["expires_at"], now=now)
    authorization = ProgramAuthorization(
        program_id=program_id,
        platform=platform,
        scope_version=scope_version,
        retrieved_at=now.isoformat(),
        in_scope_assets=in_scope_assets,
        out_of_scope_assets=out_of_scope_assets,
        allowed_methods=allowed_methods,
        prohibited_methods=prohibited_methods,
        rate_limits=rate_limits,
        source="owner",
    )
    return make_snapshot(uuid.uuid4().hex, authorization, targets, expires_at=expires_at)


def public_snapshot_summary(snapshot: ScopeSnapshot) -> dict[str, Any]:
    """Return only browser-safe summary fields; never serialize Owner session evidence."""
    authorization = snapshot.authorization
    return {
        "snapshot_id": snapshot.snapshot_id,
        "program_id": authorization.program_id,
        "platform": authorization.platform,
        "scope_version": authorization.scope_version,
        "in_scope_asset_count": len(authorization.in_scope_assets),
        "out_of_scope_asset_count": len(authorization.out_of_scope_assets),
        "target_count": len(snapshot.targets),
        "allowed_methods": list(authorization.allowed_methods),
        "prohibited_methods": list(authorization.prohibited_methods),
        "rate_limits": dict(authorization.rate_limits),
        "created_at": snapshot.created_at,
        "expires_at": snapshot.expires_at,
    }
