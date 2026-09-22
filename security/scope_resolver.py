from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit
from typing import Any

from .scope import ScopeDecision, ScopeError, ScopeSnapshot, _asset_matches, canonical_url
from .scope_store import count_rate_events, get_snapshot, record_rate_event


def _expired(value: str | None) -> bool:
    if not value:
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) <= datetime.now(timezone.utc)
    except ValueError:
        return True


def _out_of_scope(snapshot: ScopeSnapshot, host: str, path: str) -> bool:
    for asset in snapshot.authorization.out_of_scope_assets:
        candidate = str(asset.get("host") or asset.get("hostname") or "").lower().lstrip("*.")
        if host == candidate or host.endswith("." + candidate):
            excluded_paths = asset.get("paths") or asset.get("excluded_paths") or []
            if not excluded_paths or any(path == item or path.startswith(str(item).rstrip("/") + "/") for item in excluded_paths):
                return True
    return False


def resolve(snapshot_id: str, target_id: str, url: str, *, method: str = "GET", expected_program_id: str | None = None, redirect_chain: list[str] | None = None, consume_rate: bool = True) -> ScopeDecision:
    if redirect_chain is not None and len(redirect_chain) > 10:
        return ScopeDecision(False, "redirect_chain_too_long", snapshot_id=snapshot_id, target_id=target_id)
    snapshot = get_snapshot(snapshot_id)
    if snapshot is None:
        return ScopeDecision(False, "unknown_scope_snapshot", snapshot_id=snapshot_id, target_id=target_id)
    if _expired(snapshot.expires_at):
        return ScopeDecision(False, "scope_snapshot_expired", snapshot.authorization.program_id, target_id, snapshot_id)
    if expected_program_id and expected_program_id != snapshot.authorization.program_id:
        return ScopeDecision(False, "program_snapshot_mismatch", expected_program_id, target_id, snapshot_id)
    target = snapshot.target(target_id)
    if target is None:
        return ScopeDecision(False, "unknown_target", snapshot.authorization.program_id, target_id, snapshot_id)
    if target.program_id != snapshot.authorization.program_id:
        return ScopeDecision(False, "target_program_mismatch", snapshot.authorization.program_id, target_id, snapshot_id)
    try:
        normalized = canonical_url(url)
    except ScopeError as exc:
        return ScopeDecision(False, str(exc), snapshot.authorization.program_id, target_id, snapshot_id)
    parts = urlsplit(normalized)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not any(_asset_matches(asset, parts.hostname, parts.scheme, port, parts.path) for asset in snapshot.authorization.in_scope_assets):
        return ScopeDecision(False, "asset_not_in_scope", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    if parts.hostname != target.host:
        return ScopeDecision(False, "target_host_mismatch", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    if target.allowed_ports and port not in target.allowed_ports:
        return ScopeDecision(False, "target_port_not_allowed", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    if target.allowed_paths and not any(parts.path == item or parts.path.startswith(str(item).rstrip("/") + "/") for item in target.allowed_paths):
        return ScopeDecision(False, "target_path_not_allowed", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    if target.excluded_paths and any(parts.path == item or parts.path.startswith(str(item).rstrip("/") + "/") for item in target.excluded_paths):
        return ScopeDecision(False, "target_path_excluded", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    if _out_of_scope(snapshot, parts.hostname, parts.path):
        return ScopeDecision(False, "out_of_scope_asset", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    method = method.upper().strip()
    if method not in {item.upper() for item in snapshot.authorization.allowed_methods} or method in {item.upper() for item in snapshot.authorization.prohibited_methods}:
        return ScopeDecision(False, "method_not_allowed", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    for redirected in redirect_chain or []:
        redirected_decision = resolve(snapshot_id, target_id, redirected, method=method, expected_program_id=expected_program_id, consume_rate=False)
        if not redirected_decision.allowed:
            return ScopeDecision(False, "redirect_out_of_scope", snapshot.authorization.program_id, target_id, snapshot_id, normalized)
    rate_limit = int(snapshot.authorization.rate_limits.get("requests_per_minute", 0) or 0)
    rate_key = f"{snapshot.authorization.program_id}:{target_id}"
    if rate_limit:
        import time
        now = time.time()
        if count_rate_events(rate_key, now - 60) >= rate_limit:
            return ScopeDecision(False, "rate_limit_exceeded", snapshot.authorization.program_id, target_id, snapshot_id, normalized, rate_key)
        if consume_rate:
            record_rate_event(rate_key, now)
    return ScopeDecision(True, "scope_authorized", snapshot.authorization.program_id, target_id, snapshot_id, normalized, rate_key)


class ScopeResolver:
    resolve = staticmethod(resolve)
    get_snapshot = staticmethod(get_snapshot)
