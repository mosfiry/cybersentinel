from __future__ import annotations

"""Scope Firewall hard-failure battery (2026-09-22 audit).

Every case here is a fail-closed expectation: the resolver must deny,
raise, or normalize — never silently allow. If any case flips, the
firewall has a real regression.
"""

from pathlib import Path

import pytest

from security.scope import (
    ProgramAuthorization,
    ScopeError,
    TargetIdentity,
    _asset_matches,
    canonical_host,
    canonical_url,
    make_snapshot,
)
from security.scope_resolver import _out_of_scope, resolve
from security.scope_store import init_scope_store, save_snapshot
import security.scope_store as scope_store
import security.owner_policy as owner_policy


# ---------------------------------------------------------------------------
# canonical_host
# ---------------------------------------------------------------------------

def test_canonical_host_normalizes_case_and_trailing_dot():
    assert canonical_host("EXAMPLE.COM.") == "example.com"


def test_canonical_host_ipv6_is_compressed_and_lowercased():
    assert canonical_host("2001:0DB8::0001") == "2001:db8::1"


def test_canonical_host_ipv4_mapped_ipv6_stays_distinct_from_ipv4():
    # Fail-closed: the mapped form must NOT canonicalize onto the IPv4 form,
    # otherwise an IPv4 scope entry would silently cover a mapped-IPv6 host.
    assert canonical_host("::ffff:127.0.0.1") != canonical_host("127.0.0.1")


@pytest.mark.parametrize("bad", ["", "  ", "a b", "a/b", "a@b", "a\nb"])
def test_canonical_host_rejects_invalid_hosts(bad):
    with pytest.raises(ScopeError):
        canonical_host(bad)


def test_canonical_host_rejects_idna_failure():
    with pytest.raises(ScopeError):
        canonical_host("x" * 300 + ".example.invalid-tld")


# ---------------------------------------------------------------------------
# canonical_url
# ---------------------------------------------------------------------------

def test_canonical_url_rejects_non_http_schemes():
    for url in ("file:///etc/passwd", "ftp://target.example.com/x", "gopher://x/y", "javascript://x"):
        with pytest.raises(ScopeError):
            canonical_url(url)


def test_canonical_url_rejects_userinfo_credentials():
    with pytest.raises(ScopeError):
        canonical_url("https://user:pass@target.example.com/api")


def test_canonical_url_rejects_bad_ports_and_keeps_explicit_ports():
    with pytest.raises(ScopeError):
        canonical_url("https://target.example.com:notaport/api")
    assert canonical_url("https://target.example.com:8443/api") == "https://target.example.com:8443/api"
    assert canonical_url("https://target.example.com:443/api") == "https://target.example.com/api"


def test_canonical_url_normalizes_path_and_drops_fragment():
    assert canonical_url("HTTPS://TARGET.EXAMPLE.COM") == "https://target.example.com/"
    assert canonical_url("https://target.example.com/api#frag") == "https://target.example.com/api"


# ---------------------------------------------------------------------------
# wildcard / asset semantics
# ---------------------------------------------------------------------------

def _wildcard_asset():
    return {"host": "*.example.com", "schemes": ["https"], "ports": [443]}


def test_wildcard_matches_subdomains_but_not_apex():
    asset = _wildcard_asset()
    assert _asset_matches(asset, "a.example.com", "https", 443, "/")
    assert _asset_matches(asset, "deep.sub.example.com", "https", 443, "/")
    assert not _asset_matches(asset, "example.com", "https", 443, "/")
    assert not _asset_matches(asset, "notexample.com", "https", 443, "/")


def test_asset_scheme_port_and_path_restrictions():
    asset = {"host": "target.example.com", "schemes": ["https"], "ports": [8443], "paths": ["/api"]}
    assert not _asset_matches(asset, "target.example.com", "http", 8443, "/api")
    assert not _asset_matches(asset, "target.example.com", "https", 443, "/api")
    assert _asset_matches(asset, "target.example.com", "https", 8443, "/api/v1")
    assert not _asset_matches(asset, "target.example.com", "https", 8443, "/other")


# ---------------------------------------------------------------------------
# snapshot integrity
# ---------------------------------------------------------------------------

def _authorization(**overrides):
    kwargs = dict(
        program_id="program-battery",
        platform="test",
        scope_version="v1",
        retrieved_at="2026-09-22T00:00:00+00:00",
        in_scope_assets=({"host": "target.example.com", "schemes": ["https"], "ports": [443], "paths": ["/api"]},),
        out_of_scope_assets=({"host": "target.example.com", "paths": ["/admin"]},),
        allowed_methods=("GET", "HEAD"),
        prohibited_methods=("POST", "PUT", "DELETE"),
        rate_limits={},
    )
    kwargs.update(overrides)
    return ProgramAuthorization(**kwargs)


def _target():
    return TargetIdentity("target-1", "program-battery", "target.example.com", allowed_ports=(443,), allowed_paths=("/api",), excluded_paths=("/api/private",))


@pytest.fixture
def battery_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "battery-owner")
    init_scope_store()
    return save_snapshot(make_snapshot("snapshot-battery", _authorization(), [_target()]), owner_token="battery-owner")


def test_save_snapshot_requires_owner_authentication(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "battery-owner")
    init_scope_store()
    with pytest.raises(PermissionError):
        save_snapshot(make_snapshot("snapshot-noauth", _authorization(), [_target()]), owner_token="wrong-token")
    with pytest.raises(PermissionError):
        save_snapshot(make_snapshot("snapshot-noauth", _authorization(), [_target()]), owner_token=None)


def test_snapshot_evidence_hash_is_tamper_evident(battery_snapshot, tmp_path, monkeypatch):
    import json
    import sqlite3
    conn = sqlite3.connect(str(scope_store.SCOPE_DB_PATH))
    row = conn.execute("SELECT snapshot_json FROM scope_snapshots WHERE snapshot_id = 'snapshot-battery'").fetchone()
    payload = json.loads(row[0])
    payload["authorization"]["in_scope_assets"][0]["host"] = "evil.example.com"
    conn.execute("UPDATE scope_snapshots SET snapshot_json = ? WHERE snapshot_id = 'snapshot-battery'", (json.dumps(payload),))
    conn.commit()
    conn.close()
    with pytest.raises(ValueError):
        scope_store.get_snapshot("snapshot-battery")


# ---------------------------------------------------------------------------
# resolve() fail-closed matrix
# ---------------------------------------------------------------------------

def _resolve_ok(battery_snapshot, **kwargs):
    return resolve(battery_snapshot.snapshot_id, "target-1", "https://target.example.com/api", consume_rate=False, **kwargs)


def test_resolve_unknown_snapshot_fails_closed():
    decision = resolve("no-such-snapshot", "target-1", "https://target.example.com/api")
    assert decision.allowed is False
    assert decision.reason == "unknown_scope_snapshot"


def test_resolve_unknown_target_fails_closed(battery_snapshot):
    decision = resolve(battery_snapshot.snapshot_id, "target-999", "https://target.example.com/api", consume_rate=False)
    assert decision.allowed is False
    assert decision.reason == "unknown_target"


def test_resolve_program_binding_is_enforced(battery_snapshot):
    decision = _resolve_ok(battery_snapshot, expected_program_id="other-program")
    assert decision.allowed is False
    assert decision.reason == "program_snapshot_mismatch"


def test_resolve_host_mismatch_fails_closed(battery_snapshot):
    for url in (
        "https://other.example.com/api",
        "https://sub.target.example.com/api",
        "https://target.example.com.evil.com/api",
    ):
        decision = resolve(battery_snapshot.snapshot_id, "target-1", url, consume_rate=False)
        assert decision.allowed is False, url


def test_resolve_scheme_port_and_path_violations_fail_closed(battery_snapshot):
    for url in (
        "http://target.example.com/api",
        "https://target.example.com:8443/api",
        "https://target.example.com/api/private/keys",
        "https://target.example.com/admin",
        "https://target.example.com/other",
    ):
        decision = resolve(battery_snapshot.snapshot_id, "target-1", url, consume_rate=False)
        assert decision.allowed is False, url


def test_resolve_prohibited_methods_fail_closed(battery_snapshot):
    for method in ("POST", "PUT", "DELETE", "PATCH", "post"):
        decision = _resolve_ok(battery_snapshot, method=method)
        assert decision.allowed is False, method


def test_resolve_redirect_chain_out_of_scope_fails_closed(battery_snapshot):
    decision = _resolve_ok(battery_snapshot, redirect_chain=["https://evil.example.com/collect"])
    assert decision.allowed is False
    assert decision.reason == "redirect_out_of_scope"


def test_resolve_expired_snapshot_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "battery-owner")
    init_scope_store()
    expired = save_snapshot(
        make_snapshot("snapshot-expired", _authorization(), [_target()], expires_at="2020-01-01T00:00:00+00:00"),
        owner_token="battery-owner",
    )
    decision = resolve(expired.snapshot_id, "target-1", "https://target.example.com/api", consume_rate=False)
    assert decision.allowed is False
    assert decision.reason == "scope_snapshot_expired"


def test_resolve_valid_request_is_allowed(battery_snapshot):
    decision = _resolve_ok(battery_snapshot)
    assert decision.allowed is True
    assert decision.canonical_url == "https://target.example.com/api"


# ---------------------------------------------------------------------------
# out_of_scope exclusion hardening
# ---------------------------------------------------------------------------

def test_out_of_scope_matches_exact_and_subdomains():
    snapshot = make_snapshot("x", _authorization(out_of_scope_assets=({"host": "admin.example.com"},)), [_target()])
    assert _out_of_scope(snapshot, "admin.example.com", "/anything")
    assert _out_of_scope(snapshot, "sub.admin.example.com", "/anything")
    assert not _out_of_scope(snapshot, "other.example.com", "/anything")


def test_out_of_scope_wildcard_covers_apex_and_subdomains():
    snapshot = make_snapshot("x", _authorization(out_of_scope_assets=({"host": "*.forbidden.example"},)), [_target()])
    assert _out_of_scope(snapshot, "forbidden.example", "/")
    assert _out_of_scope(snapshot, "a.forbidden.example", "/")
    assert not _out_of_scope(snapshot, "forbidden.example.net", "/")


def test_out_of_scope_unicode_entry_is_canonicalized_not_silently_ignored():
    # A non-ASCII exclusion entry must still match its canonical form instead
    # of failing open because of an encoding mismatch.
    snapshot = make_snapshot("x", _authorization(out_of_scope_assets=({"host": "TARGET.example.com."},)), [_target()])
    assert _out_of_scope(snapshot, "target.example.com", "/api")


def test_out_of_scope_malformed_entry_fails_closed():
    snapshot = make_snapshot("x", _authorization(out_of_scope_assets=({"host": "bad host/with slashes"},)), [_target()])
    assert _out_of_scope(snapshot, "target.example.com", "/api")
