from __future__ import annotations

import sqlite3
from pathlib import Path

import bridge
import core.db as core_db
from core.health import readiness_snapshot
from security.owner_password import create_owner_account


def _initialize_core_store(path: Path, monkeypatch) -> None:
    monkeypatch.setattr(core_db, "DB_PATH", path)
    monkeypatch.setattr(bridge, "DB_PATH", path)
    core_db.connect().close()


def test_missing_database_is_not_created_by_readiness_probe(tmp_path: Path) -> None:
    database_path = tmp_path / "not-created.sqlite3"

    result = readiness_snapshot(database_path)

    assert result == {
        "scope": "bridge",
        "ready": False,
        "state": "SERVICE_NOT_READY",
        "checks": {
            "process": "PROCESS_ALIVE",
            "service": "SERVICE_NOT_READY",
            "database": "DATABASE_UNAVAILABLE",
            "authority": "AUTHORITY_UNAVAILABLE",
            "provider": "PROVIDER_OPTIONAL_LOCAL_FALLBACK",
            "worker": "SEPARATE_COMPOSE_HEALTHCHECK",
        },
    }
    assert not database_path.exists()


def test_incomplete_or_corrupt_database_fails_closed(tmp_path: Path) -> None:
    incomplete = tmp_path / "incomplete.sqlite3"
    with sqlite3.connect(incomplete) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")

    incomplete_result = readiness_snapshot(incomplete)
    assert incomplete_result["ready"] is False
    assert incomplete_result["checks"]["database"] == "DATABASE_SCHEMA_INCOMPLETE"
    assert incomplete_result["checks"]["authority"] == "AUTHORITY_UNAVAILABLE"

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not-a-sqlite-database")
    corrupt_result = readiness_snapshot(corrupt)
    assert corrupt_result["ready"] is False
    assert corrupt_result["checks"]["database"] == "DATABASE_UNAVAILABLE"
    assert corrupt_result["checks"]["authority"] == "AUTHORITY_UNAVAILABLE"
    assert str(corrupt) not in repr(corrupt_result)


def test_database_ready_but_owner_setup_required_then_bootstrap_recovers(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "core.sqlite3"
    _initialize_core_store(database_path, monkeypatch)

    before = readiness_snapshot(database_path)
    assert before["ready"] is False
    assert before["checks"]["database"] == "DATABASE_READY"
    assert before["checks"]["authority"] == "OWNER_SETUP_REQUIRED"

    create_owner_account("mosfiry", "unit-test-only-owner-password")
    after = readiness_snapshot(database_path)
    assert after["ready"] is True
    assert after["state"] == "SERVICE_READY"
    assert after["checks"]["authority"] == "AUTHORITY_READY"
    assert after["checks"]["provider"] == "PROVIDER_OPTIONAL_LOCAL_FALLBACK"


def test_configured_provider_is_reported_unverified_without_network_probe(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "core.sqlite3"
    _initialize_core_store(database_path, monkeypatch)
    create_owner_account("mosfiry", "unit-test-only-owner-password")

    result = readiness_snapshot(database_path, provider_configured=True)

    assert result["ready"] is True
    assert result["checks"]["provider"] == "PROVIDER_CONFIGURED_UNVERIFIED"
    assert "base_url" not in repr(result)
    assert "api_key" not in repr(result)


def test_ready_route_keeps_liveness_public_and_requires_bridge_token_for_details(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "core.sqlite3"
    _initialize_core_store(database_path, monkeypatch)
    create_owner_account("mosfiry", "unit-test-only-owner-password")
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "transport-token-test-only")
    monkeypatch.setattr(bridge.RUNTIME.router, "providers", [])

    def invoke(path: str, headers: dict[str, str]):
        handler = bridge.Handler.__new__(bridge.Handler)
        handler.path = path
        handler.headers = headers
        handler._send = lambda status, payload, *args, **kwargs: (status, payload)
        return bridge.Handler.do_GET(handler)

    live_status, live_payload = invoke("/api/health/live", {})
    assert live_status == 200
    assert live_payload["state"] == "PROCESS_ALIVE"

    unauthorized_status, unauthorized = invoke("/api/health/ready", {})
    assert unauthorized_status == 401
    assert unauthorized["error"] == "bridge authentication required"

    ready_status, ready_payload = invoke(
        "/api/health/ready",
        {"X-CyberSentinel-Token": "transport-token-test-only"},
    )
    assert ready_status == 200
    assert ready_payload["ok"] is True
    assert ready_payload["checks"]["authority"] == "AUTHORITY_READY"
    assert ready_payload["checks"]["worker"] == "SEPARATE_COMPOSE_HEALTHCHECK"
    assert "session" not in repr(ready_payload).lower()
    assert "transport-token-test-only" not in repr(ready_payload)
