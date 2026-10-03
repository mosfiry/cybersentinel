from __future__ import annotations

import sqlite3
from pathlib import Path


_REQUIRED_CORE_TABLES = frozenset(
    {"events", "executions", "owner_accounts", "owner_sessions"}
)


def _database_state(database_path: Path) -> tuple[str, str]:
    """Inspect core-store integrity without creating or migrating any data."""
    try:
        path = Path(database_path)
        if not path.is_file():
            return "DATABASE_UNAVAILABLE", "AUTHORITY_UNAVAILABLE"
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1.0) as connection:
            integrity = connection.execute("PRAGMA quick_check(1)").fetchone()
            if integrity is None or integrity[0] != "ok":
                return "DATABASE_INTEGRITY_FAILURE", "AUTHORITY_UNAVAILABLE"
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not _REQUIRED_CORE_TABLES.issubset(tables):
                return "DATABASE_SCHEMA_INCOMPLETE", "AUTHORITY_UNAVAILABLE"
            owner = connection.execute(
                "SELECT 1 FROM owner_accounts WHERE status='active' LIMIT 1"
            ).fetchone()
    except (OSError, sqlite3.Error, ValueError):
        return "DATABASE_UNAVAILABLE", "AUTHORITY_UNAVAILABLE"

    return (
        "DATABASE_READY",
        "AUTHORITY_READY" if owner is not None else "OWNER_SETUP_REQUIRED",
    )


def readiness_snapshot(
    database_path: Path, *, provider_configured: bool = False
) -> dict[str, object]:
    """Describe bridge readiness without probing external providers or workers.

    The bridge and mission worker are separate processes. Worker liveness is
    reported by its independent Compose health check; this endpoint never
    infers worker readiness from the bridge process.
    """
    database, authority = _database_state(database_path)
    ready = database == "DATABASE_READY" and authority == "AUTHORITY_READY"
    checks = {
        "process": "PROCESS_ALIVE",
        "service": "SERVICE_READY" if ready else "SERVICE_NOT_READY",
        "database": database,
        "authority": authority,
        "provider": (
            "PROVIDER_CONFIGURED_UNVERIFIED"
            if provider_configured
            else "PROVIDER_OPTIONAL_LOCAL_FALLBACK"
        ),
        "worker": "SEPARATE_COMPOSE_HEALTHCHECK",
    }
    return {
        "scope": "bridge",
        "ready": ready,
        "state": "SERVICE_READY" if ready else "SERVICE_NOT_READY",
        "checks": checks,
    }


__all__ = ["readiness_snapshot"]
