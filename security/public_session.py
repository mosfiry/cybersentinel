from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import threading
from typing import Any


@dataclass(frozen=True)
class PublicSession:
    session_id: str
    csrf_token: str
    created_at: datetime
    expires_at: datetime

    def public(self) -> dict[str, Any]:
        return {
            "csrf_token": self.csrf_token,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


class PublicSessionManager:
    """Short-lived, server-side browser sessions for the public boundary.

    A public session is not Owner authentication. The session identifier is
    intended for an HttpOnly cookie; the CSRF token is returned to the browser
    only for an in-memory request header and is not an authorization credential.
    """

    def __init__(self, ttl_seconds: int = 1800):
        if not 60 <= ttl_seconds <= 86400:
            raise ValueError("ttl_seconds must be between 60 and 86400")
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, PublicSession] = {}
        self._lock = threading.RLock()

    def create(self) -> PublicSession:
        now = datetime.now(timezone.utc)
        session = PublicSession(
            session_id=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + timedelta(seconds=self.ttl_seconds),
        )
        with self._lock:
            self._purge(now)
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str | None) -> PublicSession | None:
        now = datetime.now(timezone.utc)
        key = str(session_id or "").strip()
        if not key:
            return None
        with self._lock:
            self._purge(now)
            return self._sessions.get(key)

    def validate(self, session_id: str | None, csrf_token: str | None) -> PublicSession:
        session = self.get(session_id)
        if session is None:
            raise PermissionError("public session required")
        if not secrets.compare_digest(session.csrf_token, str(csrf_token or "")):
            raise PermissionError("invalid csrf token")
        return session

    def revoke(self, session_id: str | None) -> None:
        key = str(session_id or "").strip()
        if key:
            with self._lock:
                self._sessions.pop(key, None)

    def _purge(self, now: datetime) -> None:
        expired = [key for key, value in self._sessions.items() if value.expires_at <= now]
        for key in expired:
            self._sessions.pop(key, None)


DEFAULT_PUBLIC_SESSIONS = PublicSessionManager()
