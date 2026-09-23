from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import secrets
import threading
from typing import Any

from security.owner_policy import verify_owner


@dataclass
class OwnerSession:
    session_id: str
    challenge: str
    expires_at: datetime
    used: bool = False
    owner_identity: str = "legacy-owner"
    credential_version: int = 0

    def public(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "challenge": self.challenge,
            "expires_at": self.expires_at.isoformat(),
            "owner_identity": self.owner_identity,
            "credential_version": self.credential_version,
        }


class OwnerSessionManager:
    """Short-lived, in-memory Owner sessions bound to the authenticated token.

    The challenge is a convenience for the chat interface, not an authentication
    secret by itself. Creation still requires OWNER_TOKEN, and consumption is
    single-use, expiry checked, and bound to the session that created it.
    """

    def __init__(self, ttl_seconds: int = 120):
        if not 10 <= ttl_seconds <= 900:
            raise ValueError("ttl_seconds must be between 10 and 900")
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, OwnerSession] = {}
        self._lock = threading.RLock()

    def create(self, presented_token: str | None = None, *, username: str | None = None, password: str | None = None) -> OwnerSession:
        owner_identity = "legacy-owner"
        credential_version = 0
        if username is not None or password is not None:
            from security.owner_credentials import OwnerCredentialError, authenticate
            try:
                owner = authenticate(str(username or ""), str(password or ""))
            except (OwnerCredentialError, ValueError) as exc:
                raise PermissionError("owner authentication required") from exc
            owner_identity = owner.username
            credential_version = owner.credential_version
        else:
            ok, reason = verify_owner("Owner session", presented_token)
            if not ok:
                raise PermissionError(reason)
        now = datetime.now(timezone.utc)
        session = OwnerSession(
            session_id=secrets.token_urlsafe(24),
            challenge="CSO-" + secrets.token_hex(4).upper() + "-" + secrets.token_hex(2).upper(),
            expires_at=now + timedelta(seconds=self.ttl_seconds),
            owner_identity=owner_identity,
            credential_version=credential_version,
        )
        with self._lock:
            self._purge(now)
            self._sessions[session.session_id] = session
        return session

    def consume(self, session_id: str, challenge: str, message: str, request_id: str = "") -> dict[str, Any]:
        session_id = str(session_id or "").strip()
        challenge = str(challenge or "").strip()
        message = str(message or "")
        now = datetime.now(timezone.utc)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise PermissionError("unknown owner session")
            if session.expires_at <= now:
                del self._sessions[session_id]
                raise PermissionError("owner challenge expired")
            if session.used:
                raise PermissionError("owner challenge already used")
            if not hmac.compare_digest(session.challenge, challenge):
                raise PermissionError("invalid owner challenge")
            if challenge not in message:
                raise PermissionError("owner challenge must be included in the message")
            session.used = True
            session_proof = hmac.new(session.challenge.encode("utf-8"), f"{session.session_id}|{request_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            return {
                "owner_authenticated": True,
                "owner_session_id": session.session_id,
                "owner_identity": session.owner_identity,
                "credential_version": session.credential_version,
                "authentication_method": "owner_session_challenge",
                "authenticated_at": now.isoformat(),
                "request_id": str(request_id),
                "session_proof": session_proof,
            }

    def validate_challenge(self, session_id: str, challenge: str, message: str) -> bool:
        """Validate entry credentials without consuming the single-use challenge."""
        session_id = str(session_id or "").strip()
        challenge = str(challenge or "").strip()
        message = str(message or "")
        now = datetime.now(timezone.utc)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise PermissionError("unknown owner session")
            if session.expires_at <= now:
                raise PermissionError("owner challenge expired")
            if session.used:
                raise PermissionError("owner challenge already used")
            if not hmac.compare_digest(session.challenge, challenge):
                raise PermissionError("invalid owner challenge")
            if challenge not in message:
                raise PermissionError("owner challenge must be included in the message")
            return True

    def is_active(self, session_id: str) -> bool:
        """Return whether the authenticated session is present and unexpired.

        Challenge consumption is one-time, but the authenticated session remains
        usable until expiry for task resume/pause/cancel authorization.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            session = self._sessions.get(str(session_id or ""))
            if session is None or session.expires_at <= now:
                if session is not None:
                    self._sessions.pop(str(session_id), None)
                return False
            return True

    def invalidate_identity(self, owner_identity: str, *, except_session_id: str | None = None) -> None:
        with self._lock:
            for session_id, session in list(self._sessions.items()):
                if session.owner_identity == owner_identity and session_id != except_session_id:
                    self._sessions.pop(session_id, None)

    def verify_proof(self, session_id: str, request_id: str, proof: str) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            session = self._sessions.get(str(session_id or ""))
            if session is None or not session.used or session.expires_at <= now:
                return False
            expected = hmac.new(session.challenge.encode("utf-8"), f"{session.session_id}|{request_id}".encode("utf-8"), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, str(proof or ""))

    def _purge(self, now: datetime) -> None:
        expired = [key for key, value in self._sessions.items() if value.expires_at <= now or value.used]
        for key in expired:
            self._sessions.pop(key, None)


DEFAULT_OWNER_SESSIONS = OwnerSessionManager()


def create_owner_session(presented_token: str | None = None, *, username: str | None = None, password: str | None = None) -> dict[str, Any]:
    return DEFAULT_OWNER_SESSIONS.create(presented_token, username=username, password=password).public()


def consume_owner_challenge(session_id: str, challenge: str, message: str, request_id: str = "") -> dict[str, Any]:
    return DEFAULT_OWNER_SESSIONS.consume(session_id, challenge, message, request_id)


def validate_owner_challenge(session_id: str, challenge: str, message: str) -> bool:
    return DEFAULT_OWNER_SESSIONS.validate_challenge(session_id, challenge, message)


def verify_owner_session_proof(session_id: str, request_id: str, proof: str) -> bool:
    return DEFAULT_OWNER_SESSIONS.verify_proof(session_id, request_id, proof)
