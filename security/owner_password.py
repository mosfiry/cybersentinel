from __future__ import annotations

"""Canonical human Owner authentication: USERNAME + PASSWORD.

This module is the ONLY mechanism that may authenticate the human Owner of
CyberSentinel. Legacy OWNER_TOKEN / owner-challenge schemes never establish
Owner identity.

Mandatory invariants:
- Plaintext passwords are never stored, logged, echoed, or persisted anywhere.
  Only a memory-hard scrypt verifier with a per-user random salt is stored.
- Login failures are generic; no username enumeration, equalized timing.
- Session identifiers are cryptographically random (secrets.token_urlsafe) and
  never derived from username, password, timestamps, request ids or counters.
- Owner identity originates exclusively from the server-side session store.
  Client-supplied owner claims (booleans, roles, methods, ids, tokens, magic
  strings) are untrusted input and never authenticate anyone.
- OWNER_TOKEN and bridge tokens are transport credentials; they never imply
  Owner identity.
"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

OWNER_USERNAME = "mosfiry"
AUTHENTICATION_METHOD = "username_password"
KDF_ALGORITHM = "scrypt"
KDF_N = 16384
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32
SESSION_TTL_SECONDS = 3600
GENERIC_FAILURE = "invalid_credentials"


class OwnerAuthenticationError(PermissionError):
    """Raised when human Owner authentication fails."""


def _connect():
    from core.db import connect

    return connect()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> dict[str, Any]:
    """Return a password verifier record. Never returns or stores plaintext."""
    if not isinstance(password, str) or not password:
        raise ValueError("password_required")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=KDF_N, r=KDF_R, p=KDF_P, dklen=KDF_DKLEN
    )
    record = {
        "password_hash": "$".join(
            [KDF_ALGORITHM, str(KDF_N), str(KDF_R), str(KDF_P), salt.hex(), digest.hex()]
        ),
        "kdf_algorithm": KDF_ALGORITHM,
        "kdf_params": json.dumps(
            {"n": KDF_N, "r": KDF_R, "p": KDF_P, "dklen": KDF_DKLEN}, sort_keys=True
        ),
    }
    # Defense in depth: refuse to return any record that could carry plaintext.
    if password in json.dumps(record):
        raise RuntimeError("plaintext_password_leak_detected")
    return record


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time verification of a password against a stored verifier."""
    try:
        algo, n, r, p, salt_hex, digest_hex = str(stored_hash).split("$")
        if algo != KDF_ALGORITHM:
            return False
        stored_bytes = bytes.fromhex(digest_hex)
        if not stored_bytes:
            return False
        digest = hashlib.scrypt(
            str(password).encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(stored_bytes),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


_DUMMY_HASH: str | None = None


def _dummy_verify(password: str) -> None:
    """Burn equivalent KDF time for unknown accounts (anti-enumeration)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(24))["password_hash"]
    verify_password(_DUMMY_HASH, password)


def get_owner_account(username: str) -> dict[str, Any] | None:
    with _connect() as con:
        row = con.execute(
            "SELECT * FROM owner_accounts WHERE username=?", (str(username or "").strip(),)
        ).fetchone()
    return dict(row) if row is not None else None


def owner_account_exists(username: str = OWNER_USERNAME) -> bool:
    return get_owner_account(username) is not None


def create_owner_account(username: str, password: str) -> dict[str, Any]:
    """Idempotent-safe creation of the single canonical Owner account."""
    username = str(username or "").strip()
    if username != OWNER_USERNAME:
        raise OwnerAuthenticationError("unknown_owner_username")
    record = hash_password(password)
    with _connect() as con:
        try:
            con.execute(
                "INSERT INTO owner_accounts(username,password_hash,kdf_algorithm,kdf_params)"
                " VALUES(?,?,?,?)",
                (
                    username,
                    record["password_hash"],
                    record["kdf_algorithm"],
                    record["kdf_params"],
                ),
            )
        except Exception as exc:  # UNIQUE constraint => already initialized
            raise OwnerAuthenticationError("owner_account_already_initialized") from exc
    return {"username": username}


def login(
    username: str, password: str, *, ttl_seconds: int = SESSION_TTL_SECONDS
) -> dict[str, Any]:
    """Canonical login. Returns a secure server-side Owner session.

    Never logs or persists the submitted password. Generic failure for both
    unknown username and wrong password.
    """
    username = str(username or "").strip()
    password = str(password or "")
    if ttl_seconds <= 0:
        raise ValueError("invalid_ttl")
    account = get_owner_account(username)
    if account is None:
        _dummy_verify(password)
        raise OwnerAuthenticationError(GENERIC_FAILURE)
    if str(account.get("status") or "active") != "active":
        _dummy_verify(password)
        raise OwnerAuthenticationError(GENERIC_FAILURE)
    if not verify_password(account["password_hash"], password):
        raise OwnerAuthenticationError(GENERIC_FAILURE)
    now = _utcnow()
    expires_at = now + timedelta(seconds=ttl_seconds)
    # Cryptographically random session id: never derived from username,
    # password, timestamp, request id, or any counter.
    session_id = secrets.token_urlsafe(32)
    with _connect() as con:
        con.execute(
            "INSERT INTO owner_sessions"
            "(session_id,owner_id,created_at,expires_at,authenticated_at,status,authentication_method)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                account["id"],
                now.isoformat(),
                expires_at.isoformat(),
                now.isoformat(),
                "active",
                AUTHENTICATION_METHOD,
            ),
        )
    return {
        "session_id": session_id,
        "owner_id": account["id"],
        "username": account["username"],
        "authenticated_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "authentication_method": AUTHENTICATION_METHOD,
    }


def resolve_session(session_id: str) -> dict[str, Any] | None:
    """Resolve Owner identity exclusively from the server-side session store."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return None
    with _connect() as con:
        row = con.execute(
            "SELECT s.session_id, s.owner_id, s.expires_at, s.authenticated_at,"
            " s.status, s.authentication_method, a.username, a.status AS account_status"
            " FROM owner_sessions s JOIN owner_accounts a ON a.id = s.owner_id"
            " WHERE s.session_id=?",
            (session_id,),
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    try:
        expires = datetime.fromisoformat(item["expires_at"])
    except (TypeError, ValueError):
        return None
    if (
        item["status"] != "active"
        or item["account_status"] != "active"
        or item["authentication_method"] != AUTHENTICATION_METHOD
        or expires <= _utcnow()
    ):
        return None
    return {
        "session_id": item["session_id"],
        "owner_id": item["owner_id"],
        "username": item["username"],
        "authenticated_at": item["authenticated_at"],
        "authentication_method": item["authentication_method"],
    }


def revoke_session(session_id: str) -> bool:
    with _connect() as con:
        cur = con.execute(
            "UPDATE owner_sessions SET status='revoked' WHERE session_id=?",
            (str(session_id or "").strip(),),
        )
        return cur.rowcount == 1


def revoke_owner_sessions(owner_id: int) -> int:
    with _connect() as con:
        cur = con.execute(
            "UPDATE owner_sessions SET status='revoked' WHERE owner_id=? AND status='active'",
            (int(owner_id),),
        )
        return cur.rowcount


def reset_password(username: str, current_password: str, new_password: str) -> None:
    """Authenticated password rotation. Requires the current password.

    This is never a login bypass: without the correct current password the
    rotation fails closed with a generic error.
    """
    account = get_owner_account(username)
    if account is None or not verify_password(
        account["password_hash"], str(current_password or "")
    ):
        raise OwnerAuthenticationError(GENERIC_FAILURE)
    record = hash_password(new_password)
    with _connect() as con:
        con.execute(
            "UPDATE owner_accounts SET password_hash=?, kdf_algorithm=?, kdf_params=?,"
            " updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (
                record["password_hash"],
                record["kdf_algorithm"],
                record["kdf_params"],
                account["id"],
            ),
        )
    revoke_owner_sessions(account["id"])


# Client-supplied keys that must NEVER influence authentication. They are
# untrusted input only; Owner identity comes exclusively from the server-side
# session store resolved by resolve_session().
IGNORED_CLIENT_CLAIM_KEYS = (
    "owner_authenticated",
    "role",
    "is_owner",
    "owner",
    "authentication_method",
    "owner_id",
    "owner_token",
    "OWNER_TOKEN",
    "owner_session",
    "owner_proof",
)


def authenticated_owner(
    session_id: str, client_claims: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Return the authenticated human Owner, if any.

    ALL client-supplied owner claims are ignored: booleans, roles,
    authentication methods, ids, tokens and magic strings never authenticate
    anyone. Only a valid server-side session establishes Owner identity.
    """
    # Deliberately discard untrusted claims; they are never consulted.
    if isinstance(client_claims, dict):
        for _key in IGNORED_CLIENT_CLAIM_KEYS:
            client_claims.pop(_key, None)
    return resolve_session(session_id)
