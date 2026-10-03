"""Canonical Owner username+password authentication for CyberSentinel.

This module implements the ONLY mechanism that authenticates the human
Owner. Owner identity always originates from a server-side session created
here after successful password verification.

Invariants:
- The plaintext password is never stored, logged, echoed, or returned.
- Only a scrypt verifier (salt + KDF parameters + digest) is persisted.
- Login failures are generic to prevent account enumeration.
- Client-supplied claims (booleans, roles, tokens, magic strings) are never
  consulted and can never authenticate anyone.
- BRIDGE_TOKEN is a transport credential and never implies Owner identity.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import core.db as core_db

OWNER_USERNAME = "mosfiry"
KDF_ALGORITHM = "scrypt"
KDF_N = 16384
KDF_R = 8
KDF_P = 1
KDF_DKLEN = 32
SALT_BYTES = 16
SESSION_TTL_SECONDS = 8 * 3600
AUTH_METHOD = "username_password"
LOGIN_FAILURE_THRESHOLD = 5
LOGIN_LOCKOUT_SECONDS = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> dict:
    """Return the persisted verifier fields for a password (never plaintext)."""
    if not isinstance(password, str) or not password:
        raise ValueError("invalid_password")
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
        dklen=KDF_DKLEN,
    )
    return {
        "password_hash": digest.hex(),
        "kdf_algorithm": KDF_ALGORITHM,
        "kdf_params_json": json.dumps(
            {"n": KDF_N, "p": KDF_P, "r": KDF_R, "dklen": KDF_DKLEN, "salt_hex": salt.hex()},
            sort_keys=True,
        ),
    }


def _verify(password: str, password_hash: str, kdf_algorithm: str, kdf_params_json: str) -> bool:
    if kdf_algorithm != KDF_ALGORITHM:
        return False
    try:
        params = json.loads(kdf_params_json)
        salt = bytes.fromhex(params["salt_hex"])
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(params["n"]),
            r=int(params["r"]),
            p=int(params["p"]),
            dklen=int(params["dklen"]),
        )
    except Exception:
        return False
    return hmac.compare_digest(digest.hex(), password_hash)


# Timing-equalization verifier used when the account does not exist so that
# unknown-username and wrong-password failures take a comparable code path.
_DUMMY = hash_password("cybersentinel-dummy-verifier")


def _dummy_verify(password: str) -> None:
    _verify(password, _DUMMY["password_hash"], _DUMMY["kdf_algorithm"], _DUMMY["kdf_params_json"])


def owner_account_exists() -> bool:
    with core_db.connect() as con:
        row = con.execute("SELECT 1 FROM owner_accounts LIMIT 1").fetchone()
    return row is not None


def create_owner_account(username: str, password: str) -> int:
    """Create the single canonical Owner account (bootstrap only).

    Atomicity: the UNIQUE constraint on owner_accounts.username is the
    authoritative guard. Even if the existence pre-check races with a
    concurrent bootstrap, the INSERT itself fails closed with
    IntegrityError, which is converted to the same generic PermissionError.
    No duplicate Owner row can ever exist.
    """
    if username != OWNER_USERNAME:
        raise PermissionError("owner_username_mismatch")
    verifier = hash_password(password)
    with core_db.connect() as con:
        row = con.execute(
            "SELECT owner_id FROM owner_accounts WHERE username = ?", (username,)
        ).fetchone()
        if row is not None:
            raise PermissionError("owner_account_already_exists")
        try:
            cur = con.execute(
                "INSERT INTO owner_accounts (username, password_hash, kdf_algorithm, kdf_params_json, status)"
                " VALUES (?, ?, ?, ?, 'active')",
                (username, verifier["password_hash"], verifier["kdf_algorithm"], verifier["kdf_params_json"]),
            )
            con.commit()
        except sqlite3.IntegrityError:
            con.rollback()
            raise PermissionError("owner_account_already_exists")
        return int(cur.lastrowid)


def _create_session(owner_id: int) -> dict:
    session_id = secrets.token_urlsafe(32)
    now = _now()
    expires = now + timedelta(seconds=SESSION_TTL_SECONDS)
    with core_db.connect() as con:
        con.execute(
            "INSERT INTO owner_sessions (session_id, owner_id, created_at, authenticated_at, expires_at, status, auth_method)"
            " VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (session_id, owner_id, _iso(now), _iso(now), _iso(expires), AUTH_METHOD),
        )
        con.commit()
    return {
        "session_id": session_id,
        "owner_id": owner_id,
        "auth_method": AUTH_METHOD,
        "authenticated_at": _iso(now),
        "expires_at": _iso(expires),
    }


# --- Login throttling (fail-closed, DB-backed) --------------------------------
#
# Bounds a local brute-force amplifier: after LOGIN_FAILURE_THRESHOLD
# consecutive failures for the canonical username, further attempts are
# rejected (even with CORRECT credentials) until the lockout window
# elapses. The lockout is deterministic, stored server-side, keyed ONLY
# to the canonical username (unknown-username attempts never create
# rows, so the table cannot be flooded), and can only ever REJECT -- it
# never widens authorization and never mints a session.


def _lockout_active(username: str) -> bool:
    with core_db.connect() as con:
        row = con.execute(
            "SELECT failures, last_failure_at FROM owner_login_throttle WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or int(row["failures"]) < LOGIN_FAILURE_THRESHOLD:
        return False
    try:
        last = datetime.fromisoformat(row["last_failure_at"])
    except (TypeError, ValueError):
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return last + timedelta(seconds=LOGIN_LOCKOUT_SECONDS) > _now()


def _record_login_failure(username: str) -> None:
    if username != OWNER_USERNAME:
        # Only attempts against the canonical account can move the lockout;
        # arbitrary client-supplied usernames must not create rows.
        return
    with core_db.connect() as con:
        con.execute(
            "INSERT INTO owner_login_throttle (username, failures, last_failure_at)"
            " VALUES (?, 1, ?)"
            " ON CONFLICT(username) DO UPDATE SET"
            " failures = CASE WHEN owner_login_throttle.failures >= ? THEN 1 ELSE owner_login_throttle.failures + 1 END,"
            " last_failure_at = excluded.last_failure_at",
            (username, _iso(_now()), LOGIN_FAILURE_THRESHOLD),
        )
        con.commit()


def _clear_login_failures(username: str) -> None:
    with core_db.connect() as con:
        con.execute("DELETE FROM owner_login_throttle WHERE username = ?", (username,))
        con.commit()


def login(username: str, password: str) -> dict:
    """The single human Owner authentication entry point.

    Returns a server-side session dict on success; raises PermissionError
    with a generic message on ANY failure (unknown username, wrong
    password, disabled account, malformed input, active lockout).
    """
    if not isinstance(username, str) or not isinstance(password, str):
        raise PermissionError("invalid_credentials")
    if _lockout_active(username):
        # Timing-equalized rejection: no real verifier is consulted during
        # lockout, so repeated attempts cannot mount a KDF oracle.
        _dummy_verify(password)
        raise PermissionError("invalid_credentials")
    with core_db.connect() as con:
        row = con.execute(
            "SELECT owner_id, username, password_hash, kdf_algorithm, kdf_params_json, status"
            " FROM owner_accounts WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or row["status"] != "active":
        _dummy_verify(password)
        _record_login_failure(username)
        raise PermissionError("invalid_credentials")
    if not _verify(password, row["password_hash"], row["kdf_algorithm"], row["kdf_params_json"]):
        _record_login_failure(username)
        raise PermissionError("invalid_credentials")
    _clear_login_failures(username)
    return _create_session(int(row["owner_id"]))


def resolve_session(session_id) -> dict | None:
    """Resolve a server-side Owner session; None when unknown/expired/revoked."""
    if not isinstance(session_id, str) or not session_id:
        return None
    with core_db.connect() as con:
        row = con.execute(
            "SELECT s.session_id, s.owner_id, s.status, s.expires_at, s.auth_method,"
            " a.username, a.status AS account_status"
            " FROM owner_sessions s JOIN owner_accounts a ON a.owner_id = s.owner_id"
            " WHERE s.session_id = ?",
            (session_id,),
        ).fetchone()
    if row is None or row["status"] != "active" or row["account_status"] != "active":
        return None
    try:
        expires = datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= _now():
        return None
    return {
        "session_id": row["session_id"],
        "owner_id": int(row["owner_id"]),
        "username": row["username"],
        "auth_method": row["auth_method"],
        "expires_at": row["expires_at"],
    }


def authenticated_owner(session_id) -> dict | None:
    """The ONLY way any caller obtains an authenticated Owner identity.

    Accepts ONLY a server-side session reference. Client-supplied booleans,
    roles, tokens, and magic strings are irrelevant by construction: there
    is no parameter through which they could authenticate anyone.
    """
    session = resolve_session(session_id)
    if session is None:
        return None
    return {
        "owner_id": session["owner_id"],
        "username": session["username"],
        "session_id": session["session_id"],
        "auth_method": session["auth_method"],
    }


def revoke_session(session_id) -> bool:
    if not isinstance(session_id, str) or not session_id:
        return False
    with core_db.connect() as con:
        cur = con.execute(
            "UPDATE owner_sessions SET status = 'revoked'"
            " WHERE session_id = ? AND status = 'active'",
            (session_id,),
        )
        con.commit()
        return cur.rowcount > 0


def revoke_owner_sessions(owner_id: int) -> None:
    with core_db.connect() as con:
        con.execute(
            "UPDATE owner_sessions SET status = 'revoked' WHERE owner_id = ? AND status = 'active'",
            (owner_id,),
        )
        con.commit()


def reset_password(username: str, current_password: str, new_password: str) -> None:
    """Rotate the Owner password; requires the CURRENT password (never a login bypass)."""
    if username != OWNER_USERNAME:
        raise PermissionError("invalid_credentials")
    if _lockout_active(username):
        # The current-password check is a KDF oracle exactly like login;
        # it shares the same fail-closed lockout.
        _dummy_verify(current_password)
        raise PermissionError("invalid_credentials")
    with core_db.connect() as con:
        row = con.execute(
            "SELECT owner_id, password_hash, kdf_algorithm, kdf_params_json FROM owner_accounts WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or not _verify(
        current_password, row["password_hash"], row["kdf_algorithm"], row["kdf_params_json"]
    ):
        _dummy_verify(current_password)
        _record_login_failure(username)
        raise PermissionError("invalid_credentials")
    verifier = hash_password(new_password)
    with core_db.connect() as con:
        con.execute(
            "UPDATE owner_accounts SET password_hash = ?, kdf_algorithm = ?, kdf_params_json = ?,"
            " updated_at = CURRENT_TIMESTAMP WHERE owner_id = ?",
            (verifier["password_hash"], verifier["kdf_algorithm"], verifier["kdf_params_json"], row["owner_id"]),
        )
        con.commit()
    _clear_login_failures(username)
    revoke_owner_sessions(int(row["owner_id"]))


def logout(session_id) -> bool:
    """Revoke a session. Idempotent and safe to call repeatedly."""
    return revoke_session(session_id)
