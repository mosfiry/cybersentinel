"""Owner username/password credentials with bootstrap and rotation support.

Only salted scrypt verifiers are persisted. Plaintext credentials are accepted
only at the authentication boundary and are never included in public records.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS_PATH = Path(os.getenv("CYBERSENTINEL_OWNER_CREDENTIALS_PATH", str(ROOT / "security" / "owner_credentials_state.json")))
DEFAULT_OWNER_USERNAME = os.getenv("CYBERSENTINEL_OWNER_USERNAME", "mosfiry").strip() or "mosfiry"
_BOOTSTRAP_ENV = "CYBERSENTINEL_OWNER_BOOTSTRAP_PASSWORD"
_LOCK = threading.RLock()


class OwnerCredentialError(PermissionError):
    pass


@dataclass(frozen=True)
class AuthenticatedOwner:
    username: str
    credential_version: int
    authenticated_at: str

    def public(self) -> dict[str, Any]:
        return {
            "owner_identity": self.username,
            "credential_version": self.credential_version,
            "authenticated_at": self.authenticated_at,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_username(username: str) -> str:
    value = str(username or "").strip()
    if not value:
        raise ValueError("username is required")
    if len(value) > 128 or any(ch.isspace() for ch in value):
        raise ValueError("username must be non-empty and contain no whitespace")
    return value


def _validate_password(password: str) -> str:
    value = str(password or "")
    if not value:
        raise ValueError("password is required")
    if len(value) < 12:
        raise ValueError("password must contain at least 12 characters")
    return value


def hash_password(password: str) -> str:
    value = _validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$v1$n=16384,r=8,p=1${}${}".format(salt.hex(), digest.hex())


def verify_password(password: str, encoded: str) -> bool:
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    try:
        algorithm, version, params, salt_hex, digest_hex = encoded.split("$", 4)
        if (algorithm, version, params) != ("scrypt", "v1", "n=16384,r=8,p=1"):
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def _empty_state() -> dict[str, Any]:
    return {"schema_version": 1, "credential": None}


def _load() -> dict[str, Any]:
    if not CREDENTIALS_PATH.exists():
        return _empty_state()
    try:
        value = json.loads(CREDENTIALS_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else _empty_state()
    except (OSError, ValueError):
        return _empty_state()


def _save(state: dict[str, Any]) -> None:
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CREDENTIALS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CREDENTIALS_PATH)
    os.chmod(CREDENTIALS_PATH, 0o600)


def is_bootstrapped() -> bool:
    with _LOCK:
        return isinstance(_load().get("credential"), dict)


def bootstrap_owner(*, username: str | None = None, password: str | None = None) -> AuthenticatedOwner:
    """Create the first Owner account; fail closed if setup already exists."""
    owner = _validate_username(username or DEFAULT_OWNER_USERNAME)
    secret = _validate_password(password if password is not None else os.getenv(_BOOTSTRAP_ENV, ""))
    with _LOCK:
        state = _load()
        if state.get("credential"):
            raise OwnerCredentialError("Owner bootstrap already completed")
        now = _now()
        state["credential"] = {
            "username": owner,
            "password_hash": hash_password(secret),
            "password_algorithm": "scrypt",
            "password_algorithm_version": "v1",
            "created_at": now,
            "updated_at": now,
            "credential_version": 1,
        }
        _save(state)
    return AuthenticatedOwner(owner, 1, now)


def authenticate(username: str, password: str) -> AuthenticatedOwner:
    owner = _validate_username(username)
    if not isinstance(password, str) or not password:
        raise OwnerCredentialError("invalid Owner credentials")
    with _LOCK:
        credential = _load().get("credential")
        if not isinstance(credential, dict) or not hmac.compare_digest(str(credential.get("username", "")), owner) or not verify_password(password, str(credential.get("password_hash", ""))):
            raise OwnerCredentialError("invalid Owner credentials")
        return AuthenticatedOwner(owner, int(credential.get("credential_version", 1)), _now())


def _require_session_proof(session_manager: Any, session_id: str, request_id: str, proof: str) -> AuthenticatedOwner:
    if not session_manager.verify_proof(session_id, request_id, proof):
        raise OwnerCredentialError("valid authenticated Owner session proof required")
    with _LOCK:
        credential = _load().get("credential") or {}
    return AuthenticatedOwner(str(credential.get("username", "")), int(credential.get("credential_version", 1)), _now())


def change_password(*, session_manager: Any, session_id: str, request_id: str, session_proof: str, current_password: str, new_password: str) -> AuthenticatedOwner:
    owner = _require_session_proof(session_manager, session_id, request_id, session_proof)
    authenticate(owner.username, current_password)
    new_hash = hash_password(new_password)
    with _LOCK:
        state = _load()
        credential = state.get("credential") or {}
        version = int(credential.get("credential_version", 1)) + 1
        credential.update({"password_hash": new_hash, "password_algorithm": "scrypt", "password_algorithm_version": "v1", "updated_at": _now(), "credential_version": version})
        state["credential"] = credential
        _save(state)
    session_manager.invalidate_identity(owner.username)
    return AuthenticatedOwner(owner.username, version, _now())


def change_username(*, session_manager: Any, session_id: str, request_id: str, session_proof: str, password: str, new_username: str) -> AuthenticatedOwner:
    owner = _require_session_proof(session_manager, session_id, request_id, session_proof)
    authenticate(owner.username, password)
    replacement = _validate_username(new_username)
    with _LOCK:
        state = _load()
        credential = state.get("credential") or {}
        version = int(credential.get("credential_version", 1)) + 1
        credential.update({"username": replacement, "updated_at": _now(), "credential_version": version})
        state["credential"] = credential
        _save(state)
    session_manager.invalidate_identity(owner.username)
    return AuthenticatedOwner(replacement, version, _now())


__all__ = ["AuthenticatedOwner", "OwnerCredentialError", "authenticate", "bootstrap_owner", "change_password", "change_username", "hash_password", "is_bootstrapped", "verify_password"]
