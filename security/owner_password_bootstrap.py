from __future__ import annotations

"""Secure interactive Owner bootstrap.

Run locally:

    python -m security.owner_password_bootstrap

Creates the canonical Owner account ("mosfiry") with a securely prompted
password. The password is read with getpass (never echoed), hashed with a
memory-hard KDF, and only the verifier is stored. Zero plaintext credential
material is written to the repository, logs, or database.

Safe to re-run: if the Owner account already exists the bootstrap refuses to
overwrite it and requires the explicit --reset flow (which itself requires the
current password, and is never a login bypass).
"""

import getpass
import sys

from security import owner_password as owner_auth


def _read_secret(prompt: str) -> str:
    value = getpass.getpass(prompt)
    if not value:
        raise SystemExit("password_required")
    return value


def _initialize() -> int:
    username = input("Owner username: ").strip()
    if username != owner_auth.OWNER_USERNAME:
        print("unknown_owner_username: expected the configured Owner identity")
        return 1
    password = _read_secret("Owner password: ")
    confirm = _read_secret("Confirm password: ")
    if password != confirm:
        print("password_mismatch")
        return 1
    owner_auth.create_owner_account(username, password)
    # Never print the password or any derived secret.
    print(
        "Owner account initialized. Only the password verifier "
        f"(algorithm: {owner_auth.KDF_ALGORITHM}) was stored."
    )
    return 0


def _reset() -> int:
    current = _read_secret("Current password: ")
    new = _read_secret("New password: ")
    confirm = _read_secret("Confirm new password: ")
    if new != confirm:
        print("password_mismatch")
        return 1
    try:
        owner_auth.reset_password(owner_auth.OWNER_USERNAME, current, new)
    except owner_auth.OwnerAuthenticationError:
        print("invalid_credentials")
        return 1
    print("Owner password rotated. All existing sessions were revoked.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    reset = "--reset" in argv
    if not owner_auth.owner_account_exists(owner_auth.OWNER_USERNAME):
        if reset:
            print("owner_account_not_initialized")
            return 1
        return _initialize()
    if not reset:
        print(
            "Owner account already initialized. Use "
            "'python -m security.owner_password_bootstrap --reset' "
            "(requires the current password) to rotate the password."
        )
        return 0
    return _reset()


if __name__ == "__main__":
    raise SystemExit(main())
