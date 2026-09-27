"""Secure interactive Owner bootstrap.

Run locally:  python -m security.owner_password_bootstrap
Password reset:  python -m security.owner_password_bootstrap --reset

The password is read with getpass (never echoed, never logged) and only a
scrypt verifier is persisted. The bootstrap is idempotent: an existing
Owner account is never silently overwritten.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from security.owner_password import (
    OWNER_USERNAME,
    create_owner_account,
    owner_account_exists,
    reset_password,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CyberSentinel Owner credential bootstrap")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="change the Owner password (requires the current password)",
    )
    args = parser.parse_args(argv)

    if args.reset:
        username = input("Owner username: ").strip()
        if username != OWNER_USERNAME:
            print("owner_username_mismatch")
            return 2
        current = getpass.getpass("Current password: ")
        new = getpass.getpass("New password: ")
        confirm = getpass.getpass("Confirm new password: ")
        if new != confirm or not new:
            print("password_mismatch")
            return 2
        try:
            reset_password(username, current, new)
        except PermissionError:
            print("invalid_credentials")
            return 2
        print("owner_password_updated")
        return 0

    if owner_account_exists():
        print("owner_account_already_initialized")
        print("use --reset to change the Owner password")
        return 0

    username = input("Owner username: ").strip()
    if username != OWNER_USERNAME:
        print("owner_username_mismatch")
        return 2
    password = getpass.getpass("Owner password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm or not password:
        print("password_mismatch")
        return 2
    try:
        create_owner_account(username, password)
    except PermissionError as exc:
        print(str(exc))
        return 2
    print("owner_account_created")
    return 0


if __name__ == "__main__":
    sys.exit(main())
