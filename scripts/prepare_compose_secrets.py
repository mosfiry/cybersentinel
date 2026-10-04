#!/usr/bin/env python3
"""Prepare host files used by the self-hosted Compose runtime secrets."""
from __future__ import annotations

import argparse
import os
import secrets
import stat
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SECRET_FILES = (
    "bridge_token",
    "llm_api_key",
    "local_llm_api_key",
    "colab_llm_api_key",
    "hf_llm_api_key",
)
CONTAINER_GID = 10001
SECRET_MODE = 0o440


def _directory_from_args(value: str | None) -> Path:
    selected = value or os.environ.get("CYBERSENTINEL_SECRETS_DIR", "./secrets")
    path = Path(selected).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def _validate_existing_secret(directory_fd: int, name: str) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"refusing non-regular or symlinked secret file: {name}")
    if metadata.st_uid != 0 or metadata.st_gid != CONTAINER_GID:
        raise SystemExit(f"secret file ownership must be root:{CONTAINER_GID}: {name}")
    if stat.S_IMODE(metadata.st_mode) != SECRET_MODE:
        raise SystemExit(f"secret file mode must be 0440: {name}")


def prepare(directory: Path) -> list[str]:
    if os.geteuid() != 0:
        raise SystemExit("run this setup command with sudo so secret files can be restricted to the container UID/GID")

    if directory.is_symlink():
        raise SystemExit(f"refusing symlinked secrets directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o711)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"secrets path must be a real directory: {directory}")
    os.chown(directory, 0, 0, follow_symlinks=False)
    os.chmod(directory, 0o711, follow_symlinks=False)

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, flags)
    created: list[str] = []
    try:
        for name in SECRET_FILES:
            try:
                fd = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                _validate_existing_secret(directory_fd, name)
                continue

            try:
                if name == "bridge_token":
                    payload = (secrets.token_urlsafe(48) + "\n").encode("ascii")
                    view = memoryview(payload)
                    while view:
                        view = view[os.write(fd, view) :]
                os.fchown(fd, 0, CONTAINER_GID)
                os.fchmod(fd, SECRET_MODE)
                os.fsync(fd)
            finally:
                os.close(fd)
            created.append(name)
    finally:
        os.close(directory_fd)

    directory_fd = os.open(directory, flags)
    try:
        for name in SECRET_FILES:
            _validate_existing_secret(directory_fd, name)
    finally:
        os.close(directory_fd)
    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        help="secrets directory (default: CYBERSENTINEL_SECRETS_DIR or ./secrets)",
    )
    args = parser.parse_args()
    directory = _directory_from_args(args.directory)
    created = prepare(directory)
    print(f"Compose secret files are ready in {directory}.")
    if created:
        print("Created (existing files were preserved): " + ", ".join(created))
    else:
        print("All existing secret files were preserved and validated.")
    print("Set provider keys in their files with a root-owned editor; the bridge token is generated once and never printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
