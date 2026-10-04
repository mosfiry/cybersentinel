from __future__ import annotations

import os
import stat
from typing import Final

_MAX_SECRET_BYTES: Final[int] = 16 * 1024


def secret_env(name: str, default: str = "") -> str:
    """Read a secret from NAME_FILE, falling back to the legacy NAME variable.

    Supplying both sources is rejected so deployment overrides cannot silently
    shadow a mounted Compose secret. File reads reject symlinks and non-regular
    files and are bounded to keep malformed mounts from consuming unbounded
    memory. Secret contents are never included in raised error messages.
    """
    if not name or not name.replace("_", "").isalnum() or name[0].isdigit():
        raise ValueError("secret environment name must be an identifier")

    direct = os.environ.get(name)
    file_path = os.environ.get(f"{name}_FILE")
    if direct is not None and file_path is not None:
        raise RuntimeError(f"configure either {name} or {name}_FILE, not both")
    if file_path is None:
        return (direct if direct is not None else default).strip()
    if not file_path:
        raise RuntimeError(f"{name}_FILE must identify a secret file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(file_path, flags)
    except OSError:
        raise RuntimeError(f"{name}_FILE could not be opened safely") from None

    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{name}_FILE must refer to a regular file")
        if metadata.st_size > _MAX_SECRET_BYTES:
            raise RuntimeError(f"{name}_FILE exceeds the maximum allowed size")
        with os.fdopen(fd, "rb", closefd=True) as stream:
            fd = -1
            raw = stream.read(_MAX_SECRET_BYTES + 1)
        if len(raw) > _MAX_SECRET_BYTES:
            raise RuntimeError(f"{name}_FILE exceeds the maximum allowed size")
        try:
            return raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise RuntimeError(f"{name}_FILE must contain UTF-8 text") from None
    finally:
        if fd >= 0:
            os.close(fd)
