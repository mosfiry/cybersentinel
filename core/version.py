from __future__ import annotations

import re
import sys
from pathlib import Path

_PRODUCT_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")


def _load_version() -> str:
    if getattr(sys, "frozen", False):
        bundle_root = Path(getattr(sys, "_MEIPASS", ""))
    else:
        bundle_root = Path(__file__).resolve().parents[1]
    version_path = bundle_root / "VERSION"
    try:
        version = version_path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError(f"canonical product VERSION file is unavailable: {version_path}") from exc
    if not _PRODUCT_VERSION_PATTERN.fullmatch(version):
        raise RuntimeError(f"canonical product VERSION file is invalid: {version_path}")
    return version


VERSION = _load_version()
PRODUCT_NAME = "CyberSentinel X"
SERVER_VERSION = f"{PRODUCT_NAME}/{VERSION}"
