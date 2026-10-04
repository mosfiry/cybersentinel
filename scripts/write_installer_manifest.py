#!/usr/bin/env python3
"""Write checksums and a minimal provenance manifest for a Windows installer."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    directory = args.directory.resolve()
    installer = directory / f"CyberSentinel-Setup-{args.version}.exe"
    if not installer.is_file() or installer.stat().st_size <= 0:
        raise SystemExit(f"installer_missing_or_empty:{installer}")
    digest = sha256(installer)
    (directory / f"{installer.name}.sha256").write_text(f"{digest}  {installer.name}\n", encoding="ascii")
    manifest = {
        "product": "CyberSentinel Desktop",
        "version": args.version,
        "installer": installer.name,
        "size_bytes": installer.stat().st_size,
        "sha256": digest,
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "distribution": "private workflow artifact; no GitHub Release or tag created",
    }
    (directory / "installer-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{installer.name}: {digest} ({installer.stat().st_size} bytes)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
