#!/usr/bin/env python3
"""Build and smoke-test the bundled CyberSentinel Python backend."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "desktop"
BUILD = DESKTOP / "build"
DIST = BUILD / "backend"
WORK = BUILD / "pyinstaller"
SPEC = BUILD / "spec"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-clean", action="store_true", help="reuse PyInstaller work directories")
    args = parser.parse_args()
    if not args.no_clean:
        for path in (DIST, WORK, SPEC):
            shutil.rmtree(path, ignore_errors=True)
    for path in (DIST, WORK, SPEC):
        path.mkdir(parents=True, exist_ok=True)

    separator = os.pathsep
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        "cybersentinel-backend",
        "--distpath",
        str(DIST),
        "--workpath",
        str(WORK),
        "--specpath",
        str(SPEC),
        "--paths",
        str(ROOT),
        "--add-data",
        f"{ROOT / 'web'}{separator}web",
        "--add-data",
        f"{ROOT / 'agent' / 'local_runtime' / 'catalog.json'}{separator}agent/local_runtime",
        "--collect-submodules",
        "tools",
        str(ROOT / "bridge.py"),
    ]
    print("Building bundled backend with PyInstaller...", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)
    executable = DIST / "cybersentinel-backend" / ("cybersentinel-backend.exe" if os.name == "nt" else "cybersentinel-backend")
    if not executable.is_file():
        raise SystemExit(f"backend_executable_missing:{executable}")

    result = subprocess.run(
        [str(executable), "--desktop-self-test"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    output = result.stdout.strip()
    if '"ok": true' not in output or '"web_assets": 3' not in output:
        raise SystemExit(f"backend_bundle_smoke_failed:{output}:{result.stderr.strip()}")
    print(f"Backend executable: {executable}", flush=True)
    print(f"Backend smoke: {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
