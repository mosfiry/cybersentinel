#!/usr/bin/env python3
"""Build and smoke-test the bundled CyberSentinel Python backend."""
from __future__ import annotations

import argparse
from importlib.metadata import version
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
PLAYWRIGHT_VERSION = "1.62.0"


def _browser_cache_root() -> Path:
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if configured == "0":
        raise SystemExit("playwright_package_local_browser_cache_is_not_supported_for_packaging")
    if configured:
        return Path(configured).expanduser().resolve()
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
        capture_output=True, text=True, timeout=15, check=True,
    )
    first_location = next(
        (line.split("Install location:", 1)[1].strip() for line in result.stdout.splitlines() if "Install location:" in line),
        "",
    )
    if not first_location:
        raise SystemExit("playwright_browser_cache_location_unavailable")
    return Path(first_location).expanduser().resolve().parent


def _prepare_browser_resource() -> Path:
    installed = version("playwright")
    if installed != PLAYWRIGHT_VERSION:
        raise SystemExit(f"playwright_version_mismatch:{installed}:expected={PLAYWRIGHT_VERSION}")
    cache_root = _browser_cache_root()
    if not cache_root.is_dir():
        raise SystemExit(f"playwright_browser_cache_missing:{cache_root}")
    executables = (
        Path("chrome-win64/chrome.exe"), Path("chrome-linux64/chrome"),
        Path("chrome-linux/chrome"), Path("chrome-mac/Chromium.app/Contents/MacOS/Chromium"),
        Path("chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium"),
    )
    # Chromium's versioned install directory is reported separately from the
    # common Playwright cache root by the dry-run metadata.
    chromium_dirs = [item for item in cache_root.glob("chromium-*") if item.is_dir()]
    if not any((chromium_dir / executable).is_file() for chromium_dir in chromium_dirs for executable in executables):
        raise SystemExit(f"playwright_chromium_missing:{cache_root}")

    packaged_root = BUILD / "browser" / "ms-playwright"
    if cache_root.resolve() != packaged_root.resolve():
        shutil.rmtree(packaged_root, ignore_errors=True)
        packaged_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(cache_root, packaged_root, dirs_exist_ok=True)
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(packaged_root.resolve())
    return packaged_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-clean", action="store_true", help="reuse PyInstaller work directories")
    args = parser.parse_args()
    if not args.no_clean:
        for path in (DIST, WORK, SPEC):
            shutil.rmtree(path, ignore_errors=True)
    for path in (DIST, WORK, SPEC):
        path.mkdir(parents=True, exist_ok=True)
    browser_root = _prepare_browser_resource()

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
        f"{ROOT / 'VERSION'}{separator}.",
        "--add-data",
        f"{ROOT / 'web'}{separator}web",
        "--add-data",
        f"{ROOT / 'agent' / 'local_runtime' / 'catalog.json'}{separator}agent/local_runtime",
        "--collect-submodules",
        "tools",
        "--collect-all",
        "playwright",
        "--collect-all",
        "greenlet",
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
    browser_smoke = subprocess.run(
        [str(executable), "--desktop-browser-self-test"],
        cwd=ROOT,
        env={**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(browser_root.resolve())},
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    browser_output = browser_smoke.stdout.strip()
    if '"ok": true' not in browser_output or '"browser_runtime": "chromium"' not in browser_output:
        raise SystemExit(f"backend_chromium_smoke_failed:{browser_output}:{browser_smoke.stderr.strip()}")
    print(f"Bundled Chromium smoke: {browser_output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
