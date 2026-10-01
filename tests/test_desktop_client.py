"""Contract tests for the CyberSentinel Desktop client.

The desktop application is a thin Electron shell over the existing backend.
These tests pin the product contract:

- the desktop shell starts the checked-in bridge server (python bridge.py)
  and loads the served web client from the loopback origin,
- the desktop process never mints, stores, or weakens credentials,
- the backend is consumed only through its existing public API,
- the Windows packaging pipeline builds real executables from the desktop
  sources in CI.

Backend code is not modified by the desktop client and these tests must not
require any backend change.
"""

from __future__ import annotations

import json
from pathlib import Path

MAIN = Path("desktop/main.js").read_text(encoding="utf-8")
PRELOAD = Path("desktop/preload.js").read_text(encoding="utf-8")
UNAVAILABLE = Path("desktop/unavailable.html").read_text(encoding="utf-8")
PACKAGE = json.loads(Path("desktop/package.json").read_text(encoding="utf-8"))
WORKFLOW = Path(".github/workflows/desktop-build.yml").read_text(encoding="utf-8")


def test_desktop_shell_runs_the_existing_bridge_and_loads_the_served_ui():
    # The desktop client reuses the existing backend entrypoint and the
    # existing web client instead of embedding a new application.
    assert 'spawn(python, ["bridge.py"]' in MAIN
    assert "PUBLIC_WEB_ENABLED" in MAIN
    assert 'env.BRIDGE_HOST = "127.0.0.1"' in MAIN
    assert "http://127.0.0.1" in MAIN
    assert 'mainWindow.loadURL(`${appOrigin()}/`)' in MAIN
    assert "/api/health" in MAIN


def test_desktop_does_not_invent_or_weaken_credentials():
    # No bridge token handling, no Owner credentials, no storage of secrets.
    for forbidden in ("BRIDGE_TOKEN", "OWNER_TOKEN", "cs_bridge_token", "cs_owner_token", "localStorage", "sessionStorage"):
        assert forbidden not in PRELOAD
    # The desktop shell never reads, assigns, or stores bridge tokens; it only
    # passes the operator's environment through to the backend process.
    assert 'env["BRIDGE_TOKEN"]' not in MAIN
    assert "BRIDGE_TOKEN =" not in MAIN
    assert "OWNER_TOKEN" not in MAIN
    # Renderer hardening stays enabled.
    assert "contextIsolation: true" in MAIN
    assert "nodeIntegration: false" in MAIN
    assert "sandbox: true" in MAIN


def test_desktop_handles_backend_unavailable_truthfully():
    # A real unavailable state with retry; no fabricated data.
    assert "unavailable.html" in MAIN
    assert "backend-unavailable" in MAIN
    assert "desktop:retry" in MAIN
    assert "لم يتم توليد أي بيانات بديلة" in UNAVAILABLE
    assert "إعادة المحاولة" in UNAVAILABLE


def test_desktop_builds_windows_executables_in_ci():
    build = PACKAGE["build"]
    targets = [item["target"] for item in build["win"]["target"]]
    assert "nsis" in targets
    assert "portable" in targets
    assert build["win"]["icon"] == "build/icon.png"
    assert PACKAGE["main"] == "main.js"
    # The CI workflow checks syntax, generates the icon, builds, and uploads
    # the produced executables as artifacts.
    assert "windows-latest" in WORKFLOW
    assert "node --check desktop/main.js" in WORKFLOW
    assert "node desktop/tools/make-icon.js" in WORKFLOW
    assert "electron-builder --win nsis portable" in WORKFLOW
    assert "actions/upload-artifact@v4" in WORKFLOW
    assert "contents: read" in WORKFLOW
    assert "git commit" not in WORKFLOW
