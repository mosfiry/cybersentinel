"""Contract tests for the CyberSentinel Desktop client.

The desktop application is a thin Electron shell over the existing backend.
These tests pin the product contract:

- the desktop shell starts the checked-in bridge server (python bridge.py)
  and loads the served web client from the loopback origin,
- the desktop process never mints, stores, or forwards credential values,
- the public API uses Owner-only sessions, CSRF, and independent backend checks,
- the Windows packaging pipeline builds real executables from the desktop
  sources in CI.

Desktop UI, shell, and backend changes are integrated on the release branch and
tested together; no other branch is part of this test contract.
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
    assert 'spawn(python, ["bridge.py", "--desktop-stdio-control"]' in MAIN
    assert "PUBLIC_WEB_ENABLED" in MAIN
    assert 'env.BRIDGE_HOST = "127.0.0.1"' in MAIN
    assert "http://127.0.0.1" in MAIN
    assert 'mainWindow.loadURL(`${appOrigin()}/`)' in MAIN
    assert "/api/health" in MAIN


def test_packaged_desktop_requires_an_explicit_repository_path():
    repo_root = MAIN.split("function repoRoot()", 1)[1].split("\n}", 1)[0]
    assert "process.env[REPO_ENV_KEY]" in repo_root
    assert "if (!app.isPackaged)" in repo_root
    assert repo_root.index("if (!app.isPackaged)") < repo_root.index("process.cwd()")


def test_desktop_does_not_invent_or_weaken_credentials():
    # No token/credential values are read from .env, passed by Electron, or
    # exposed to the renderer. Python loads its own private configuration.
    for forbidden in ("OWNER_TOKEN", "cs_bridge_token", "cs_owner_token", "localStorage", "sessionStorage"):
        assert forbidden not in PRELOAD
    assert "parseDotEnv" not in MAIN
    assert "readFileSync(envPath" not in MAIN
    assert "Object.entries(process.env)" not in MAIN
    assert '"BRIDGE_TOKEN",' not in MAIN
    assert '"LLM_API_KEY",' not in MAIN
    assert '"BRIDGE_TOKEN_FILE"' in MAIN
    assert 'env.BRIDGE_HOST = "127.0.0.1"' in MAIN
    assert "OWNER_TOKEN" not in MAIN
    # Renderer hardening stays enabled.
    assert "contextIsolation: true" in MAIN
    assert "nodeIntegration: false" in MAIN
    assert "sandbox: true" in MAIN
    bridge = Path("bridge.py").read_text(encoding="utf-8")
    assert "--desktop-stdio-control" in bridge
    assert "CYBERSENTINEL_DESKTOP_SHUTDOWN" in bridge
    assert 'child.stdin.end("CYBERSENTINEL_DESKTOP_SHUTDOWN\\n")' in MAIN
    assert 'child.kill("SIGKILL")' in MAIN


def test_desktop_navigation_allows_only_the_trusted_unavailable_file():
    assert "function isUnavailableFile(url)" in MAIN
    assert "fileURLToPath(parsed)" in MAIN
    assert "isAppOrigin(url) || isUnavailableFile(url)" in MAIN
    assert 'on("will-navigate", guardNavigation)' in MAIN
    assert 'on("will-redirect", guardNavigation)' in MAIN
    assert 'url.startsWith("file://")' not in MAIN


def test_desktop_child_environment_and_logs_are_restricted():
    assert '"PYTHONPATH"' not in MAIN
    assert '"PYTHONHOME"' not in MAIN
    assert '"PUBLIC_WEB_ORIGIN"' not in MAIN
    assert 'env.PUBLIC_WEB_ORIGIN = ""' in MAIN
    assert "bridgeProcess.stdout.resume()" in MAIN
    assert "bridgeProcess.stderr.resume()" in MAIN
    assert "process.stdout.write(`[bridge]" not in MAIN
    assert "process.stderr.write(`[bridge]" not in MAIN


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
    assert PACKAGE["version"] == "5.0.0"
    assert PACKAGE["devDependencies"]["electron"] == "44.5.1"
    assert PACKAGE["devDependencies"]["electron-builder"] == "26.15.3"
    assert PACKAGE["overrides"]["@electron/get"] == "5.1.0"
    assert Path("desktop/package-lock.json").is_file()
    assert 'node-version: "22"' in WORKFLOW
    assert "npm ci --no-audit --no-fund" in WORKFLOW
    assert "npm audit --audit-level=high" in WORKFLOW
