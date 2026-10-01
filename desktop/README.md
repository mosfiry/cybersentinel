# CyberSentinel Desktop — Windows Build Instructions

CyberSentinel Desktop is an Electron shell around the existing Arabic web UI
served by the existing local bridge (bridge.py). It contains no backend
logic of its own. See docs/DESKTOP_ARCHITECTURE.md and
docs/DESKTOP_BACKEND_CONTRACT.md for the boundaries.

## Prerequisites

- Node.js 20 or newer (for building)
- Python 3.13 (only to generate the application icon and to run the bridge)
- The bridge running locally (see below) whenever the application is used

## Local build (development check)

```bash
python desktop/scripts/make_icon.py   # generates desktop/build/icon.ico
cd desktop
npm install
npm start                             # launches the shell against 127.0.0.1:8787
npm run dist                          # produces dist/CyberSentinel-Desktop-Setup-1.0.0.exe
                                      # and dist/CyberSentinel-Desktop-Portable-1.0.0.exe
```

## CI build (authoritative Windows .exe)

The workflow .github/workflows/desktop-windows-build.yml runs on every push
to a desktop/** branch and on manual dispatch. It:

1. checks out the branch,
2. generates desktop/build/icon.ico with desktop/scripts/make_icon.py,
3. runs electron-builder --win nsis portable --publish never on windows-latest,
4. verifies that at least one .exe was produced,
5. uploads CyberSentinel-Desktop-Windows as a workflow artifact containing
   the installer and the portable executable.

## Runtime requirements (no code installs the backend)

The packaged application is a client. To use it:

```bash
python -m pip install -r requirements.txt
cp .env.example .env            # set a random BRIDGE_TOKEN and PUBLIC_WEB_ENABLED=true
python -m security.owner_password_bootstrap
python bridge.py                # binds 127.0.0.1:8787
```

Then launch CyberSentinel Desktop. When the environment variable
CYBERSENTINEL_REPO_DIR points at the repository root, the shell starts
python bridge.py itself; otherwise it connects to an already-running
bridge and shows the offline screen (with retry) when none is reachable.

Environment variables understood by the shell:

- CYBERSENTINEL_BRIDGE_URL (default http://127.0.0.1:8787)
- CYBERSENTINEL_REPO_DIR (repository root containing bridge.py)
- CYBERSENTINEL_PYTHON (default python)
- CYBERSENTINEL_AUTOSTART=0 (disable auto-start of the bridge)
