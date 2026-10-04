# CyberSentinel Desktop — build and run

## Prerequisites

- Windows 10 or later (x64) for the packaged target; Node.js 22.12 or newer for building the shell.
- Python 3.12 or newer with repository dependencies installed:
  `python -m pip install -r requirements.txt` from the repository root.
- The CyberSentinel repository. For packaged installs, set `CYBERSENTINEL_REPO`
  to its location; the packaged shell refuses to discover a backend from an
  arbitrary working directory. Development builds may use the repository-root
  working directory. The installed shell does not bundle the backend.
- A private repository `.env` containing `BRIDGE_TOKEN` (at least 32 random
  characters) or the supported file-backed bridge-token configuration. Python
  loads private settings itself; Electron does not parse `.env` or forward
  credential values. Keep `.env` private (`chmod 600` on POSIX).
- An Owner account bootstrapped through
  `python -m security.owner_password_bootstrap`.

## Development run

```sh
cd desktop
npm install
npm run icon
npm start
```

The shell starts `python bridge.py --desktop-stdio-control` on loopback, waits
for `/api/health`, then opens the served client at
`http://127.0.0.1:8787/` (or the `BRIDGE_PORT` provided in the process
environment). The bridge starts its durable mission worker for this loopback
Desktop mode. The client uses Owner-only cookies and CSRF, displays provider
configuration without secrets, and calls the same mission/evidence APIs as the
backend. Chat uses request/response; public streaming is not exposed.

When the app exits it asks the child bridge to shut down over a private stdin
pipe, waits for the worker/service to drain, and force-terminates only after a
ten-second grace period. The backend's crash-recovery/fencing remains the
fallback if the process cannot exit cleanly.

## Windows packaging

```sh
cd desktop
npm run dist
```

The outputs are `desktop/dist/CyberSentinel-Setup-5.0.0.exe` and
`desktop/dist/CyberSentinel-Portable-5.0.0.exe`. The release-branch GitHub
workflow builds both x64 targets on `windows-latest`, uses
`electron-builder --publish never`, and uploads the executables as an expiring
workflow artifact subject to the repository's access controls. This is not a
public release or a final tag.

The workflow disables signing-identity auto-discovery and does not provide a
code-signing identity, so both executables are unsigned. Windows may show
publisher or SmartScreen warnings; do not treat these files as code-signed.

The executable contains the Electron shell only. The Python runtime, repository,
requirements, private configuration, and state must be installed/provisioned
separately. Current packaging support is Windows x64 only; no macOS or Linux
graphical package is claimed. CI builds the artifacts but does not execute the
`.exe` or perform an interactive Windows runtime rehearsal.

The public workspace file-list, file-view, and Git-summary endpoints fail closed
with an unsupported response on Windows until equivalent handle-relative
no-follow path access is available. Mission operations and other supported
Owner APIs remain separate.
