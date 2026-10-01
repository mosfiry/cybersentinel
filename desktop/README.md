# CyberSentinel Desktop — build and run

## Prerequisites

- Windows 10+ (x64), Node.js 20 (for packaging only).
- Python 3.13 with the repository's dependencies:
  `python -m pip install -r requirements.txt` (from the repository root).
- The CyberSentinel repository beside this desktop directory (or set
  `CYBERSENTINEL_REPO` to its path).
- A repository `.env` containing `BRIDGE_TOKEN` (the backend fails closed
  without it). The desktop shell never reads this value itself; it passes the
  environment through to the backend process.
- Owner credentials bootstrapped once via the existing backend flow:
  `python -m security.owner_password_bootstrap`.

## Development run

```
cd desktop
npm install
npm run icon
npm start
```

The shell starts `python bridge.py` (loopback-only), waits for
`/api/health`, then opens the served web client at
`http://127.0.0.1:8787/`. All authentication, missions, evidence, findings,
and workspace features are the existing web client against the existing
backend.

## Windows packaging

```
cd desktop
npm run dist
```

Outputs:

- `desktop/dist/CyberSentinel-Setup-1.0.0.exe` — NSIS installer.
- `desktop/dist/CyberSentinel-Portable-1.0.0.exe` — portable executable.

The same build runs in CI on `windows-latest`
(`.github/workflows/desktop-build.yml`) and uploads the executables as the
artifact `cybersentinel-desktop-windows`.

## Runtime notes

- The executable is a shell; the Python backend and the repository must be
  present on the machine (see `docs/DESKTOP_ARCHITECTURE.md` for the
  rationale — the backend deployment is intentionally explicit in this
  repository).
- If the backend cannot start (missing repository, missing Python, missing
  `BRIDGE_TOKEN`, or a crash), the application shows a truthful unavailable
  screen with a retry action. It never fabricates data.
- The desktop process never handles tokens, credentials, or sessions; the
  browser security model of the served client is preserved unchanged.
