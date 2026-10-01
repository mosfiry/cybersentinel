# CyberSentinel Desktop Architecture

## 1. Scope and non-goals

CyberSentinel Desktop is a Windows desktop shell over the existing
CyberSentinel backend and the existing web client. It is not a new
application: it reuses, without modification, the checked-in bridge server
(`bridge.py`), the served web client (`web/app.js`, `web/index.html`,
`web/style.css`), the public API surface (`/api/public/*`), and the existing
Owner authentication and authorization model.

The backend is consumed read-only. No backend file is edited, refactored,
renamed, migrated, or reformatted by this work.

## 2. Selection rationale (based on repository reality)

The repository was audited before choosing the stack:

- There is no React/Vite frontend, no `package.json`, no Node build chain, and
  no existing Electron/Tauri code in the repository.
- The shipped web client is dependency-free vanilla JavaScript served
  same-origin by `bridge.py` (`/` serves `web/index.html`, `/app.js`,
  `/style.css`).
- The public API is reachable only from the same loopback origin under the
  existing security contract: browser writes require the public CSRF session
  plus the server-side Owner cookie; the bridge validates the `Origin` header
  (empty origin or an origin matching the `Host` header when
  `PUBLIC_WEB_ORIGIN` is unset).
- `web/app.js` already implements the desktop transport boundary
  (`window.CYBERSENTINEL_API_BASE` and `apiUrl(path)`), reconnect re-fetch,
  and truthful unavailable states.

Given that reality, Electron was selected as the minimal shell technology: it
embeds a Chromium window without introducing a new application framework, and
it allows the served web client to run at its real origin
(`http://127.0.0.1:<BRIDGE_PORT>/`), which is the only way to satisfy the
existing same-origin cookie and CSRF contract without touching the backend.

## 3. Desktop shell responsibilities (desktop/main.js)

The desktop process performs exactly five jobs:

1. Locate the CyberSentinel repository (`bridge.py`) via
   `CYBERSENTINEL_REPO`, the packaged application directory, or the current
   working directory.
2. Start the existing backend entrypoint (`python bridge.py`) as a child
   process, with the environment assembled from the operator's environment
   plus the repository `.env` file, forcing `BRIDGE_HOST=127.0.0.1` and
   `PUBLIC_WEB_ENABLED=true`. The bridge keeps its own fail-closed rules
   (it refuses to start without `BRIDGE_TOKEN`).
3. Wait for `GET /api/health` to answer 200 on the loopback port
   (`BRIDGE_PORT`, default 8787), then load the served web client at
   `http://127.0.0.1:<port>/`.
4. Render a truthful unavailable state (`desktop/unavailable.html`) when the
   repository is missing, Python is missing, the backend exits, or the health
   check times out — with an explicit retry action and no fabricated data.
5. Provide clean desktop lifecycle behavior: proper window sizing, minimize and
   maximize, external links opened in the system browser, navigation locked to
   the application origin, and clean child-process shutdown on quit.

## 4. What the desktop deliberately does not do

- It does not read, store, mint, or forward bridge tokens, Owner credentials,
  CSRF tokens, or session identifiers. Cookies stay in the Chromium session of
  the same origin, HttpOnly, exactly as in the browser deployment.
- It does not add UI capabilities that the backend does not expose. The web
  client is reused verbatim; every rendered capability maps to an existing
  public API endpoint.
- It does not weaken Origin validation, CSRF, Owner authorization, mission
  scope, tool restrictions, or approval requirements. It cannot: those are
  enforced server-side by the unmodified backend.
- It does not bundle the Python backend or its virtualenv into the
  executable. The runtime requirements (Python and the repository) are
  documented below; bundling a Python runtime would duplicate backend
  deployment concerns that the repository intentionally keeps explicit.

## 5. Security boundary

- Renderer hardening: `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true`. The preload exposes only a retry signal
  (`window.cybersentinelDesktop.retry()`); the served web client does not
  use it and remains a plain web page.
- The desktop process is a client, not an authority. Authorization state,
  mission scope, evidence verification, and Owner identity all come from the
  backend over the existing API.
- The unavailable page uses a strict CSP and no remote resources.

## 6. Build process

Development:

```
cd desktop
npm install
npm run icon          # generates desktop/build/icon.png (256x256, no dependencies)
npm start             # requires the repository and Python on this machine
```

Windows packaging (produces the NSIS installer and the portable executable):

```
cd desktop
npm run dist          # electron-builder --win nsis portable
# outputs: desktop/dist/CyberSentinel-Setup-1.0.0.exe
#          desktop/dist/CyberSentinel-Portable-1.0.0.exe
```

CI builds the same executables on `windows-latest` via
`.github/workflows/desktop-build.yml` and uploads them as artifacts
(`cybersentinel-desktop-windows`). The workflow runs the JavaScript syntax
checks, generates the icon, installs the toolchain, builds with
`electron-builder --win nsis portable --publish never`, and uploads the
resulting `.exe` files.

## 7. Runtime requirements

- Windows 10 or later (x64).
- Python 3.13 with the repository's `requirements.txt` installed
  (`python -m pip install -r requirements.txt`), matching the CI runtime.
- The CyberSentinel repository present beside the application (or its path
  provided via `CYBERSENTINEL_REPO`).
- A repository `.env` with `BRIDGE_TOKEN` set (the bridge fails closed
  without it) and Owner credentials bootstrapped via the existing
  `python -m security.owner_password_bootstrap` flow.

## 8. Backend change policy

The backend is frozen for this work. Any observed backend problem is recorded
in `DESKTOP_BACKEND_BLOCKERS.md` at the repository root and is not fixed
here. If the backend contract changes upstream, the desktop client adapts;
the backend is never patched from this branch.
