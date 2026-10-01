# CyberSentinel Desktop — Architecture

Document date: 2026-10-01. Basis: actual repository state (audit of
`mosfiry/cybersentinel`, default branch `main` at `8a3fd109c0e5`, and
PR #17 head `71ce3c9550ad` on branch `work/arabic-auth-ci-docs-20260929`).
This desktop work lives on branch `desktop/windows-exe`, created from the
PR #17 head commit. No backend file was modified.

## 1. Goal and formula

"Existing CyberSentinel Web UI + Desktop shell + existing Backend."

The repository already ships a complete Arabic, RTL, single-page web
application (`web/index.html`, `web/app.js`, `web/style.css`) that talks to
the local bridge (`bridge.py`, bound to `127.0.0.1:8787`) through
`/api/public/*` endpoints with a public session cookie, CSRF token, and
Owner username/password login. The desktop application therefore does not
re-implement any UI, API client, authentication flow, or state management.
It is an Electron shell that:

1. optionally starts `python bridge.py` in the repository checkout
   (`CYBERSENTINEL_REPO_DIR`), otherwise connects to an already-running bridge;
2. probes `GET /api/public/health` until the backend answers;
3. loads the existing UI from the bridge origin (`http://127.0.0.1:8787/`);
4. renders a native offline/backend-unavailable screen (with retry) whenever
   the bridge is unreachable, exits, or has the public web boundary disabled;
5. enforces window behavior: 1280x800 default, 960x600 minimum, single
   instance, clean shutdown that terminates a shell-started bridge process;
6. restricts navigation to the bridge origin; everything else opens in the
   system browser.

## 2. Why Electron

- The existing UI is a browser application using cookies
  (`Path=/api/public`, `HttpOnly`, `Secure`, `SameSite=Lax`), `fetch`, SSE,
  and CSRF headers. Loading the bridge origin directly preserves the exact
  same-origin semantics with zero changes to the frontend.
- Chromium treats `http://127.0.0.1` as a secure context, so the `Secure`
  cookies issued by the backend work unchanged inside the shell.
- Tauri would require bundling the UI into a custom origin, which would
  break the backend's same-origin checks (`_public_origin_allowed` compares
  the `Origin`/`Host` pair) and would risk frontend drift. Electron was
  chosen for contract fidelity, not preference.

## 3. Component map

| Path | Role | Reused or new |
| --- | --- | --- |
| `web/index.html`, `web/app.js`, `web/style.css` | Full application UI (chat, missions workspace, evidence, files, git, status, Owner login) | Reused, untouched |
| `bridge.py` and everything under `api/`, `agent/`, `core/`, `security/`, `tools/`, `workspace/` | Backend | Reused, untouched (read-only) |
| `desktop/main.js` | Electron main process: bridge lifecycle, health probe, offline state, window/navigating policy | New (shell only) |
| `desktop/preload.js` | contextBridge with three IPC helpers (`retry`, `getState`, `onState`) | New (shell only) |
| `desktop/offline.html` | Native offline/backend-unavailable screen, Arabic, retry button | New (shell only) |
| `desktop/package.json` | electron-builder config: NSIS installer + portable .exe for Windows x64 | New |
| `desktop/scripts/make_icon.py` | Generates `desktop/build/icon.ico` (stdlib-only PNG-in-ICO) | New |
| `.github/workflows/desktop-windows-build.yml` | Builds and publishes the Windows executables as CI artifacts | New |

## 4. Authentication and security boundary

- The shell performs no authentication and stores no credentials. Owner
  login happens inside the existing web UI through
  `POST /api/public/auth/login` exactly as in the browser.
- The backend remains the only authority: sessions live in server-side
  stores; the shell never reads, writes, or forwards cookies or tokens.
- Browser sandboxing: `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true`; the preload exposes only retry/state IPC.
- The shell cannot widen any scope: all authorization, tool budgets,
  workspace confinement, and completion proofs stay inside the backend.

## 5. Backend freeze compliance

The desktop branch adds files only. `git diff 71ce3c9550ad..desktop/windows-exe`
contains zero modifications under `bridge.py`, `api/`, `agent/`, `core/`,
`security/`, `tools/`, `workspace/`, `web/`, `tests/`, `migrations`, or any
other backend path. Backend observations that were not fixed are recorded in
`DESKTOP_BACKEND_BLOCKERS.md`.

## 6. Build and runtime requirements

See `desktop/README.md`. Summary: the CI workflow builds the Windows
installer and portable executables on `windows-latest` and attaches them as
artifacts. At runtime the machine must have Python 3.13 with the project
requirements installed, a configured `.env` (`BRIDGE_TOKEN`,
`PUBLIC_WEB_ENABLED=true`), a bootstrapped Owner account
(`python -m security.owner_password_bootstrap`), and `bridge.py` running —
or `CYBERSENTINEL_REPO_DIR` set so the shell starts the bridge itself.

## 7. Deliberate non-features

The shell deliberately does not add provider switching, evidence streaming,
mission features, or any capability absent from the backend. Every UI
capability visible in the desktop app is the existing web UI rendered from
the live bridge.
