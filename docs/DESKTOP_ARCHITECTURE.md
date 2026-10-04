# CyberSentinel Desktop Architecture

CyberSentinel Desktop is a Windows x64 Electron shell over the checked-in Python bridge and the same-origin web client. It is integrated with the release branch's backend contract and does not provide a separate authority, database, or mission engine.

## Components and lifecycle

The Electron main process locates the repository and Python executable, constructs a small non-secret environment allowlist, and starts `python bridge.py --desktop-stdio-control` with the repository as its working directory. Packaged builds require an explicit `CYBERSENTINEL_REPO`; they do not search the arbitrary current working directory. Development builds can use the checked-out app parent or working directory. Electron does not read `.env` or forward credential values. Python's own configuration layer loads the private `.env` and supported file-backed secret settings; the bridge fails closed if its bridge token is missing.

The bridge binds to `127.0.0.1` for Desktop, enables the public boundary, and starts its durable mission worker under `RuntimeSupervisor`. The shell waits for `/api/health` before opening the served UI at the bridge's real loopback origin. The public API uses server-managed Owner sessions, HttpOnly Secure cookies, same-origin checks, and CSRF tokens. Mission authorization, queueing, verifier evidence, and effect reconciliation remain backend responsibilities.

On application shutdown, Electron sends a fixed command through the private child stdin pipe. The bridge requests HTTP shutdown and stops the worker; the shell waits up to ten seconds before a forced child termination. A worker that cannot drain is still subject to the backend's durable fencing and crash-recovery logic.

## Security boundary

- Chromium renderer runs with `contextIsolation`, `sandbox`, and `nodeIntegration: false`. The preload exposes only a retry signal.
- The renderer never stores Owner credentials, bearer tokens, or session identifiers in browser storage. Authentication uses same-origin server cookies and CSRF.
- Electron forwards only allowlisted non-secret configuration values. It does not parse the `.env` file; Python reads it in the backend process. Credential values such as `BRIDGE_TOKEN` and provider API keys are not in the Electron-to-child allowlist.
- Public mission reads reject legacy missions not bound to the authenticated Owner. Public workspace file listing/reads and Git summaries require secure descriptor-relative workspace access, `O_NOFOLLOW`, sensitive-path filtering, and output bounds; all workspace views fail closed when the platform lacks the required handle primitives.
- Goal completion depends on independent deterministic backend verifiers. User-visible reconciliation records a specific external effect and evidence reference; it does not fabricate completion evidence.
- Provider settings shown in the Owner UI are deliberately reduced to configuration flags, a bounded failure count, and Boolean capabilities. URLs, model identifiers, API keys, and error text are not returned by that endpoint.

## Build and runtime support

Development run (Node.js 22.12+):

```sh
cd desktop
npm install
npm run icon
npm start
```

The machine needs Python 3.12 or newer, the repository, and its installed requirements. Configure a private `.env` in the repository and bootstrap an Owner account using the existing backend flow. The Desktop executable does not bundle the Python backend, repository, or virtual environment.

Windows packaging:

```sh
cd desktop
npm run dist
```

The workflow builds `CyberSentinel-Setup-5.0.0.exe` and `CyberSentinel-Portable-5.0.0.exe` on `windows-latest` and uploads a workflow artifact. It uses the committed npm lockfile and `npm ci`; publishing is disabled. The project currently defines a Windows x64 packaging target only; macOS and Linux GUI packages are not claimed. The Windows build verifies packaging and JavaScript syntax but does not launch the executable or exercise an interactive Windows backend session.

The ordinary Linux/Python regression suite exercises the public API, authentication, mission queue/recovery controls, provider-summary redaction, and Workspace boundaries. It complements rather than replaces a native Windows runtime rehearsal.
