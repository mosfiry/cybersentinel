# CyberSentinel Desktop — Backend Contract

Document date: 2026-10-01. Every endpoint below was read from the actual
source at commit `71ce3c9550ad` (branch `work/arabic-auth-ci-docs-20260929`,
PR #17 head): `bridge.py` (GET/POST handlers), `web/app.js` (the client that
calls them), and PR #17's diff. No endpoint is invented; none is assumed.

The desktop application consumes this contract exclusively through the
existing `web/app.js` running inside the shell. The shell itself calls only
one endpoint directly: `GET /api/public/health`.

## 0. Transport and security invariants (observed in source)

- Bridge binds to loopback only (`127.0.0.1`), port from `.env`
  (`BRIDGE_PORT`, default 8787).
- `BRIDGE_TOKEN` authenticates only the internal HTTP transport
  (`Authorization` header checked by `_bridge_auth`); it is never a browser
  credential.
- Public web boundary requires `PUBLIC_WEB_ENABLED=true`; otherwise public
  routes return `404 public_boundary_disabled`.
- Origin check `_public_origin_allowed`: no `Origin` header is allowed;
  with `PUBLIC_WEB_ORIGIN` set, the Origin must match exactly; otherwise the
  Origin host must equal the `Host` header (same-origin only).
- Public session cookie `cs_public_session`: `Path=/api/public`, `HttpOnly`,
  `Secure`, `SameSite=Lax`, TTL `PUBLIC_SESSION_TTL_SECONDS` (default 1800).
- Owner session cookie `cs_owner_session`: same attributes, TTL from
  `owner_password.SESSION_TTL_SECONDS`. Owner identity is
  username/password (scrypt verifier, server-side store), created via
  `python -m security.owner_password_bootstrap`.
- CSRF: every `/api/public/*` request except `POST /api/public/session` must
  send `X-CSRF-Token` with the public session's CSRF value; `web/app.js`
  obtains it from the session creation response and retries once with a
  fresh session on `401`.
- Owner-authenticated responses use `Mission.to_public_dict()` which redacts
  `session_id`/`owner_session_id` fields.
- SSE exists only on internal bridge-token routes (`/api/chat/stream`,
  `/api/tasks/{id}/stream`); the browser chat route is JSON request/response.

## 1. Public endpoints (used by the shipped web UI)

### POST /api/public/session
Creates the anonymous public session. No CSRF needed.
Response `201 {"ok": true, "session": <public session object with csrf>}` and
`Set-Cookie: cs_public_session=...`.

### GET /api/public/health
No cookies needed. `200 {"ok": true, "service": PRODUCT_NAME, "version": VERSION}`
or `404 {"ok": false, "error": "public_boundary_disabled"|"not_found"}`.
Used by the desktop shell as its connection probe.

### GET /api/public/auth/session
Requires public session cookie (no CSRF). `200 {"ok": true, "authenticated": bool}`
plus `username`, `expires_at` when an Owner session cookie resolves. Clears
the owner cookie when it no longer resolves.

### POST /api/public/auth/login
Public session + CSRF. Body `{"username": str<=128, "password": str<=4096}`.
Success: `200 {"ok": true, "authenticated": true, "username", "expires_at"}`
+ owner `Set-Cookie`. Failure: `400/403 {"ok": false, "error": "invalid_credentials"}`,
`500 "owner_login_failed"`. A previous owner session is revoked on rotation.

### POST /api/public/auth/logout
Public session + CSRF. `200 {"ok": true, "authenticated": false}` and expires
the owner cookie.

### POST /api/public/chat
Public session + CSRF + Owner session. Body is the chat payload; the handler
forces `scope_context` to `{"workspace_root": <repo root>, "target_id": "cybersentinel-repository"}`.
Success: `200 {"ok": true, ...chat result}`. Errors: `403 owner_authorization_required`,
`403/400 {"ok": false, "error": ...}`, `500 "chat_failed"`.

### GET /api/public/missions?limit=N
Owner session. `200 {"ok": true, "missions": [public mission dicts]}`.

### POST /api/public/missions
Owner session + CSRF. Body `{"objective": str, "completion_criteria": list<=100}`.
Creates and enqueues a mission (does not run it inline). `201 {"ok": true,
"mission": <public dict>, "mission_id", "queue": {...}}`.

### POST /api/public/missions/{id}/{start|resume}
Owner session + CSRF. Re-authorizes with the live Owner session and enqueues
the mission. `200 {"ok": true, "result": {"mission": ..., "queue": ...}}`.
Rejects in-flight missions that need reconciliation and terminal missions
except `OWNER_INPUT_REQUIRED`/`AUTHORIZATION_BLOCKED`.

### POST /api/public/missions/{id}/pause
`200 {"ok": true, "result": <public mission dict>}` (service `pause_mission`).

### POST /api/public/missions/{id}/cancel
`200 {"ok": true, "result": <public mission dict>}` (service `cancel_mission`).

### POST /api/public/missions/{id}/reconcile
Body `{"executed": bool}` (strictly boolean). Owner resolves only whether the
ambiguous in-flight side effect happened; a browser-supplied observation is
never completion proof. `200 {"ok": true, "result": ...}`.

### GET /api/public/missions/{id}/{status|timeline|evidence|artifacts|logs}
Owner session. `200 {"ok": true, "mission_id", "<action>": value}`.

### GET /api/public/workspace/{id}/files?path=...
Read-only `workspace_read` capability from the mission's authorization
snapshot. Lists a directory; sensitive paths (`.env*`, `*.key`, `*.pem`,
`*.p12`, `*.pfx`, `*.sqlite*`, `*.db*`, `.git`, `.ssh`, `.gnupg`, `secrets`,
`credentials`, ...) are excluded/404.

### GET /api/public/workspace/{id}/file?path=...
Reads one file inside the mission workspace boundary with the same
sensitive-path exclusions.

### GET /api/public/workspace/{id}/git?operation={status|branch|log|diff|head|repository|remote}
Read-only `git_read` capability. Only fixed git operations are accepted;
`remote` output is redacted. `200 {"ok": true, "operation", "exit_code",
"output", "error_output"}`.

## 2. Internal endpoints (BRIDGE_TOKEN transport; not used by the desktop UI)

Observed in source, listed for completeness only: `GET /api/health`,
`POST /api/auth/login`, `POST /api/auth/logout`, `POST /api/chat`,
`GET /api/session/{id}`, `GET /api/chat/stream` (SSE), `POST /api/cancel`,
`GET /api/tasks/{id}` and `/api/tasks/{id}/stream` (SSE),
`POST /api/missions` (plan-based creation with Owner tool-budget
intersection), `POST /api/missions/{id}/{start|resume|pause|cancel|reconcile|schedule}`,
`GET /api/missions/{id}/{status|timeline|evidence|artifacts|logs}`,
`GET /api/status`, `GET /api/execution/{request_id}`,
`GET /api/reasoning/{request_id}`, `GET /api/tools`.
All require bridge authentication and, for sensitive routes, a live Owner
session resolved via `security.owner_password.resolve_session`.

## 3. Error and lifecycle behavior relevant to the desktop shell

- `404 public_boundary_disabled` → the shell reports "backend disabled"
  (Owner must set `PUBLIC_WEB_ENABLED=true`).
- Connection refused → offline screen with automatic retry.
- Bridge process exit (when shell-started) → offline screen with exit code.
- Mission state machine (CREATED → PLANNING → READY → RUNNING → OBSERVING →
  VERIFYING → REPLANNING → PAUSED → GOAL_COMPLETED / CANCELLED /
  OWNER_INPUT_REQUIRED / AUTHORIZATION_BLOCKED / RECOVERY_REQUIRED /
  FAILED) is owned entirely by the backend; the desktop renders whatever
  the backend returns.
