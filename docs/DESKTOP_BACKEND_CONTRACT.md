# CyberSentinel Desktop Backend Contract

Every capability rendered by CyberSentinel Desktop maps to an endpoint that
exists in the audited backend source (`bridge.py`, `api/chat.py`,
`api/missions.py`, `core/config.py`) at the branch point of this work
(commit `2e24d9904920d2c17cc1003846889b57005775d9`, the PR #17 head at the
time of the audit). No endpoint is invented.

## Transport

- The bridge binds to `127.0.0.1` only (`BRIDGE_HOST` is fixed in the backend;
  the desktop forces `BRIDGE_HOST=127.0.0.1` in the child environment, which is
  the backend's own required value).
- `BRIDGE_PORT` (default `8787`).
- Startup: `python bridge.py` starts the loopback HTTP bridge, one durable
  mission worker, and the persistent schedule dispatcher
  (`docs/OPERATIONS.md`).
- The bridge fails closed without `BRIDGE_TOKEN`; the desktop passes the
  operator environment and repository `.env` through and never handles the
  token itself.

## Static web client (served by the same bridge)

| Path | Serves |
| --- | --- |
| `/` | `web/index.html` |
| `/app.js` | `web/app.js` |
| `/style.css` | `web/style.css` |

## Public API consumed by the web client (and therefore by Desktop)

| Endpoint | Method | Auth requirement |
| --- | --- | --- |
| `/api/public/session` | POST | none; issues the public CSRF session cookie |
| `/api/public/auth/login` | POST | public CSRF session; sets HttpOnly Owner cookie |
| `/api/public/auth/session` | GET | cookies only |
| `/api/public/auth/logout` | POST | public CSRF session + Owner cookie |
| `/api/public/health` | GET | public web enabled + origin allowed |
| `/api/public/chat` | POST | public CSRF session + Owner cookie; body `{text, conversation_id}` |
| `/api/public/missions` | GET | Owner session; lists missions |
| `/api/public/missions` | POST | Owner session; body `{objective}` |
| `/api/public/missions/<id>/status` | GET | Owner session |
| `/api/public/missions/<id>/timeline` | GET | Owner session |
| `/api/public/missions/<id>/evidence` | GET | Owner session |
| `/api/public/missions/<id>/artifacts` | GET | Owner session |
| `/api/public/missions/<id>/logs` | GET | Owner session |
| `/api/public/missions/<id>/start` | POST | Owner session |
| `/api/public/missions/<id>/resume` | POST | Owner session |
| `/api/public/missions/<id>/pause` | POST | Owner session |
| `/api/public/missions/<id>/cancel` | POST | Owner session |
| `/api/public/missions/<id>/reconcile` | POST | Owner session; body `{executed: boolean}` |
| `/api/public/workspace/<id>/files` | GET | Owner session; read-only |
| `/api/public/workspace/<id>/file` | GET | Owner session; read-only |
| `/api/public/workspace/<id>/git` | GET | Owner session; read-only |

## Authentication and authorization model (unchanged, reused)

- Two server-managed sessions: a short-lived public CSRF session and the
  canonical Owner session (username/password, eight hours, server-side).
- The Owner cookie is `HttpOnly; Secure; SameSite=Lax; Path=/api/public`.
- Browser writes require both the CSRF proof and the Owner cookie.
- Origin validation: no `Origin` header is accepted; when `PUBLIC_WEB_ORIGIN`
  is set the origin must match exactly; otherwise the origin must match the
  `Host` header. The desktop satisfies this by loading the served client at
  the real loopback origin.
- The desktop process never receives or stores any token, credential, or
  session identifier.

## Capabilities with no public API contract (rendered as truthful unavailable states)

These were verified absent from the audited public surface; the client shows
explicit unavailable states instead of fabricating them:

- Public Owner approve/reject endpoints (no approval API exists publicly).
- Public tools-list endpoint.
- Public transcript-fetch endpoint (the chat response returns a
  `conversation_id`, but no public endpoint returns the stored transcript; the
  UI transcript is in-memory per session).
- Public SSE/streaming chat (internal `sse`/`task_stream` helpers exist for
  the internal API, but the public chat endpoint is request/response).
- Multi-agent task visualization API (agent activity is rendered from real
  timeline/activity events only).

## Error and lifecycle behavior (from source)

- `401 {"error": "invalid csrf token"}` — missing/invalid CSRF.
- `403 {"error": "owner_authorization_required"}` — chat attempted without an
  Owner session.
- `403 {"error": "origin_not_allowed"}` — foreign origin.
- `403 {"error": "invalid_credentials"}` — wrong Owner password (generic).
- `400 {"error": "executed_boolean_required"}` — malformed reconcile payload.
- `404 {"error": "public_boundary_disabled"}` — `PUBLIC_WEB_ENABLED` unset.
- Mission completion is server-proven only:
  `status === "GOAL_COMPLETED"` together with `verification.verified === true`
  and a signed `completion_proof`; unknown is never rendered as success
  (pinned by `tests/test_mission_worker_lifecycle.py`).

## Upstream drift

While this work was in progress, four backend commits were pushed to the PR
#17 branch (`agent/mission.py`, `agent/mission_runtime.py`, `README.md`;
head moved to `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`). They do not alter
the public API surface listed above. Per the backend-freeze policy they were
read as the source of truth and were not merged or modified here.
