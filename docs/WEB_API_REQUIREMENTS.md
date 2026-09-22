# WEB_API_REQUIREMENTS — CyberSentinel X

## Part 1 — VERIFIED contracts (read directly from bridge.py on main)

The IDE consumes ONLY these. Authentication model (verified):
- Bridge auth: `X-CyberSentinel-Token` header must equal backend BRIDGE_TOKEN.
- Owner auth: `X-CyberSentinel-Owner-Token`, `X-CyberSentinel-Owner-Session`,
  `X-CyberSentinel-Owner-Challenge` headers; the backend (create_owner_session,
  verify_owner) is the sole authority. The frontend never grants anything.

| Endpoint | Method | Auth | Response shape |
|---|---|---|---|
| /api/health | GET | none | {ok, service, version} |
| /api/tools | GET | bridge | {ok, tools} |
| /api/status | GET | bridge | engine status |
| /api/session/{id} | GET | bridge | {ok, session} |
| /api/chat | POST | bridge+owner | {ok, ...chat result} |
| /api/chat/stream | GET (SSE) | bridge+owner | SSE events |
| /api/tasks | POST | bridge+owner | {ok, task...} (201) |
| /api/tasks/{id} | GET | bridge+owner(verify_owner) | task snapshot |
| /api/tasks/{id}/stream | GET (SSE) | bridge+owner | SSE task events |
| /api/tasks/{id}/pause|resume|cancel | POST | bridge+owner | control result |
| /api/execution/{request_id} | GET | bridge | {ok, request_id, lifecycle, events} |
| /api/reasoning/{request_id} | GET | bridge+owner | reasoning memory |
| /api/owner/session | POST | bridge+owner-token | {ok, session} (201) |
| /api/cancel | POST | bridge | {ok, request_id, lifecycle, cancel_requested} |
| /api/command | POST | bridge | {ok, request_id...} one-shot authorized command |

## Part 2 — REQUIRED but NOT IMPLEMENTED in backend (contract blockers)

These are consumed through adapters that fail with
ContractNotAvailableError; the UI renders an explicit blocked state.

| Capability | Missing endpoints | Notes |
|---|---|---|
| Missions | GET/POST /api/missions, mission lifecycle | tasks are the closest existing analog |
| Workspace | /api/missions/{id}/workspace/tree + file GET/PUT | Manus parallel workstream |
| Terminal sessions | interactive streaming exec contract | /api/command covers one-shot submit only |
| Git | /api/missions/{id}/git | branch/diff/commits |
| Evidence | /api/evidence/{id}, mission linkage | provenance chain UI depends on this |
| Findings | /api/findings?mission={id} | claim vs validated status from backend |
| Scheduler | /api/schedules | schedule CRUD + next/last run |
