# Desktop ↔ Manus Current Backend — Compatibility Audit

Audit date: 2026-10-01. Mode: READ/COMPARE ONLY. No backend file was
touched, merged, rebased, or committed by Vibe in this audit.

## References

- Stable backend checkpoint (the tree Desktop was built on and remains
  byte-identical to): `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`
  (branch `work/arabic-auth-ci-docs-20260929`).
- Desktop baseline: `b7d01bf302a61a1baa2a33b711f1bc535d2992d1`
  (branch `desktop/windows-exe`, direct child of the checkpoint).
- Manus current state: **UNCOMMITTED / DIRTY** (reported: 112 dirty
  paths, no safe checkpoint possible at this time). Per the audit rules,
  every Manus change below is labeled a
  "CURRENT UNCOMMITTED BACKEND CHANGE" — it is NOT treated as a final
  backend contract, and Desktop was not changed because of any of them
  unless a direct, code-level impact was proven.

## Audit method

Desktop behavior was taken from the actual client code shipped in the
Desktop branch — `web/app.js` (25,430 bytes at `b7d01bf3`), plus the
Electron shell (`desktop/main.js`, `desktop/preload.js`,
`desktop/offline.html`). Manus behavior was taken from the Manus report
(transmitted findings A-E). Each finding was searched for in the client
source; the compatibility verdict is based only on observed client code.

## Compatibility table

| Area | Desktop behavior | Manus current behavior | Compatibility | Action |
| --- | --- | --- | --- | --- |
| Health | Shell probes `GET /api/public/health`; UI polls it for connection state | Route unchanged in the Manus report | COMPATIBLE | None |
| Auth | UI performs `POST /api/public/auth/login`/`logout`, `GET /api/public/auth/session` with the existing cookie/CSRF flow; shell touches no credentials | No reported change to the auth routes | COMPATIBLE | None |
| CSRF | `web/app.js` obtains the CSRF token from `POST /api/public/session` and sends `X-CSRF-Token` on every public request; retries once on 401 | No reported change | COMPATIBLE | None |
| Chat | UI sends `{"text", "conversation_id"}` only to `POST /api/public/chat` and renders the server answer | No reported change to the chat route | COMPATIBLE | None |
| request_id | Client never sends `request_id`. It only reads/displays it from server responses (mission detail, activity bubbles). The Electron shell sends no request body at all (only the health GET) | CURRENT UNCOMMITTED BACKEND CHANGE: client-supplied `request_id` is rejected or replaced | COMPATIBLE | None — the client does not depend on supplying request IDs; the replacement behavior cannot affect it |
| Missions | UI lists/creates missions, start/resume/pause/cancel/reconcile, status/timeline/evidence/artifacts/logs views | No reported change to these routes | COMPATIBLE | None |
| Mission delete | No delete UI, no delete button, no delete call anywhere in `web/app.js` or the shell | CURRENT UNCOMMITTED BACKEND CHANGE: new route `POST /api/public/missions/{id}/delete` | COMPATIBLE | None — no button is added merely because an endpoint exists (rule 8); a future UI addition is an Owner decision, not a compatibility fix |
| run_at | Client never schedules missions; `run_at` / `schedule` do not appear in `web/app.js` at all | CURRENT UNCOMMITTED BACKEND CHANGE: `run_at` now requires a timezone and is normalized to UTC | NOT APPLICABLE | None — no client payload can violate the new rule |
| Workspace | UI uses `files`/`file`/`git` read-only views through the existing capability-gated routes | No reported change | COMPATIBLE | None |
| Evidence | UI renders evidence from `GET /api/public/missions/{id}/evidence`; no local synthesis | No reported change | COMPATIBLE | None |
| Reports | No UI exists that claims to retrieve a security report; nothing renders one | CURRENT UNCOMMITTED BACKEND FINDING: no public route exists for report retrieval | COMPATIBLE | None — the UI makes no claim the API cannot support; no capability invented |
| Owner approval | No approval UI exists; the UI never claims to approve anything. Mission states such as `OWNER_INPUT_REQUIRED` are rendered as server-provided status labels only | CURRENT UNCOMMITTED BACKEND FINDING: workflow may pause awaiting approval, with no public route to approve | COMPATIBLE | None — the UI shows the state the backend returns and does not fake an approval action; recorded as a backend gap, not a desktop gap |
| SSE | `web/app.js` contains no `EventSource`; browser chat is request/response JSON. SSE exists only on internal bridge-token routes the UI does not use | No reported change to public streaming | NOT APPLICABLE | None |
| Provider protocol | Desktop has zero provider knowledge: no provider, model, schema, `tool_choice`, or RAG handling in `web/app.js` or the shell | CURRENT UNCOMMITTED BACKEND CHANGE: internal provider protocol may require JSON Schema and `tool_choice=required` | NO DESKTOP CHANGE | None — purely internal to the backend; the desktop consumes only the chat response |

## Conclusion

No uncommitted Manus change breaks the current Desktop. The only client
inputs that could have been affected (`request_id`, `run_at`) are never
sent by the existing client code, and the newly reported capabilities
(delete route, report retrieval, Owner approval) have no corresponding UI
claims, so nothing misrepresents the API. No Desktop code change was made
and none is required at this time. Items marked as uncommitted backend
changes remain UNVERIFIED as final contract until Manus produces a safe
checkpoint; Desktop will re-audit against that checkpoint when it exists.
