# DESKTOP_BACKEND_BLOCKERS

Backend problems observed during the CyberSentinel Desktop work. Per the
backend-freeze policy, none were fixed here; the backend is read-only for
this work. Each entry records the observation, evidence, and desktop impact.

## 1. No public transcript-fetch endpoint

- File: `bridge.py` (public gateway section), `api/chat.py`.
- Observed behavior: `POST /api/public/chat` returns `conversation_id`, but
  no public endpoint returns the stored conversation transcript.
- Expected behavior: a public `GET /api/public/conversations/<id>` would let a
  reconnected desktop client restore the transcript from server state.
- Evidence: public route enumeration of `bridge.py` (do_GET/do_POST public
  branches) at commit `2e24d990`.
- Impact on Desktop: after a desktop restart the in-session transcript is not
  restorable from the server; mission state, evidence, timeline, and findings
  are restored (they have endpoints), but the chat transcript view starts
  empty. The client renders truthfully and does not fabricate history.

## 2. No public Owner approve/reject endpoints

- File: `bridge.py`, `security/authorization.py`.
- Observed behavior: no public approval API exists; approval requirements are
  enforced inside the runtime.
- Expected behavior: a public approval contract would allow Owner approval
  actions from the desktop UI.
- Evidence: public route enumeration; the web client renders an explicit
  "missing contract" unavailable state for this capability.
- Impact on Desktop: approval actions cannot be offered; the client shows a
  truthful unavailable state instead of a dead button.

## 3. No public tools-list endpoint

- File: `bridge.py`, `tools/registry.py`.
- Observed behavior: `tool_definitions` exists internally but is not exposed
  on the public gateway.
- Expected behavior: a public read-only tools listing for the Owner.
- Evidence: public route enumeration.
- Impact on Desktop: the tools panel renders a truthful "missing contract"
  state; no fabricated tool list is shown.

## 4. Secure cookies over plain HTTP loopback

- File: `bridge.py` (`_public_cookie_header`, `_public_owner_cookie_header`).
- Observed behavior: session cookies are set with the `Secure` attribute while
  the public gateway serves plain HTTP on `127.0.0.1`.
- Expected behavior: for the browser deployment this is intentional
  (loopback is treated as trustworthy by Chromium and the deployment
  architecture is loopback-only); noting it because a non-Chromium embedded
  webview might reject Secure cookies over plain HTTP.
- Evidence: `bridge.py` lines emitting the cookie headers; documented
  loopback-only deployment in `docs/OPERATIONS.md`.
- Impact on Desktop: none for the selected Electron/Chromium shell (Chromium
  accepts Secure cookies on trustworthy loopback origins). This is a
  constraint on any future non-Chromium shell choice, not a defect to fix in
  the backend.

No other backend blockers were observed. The backend was not modified; the
backend diff for this branch is zero.
