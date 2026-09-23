# CyberSentinel X — Web IDE (production integration layer)

**Branch:** feature/cybersentinel-ide-ui (never merged to main from this task).

## The conversational experience (primary)
The Owner talks to CyberSentinel in natural language
(`panels/ChatPanel.jsx`). The UI is a window onto the verified agent
contract — it does not limit the agent, choose tools, or build plans:

- **GET /api/chat/stream** (verified, SSE): started -> structured activity
  events -> completed with the natural-language answer and mission record.
- **POST /api/missions** (verified, blocking chat path): resume/continue a
  mission (e.g. after OWNER_INPUT_REQUIRED) with { text, conversation_id,
  mission_id }.
- **Mission lifecycle** (verified): status/timeline/evidence/artifacts/logs
  via GET /api/missions/{id}/{action}; start/resume/pause/cancel via POST.
- Structured progress uses the verified trajectory EventType set
  (agent/trajectory.py). Raw chain-of-thought (ModelTurn content) is
  deliberately never rendered.

## What is real (verified)
- API client (web/src/api/*) over endpoints read directly from bridge.py,
  api/chat.py and api/missions.py on main: health, status, tools, chat
  stream, missions (create/get/control), conversation sessions, tasks,
  execution lifecycle, owner session, cancel, command.
- SSE EventTransport with backoff, bounded retries, dedupe and resync.
- Credentials are memory-only (web/src/api/config.js). No secrets in
  bundle or localStorage. The frontend is never the authority.

## What is blocked (honest)
Workspace tree/file, interactive terminal sessions (beyond one-shot
/api/command), git, generic evidence listing, findings, scheduler
management (web/src/api/adapters.js) throw ContractNotAvailableError
because the backend endpoints do not exist yet — the UI renders explicit
blocked states, no fake data. See docs/WEB_API_REQUIREMENTS.md.

## Run / build / test
- npm install && npm run dev (Vite)
- npm run build
- npm test (vitest)
**NOT VERIFIED**: build and tests have NOT been executed in this
environment (no Node toolchain available to the agent). CI on this
branch runs the Python suite only.

## Architecture
web/src/{api,events,state,hooks,components,panels} + thin App.jsx
composition root. See docs/WEB_API_REQUIREMENTS.md for the verified
contract map and blockers.
