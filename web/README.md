# CyberSentinel X — Web IDE (production integration layer)

**Branch:** feature/cybersentinel-ide-ui (never merged to main from this task).

## What is real (verified)
- API client (web/src/api/*) over endpoints read directly from bridge.py
  on main: health, status, tools, tasks (create/get/stream/pause/resume/
  cancel), execution lifecycle, owner session, cancel, command.
- SSE EventTransport (web/src/events/EventTransport.js) with backoff,
  bounded retries, event dedupe and resync reconciliation.
- Credentials are memory-only (web/src/api/config.js). No secrets in
  bundle or localStorage. The frontend is never the authority.

## What is blocked (honest)
Missions/workspace/git/evidence/findings/scheduler adapters
(web/src/api/adapters.js) throw ContractNotAvailableError because the
backend endpoints do not exist yet (see docs/WEB_API_REQUIREMENTS.md
Part 2). The UI renders explicit blocked states — no fake data.

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
