# UI Verification (honesty-first)

## Verified in this phase (source-level, agent environment)
- Every consumed endpoint re-read from bridge.py / api/chat.py /
  api/missions.py / agent/mission.py / agent/trajectory.py on main.
- Chat SSE wire format: event name + JSON data blocks (api/chat.py sse()).
- MissionStatus enum and trajectory EventType set mapped 1:1 in
  web/src/state/lifecycle.js with icon+text+tone (never color alone).
- No raw chain-of-thought rendered: ModelTurn content is excluded by the
  trajectory display model (tested in web/tests/conversation.test.js).
- No mock data in any runtime path; blocked capabilities render explicit
  contract-blocked states.

## NOT VERIFIED (no Node/browser in the agent environment)
- npm run build
- npm test (vitest) — tests exist but were not executed here
- live conversation against a running backend
- responsive layout at 1280-1920px, mobile, RTL/LTR rendering

## Honest limitations
- The chat stream is blocking (backend runs the mission synchronously);
  the UI does not fake streaming progress.
- Mission resume is only available via POST /api/missions (chat path);
  the GET stream contract has no resume parameter.
- Scheduler/evidence-listing/findings/workspace/git remain BLOCKED until
  backend contracts exist (BACKEND_DEPENDENCY — do not work around).
