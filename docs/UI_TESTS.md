# UI TEST PLAN — CyberSentinel X (Product/UI Layer)

Honest scope: this branch ships the UI layer and this PLAN. Automated test
harnesses are listed as required follow-up once the backend endpoints in
docs/WEB_API_REQUIREMENTS.md exist. Nothing here claims backend features
that do not exist.

Required test matrix (each maps to an acceptance gate):
1. UI rendering — app mounts, all 9 views render without crash (GATE 1)
2. Mission states — running/paused/scheduled/needs_input/completed/failed/
   cancelled all render with correct color/label (GATE 9)
3. Timeline — 16 event types render, per-event detail opens/closes (GATE 4)
4. Workspace navigation — tree browse, search filter, tab open/close,
   modified indicator (GATE 2)
5. Evidence rendering — hash fields, provenance, validation shown (GATE 5)
6. Finding states — VERIFIED / CLAIM(not verified) / UNKNOWN visually
   distinct; a claim is never rendered as verified fact (GATE 5)
7. Pause/Resume/Cancel — confirmation dialog appears; backend denial
   (403) renders authorization-denied state (GATE 6)
8. API failure states — 401 → login redirect; 403 → denied view;
   5xx/network → reconnect banner with last-checkpoint info (GATE 7)
9. Reconnect/reload — mission state restored from checkpoint endpoint;
   "what happened while away" delta rendered (GATE 7)
10. Authorization display — full snapshot view renders; UI-only
    acknowledgment checkbox does not alter backend state (GATE 6)
11. Secrets scan — no OWNER_TOKEN / BRIDGE_TOKEN / API keys in bundle,
    localStorage, or source (GATE 8)
