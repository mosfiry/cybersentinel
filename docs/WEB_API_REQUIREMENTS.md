# CyberSentinel X — Web API Requirements (verified contract map)

Method: every VERIFIED entry below was read directly from the backend
source on main (bridge.py routing, api/chat.py, api/missions.py,
agent/mission.py MissionStatus, agent/trajectory.py EventType).
Anything not listed as VERIFIED does not exist; the UI must fail loudly
(ContractNotAvailableError) and never fake it.

## Part 1 — VERIFIED contracts

### Conversational agent (primary UI path)
| Contract | Endpoint | Shape |
|---|---|---|
| chatStream | GET /api/chat/stream?text=&conversation_id= (SSE) | blocks: `event: started` -> per-activity event names (trajectory EventType) -> `event: completed` with { conversation_id, answer, mission_id, status, activity, mission } |
| missionChat | POST /api/missions { text, conversation_id, mission_id? } | blocking chat path; mission_id resumes an existing mission; response { ok, mission, mission_id, status } |
| sessionGet | GET /api/session/{id} | owner-only conversation info + messages + tasks |

Owner auth: X-CyberSentinel-Owner-Token, or -Owner-Session/-Owner-Challenge
(single-use). Bridge auth: X-CyberSentinel-Token. The frontend is never
the authority.

### Mission lifecycle
| Contract | Endpoint |
|---|---|
| missionGet | GET /api/missions/{id}/{status|timeline|evidence|artifacts|logs} |
| missionControl | POST /api/missions/{id}/{start|resume|pause|cancel|schedule} |
| missionCreate | POST /api/missions (structured plan dict OR chat fallback) |

Mission statuses (agent/mission.py): CREATED, PLANNING, READY, RUNNING,
OBSERVING, VERIFYING, REPLANNING, GOAL_COMPLETED, OWNER_INPUT_REQUIRED,
AUTHORIZATION_BLOCKED, SCOPE_BLOCKED, RESOURCE_BLOCKED, RECOVERY_REQUIRED,
SAFETY_BLOCKED, FAILED_RETRY_EXHAUSTED, CANCELLED.

### Engine / task compatibility layer
health, status, tools, tasks (create/get/stream/pause/resume/cancel),
execution lifecycle, reasoning memory (owner-only), owner session,
cancel, one-shot command. (Full list in web/src/api/endpoints.js.)

## Part 2 — BLOCKED (backend contract missing — BACKEND_DEPENDENCY)
| Capability | Missing endpoint |
|---|---|
| workspaceTree | GET /api/missions/{id}/workspace/tree |
| workspaceFile (read/write/create/rename/delete/search) | GET/PUT /api/missions/{id}/workspace/file |
| terminal (interactive session, streaming exec) | beyond one-shot /api/command |
| git (branch/diff/commits) | GET /api/missions/{id}/git |
| evidence (generic listing) | GET /api/evidence/{id} (mission-scoped evidence EXISTS via /api/missions/{id}/evidence) |
| findings (claim/validated status) | GET /api/findings?mission={id} |
| scheduler (listing/management) | GET/POST /api/schedules (mission schedule action exists; no listing) |

Notes:
- The GET chat stream does not carry mission resume (query contract is
  text+conversation_id only); resume uses the verified POST /api/missions
  chat path. Documented, not worked around.
- The chat stream is blocking: activity arrives when the mission run
  finishes in-process. The UI shows honest live progress as events
  arrive; it does not simulate intermediate steps.
