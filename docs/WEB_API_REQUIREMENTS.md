# WEB_API_REQUIREMENTS — CyberSentinel X UI Layer

> PRODUCT/UI LAYER ONLY. This document REQUESTS backend capabilities.
> It does not redefine Authorization Core / OwnerSession / MissionRuntime /
> AgentCore / Policy Engine / Scope Firewall / Evidence Chain semantics.
> Every endpoint must be enforced server-side by the existing backend.

## Global
- Authentication: server-side Owner session cookie (HttpOnly, SameSite=Strict).
  The frontend never touches OWNER_TOKEN or BRIDGE_TOKEN; no secrets in
  localStorage or the JS bundle. 401 -> login redirect, 403 -> authorization
  denied view (the UI shows state, the backend decides).

| # | Endpoint | Method | Request | Response | Mission relation | Security considerations |
|---|----------|--------|---------|----------|------------------|--------------------------|
| 1 | /api/missions | GET | query: status?, limit | mission summaries (id, status, objective, target, phase, progress, timestamps) | list | only missions visible to the authenticated Owner |
| 2 | /api/missions/{id} | GET | - | full dashboard DTO (elapsed, eta, current action, next planned action, last checkpoint) | one | read requires Owner ownership |
| 3 | /api/missions/{id}/timeline | GET | query: cursor? | ordered events + per-event detail | one | no model chain-of-thought — operational events only |
| 4 | /api/missions/{id}/activity | GET | query: since? | agent activity feed (phase, action, tool outputs, evidence refs, provenance) | one | no chain-of-thought; provenance required |
| 5 | /api/missions/{id}/controls | POST | {action: pause\|resume\|cancel} + confirmation nonce | 202 accepted / 403 denied + reason | one | backend re-checks authorization; sensitive actions need confirm nonce |
| 6 | /api/missions/{id}/workspace/tree | GET | - | file tree with per-node permissions from backend | one | permissions from Scope Firewall; UI never widens them |
| 7 | /api/missions/{id}/workspace/file | GET | query: path | file content + hash | one | path traversal rejected server-side |
| 8 | /api/missions/{id}/workspace/file | PUT | {path, content, base_hash} | diff created, pending Owner review | one | writes only in mission workspace; conflicts -> 409 |
| 9 | /api/missions/{id}/executions | GET | query: cursor? | terminal records: cmd, stdout, stderr, exit, duration, exec id | one | credentials redacted server-side BEFORE reaching browser |
| 10 | /api/evidence/{id} | GET | - | evidence DTO (hashes, artifact, provenance, validation) | cross-ref | immutable; hash-anchored |
| 11 | /api/findings?mission={id} | GET | - | findings with status CLAIM / VERIFIED / UNKNOWN + validator, confidence | one | backend marks claim vs verified — UI renders, never decides |
| 12 | /api/missions/{id}/git | GET | - | branch, commits, changed files, diffs, test results | one | repo read-only unless Owner-approved diff |
| 13 | /api/missions/{id}/authorization | GET | - | authorization snapshot (all boundaries, approval, version) | one | display-only; enforcement stays in Policy Engine |
| 14 | /api/schedules | GET/POST | schedule DTO (mode, cron/wake, retry policy) | schedule + next/last run | many | scheduling decisions server-side |
| 15 | /api/missions/{id}/checkpoint | GET | query: since? | last checkpoint + "what happened while away" delta | one | enables restore after reload/reconnect |
| 16 | /api/tools | GET | - | tool inventory (id, name, scope tags) | global | tools usable only within a mission authorization window |

## Long-running / reconnect contract
- GET /api/missions/{id} after reload must return enough state to render
  "still running / last checkpoint / current state / recent activity /
  what happened while away" without replaying the full event log.
