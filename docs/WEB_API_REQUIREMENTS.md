# WEB_API_REQUIREMENTS — CyberSentinel X UI Layer

> PRODUCT/UI LAYER ONLY. This document REQUESTS backend capabilities.
> It does not redefine Authorization Core / OwnerSession / MissionRuntime /
> AgentCore / Policy Engine / Scope Firewall / Evidence Chain semantics.
> Every endpoint below must be enforced server-side by the existing backend.

## Global
- Authentication: server-side Owner session cookie (HttpOnly, SameSite=Strict).
  The frontend never touches OWNER_TOKEN or BRIDGE_TOKEN; no secrets in
  localStorage or the JS bundle. 401 → login redirect, 403 → authorization
  denied view (the UI shows state, the backend decides).

| # | Endpoint | Method | Request | Response | Mission relation | Security considerations |
|---|----------|--------|---------|----------|------------------|--------------------------|
| 1 | /api/missions | GET | query: status?, limit | mission summaries (id, status, objective, target, phase, progress, risk, timestamps) | list | only missions visible to the authenticated Owner |
| 2 | /api/missions/{id} | GET | — | full mission dashboard DTO incl. elapsed, eta, current action, next planned action, last checkpoint | one | read requires Owner ownership |
| 3 | /api/missions/{id}/timeline | GET | query: cursor? | ordered events (created, auth-approved, workspace, planning, recon, tool, observation, hypothesis, code-change, test, failure, repair, retry, verification, finding, report) + per-event detail | one | event detail must not include model chain-of-thought — operational events only |
| 4 | /api/missions/{id}/activity | GET | query: since? | agent activity feed (phase, action text, tool outputs, evidence refs, provenance) | one | no chain-of-thought; provenance required per event |
| 5 | /api/missions/{id}/controls | POST | {action: pause|resume|cancel} + confirmation nonce | 202 accepted / 403 denied + reason | one | backend re-checks authorization window + scope; sensitive actions require explicit confirm nonce |
| 6 | /api/missions/{id}/workspace/tree | GET | — | file tree with per-node permissions (read/write) from backend | one | permissions come from backend Scope Firewall; UI never widens them |
| 7 | /api/missions/{id}/workspace/file | GET | query: path | file content + hash | one | path traversal rejected server-side |
| 8 | /api/missions/{id}/workspace/file | PUT | {path, content, base_hash} | diff created, pending Owner review | one | writes allowed only in mission workspace; conflicts → 409 |
| 9 | /api/missions/{id}/executions | GET | query: cursor? | terminal records: cmd, stdout, stderr, exit, duration, exec id, redaction state | one | credentials redacted server-side BEFORE reaching the browser |
| 10 | /api/evidence/{id} | GET | — | evidence DTO (id, mission, step, source, timestamp, tool, input/output hashes, artifact, provenance, validation result) | cross-ref | immutable; hash-anchored |
| 11 | /api/findings?mission={id} | GET | — | findings with status CLAIM / VERIFIED FINDING / UNKNOWN + evidence ids, validator, confidence, severity | one | backend must mark claim vs verified — UI renders, never decides |
| 12 | /api/missions/{id}/git | GET | — | branch, commits, changed files, diffs, test results | one | repo is read-only unless Owner-approved diff |
| 13 | /api/missions/{id}/authorization | GET | — | authorization snapshot (target, scope, allowed/forbidden actions, tools, window, rate limits, network/data/credential/workspace boundaries, approval, version) | one | display-only; enforcement stays in Policy Engine |
| 14 | /api/schedules | GET/POST | schedule DTO (mode, cron/wake, retry policy) | schedule + next/last run | many | scheduling decisions server-side |
| 15 | /api/missions/{id}/checkpoint | GET | query: since? | last checkpoint + "what happened while away" delta | one | enables long-running mission restore after reload/reconnect |

## Long-running / reconnect contract
- GET /api/missions/{id} after reload must return enough state to render
  "still running / last checkpoint / current state / recent activity /
  what happened while away" without replaying the full event log.
