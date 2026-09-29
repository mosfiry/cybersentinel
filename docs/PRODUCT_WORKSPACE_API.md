# Product Workspace API and client contract

## Scope and authority

The Arabic Product Workspace is served by the Python `bridge.py` HTTP application and the vanilla-JavaScript client in `web/`. The browser is a client, not an authority: Owner identity, mission ownership, authorization, scope, allowed tools, evidence validity, and mission completion are decided server-side by the authenticated Owner/session, `AgentCore`, the mission authorization snapshot, `MissionRuntime`, and the tool registry. The browser cannot choose a workspace root or expand mission scope through JSON.

The HTML shell is Arabic (`lang="ar"`, `dir="rtl"`). Its primary task interface is the free-form chat composer and natural-language mission objective. Mission lifecycle buttons (start, resume, pause, cancel) are controls over saved runtime state; they are not security approvals. System health is a read-only status view. Workspace file and Git views are mission-scoped and read-only.

## Browser session and authentication

The browser first obtains a short-lived public anti-CSRF session; that session does **not** grant Owner authority. Owner login separately authenticates username/password and sets a server-resolved Owner session cookie. The browser JavaScript keeps the CSRF token in memory and sends cookies with `credentials: "include"`. It stores only a non-secret `{owner username, conversation_id}` pointer for reload continuity; transcript content, credentials, CSRF tokens and Owner session IDs remain server-side or in HttpOnly cookies.

Public cookies are `HttpOnly`, `Secure`, `SameSite=Lax`, and scoped to `/api/public`. Public mutation requests require `X-CSRF-Token`; requests with an `Origin` are checked against `PUBLIC_WEB_ORIGIN` when configured, otherwise against the same request host. GET endpoints require the public session and, for Owner-only resources, a valid Owner session as well. The stable Owner account ID—not the rotating session ID—owns persisted conversations and missions.

| Method and path | Purpose | Success |
|---|---|---|
| `POST /api/public/session` | Create the anti-CSRF public session; no Owner authority | `201 {ok, session:{csrf_token, created_at, expires_at}}` and an HttpOnly cookie |
| `GET /api/public/health` | Read service health/version | `200 {ok, service, version}` |
| `GET /api/public/auth/session` | Inspect current browser Owner authentication | `200 {ok, authenticated, username?, expires_at?}` |
| `GET /api/public/conversations/{id}` | Restore messages/tasks after reload or reconnect, filtered by the stable authenticated Owner identity; unknown and foreign conversations both return `404 unknown_conversation` | `200 {ok:true, conversation:{...,messages:[...],tasks:[...]}}` |
| `POST /api/public/auth/login` | Authenticate the Owner; requires public cookie and CSRF token | `200 {ok, authenticated:true, username, expires_at}` and Owner cookie |
| `POST /api/public/auth/logout` | Revoke the Owner session; requires public cookie and CSRF token | `200 {ok, authenticated:false}` and expired Owner cookie |
| `POST /api/public/program-authorizations` | Persist an explicit manual scope authorization; requires public cookie, CSRF token, and Owner cookie | `201 {ok:true, snapshot:{snapshot_id, program_id, platform, scope_version, asset counts, target_count, methods, rate_limits, created_at, expires_at}}` |
| `POST /api/public/logout` | Revoke the public anti-CSRF session | `200 {ok:true}` and expired public cookie |

Login failure is deliberately generic (`403 invalid_credentials`) so it does not reveal whether a username exists. Owner cookies are resolved server-side; neither username text nor browser UI state is accepted as identity evidence.

## Manual program authorization API

`POST /api/public/program-authorizations` accepts only Owner-submitted scope data. It derives the Owner session from the existing server-resolved Owner cookie, also requires the public anti-CSRF cookie and `X-CSRF-Token`, and binds persistence with that Owner session token. Owner IDs, session IDs, evidence hashes, source markers, and other unknown request fields are rejected; Owner session evidence is never included in the browser-safe response summary. The Arabic Product Workspace provides a manual Owner form that submits through its existing cookie/CSRF-aware `api()` helper and renders only the returned safe summary. Saving a snapshot does not run tests or change tool permissions.

The JSON object requires `program_id`, `platform`, `scope_version`, `in_scope_assets`, `out_of_scope_assets`, `targets`, `allowed_methods`, `prohibited_methods`, and timezone-qualified `expires_at`. Each in-scope asset must explicitly provide `host`, `schemes` (`http` and/or `https`), `ports`, and path prefixes. Each out-of-scope asset contains `host` and may contain `paths` (omitting or supplying an empty path list excludes the whole host). Each target must provide `target_id`, `host`, `allowed_ports`, and `allowed_paths`; `asset_type`, `environment`, and `excluded_paths` are optional. Target host/port/path combinations must remain within the declared in-scope assets.

Allowed and prohibited methods must be explicit, use uppercase standard HTTP methods, and cannot overlap. `prohibited_methods` may be an empty array. `rate_limits` is optional and, when present, accepts only `{"requests_per_minute": N}` with an integer from 1 through 1,000. Limits are 32 in-scope assets, 32 out-of-scope assets, 32 targets, 20 ports per asset/target, 32 paths per list, and an expiration strictly in the future but no more than 365 days ahead. `expires_at` must include a timezone and is persisted in UTC. Unknown fields, duplicate JSON keys, malformed lists, invalid ports/paths, and out-of-bounds values fail with `400` before persistence.

Each successful POST creates a new persisted snapshot; it is not idempotent and clients should not blindly retry an uncertain request. The response summary includes the generated `snapshot_id`, program/version labels, counts, method lists, rate limits, and creation/expiration times, but not the submitted asset contents, Owner identity/session identifiers, or secrets.

## Mission client endpoints

All public mission endpoints require both a valid public session and an authenticated Owner session. Mutating POST actions additionally require CSRF validation.

| Method and path | Purpose and response |
|---|---|
| `GET /api/public/missions?limit=100` | List missions filtered by stable Owner account; `{ok:true, missions:[...]}`. Default `limit` is 100. |
| `POST /api/public/missions` | Create a natural-language mission objective and enqueue it; response includes `mission`, `mission_id`, and `queue`. The server fixes the browser scope to the configured CyberSentinel repository root. |
| `GET /api/public/missions/{id}/status` | Persisted mission state and queue state; `{ok:true, mission_id, status:...}`. |
| `GET /api/public/missions/{id}/timeline` | Saved trajectory events. |
| `GET /api/public/missions/{id}/evidence` | Saved evidence records. |
| `GET /api/public/missions/{id}/artifacts` | Saved artifacts. |
| `GET /api/public/missions/{id}/logs` | Mission logs. |
| `POST /api/public/missions/{id}/start` | Revalidate the live Owner session/scope and queue work. |
| `POST /api/public/missions/{id}/resume` | Reauthorize and queue work; ambiguous in-flight actions require reconciliation first. |
| `POST /api/public/missions/{id}/pause` | Request a safe pause at the runtime boundary or persist PAUSED immediately when no action is in flight. |
| `POST /api/public/missions/{id}/cancel` | Request cancellation; an ambiguous external side effect is not silently treated as cancelled or completed. |
| `POST /api/public/missions/{id}/reconcile` | Requires JSON `{executed:boolean}`. This records an Owner recovery decision and reauthorizes; the browser assertion is **not** completion evidence. |
| `POST /api/public/missions/{id}/schedule` | Persist a one-time scheduled dispatch; requires `run_at`, rejects recurring `interval_seconds` and requires `retry_limit: 0`. The scheduler is not a general recurring automation system or a hidden execution thread. |

Mission status and completion fields are backend truth. The UI only renders `GOAL_COMPLETED` as complete when the server also returns verified completion state and a signed completion proof. The Findings tab is explicitly a view over system-signed criterion evidence; the application does not currently persist an independent `Finding` entity.

## Mission-bound read-only Workspace endpoints

Each Workspace request loads the mission by stable Owner identity, reconstructs and validates that mission's authorization snapshot, checks the `workspace_read` or `git_read` capability in both allowed actions and allowed tools, verifies the snapshot is bound to that mission/account, and uses the root recorded in that snapshot. A missing or stale mission/root/capability fails closed.

| Method and path | Contract |
|---|---|
| `GET /api/public/workspace/{id}/files?path=.` | List one root-confined relative directory: `{ok:true,mission_id,path,files:[{name,directory,size}]}`. Hidden/sensitive paths are filtered. |
| `GET /api/public/workspace/{id}/file?path=README.md` | Read a UTF-8 regular file only: `{ok:true,mission_id,path,content}`. |
| `GET /api/public/workspace/{id}/git?operation=status\|branch\|log\|diff\|head\|repository\|remote` | Execute one fixed read-only Git command and return `{ok:true,mission_id,operation,exit_code,output,error_output}`. No browser-provided shell command or Git arguments are accepted. |

Filesystem paths must be relative and remain beneath the resolved mission root; absolute paths, traversal, escaping symlinks, directories passed as files, binary/invalid UTF-8 files, missing files, and files over 1,000,000 bytes are rejected. Directory listing is limited to 1,000 entries. `.git`, SSH/key material, credential directories, databases, and secret files (including `.env`, `.env.*`, and `.envrc`) are hidden or denied at every depth; safe templates such as `.env.example` remain available. These rules are enforced by the server, not just the UI.

Git operations are allowlisted. The log view is limited to the latest eight one-line commits. File reads/listings and the diff view hide secret paths case-insensitively, including root/nested `.env*` files, common credential stores (`.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.config`, `.ssh`, `.gnupg`, `.terraform`, `.pulumi`, `.vercel`, `secrets`, and `credentials`), standard SSH key filenames, certificate/key extensions, Terraform state, and local database files. The origin URL is redacted before returning it. Browser Git access rejects `commit`, `push`, and every operation outside the fixed read-only set. The workspace policy disables network and credential access for these browser views; the file/Git endpoints cannot write, execute arbitrary commands, or deploy code.

## Error contract

Errors are JSON objects `{ok:false,error:"stable_code_or_message"}`. Common outcomes are: `401` for missing/invalid public session or CSRF; `403` for rejected Origin, missing Owner authorization, ownership/capability denial, or blocked workspace path; `400` for malformed request, invalid path/content, missing required parameters, or unsupported Git operation; `404` for unknown/foreign mission or hidden/missing resources; `413` for oversized request bodies on routes with that limit; and `500` for sanitized server-side failures. Exact messages are not guaranteed beyond stable codes explicitly used by the route handlers; clients should display a safe localized fallback rather than infer a successful action from HTTP transport alone.

## Browser behavior and limits

The browser re-fetches mission state after lifecycle actions and periodically refreshes the selected mission. When the service reconnects, it reloads the authenticated Owner mission list and restores server-owned conversation messages and Owner-filtered Task records from the conversation endpoint. Chat submission uses only `/api/public/chat` and free-form user text. The workspace client performs GET requests for mission panels, file listing/reading, and Git output; it does not send file writes or Git mutations. The Findings panel reuses only records with `system_evidence`. An Owner reconciliation confirmation is recorded as a recovery choice only, never as evidence that a goal was achieved.

The current Product Workspace serves files from the repository root configured by the Python bridge. It is not a generic arbitrary-path editor, and this interface does not provide file editing, uploads, terminal access, commit/push, or deployment. The external Cloudflare Workers Build integration invokes `npx wrangler preview`, while this repository has no Wrangler configuration or Worker entrypoint. A read-only API snapshot taken 2026-09-29 11:35–11:37 UTC found four failed builds, no previews, and three existing deployments with version 3 receiving 100% of traffic; the deployed source relationship and live health were not verified. This does not establish a deployment by this repository, and no Cloudflare setting, trigger, or deployment was changed.

## Verified boundary tests

`tests/test_product_workspace_boundary.py` exercises Owner account filtering, private-mission 404 behavior, mission-bound workspace separation, traversal/symlink rejection, root and nested secret filtering (including Git diff), read-only Git allowlisting and remote redaction, plus SQLite directory/file permissions. `tests/test_public_web_boundary.py` covers public-vs-Owner sessions, CSRF/Origin behavior, cookie flags and revocation, Owner-authenticated chat and transcript isolation, and frontend credential-storage/truthfulness constraints.
