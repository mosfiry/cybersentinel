# CyberSentinel Desktop/backend contract

This contract describes the Desktop shell and the hardened backend integration on the release branch. The UI, Electron shell, bridge, and backend are tested together; this is not a claim that the earlier Desktop source branch already matched the backend.

## Runtime and transport

- The Windows x64 Electron shell starts the checked-in Python bridge at `127.0.0.1` and opens the same-origin UI at `http://127.0.0.1:<BRIDGE_PORT>/` (default port `8787`).
- Desktop starts the durable mission worker through the bridge's runtime supervisor. The bridge does not start that worker for non-loopback deployments; Compose runs its own worker service.
- Electron passes a reviewed allowlist of non-secret environment settings. It does not parse `.env` or forward credential values. Python loads the private `.env` and file-backed secrets itself; the Desktop deployment requires a private `.env` containing `BRIDGE_TOKEN` (or the supported secret-file configuration).
- Electron and the renderer do not receive Owner session tokens. The renderer uses same-origin cookies, `HttpOnly`, `Secure`, `SameSite=Lax`, and CSRF protection.
- On Desktop shutdown, Electron sends a private command over the child process's stdin pipe. The bridge stops the worker and HTTP service; Electron waits for process exit and force-terminates only after a 10-second grace period.
- The packaged `.exe` contains the Electron shell, not the Python backend, repository, or virtual environment. Python 3.12+ and a separately provisioned CyberSentinel repository/dependencies are required; packaged launches must set `CYBERSENTINEL_REPO`. This workflow builds Windows x64 installer and portable artifacts; it does not certify macOS or Linux GUI packaging.

## Public API

| Endpoint | Method | Requirement and behavior |
| --- | --- | --- |
| `/api/public/session` | POST | Issues the short-lived public CSRF session cookie. |
| `/api/public/auth/login` | POST | Public session + CSRF; verifies Owner credentials and sets a server-managed HttpOnly Owner cookie. |
| `/api/public/auth/session` | GET | Returns only authenticated state, username, and expiry; never returns a session identifier. |
| `/api/public/auth/logout` | POST | Public session + CSRF; revokes the Owner session and clears its cookie. |
| `/api/public/logout` | POST | Public session + CSRF; revokes both public and Owner sessions and clears both cookies. |
| `/api/public/health` | GET | Reports service/version and worker readiness without provider URLs or credentials. |
| `/api/public/providers` | GET | Owner session; exposes only known provider label, configured flag, failure count, and Boolean capabilities. Does not expose model, base URL, key, or error text. `configured` is not a live connectivity check. |
| `/api/public/chat` | POST | Owner session + CSRF; request/response JSON, fixed server-side scope, no public SSE stream. |
| `/api/public/missions` | GET | Owner session; bounded, minimized list of missions bound to that Owner. |
| `/api/public/missions` | POST | Owner session + CSRF; accepts an objective, constructs scope server-side, creates a mission and queues it. Client-provided scope/completion criteria are ignored. |
| `/api/public/missions/<id>/<status\|timeline\|evidence\|artifacts\|logs\|report\|effects>` | GET | Owner session; rejects unbound legacy missions; returns server records only. |
| `/api/public/missions/<id>/<start\|resume\|pause\|cancel>` | POST | Owner session + CSRF; delegates to MissionService owner authorization/revalidation. |
| `/api/public/missions/<id>/effects/<effect-id>/reconcile` | POST | Owner session + CSRF; requires a specific ledger effect, an allowed reconciliation outcome, and a non-empty evidence reference of at most 512 characters. Owner statements are not independent proof of goal completion. |
| `/api/public/workspace/<id>/files?path=...` | GET | Owner session; read-only descriptor-relative listing, at most 500 entries; symlinks and sensitive paths are excluded. Returns `501 secure_workspace_access_unavailable` unless secure descriptor-relative no-follow support is available. |
| `/api/public/workspace/<id>/file?path=...` | GET | Owner session; read-only bounded UTF-8 file view, maximum 256 KiB; symlinks, escapes, and sensitive paths are rejected. Returns `501 secure_workspace_access_unavailable` unless secure descriptor-relative no-follow support is available. |
| `/api/public/workspace/<id>/git?operation=...` | GET | Owner session; fixed read-only operations only: `status`, `branch`, `log`, `diff`, `repository`, `head`, `remote`. No arbitrary arguments or mutations; optional index writes, fsmonitor, pager, external diff, and textconv are disabled; remote URL user-info and recognized secret query values are redacted. Returns `501 secure_workspace_access_unavailable` unless secure descriptor-relative workspace/cwd support is available. |

All write routes validate same-origin/Origin and CSRF, and require server-side Owner authorization. Public health is informational; it does not authenticate a user. Responses use stable, explicit error codes and do not expose stack traces.

## Evidence, lifecycle, and unavailable capabilities

- The Desktop renders mission completion only when the backend reports `GOAL_COMPLETED`, independent verification is true, and a completion proof is present. Model text, tool output, provider status, and an Owner reconciliation decision are not accepted as independent completion proof.
- Reconciliation is effect-specific and preserves the backend's recovery state machine; the client cannot submit a free-standing `{executed: true}` result.
- The public client does not claim a general approve/reject API, public tools listing, transcript retrieval, or streaming chat. The chat UI is request/response; conversation text held only in the renderer is not represented as a server transcript.
- The provider panel is a sanitized configuration summary, not a provider health probe. A successful provider call remains the only evidence of a successful request.

## Build validation boundary

The Windows workflow runs on `windows-latest` only for `release/cybersentinel-final-20261003`, builds NSIS and portable x64 executables, and uploads them as a non-release workflow artifact (`electron-builder --publish never`). CI and the Python suite validate the API and contracts, but the `.exe` is not executed on the Linux development computer; interactive Windows runtime behavior remains unverified unless a Windows runtime rehearsal is separately performed.
