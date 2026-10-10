# CyberSentinel Desktop/backend contract — 5.1.0 work branch

This contract applies to `work/windows-native-local-llm`, derived from the published `v5.0.0` source. The Electron renderer is an untrusted client. No API in this document widens Owner authority, mission scope, evidence trust, or Tool Registry capabilities.

## Runtime and persistence

- The Windows x64 installer contains the Electron shell, PyInstaller backend, and pinned llama.cpp CPU runtime. Packaged launch uses `process.resourcesPath/backend/cybersentinel-backend.exe`; user devices do not need a Python executable or repository checkout.
- Electron chooses an ephemeral `127.0.0.1` port, generates process-scoped bridge and desktop-setup tokens, and sends a fixed shutdown message through the child stdin pipe. The backend starts the durable `RuntimeSupervisor` only in loopback Desktop mode.
- DBs, Owner policy, model manager state, verified models, managed project folders, and local secrets live below Electron `userData`, separate from installed binaries. Mission checkpoints and application DB state are durable across restarts.
- Development `npm start` may use a developer Python interpreter and checked-out source; that path is not used by packaged launch.
- Renderer has `contextIsolation`, `sandbox`, and `nodeIntegration: false`. Preload exposes a small set of IPC methods for retry, one-time Owner creation, and the native project-folder picker. It does not expose filesystem/child-process access or bridge/setup secrets.

## API routes

| Endpoint | Method | Requirement and behavior |
| --- | --- | --- |
| `/api/desktop/bootstrap-owner` | POST | Desktop-only loopback route; process setup capability and expected Origin required; creates the local `owner` account only if none exists. It is not a public renderer route. |
| `/api/public/session` | POST | Issues a short-lived public CSRF session cookie. |
| `/api/public/auth/login` | POST | Public session + CSRF; validates Owner credentials and sets a server-managed HttpOnly Owner cookie. |
| `/api/public/auth/session` | GET | Returns only authenticated state, username, and expiry; no session identifier. |
| `/api/public/auth/logout` or `/api/public/logout` | POST | Public session + CSRF; revokes Owner and/or public session and clears cookies. |
| `/api/public/desktop/setup` | GET | Public session; returns Desktop mode, whether Owner setup is complete, and sanitized model-manager state. |
| `/api/public/desktop/models` | GET | Public session; returns the fixed bundled catalog, hardware compatibility, installed/active state, and bounded manager status. |
| `/api/public/desktop/models/<id>/install` | POST | Public session + CSRF; before an Owner exists this permits only the fixed pinned catalog; after setup, Owner auth is required. Checks hardware and downloads only the pinned file. |
| `/api/public/desktop/models/<id>/activate` | POST | Public session + CSRF and Owner auth after setup; refuses an incompatible or unverified model and blocks switching while nonterminal missions are active. |
| `/api/public/projects` | GET | Owner session; creates/returns a default General project and an Owner-scoped project list without absolute root paths. |
| `/api/public/projects` | POST | Owner session + CSRF; creates an app-managed project and local root. |
| `/api/public/projects/import` | POST | Owner session + CSRF, expected Origin, and main-process native-picker capability; imports the selected directory only after backend path validation. |
| `/api/public/projects/<id>` | POST | Owner session + CSRF; rename, description update, archive, or restore for that Owner's project. |
| `/api/public/health` | GET | Reports service/version/worker readiness without provider secrets. |
| `/api/public/providers` | GET | Owner session; exposes only known provider labels, configured flags, failure count, and Boolean capabilities—not URLs, model names, keys, or error text. |
| `/api/public/chat` | POST | Owner session + CSRF; accepts `project_id`; server resolves Owner/project mapping and constructs scope. |
| `/api/public/missions` | GET | Owner session; bounded, minimized mission list with server-derived `project_id`. Legacy unassigned missions are deterministically moved to General on listing. |
| `/api/public/missions` | POST | Owner session + CSRF; accepts objective and project ID, ignores client-supplied scope/completion criteria, creates and queues a mission with server-derived project root. |
| `/api/public/missions/<id>/<status\|timeline\|evidence\|artifacts\|logs\|report\|effects>` | GET | Owner session; rejects missions unbound to this Owner; returns persisted backend records only. |
| `/api/public/missions/<id>/<start\|resume\|pause\|cancel>` | POST | Owner session + CSRF; delegates to MissionService authorization and revalidation. |
| `/api/public/missions/<id>/effects/<effect-id>/reconcile` | POST | Owner session + CSRF; requires a specific effect ledger record, allowed outcome, and evidence reference; owner statement alone is not proof of goal completion. |
| `/api/public/workspace/<id>/files?path=...` | GET | Owner session; bounded read-only listing; symlinks and sensitive paths excluded. Fails closed when secure descriptor-relative no-follow support is unavailable. |
| `/api/public/workspace/<id>/file?path=...` | GET | Owner session; read-only UTF-8 view bounded to 256 KiB; escapes/symlinks/sensitive paths rejected; fails closed without secure handle-relative access. |
| `/api/public/workspace/<id>/git?operation=...` | GET | Owner session; fixed read-only operations only; no arbitrary arguments/mutations; fails closed when secure workspace cwd support is unavailable. |

Public write routes validate same-origin/Origin and CSRF and require Owner authorization, except the one-time bootstrap route, which has its own main-process capability and no-existing-account condition. Health/status APIs do not grant authority. Errors do not include stack traces or credentials.

## Mission, model, evidence, and agent visibility

- The ModelRouter remains Core's provider abstraction. The local manager owns pinned model acquisition, integrity verification, activation, status persistence, and `RuntimeAdapter` lifecycle. `llama.cpp` binds loopback only with a random API key; CPU is the supported backend in this installer.
- Switching models cannot happen while a mission is active. A model download is resumable from a partial file and installation requires exact size and SHA-256.

### Public model-row state contract

The `/api/public/desktop/models` catalog row distinguishes a saved preference from live runtime state:

- `selected` is the persisted model preference. It can remain true while the runtime is stopped or being restored; it does not imply readiness.
- `active` is true only when the manager runtime is `ready` and both the runtime model ID and active provider/model ID match that row's `model_id`. A persisted selection alone is insufficient; starting, stopping, stopped, failed, or mismatched runtime state is not active.
- `installed_sha256` is a display observation of the on-disk artifact digest, exposed only after the pinned manifest and expected size match and the actual file hash matches the catalog digest. A successful observation may be cached against the verified artifact fingerprint and pinned identity for status display; it is not authorization or inference authority. Install and activation perform their own fresh verification.
- Missing, partial, tampered, manifest-invalid, or failed-verification artifacts report `installed: false` and `installed_sha256: null`. Failed runtime verification/startup does not leave the model ready or active.

- Mission status controls, checkpoint/recovery, evidence chain, provenance, deterministic validation, findings, reports, scope firewall, target identity, tool registry, and bounded execution remain backend-owned.
- The inspected source stores mission plan steps, queue/worker data, and tool results, but does not define a persistent independent sub-agent identity/run schema. The UI does not invent one; per-agent tracking requires a future Core data model with authorization, budget, checkpoint, and evidence lineage.
- Filesystem and Git viewer routes keep their platform-specific fail-closed boundary; the app does not replace it with insecure path-based reads to make the UI appear more capable.

## Build and verification

`.github/workflows/desktop-build.yml` runs on `windows-latest` for `work/windows-native-local-llm`. It tests Python, npm lock/audit, renderer/Electron syntax, Desktop contracts, backend PyInstaller smoke, pinned llama.cpp digest, and NSIS output; the artifact includes installer SHA-256 and manifest. The job has `contents: read`, `--publish never`, and no release/tag step. No signing identity is configured, so the installer is unsigned. The current computer is Linux without Wine/native Windows GUI; hosted CI does not prove interactive Windows installation, SmartScreen, or first-run window behavior.
