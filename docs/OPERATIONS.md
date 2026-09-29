# CyberSentinel X 5.0.0 — Operations

## Supported runtime in this repository

The checked-in production entrypoint is `python bridge.py`. It starts the loopback-only HTTP bridge, one durable mission worker, and the persistent schedule dispatcher. `BRIDGE_HOST` is intentionally fixed at `127.0.0.1`; the service refuses a different bind address. This repository does **not** contain a Docker/Compose, cloud-hosting, systemd, or other production deployment manifest. Do not treat the local bridge or a GitHub Actions run as a deployed service.

## Read-only external hosting snapshot (2026-09-29 11:35–11:37 UTC)

The separate Cloudflare Workers Builds integration for external service `cybersentinel` runs `npx wrangler preview`, but this repository contains no Wrangler configuration or Worker entrypoint. The read-only API snapshot returned four stopped/failed builds and no previews; the latest build (`d898f9d5-9a84-4f8c-98e1-e9ab445133d9`, source SHA `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`) has no preview URL. Its log reports a missing Wrangler `previews` block; that external diagnostic was recorded, not followed as a configuration instruction.

The same snapshot returned three pre-existing deployments, with 100% traffic routed to version 3 (`39fb0620-a8a5-4566-b7e1-8b085529fa1b`). It did not establish that version's source relationship to this repository or verify its live health. The local Python bridge remains loopback-only. No Cloudflare settings, triggers, Worker configuration, or deployment were changed as part of this task.

## Reproducible local installation

1. Use a supported Python version (CI currently uses Python 3.13) and Node.js for the shipped UI syntax check.
2. Create and activate an isolated environment; install the pinned project dependencies:

   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -r requirements.txt
   cp .env.example .env
   ```

3. Set `BRIDGE_TOKEN` to a fresh random transport secret. Keep `.env` outside version control and restrict it to the service account (`chmod 600 .env`). Do not reuse the Owner password as the bridge token.
4. Create the single Owner account interactively. The password is not echoed and only a scrypt verifier is stored:

   ```bash
   python -m security.owner_password_bootstrap
   ```

5. Configure `PUBLIC_WEB_ENABLED=true` only when using the bundled UI. `PUBLIC_WEB_ORIGIN` may be blank for same-origin local use or set to the one exact HTTPS origin when deployed behind a trusted reverse proxy. This is an Origin restriction, not CORS configuration.
6. Start with `python bridge.py`, then open `http://127.0.0.1:8787/` on the same computer and authenticate as the Owner.

A startup without `BRIDGE_TOKEN` fails closed. The Owner session is a separate username/password-backed, eight-hour server-side session. Browser writes require the short-lived public CSRF session plus the HttpOnly Owner cookie. The browser does not receive the bridge token or raw Owner session identifier.

## Configuration and credentials

Configuration is loaded from the process environment and `.env`. See `.env.example` for the authoritative current names:

| Setting | Purpose |
| --- | --- |
| `BRIDGE_TOKEN` | Required internal HTTP transport credential; never Owner authority. |
| `BRIDGE_HOST`, `BRIDGE_PORT` | Loopback listener; host is required to remain `127.0.0.1`. |
| `DB_PATH` | Primary application/Owner database path; defaults to `~/.cybersentinel-x/intel.db`. |
| `PUBLIC_WEB_ENABLED` | Enables the same-origin browser boundary. |
| `PUBLIC_WEB_ORIGIN` | Optional exact accepted browser Origin; it does not enable CORS. |
| `PUBLIC_SESSION_COOKIE`, `PUBLIC_OWNER_SESSION_COOKIE`, `PUBLIC_SESSION_TTL_SECONDS` | Browser cookie names and public CSRF-session lifetime. |
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` | Optional OpenAI-compatible model provider. Keep the key in the environment/secret store, never source control. |
| `LOCAL_LLM_*`, `COLAB_LLM_*`, `HF_LLM_*` | Optional provider-specific model configuration; see `.env.example`. |
| `CYBERSENTINEL_OWNER_EVIDENCE_KEY` | Optional override for the protected Owner-evidence signing key file. |
| `CYBERSENTINEL_PROVENANCE_KEY` | Optional override for the protected system-evidence signing key file. |

With no model provider, deterministic local behavior is used; that is not a live-provider acceptance result. General web search is not configured and must not be represented as an available capability.

The Owner-only `run_project_tests` tool is enabled only when startup verifies `bubblewrap` and `prlimit` can establish an isolated user/PID/network namespace. It runs pytest from a filtered, read-only project snapshot with no inherited credentials, no network, disabled third-party pytest plugin autoload, and explicit CPU, memory, process, file, tmpfs, entry-count, and depth limits. Hosts that cannot satisfy the OS sandbox preflight expose the capability as unavailable; tests are never silently run as an ordinary application-user subprocess. See [Tool Execution](TOOL_EXECUTION.md) for the exact limits and evidence contract.

The GitHub `tests` and `pytest-diagnostics` workflows install `bubblewrap` and `util-linux` (which provides `prlimit`) and require the same startup namespace preflight to pass before pytest runs. If the hosted runner cannot create the required user/PID/network isolation, the job fails closed; sandbox tests are not skipped and no unisolated fallback is used.

The optional manually dispatched live-provider workflow is limited to `main`, validates its `max_iterations` input (1–16), and uses repository Actions secrets named `OPENAI_API_BASE`, `OPENAI_API_KEY`, and `CYBERSENTINEL_OWNER_PASSWORD`; `REAL_PROVIDER_MODEL` is optional. It creates a disposable Owner account/session in the workflow runner's temporary database. Do not put any of these values in source or workflow inputs. When a required secret is absent, the workflow records a `BLOCKED` artifact without starting a mission; this is not a passing live-provider test.

## Persistent state, permissions, and backup

`DB_PATH` is the base path, not the only state file. The bridge places these durable files in the same directory using fixed sibling names: `missions.sqlite3`, `mission_queue.sqlite3`, and `mission_scheduler.sqlite3`. The mission evidence chain is stored as `evidence_chain.db` beside the mission store. Owner-authentication and system-evidence signing keys default to `~/.cybersentinel-x/owner_evidence.key` and `~/.cybersentinel-x/evidence_provenance.key`; preserve them with their database backups or previously issued signed records will no longer verify. Database files and signing keys are created with restrictive private permissions; do not copy them into the repository or public CI artifacts.

For a consistent backup, stop the bridge first, then copy the complete database set and both signing keys to an access-controlled backup location. Recheck ownership and restrictive file permissions when restoring. Keep backups encrypted according to the host's policy.

## Worker lifecycle and recovery

The bridge runs one bounded mission worker alongside HTTP service. It accepts at most 10 active queue entries by default; an enqueue beyond that limit is rejected (`mission_queue_full`, HTTP 429) rather than growing the active backlog without bound. The worker claims durable SQLite leases and renews them on a daemon heartbeat while a model/tool call is running, executes at most one mission slice at a time, releases unfinished work for a later slice, recovers expired leases, and on process startup returns interrupted queue leases for checkpoint recovery. A process restart does not itself establish whether an external side effect happened: the runtime preserves an in-flight checkpoint and requires Owner reconciliation before retrying or accepting completion. Owner pause/cancel controls are intended to take effect at safe slice boundaries; a concurrent request/result race remains a separately tracked verification limitation. Queue state is operational metadata; mission status/evidence remain the source of truth.

The persistent scheduler currently supports one-time dispatch only. It rejects recurring `interval_seconds` and nonzero `retry_limit` because it does not yet create a fresh execution per recurrence or retry failed schedule dispatches. It is not a general recurring automation system.

`SIGTERM` and `SIGINT` request HTTP shutdown and signal the worker to stop; the worker join is bounded. If a host terminates the process during an external tool call, the persisted checkpoint and recovery flow remain authoritative. Standard output contains service/worker diagnostics. Keep host logs private and rotate them according to the host's retention policy.

## Health checks and reverse proxy expectations

When `PUBLIC_WEB_ENABLED=true`, `GET /api/public/health` reports bridge health/version without returning a credential. It is an application liveness check, not a provider, database-write, or deployment-health attestation. Check provider availability and database persistence separately using the configured operator procedures and actual Actions artifacts.

The bridge binds only to loopback. Any external deployment therefore needs a separately configured and validated trusted reverse proxy that terminates HTTPS, keeps the upstream private, enforces its own network policy, and serves the browser from one same-origin URL. Set `PUBLIC_WEB_ORIGIN` to that exact HTTPS origin. Do not publish the bridge listener directly to a network or assume forwarded headers, CORS, TLS certificates, proxy timeouts, or proxy security policy are configured by this repository. The Owner cookie is HttpOnly, Secure, and SameSite=Lax.

## Schema migration and rollback

SQLite schema initialization/migration is performed by the application database connection code and is designed to be safe to run repeatedly. There is no standalone migration CLI, production migration manifest, or verified automatic down-migration. Before upgrading, stop the service and back up the entire state set (including signing keys). Roll back code only together with the compatible pre-upgrade database snapshot; do not delete or hand-edit the current database to force an older binary to start. Validate restored data in an isolated copy before replacing active state.

## Release validation

Run the actual checks locally before proposing a release:

```bash
python -m compileall -q .
node --check web/app.js
python -m pytest -q
```

The primary PR workflow and the diagnostics workflow have read-only repository permissions, perform compile/frontend/test/whitespace/secret checks, and retain a compact status artifact. They do not export repository source as a diagnostics artifact and do not commit or push to any branch. Their exact current run IDs and conclusions must be checked on GitHub; local validation is not CI.

This is operational documentation for the repository-controlled local runtime, not legal advice, an infrastructure attestation, or proof of a production deployment.
