# CyberSentinel X — Current Runtime Truth

**Audit date:** 2026-09-29
**Starting commit:** `8a3fd10` (`main`)
**Implementation branch:** `work/arabic-auth-ci-docs-20260929`
**Basis:** direct inspection of the verified main source, imports, entrypoints, and tests.

## Actual entrypoint graph

```text
Browser: GET /, /app.js, /style.css
  ├── POST /api/public/session -> PublicSessionManager (CSRF token, no Owner authority)
  ├── POST /api/public/auth/login -> owner_password.login -> SQLite Owner session
  │   └── opaque session ID returned only as HttpOnly; Secure; SameSite=Lax cookie
  ├── GET /api/public/auth/session -> resolve the cookie-backed Owner session
  ├── POST /api/public/auth/logout -> revoke Owner session
  └── POST /api/public/chat -> public CSRF validation + Owner cookie validation
      └── api.chat.chat -> AgentCore -> MissionRuntime
          ├── persistent MissionStore and typed authorization boundary
          ├── ModelRouter planning proposals and deterministic authorization
          ├── tools.registry.execute()
          ├── observations, evidence, trajectory, recovery/reconciliation
          └── deterministic goal verification

Internal HTTP clients
  ├── X-CyberSentinel-Token -> local transport authentication
  ├── X-CyberSentinel-Owner-Session -> server-side Owner session reference
  ├── POST /api/chat -> api.chat.chat -> AgentCore -> MissionRuntime
  ├── /api/tasks -> AgentTaskRuntime compatibility task routes
  └── /api/command -> core.engine / AgentRuntime compatibility route
```

## Runtime inventory

| Component | Current role | Status against one-runtime requirement |
|---|---|---|
| `agent/mission_runtime.py::MissionRuntime` | Durable mission lifecycle, model loop, recovery, evidence, deterministic verification | Canonical Owner chat engine |
| `agent/agent_core.py::AgentCore` | Mission orchestration facade | Active `/api/chat` and browser-chat entry boundary |
| `agent/task_runtime.py::AgentTaskRuntime` | Durable compatibility task lifecycle | Active through `/api/tasks`; not the chat path |
| `core/engine.py` / `agent/runtime.py` | Command planner and local/default compatibility execution | Active through `/api/command` |
| `agent/loop.py::AgentLoop` | Legacy conversational loop and tool metadata export | Legacy module; bridge imports tool metadata for `/api/tools` |
| `tools/registry.py` | Tool metadata, validation, authorization-decision revalidation, execution | Shared registry and execution boundary |
| `security/authorization.py` | Typed authorization and decision issuance | Active security boundary |
| `security/authorization_context.py` | Typed immutable context and signed decision | Active for sensitive mission execution |
| `security/scope*.py` | Scope snapshot persistence/resolution/firewall | Active for scope-bound tools |
| `core/lifecycle.py` | Request lifecycle persistence for command path | Active in compatibility path |
| `agent/mission.py::MissionStore` | Durable SQLite mission state and integrity hash | Active in canonical mission path |
| `security/owner_password.py` | Username/password verification and revocable Owner sessions | Canonical Owner authentication |
| `security/public_session.py` | Short-lived browser CSRF sessions | Browser CSRF boundary only; never Owner authority |

## Security facts observed in source

The browser Owner cookie and internal `X-CyberSentinel-Owner-Session` header both resolve to the same SQLite-backed username/password session; the public CSRF session is separate and cannot authorize chat. The canonical mission loop does not accept a bare `owner_authenticated=True` as authority. Sensitive tools require an `AuthorizationContext` and `tools.registry.execute()` revalidates an `AuthorizationDecision` against tool name, request ID, and argument hash. Mission tool proposals carry mission/run/turn/tool-call identity and duplicate or stale identities are rejected.

The model cannot directly set completion status. `MissionRuntime` invokes deterministic verification and only then transitions to `GOAL_COMPLETED`. Crash recovery records an ambiguous in-flight side effect as `RECOVERY_REQUIRED`; it does not infer success or retry blindly.

## Remaining gaps observed in source

1. `/api/tasks` and `/api/command` remain supported compatibility routes beside the canonical `api.chat.chat -> AgentCore -> MissionRuntime` path.
2. The browser public-session store is in memory; Owner sessions are persisted in SQLite. The bridge remains loopback-only, no production web deployment is configured, and cross-origin CORS/preflight is not implemented.
3. Live-provider acceptance remains gated and may be skipped when credentials/factory are absent; deterministic tests are not REAL-PROVIDER evidence.
4. The 199 tracked files under `diagnostics/` are historical source snapshots and CI reports. They are preserved unchanged; main-branch CI now uploads a status artifact instead of committing diagnostics and retriggering itself.

## Deterministic implementation-branch validation

Executed from `/workspace/cybersentinel` with the declared requirements installed:

```text
713 passed, 1 skipped in 14.13s
TEST_EXIT_CODE=0
```

`python -m compileall -q .`, `node --check web/app.js`, and `git diff --check` also passed. The skipped test is the live-provider long-horizon acceptance test and is explicitly labeled unavailable when provider credentials/factory are absent. These deterministic results are not evidence of a real-provider run or production deployment.
