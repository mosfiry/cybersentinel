# CHECKPOINT — Owner Password Authentication Migration

AUTONOMOUS-CONTINUATION CHECKPOINT. The next session MUST start from
`NEXT_SESSION_FIRST_ACTION` below and must NOT restart completed work.

## CURRENT_PHASE
CYBERSENTINEL X — CRITICAL OWNER AUTHENTICATION MIGRATION (username+password
replaces all OWNER_TOKEN / owner-challenge mechanisms).

## CURRENT_UNIT
Unit 3 of the migration plan (repository-wide audit classification was done;
integration of password sessions into ALL live Owner paths is pending).

## BRANCH / COMMITS

- branch: `security/owner-password-auth-migration` (created from `main` @ `5ed08d9`)
- starting HEAD: `5ed08d9f73a79f68467dc0a5db68e68b2712a63a` (main)
- COMMIT 1 — `5b92d3e721c4d7b92bd056d088102daff7fc0e6f`:
  - `core/db.py`: new tables `owner_accounts`, `owner_sessions` (verifier-only
    password storage, KDF algorithm/params, account status, session
    status/expiry/revocation, authentication_method).
  - `security/owner_password.py`: the ONLY canonical human Owner
    authentication mechanism — scrypt KDF (N=16384, r=8, p=1, dklen=32,
    per-user 16-byte salt), generic login failures (anti-enumeration +
    timing-equalized dummy verify), cryptographically random server-side
    sessions (`secrets.token_urlsafe(32)`, never derived from identity
    material), `resolve_session`, `revoke_session`, `reset_password`
    (requires current password; revokes all sessions), and
    `authenticated_owner()` which IGNORES all client claims.
  - `security/owner_password_bootstrap.py`: secure interactive bootstrap
    (`python -m security.owner_password_bootstrap`), getpass (never echoes),
    idempotent (never overwrites), `--reset` requires current password.
  - `tests/test_owner_password_auth.py`: 24 adversarial tests (see
    INVARIANTS_PROVEN).
- COMMIT 2 — `01e2307e6bf8e5fd5c16cce219ea38a487c71a55`:
  - `bridge.py`: `POST /api/auth/login` (username+password only, generic 403)
    and `POST /api/auth/logout` (server-side session revocation). BRIDGE_TOKEN
    remains a transport credential only; it never implies Owner identity.

## LAST_COMPLETED_STEP
Bridge login/logout routes live; canonical auth module + bootstrap + schema
+ adversarial test battery committed.

## NEXT_STEP (remaining migration, in order)
1. Wait for / verify CI green on `01e2307` (workflow `tests.yml` runs pytest,
   compileall, git diff --check, secret scan on every push). Diagnose and fix
   any failure — never hide it.
2. Owner bootstrap (interactive, local, by the human Owner):
   instruct the Owner to run `python -m security.owner_password_bootstrap`
   locally and enter the established password. NO agent may ever request,
   store, or commit that password.
3. Integrate password sessions into ALL live Owner-controlled paths — replace
   `verify_owner`/OWNER_TOKEN checks with `owner_password` session resolution:
   - `api/chat.py` (`_validate_chat_entry`, create/resume/pause/cancel)
   - `api/missions.py` + `bridge.py` `_mission_owner` / `/api/missions*`
   - `agent/task.py`, `agent/task_runtime.py`, `agent/task_manager.py`,
     `agent/loop.py`, `agent/agent_core.py`, `agent/mission_task_adapter.py`
     (thread `owner_session_id` -> `owner_password` session reference)
   - `core/context.py`, `core/engine.py` (runtime entry)
   - `security/owner_policy.py` (`verify_owner` removal),
     `security/owner_session.py` (challenge mechanism removal),
     `security/scope_store.py`
   - worker/recovery paths: `agent/mission_worker.py`,
     `agent/mission_runtime.py` — persisted provenance must reference the
     authenticated session; recovery must fail closed on missing/forged
     Owner provenance (never mint Owner identity).
4. REMOVE legacy authentication completely: `OWNER_TOKEN`, `verify_owner`,
   `CYBERSENTINEL_OWNER_PHRASE`, owner-challenge flow, `.env.example` /
   `.env.agent.example` OWNER_TOKEN entries. No fallback, no compatibility
   mode, no dual acceptance.
5. Owner authentication evidence: derive from the username_password session
   (owner id, session id, authenticated_at, method) — never secrets, never
   verifier material.
6. Update/replace the adversarial battery for live paths: forged mission
   context, forged queue item claiming Owner authority, model escalation,
   scope expansion, external-data injection; rejection tests must assert
   handler_calls == 0 where applicable.
7. Update docs (SECURITY_MODEL.md, OPERATIONS.md, OWNER_POLICY.md, README)
   and this checkpoint after every unit.

## NEXT_SESSION_FIRST_ACTION
Check CI status of `01e2307e6bf8e5fd5c16cce219ea38a487c71a55`; if green,
proceed with NEXT_STEP 2 and 3 above (start with `api/chat.py` +
`bridge.py` `_mission_owner`), one logical commit per unit, updating this
checkpoint file in each commit.

## LAST_VERIFIED_COMMIT
`01e2307e6bf8e5fd5c16cce219ea38a487c71a55` (CI: pending at checkpoint time —
must be verified, not assumed)

## TEST_STATUS
- 24 new adversarial tests in `tests/test_owner_password_auth.py`
  (bootstrap verifier-only, idempotency, CLI interactive flow, login
  success/generic failures, session expiry/revocation/forgery/tampering,
  client boolean/role/method/id forgery, magic "Owner" string, token-value
  rejection, reset fail-closed, KDF salting/malformed-hash rejection).
- Full-suite result: pending CI (agent cannot run pytest locally; rely on
  `tests.yml` and record its outcome here in the next session).

## CI_STATUS
Pending for commits `5b92d3e` and `01e2307`. Verify before further work.

## OPEN_ISSUES
1. CI outcome of the two commits above is unverified (pending).
2. `requirements.txt` has no argon2 dependency; scrypt (stdlib, memory-hard)
   was chosen to avoid new CI dependencies. If the Owner prefers Argon2id,
   add `argon2-cffi` and swap the KDF in `security/owner_password.py`
   (verifier records carry algorithm + params, so migration is explicit).
3. Session TTL is 3600s (`owner_password.SESSION_TTL_SECONDS`) — confirm the
   Owner's desired policy value.
4. Legacy mechanisms are STILL ACTIVE in production paths until NEXT_STEP 3–4
   complete. Do not declare the migration done before that.

## INVARIANTS_PROVEN (by tests/test_owner_password_auth.py)
- Correct credentials authenticate; wrong password / unknown username fail
  with an identical generic error (anti-enumeration).
- Only a scrypt verifier is stored; plaintext absent from every DB table and
  from captured stdout/stderr of the bootstrap CLI.
- Bootstrap is idempotent and never overwrites; reset requires the current
  password and revokes all sessions.
- Session ids are random, independent, never derived from username/password.
- Expired / revoked / forged / tampered sessions are rejected.
- Client-supplied booleans, roles, methods, ids, OWNER_TOKEN values, and the
  magic "Owner" string never authenticate anyone; a valid server-side session
  wins while client claims are discarded.
- Malformed verifier records fail closed.

## INVARIANTS_NOT_PROVEN (yet)
- OWNER_TOKEN cannot authenticate Owner on LIVE paths (legacy paths still
  active — removal pending).
- MissionWorker cannot forge Owner identity; durable recovery cannot
  manufacture Owner authorization (integration pending).
- Model output / external data cannot manufacture Owner authority on live
  paths (existing invariants must be re-verified after integration).
- Full CI green on this branch (pending).

## FILES_CHANGED
- core/db.py (schema: owner_accounts, owner_sessions)
- security/owner_password.py (new)
- security/owner_password_bootstrap.py (new)
- tests/test_owner_password_auth.py (new)
- bridge.py (login/logout routes)
- docs/CHECKPOINT_OWNER_AUTH_MIGRATION.md (this file)

## REPOSITORY-WIDE AUDIT (OWNER_TOKEN occurrences, classification)
Production code (must migrate in NEXT_STEP 3–4):
bridge.py, api/chat.py, core/context.py, core/engine.py,
security/owner_policy.py, security/owner_session.py, security/scope_store.py,
agent/task.py, agent/task_runtime.py, agent/task_manager.py, agent/loop.py,
agent/agent_core.py, agent/mission_task_adapter.py
Scripts (migrate or delete): scripts/real_chat_runner.py,
scripts/real_model_smoke.py, scripts/run_real_provider_mission.py,
scripts/run_agent_intelligence_audit.py
Config/examples (remove OWNER_TOKEN entries): .env.example,
.env.agent.example, security/owner_policy.json
Docs (rewrite): README.md, docs/TESTING.md, docs/OPERATIONS.md,
docs/SECURITY_MODEL.md, docs/OWNER_POLICY.md, docs/GITHUB_ONLY_POC_RESULTS.md,
docs/PUBLIC_WEB_ARCHITECTURE.md, docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md,
docs/AGENT_ARCHITECTURE.md, .github/workflows/github-only-poc.yml
Tests referencing legacy auth (rewrite alongside production removal):
tests/test_owner_auth.py, tests/test_phase6k5_core.py,
tests/test_agent_platform.py, tests/test_phase5e_runtime.py,
tests/test_message0003_auth.py, tests/test_v50_owner_session.py,
tests/test_public_web_boundary.py, tests/test_scope_firewall_battery.py,
tests/test_agent_core_integration.py, tests/test_phase6c_scope_firewall.py,
tests/test_phase6k4_deep_hardening.py, tests/test_phase6b_program_adapters.py,
tests/test_v47_red_team.py, tests/test_phase21_restart_authorization.py,
tests/test_security_integrity_adversarial.py, tests/test_phase6a1_hardening.py,
tests/test_phase6k6_unified.py, tests/test_phase3_context.py,
tests/test_governed_execution.py, tests/test_owner_authority_refactor.py,
tests/test_phase6k7b_mission_runtime.py, tests/test_phase5_long_horizon.py

## GIT SAFETY
Dedicated branch only; never touch main; no force push, no destructive
reset, no history rewriting, no hidden failures.
