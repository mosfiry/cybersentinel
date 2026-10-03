# V9 Implementation Checklist — Scheduled-Mission Authorization Snapshots

## Task 1: Fresh Owner authority when scheduling

- [x] Require a current authenticated Owner session and exact durable mission Owner identity.
- [x] Run existing Owner revalidation before persisting a schedule; do not use `created_by`, `owner_id`, or a stored session alone as authority.
- [x] Authenticate fresh Owner evidence through the bridge revalidator; verify snapshot integrity, mission/Owner binding, provenance version, active expiry, and current session/account status.
- [x] Reject active leases, recovery-required missions, terminal missions, unbound legacy missions, and invalid schedule inputs.

## Task 2: Durable schedule snapshot binding

- [x] Add an additive, idempotent schema migration for stable Owner identity, snapshot digest/version, and expiry.
- [x] Persist no session token or raw Owner evidence in a schedule row; validate durable evidence-to-snapshot bindings through MissionStore and the Owner auth store.
- [x] Ensure legacy schedules lacking an explicit binding cannot dispatch and are quarantined rather than adopted.
- [x] Normalize due times consistently; Owner-bound recurring intervals and retries are rejected, and low-level schedule/dispatch mutations fail closed without an authoritative MissionStore.

## Task 3: Due-time validation and crash-safe queue handoff

- [x] Reload authoritative MissionStore data and validate schedule, mission, Owner, exact snapshot hash/version, evidence request/proof/expiry fields, active Owner session/account, and expiry immediately before dispatch.
- [x] Prevent terminal, recovery-required, cancelled, active-lease, already-claimed, or mismatched queue states from being reopened by `enqueue`.
- [x] Atomically transition schedule and queue with the existing rollback-journal attached SQLite transaction spanning scheduler, queue, MissionStore, and Owner-authentication stores.
- [x] Quarantine stale, expired, revoked, tampered, mismatched, legacy-unbound, or structurally malformed authority/data; never queue execution.
- [x] Wire bounded due dispatch into existing supervised `MissionWorker.run_once()` before claim; no hidden thread or new infrastructure.
- [!] BLOCKED SUB-CAPABILITY: recurring/cron execution and auto-retries remain rejected until the Owner-approved per-occurrence mission-identity/authorization contract exists. Do not reopen a terminal mission or reuse one snapshot for repeat executions.

## Task 4: Adversarial negative tests and checkpoint

- [x] Cover stale/revoked/foreign Owner sessions, unbound legacy rows, tampered hash/version, identity mismatch, expired snapshot, and expiry-window rejection.
- [x] Cover schedule-insert/queue-write/queue-promotion crash boundaries, duplicate due polling, restart quarantine, terminal/cancelled missions, active-worker races, and revoked Owner-session status at due time.
- [x] Prove invalid cases never reach executor or a claimable queue state; direct `SCHEDULED` rows remain unclaimable.
- [x] Cover independent-review fixes: no unbound scheduler mutation, malformed mission/service provenance/queue/schedule state and timestamps, strict Owner-bound offset normalization, due-poll/start race, and immediate start/resume/cancel schedule retirement.
- [x] Rerun final full repository suite and checkpoint hygiene after the independent-review fixes (931 passed, 1 skipped; V9 suite 39 passed; compileall, py_compile, diff hygiene, dispatch/call-graph, secret-pattern, and protected-ref checks passed).
- [ ] Commit V9 code and evidence locally on `task/m3-production-runtime-20261003`; preserve `main` and M2D.
- [x] Keep remote push withheld while exact-SHA V6 Cloudflare build outcome remains unresolved and potentially production-associated.
