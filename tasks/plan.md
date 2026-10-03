# Implementation Plan: M3 V9 — Scheduled-Mission Authorization Snapshots

## Previous checkpoint

V8 is complete at code commit `0ce8730ca7a0a49d2e51ece94fadfb0139890b4f`. The full suite passed 892 tests with 1 skipped; focused Owner control-plane/bridge/recovery tests passed 27. See `docs/M3_STATE.md` for V8 evidence and remote-state reconciliation.

## V9 objective

Cover delayed/scheduled missions and queued/resumed work with verifiable Owner authority. A schedule must not derive authority from `created_by`, `owner_id`, or an old session alone. At restart or expiry, work must be reauthorized or blocked; it must never resurrect authority.

## Source findings

- The original scheduler schema lacked Owner identity, snapshot digest/version, and expiry.
- The original service did not reauthorize Owner authority before scheduling; the original due-dispatch path did not validate mission or snapshot state.
- Scheduler, queue, MissionStore, and Owner-authentication data are held in existing SQLite stores. Production scheduling can use the existing supervised `MissionWorker` poll without adding a thread.
- The production call path was wired so the worker performs bounded due-dispatch before claim. A scheduled queue row is never directly claimable.
- The Owner evidence already persisted in the authoritative MissionStore includes an evidence record and session reference. Its HMAC uses a process-local key, so an independent worker cannot re-verify that HMAC. The bridge authenticates and creates the snapshot; the scheduler does not duplicate a session token and due dispatch validates the durable evidence-to-snapshot bindings plus current Owner session/account status inside the attached transaction. `AuthorizationContext` uses the same active-session fallback only when its local HMAC does not verify.

## Architecture decisions

1. Schedule creation goes through the existing active Owner session and `owner_revalidator`. Only the exact durable `owner:<id>` matching the mission may schedule it. The renewed `MissionAuthorizationSnapshot` must match mission ID, stable Owner identity, current provenance version, and live expiry.
2. Persist only non-secret binding metadata in `mission_schedules`: stable Owner identity, authorization hash/version, and snapshot expiry. Do not store a session token in a schedule row. Schedule creation flows through the existing authenticated Owner revalidator; due-time verification is portable across worker processes by checking exact durable evidence/snapshot fields and the current active Owner session/account rather than trusting a process-local HMAC.
3. At due time, reload the authoritative MissionStore record and check schedule/mission/Owner/snapshot bindings, evidence request/proof/expiry fields, active session, current account status, expiry, queue state, lease, and mission readiness. Invalid or revoked authority is quarantined; terminal/cancelled missions are retired; no path refreshes authorization in the background. Owner start/resume retires pending due rows after reauthorization and reloads status before queueing; cancellation immediately retires pending due rows after the queue state change.
4. Schedule and queue writes are one attached SQLite transaction spanning scheduler, queue, MissionStore, and Owner-authentication stores. Every participant must use rollback-journal mode. A missing store, unsupported journal mode, malformed row, or transaction failure does not promote work. Startup migration also catches malformed legacy queue/schedule states and timestamps, moving them to non-claimable recovery states instead of aborting before the supervisor can recover.
5. Strict startup recovery still runs before polling. It quarantines previously scheduled work after restart, requiring a fresh Owner action before any future schedule; the old schedule cannot revive it.
6. Production supports one-shot delayed schedules only. Recurring/cron execution and automatic retries are explicitly blocked because the existing model has no safe per-occurrence mission identity plus explicit Owner authorization contract; reopening a completed mission or silently reusing one snapshot would broaden authority. The bridge/service returns a validation error instead of emulating recurring work. `MissionScheduler.schedule()` and `dispatch_due()` also fail closed without an authoritative MissionStore; legacy unbound schedule rows may be inspected/migrated but never dispatched.
7. Integrate due polling into the existing `MissionWorker.run_once()` and supervisor lifecycle only; add no daemon/thread or external service.

## Verification

`tests/test_v9_scheduled_authorization.py` contains 39 adversarial cases for fresh/foreign/revoked sessions, active and expired snapshots, tampered hashes/versions, malformed persisted provenance/version/mission/queue/schedule data, corrupted and NULL startup timestamps, legacy unbound rows, active leases, duplicate polls, crash boundaries in schedule and queue writes, Owner start versus due-poll races, cancellation, restart quarantine, WAL rejection, normalized offset times, one-shot worker dispatch, explicit recurring/retry rejection, and bridge/worker key-rotation portability with revocation rejection. Separate legacy-API tests prove missing-MissionStore scheduling/dispatch/cancellation fail closed and SCHEDULED queue rows remain unclaimable. Bridge-level HTTP and production worker-factory tests cover the public route and supervisor wiring.

## Checkpoint gate

V9 gates passed: the full suite reports 931 passed and 1 skipped; the dedicated V9 suite reports 39 passed; compilation, diff hygiene, static dispatch/call-graph review, secret scan, protected-ref checks, and final independent review are clean. V9 is complete after the new code and state evidence are committed locally on `task/m3-production-runtime-20261003`; `main`/M2D remain unchanged. Recurring/cron remains a separately recorded BLOCKED sub-capability pending an explicit per-occurrence authority model. Do not push while the exact-SHA V6 Cloudflare production-build check remains unresolved.
