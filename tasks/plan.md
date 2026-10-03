# Implementation Plan: M3 V9 — Scheduled-Mission Authorization Snapshots

## Previous checkpoint

V8 is complete at code commit `0ce8730ca7a0a49d2e51ece94fadfb0139890b4f`. The full suite passed 892 tests with 1 skipped; focused Owner control-plane/bridge/recovery tests passed 27. See `docs/M3_STATE.md` for the detailed V8 evidence and remote-state reconciliation.

## V9 objective

A scheduled or delayed mission must never inherit authority merely because it was created by, queued for, or once belonged to an Owner. Schedule creation requires fresh authenticated Owner reauthorization. Each durable schedule is bound to the exact mission, stable Owner identity, authorization snapshot digest/version, and expiry. At due time the runtime must validate those bindings and the mission's current status before making the queue item claimable. Expired, changed, mismatched, or corrupt authorization is quarantined; it is not silently refreshed or resurrected.

## Source findings

- `MissionScheduler.mission_schedules` currently stores only schedule ID, mission ID, due time, interval, retry counters, and state. It stores no Owner or authorization-snapshot binding.
- `MissionService.schedule_mission()` checks the current Owner-to-mission identity and active lease, but does not run the fresh reauthorization path used by start/resume.
- `MissionScheduler.dispatch_due()` blindly calls `MissionQueue.enqueue()` and then updates the schedule row. It does not validate mission status, snapshot identity, snapshot expiry, or the current Owner binding.
- `MissionScheduler` uses its own database path in the bridge; queue and MissionStore also have separate database paths. The current schedule enqueue/state update is not one crash-safe transaction. All strict databases must retain rollback-journal mode if an attached-database transaction is used.
- The source search found no production invocation of `dispatch_due()` from `MissionWorker`, `RuntimeSupervisor`, or bridge startup. The existing API persists schedules but does not establish a supervised due-dispatch loop. Do not call a dormant interface production-ready; wire a bounded, observable due-dispatch path only if it can be integrated into the existing supervisor without hidden threads or invented infrastructure.

## Architecture decisions

1. Reuse the existing authenticated Owner session and `owner_revalidator`; schedule creation is a fresh Owner action. Validate the renewed `MissionAuthorizationSnapshot` against mission ID, stable `owner:<id>`, integrity hash, provenance version, and active time range.
2. Persist only non-secret binding metadata with the schedule: stable Owner identity, authorization hash/version, and snapshot expiry. Do not persist a session token or attempt to refresh the stored authorization at dispatch time.
3. Before due dispatch, reload the authoritative MissionStore record and compare the schedule binding to the current, hash-valid authorization snapshot and provenance version. Require an allowed nonterminal mission status and no active lease. If any check fails or the snapshot expired, place the mission/schedule into a durable non-claimable Owner-reauthorization state.
4. Make schedule state transition and queue insertion idempotent under crash/retry. Prefer one attached rollback-journal transaction over best-effort sequential writes; otherwise use an explicit durable dispatch saga that can only fail closed. Validate all participating database journal modes.
5. Bind recurring schedules to one snapshot. Once that snapshot expires or changes, stop the schedule and quarantine it. Renewal requires a new explicit Owner action; never update a schedule's authorization from a background worker.
6. Use the existing supervisor polling/lifecycle rather than adding a hidden daemon. Any due dispatcher must be bounded, recoverable, observable, and run before a scheduled queue item is claimed.

## Task list

### Phase 1: Snapshot-bound schedule persistence
- Add strict schedule input validation and Owner reauthorization before schedule insertion.
- Migrate the schedule table additively for Owner identity, authorization hash/version, and expiry.
- Reject schedules for unbound, terminal, recovery-required, leased, malformed, or already-expired mission authority.

### Phase 2: Fail-closed due dispatch and lifecycle integration
- Verify exact current mission/Owner/snapshot bindings and expiry at due time.
- Atomically or saga-safely transition schedule and queue; quarantine invalid or expired records without dispatch.
- Inspect runtime-supervisor wiring; if an existing lifecycle can support scheduled dispatch, integrate a bounded pre-claim poll. Do not create a new hidden thread or external service.

### Phase 3: Adversarial verification
- Test stale/expired/foreign/unbound/tampered snapshot rejection; mission/version/Owner mismatch; duplicate due dispatch; crash between schedule/queue writes; recurring schedule expiry; and stale session/replay.
- Prove invalid schedules never reach the executor and no background path renews authority.
- Run full suite, compileall, diff hygiene, static dispatch/scheduler call-graph scans, and secret scanning.

## Checkpoint gate

V9 is complete only when schedule creation and due dispatch are both demonstrably Owner- and snapshot-bound, restart/expiry fail closed, the production scheduling path is either actually integrated or explicitly remains unavailable without being advertised as active, all negative tests pass, and the local code/evidence checkpoint is committed. Preserve `main` and M2D. Do not push while the V6 Cloudflare production-build check remains unresolved.
