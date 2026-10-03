# V9 Implementation Checklist — Scheduled-Mission Authorization Snapshots

## Task 1: Fresh Owner authority when scheduling

- [ ] Require current authenticated Owner session and exact durable mission Owner identity.
- [ ] Run existing Owner revalidation before persisting a schedule; do not use `created_by`, `owner_id`, or a stored session as authority.
- [ ] Validate snapshot integrity, mission/Owner binding, provenance version, and active expiry.
- [ ] Reject active leases, recovery-required missions, terminal missions, unbound legacy missions, and malformed schedule inputs.

## Task 2: Durable schedule snapshot binding

- [ ] Add an additive, idempotent schema migration for stable Owner identity, snapshot digest/version, and expiry.
- [ ] Persist no session token, raw secret, raw Owner evidence, or mutable authorization object.
- [ ] Ensure legacy schedules lacking an explicit binding cannot dispatch and are quarantined rather than adopted.
- [ ] Validate positive intervals/retry bounds and normalize due times consistently.

## Task 3: Due-time validation and crash-safe queue handoff

- [ ] Reload authoritative MissionStore data and validate schedule, mission, Owner, exact snapshot hash/version, and active expiry immediately before dispatch.
- [ ] Prevent terminal, recovery-required, cancelled, already-claimed, or mismatched queue states from being reopened by `enqueue`.
- [ ] Make schedule state and queue insertion atomic using existing rollback-journal attached SQLite transactions, or implement a durable fail-closed saga with restart recovery markers.
- [ ] On stale/expired/tampered bindings, set a non-claimable Owner-reauthorization/quarantine state and never queue execution.
- [ ] Bind recurring schedules to the original snapshot and stop/quarantine them on expiry; require a separate Owner action to create a newly authorized schedule.
- [ ] Integrate due dispatch into the existing supervised lifecycle only if an existing production path supports it without hidden threads or new infrastructure; otherwise keep the feature explicitly non-active and fail closed.

## Task 4: Adversarial negative tests and checkpoint

- [ ] Cover no/expired/revoked Owner session, foreign Owner, forged/unbound mission, old/tampered snapshot hash, wrong mission/version/identity, and expired snapshot.
- [ ] Cover crash between scheduler-state and queue-state writes, duplicate due polling, recurring expiry, stale schedule replay, terminal/cancelled missions, and active-worker races.
- [ ] Prove failed cases never call the executor or produce a claimable queue item.
- [ ] Run full pytest, compileall, `git diff --check`, static direct-dispatch and scheduler call-graph scans, and changed-source secret scan.
- [ ] Commit V9 code and evidence locally on `task/m3-production-runtime-20261003`; preserve `main` and M2D.
- [ ] Keep remote push withheld while exact-SHA V6 Cloudflare build outcome remains unresolved and potentially production-associated.
