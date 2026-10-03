# V10 Implementation Checklist — Real Process Death and Multi-Process Harness

## Task 1: Process-test contract and bounded harness

- [x] Re-read the original V10 requirements and map current production worker, supervisor, SQLite, Owner-session, evidence, and external-effect call paths.
- [x] Confirm existing V9 crash coverage is failpoint-based and current multi-worker tests do not kill supervised mission-worker processes.
- [ ] Add an optional stable logical `worker_id` to the existing bridge worker factory and supervised CLI, preserving the current default.
- [ ] Create a test-only subprocess harness using `Popen`, isolated `DB_PATH`, JSON-line/stdin barriers, timeouts, real signals, and unconditional child cleanup.
- [ ] Ensure all test processes use only temporary rollback-journal databases and local deterministic handlers; make no network/provider calls.

## Task 2: Real process-death cases at durability boundaries

- [ ] SIGTERM before claim; prove no claim/effect, then prove restart recovery quarantines pending Owner work.
- [ ] SIGKILL after claim but before bind; reopen in a fresh worker and prove no unauthorized claim retry.
- [ ] SIGKILL during execution after durable in-flight checkpoint; prove no implicit replay.
- [ ] SIGKILL after effect-ledger DISPATCHED and before handler outcome; preserve the ambiguous ledger state.
- [ ] SIGKILL after evidence-chain append; verify committed evidence/hash chain and no duplicate execution.
- [ ] SIGKILL after terminal MissionStore commit but before queue completion; prove recovery recognizes terminal state.

## Task 3: Independent-worker and stale-writer races

- [ ] Start two distinct supervised worker processes simultaneously against one queue; assert exactly one durable claim and at-most-once dispatch.
- [ ] Hold an old worker across lease/generation retirement, let a new worker claim, then release the old worker; prove every stale mission/queue/effect write is rejected and the new claim is unchanged.

## Task 4: Ambiguous-effect restart and Owner authority

- [ ] Kill after the local ledgered side effect has committed but before a terminal outcome is recorded; restart and prove the effect remains ambiguous, is not replayed, and the local side-effect count remains one.
- [ ] Revoke the pre-crash Owner session and reject its resume; create a fresh active test Owner session, reauthorize through MissionService, and prove only the exact renewed snapshot can requeue.
- [ ] Map test assertions to the relevant V0–V9 durability/fence/evidence/effect boundaries; do not treat exception failpoints as process-death coverage.

## Task 5: Phase gates and checkpoint

- [ ] Run the process-death matrix repeatedly, then the full repository suite; preserve exact exit codes, signal, and durable post-crash state.
- [ ] Run compileall, py_compile, diff hygiene, dispatch/recovery/worker-ID static scans, secret-pattern scan, protected-ref comparison, and an independent read-only review.
- [ ] Commit V10 helper/tests and any narrowly required runtime/CLI fix locally; update `docs/M3_STATE.md` and preserve `main`/M2D.
- [ ] Keep all remote pushes and production deployment withheld; V6 Cloudflare production-associated check remains unresolved.
