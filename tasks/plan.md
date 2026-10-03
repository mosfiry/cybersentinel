# Implementation Plan: M3 V10 — Real Process Death and Multi-Process Harness

## Previous checkpoint

V9 is complete on local branch `task/m3-production-runtime-20261003`: implementation `18a25a81619b2e15e2e2f0819e424b806f0392b6`, adversarial tests `c9178fa1ee4e34100457aacff705afbb04af3209`. The latest full suite passed 931 tests with 1 skipped; the V9-specific suite passed 39. Final independent review and static gates are clean. Recurring/cron remains a separately documented blocked sub-capability. Remote pushes remain withheld because the exact-SHA V6 Cloudflare production-associated build result is unresolved. See `docs/M3_STATE.md`.

## V10 objective

Prove durability and fencing with **real OS process death and independent processes**, not only exceptions, monkeypatched rollback callbacks, threads, or `multiprocessing` forks. After each crash, a fresh process must reopen the existing SQLite stores, run strict startup recovery, and prove there was no stale write, unintended dispatch, duplicate side effect, or authority resurrection.

## Source findings

- `scripts/run_mission_worker.py` is the existing supervised process entry point; it uses `RuntimeSupervisor` and `bridge.build_mission_worker()`.
- `bridge.build_mission_worker()` wires the existing AgentCore, strict MissionQueue, MissionScheduler, MissionRuntime, and MissionStore. `MissionWorker` already supports distinct logical `worker_id` values, but the bridge factory and CLI do not currently expose one.
- `DB_PATH` is already environment-configured and production stores derive their existing SQLite paths from it. Child processes can therefore use isolated temporary databases without adding infrastructure or touching the user's real state.
- `tests/test_v9_crash_injection.py` covers in-process failpoint exceptions, and `tests/test_v10_multiworker_adversarial.py` covers threads/forked TaskRuntime and low-level queue claims. Neither proves process death in the supervised mission worker with a fresh process reopening the stores.
- Production tool execution follows `AgentCore._executor -> tools.registry.execute`; the registry writes PLANNED/RESERVED/DISPATCHED/outcome in the durable effect ledger and appends evidence through `EvidenceChainStore`. The existing local `watch` tool is state-changing, ledgered, and performs a local SQLite write, so it can exercise this production boundary without external network or provider credentials.
- Strict worker recovery runs before the first poll. Any process test that needs a newly Owner-authorized queue row must have the worker complete recovery before the parent enqueues it, or must perform a fresh Owner reauthorization after restart.

## Architecture decisions

1. Add an optional `worker_id` argument to the existing `bridge.build_mission_worker()` factory and an additive `--worker-id` CLI option to `scripts/run_mission_worker.py`. Preserve the current default identity (`worker`) and behavior. This exposes the existing worker identity mechanism; it does not add a service, thread, cloud resource, or new persistence system.
2. Add a test-only child-process harness under `tests/`. It imports the production bridge/worker/supervisor stack, uses `DB_PATH` pointing at a `tmp_path`, synchronizes through bounded JSON-line/stdin barriers, and uses real `SIGTERM`/`SIGKILL`. The harness must always enforce timeouts and kill/reap children in cleanup.
3. Create a real temporary Owner account/session through the existing auth store, create an Owner-bound mission through MissionRuntime/MissionService, and reauthorize through the same public control-plane method after restart. Never use the real profile database, network provider, production secret, or persistent user data.
4. Use only narrow test-process barriers after an already-durable boundary (e.g. inside the local `watch` handler after ledger dispatch, after evidence append, or after mission save). A barrier may pause a child; it must not replace a crash with a Python exception or change production ordering. The parent terminates the process with an OS signal and inspects the database from a fresh connection/process.
5. Cover the ten required adversarial cases:
   1. SIGTERM before claim: no claim or dispatch; restart recovery quarantines pending Owner work.
   2. SIGKILL after claim but before mission binding: claim is not reissued without recovery/reauthorization.
   3. SIGKILL during tool execution after the in-flight checkpoint: no implicit replay.
   4. SIGKILL after durable effect `DISPATCHED` and before provider/handler outcome: ambiguous effect remains quarantined.
   5. SIGKILL after durable evidence append: evidence remains valid and no duplicate action occurs.
   6. SIGKILL after terminal MissionStore commit but before queue completion/ack: restart recognizes terminal state and does not re-execute.
   7. Two independent worker processes race for one mission: exactly one claim/dispatch wins.
   8. An old worker returns after its lease/generation is retired and a new worker claims: stale completion cannot overwrite the current generation or state.
   9. Restart after an ambiguous effect has actually applied its local side effect: ledger stays ambiguous, the side effect count remains one, and the worker does not replay it.
   10. Owner reauthentication after restart: an old/revoked session fails; a new active Owner session renews the bound snapshot before requeue, with no background resurrection.
6. Preserve and run the existing V0–V9 crash-failpoint and regression suites. Do not broaden this phase into deployment, public service settings, or real-provider configuration.

## Verification

For every scenario, record the exact process exit/signal and inspect MissionStore, queue, effect history, and evidence chain only after the child has died. Verify the stores remain in rollback-journal mode and are reopenable; verify old process handles cannot mutate a newer worker generation. Assert no effect/tool handler is called unless the scenario explicitly authorizes it, and assert it is called at most once when an effect has already applied.

Run the focused subprocess matrix repeatedly to detect races, then the full repository suite, `compileall`, `py_compile`, `git diff --check`, static dispatch/recovery/worker-ID scans, changed-source credential-pattern scan, protected-ref comparison, and an independent read-only review. Commit tests/helper separately from any required runtime/CLI fix, then checkpoint the phase record. Do not push or deploy.

## Checkpoint gate

V10 is complete only when all ten real-process cases pass repeatedly, the complete regression suite passes, review findings are closed, the local checkpoint is clean, and `main`/M2D remain unchanged. Any specific case that is genuinely blocked must be recorded separately while the other cases continue; no Python exception-only substitute counts as process-death evidence.
