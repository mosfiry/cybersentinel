# V10 Implementation Checklist — Real Process Death and Multi-Process Harness

## Task 1: Process-test contract and bounded harness

- [x] Re-read the original V10 requirements and map current production worker, supervisor, SQLite, Owner-session, evidence, and external-effect call paths.
- [x] Confirm existing V9 crash coverage is failpoint-based and current multi-worker tests do not kill supervised mission-worker processes.
- [x] Add an optional stable logical `worker_id` to the existing bridge worker factory and supervised CLI, preserving the current default.
- [x] Create a test-only subprocess harness using `Popen`, isolated `DB_PATH`, JSON-line/stdin barriers, timeouts, real signals, and unconditional child cleanup.
- [x] Ensure all test processes use only temporary rollback-journal databases and local deterministic handlers; make no network/provider calls.

## Task 2: Real process-death cases at durability boundaries

- [x] SIGTERM before claim; prove no claim/effect, then prove restart recovery quarantines pending Owner work.
- [x] SIGKILL after claim but before bind; reopen in a fresh worker and prove no unauthorized claim retry.
- [x] SIGKILL during execution after durable in-flight checkpoint; prove no implicit replay.
- [x] SIGKILL after effect-ledger DISPATCHED and before handler outcome; preserve the ambiguous ledger state.
- [x] SIGKILL after evidence-chain append; verify committed evidence/hash chain and no duplicate execution.
- [x] SIGKILL after terminal MissionStore commit but before queue completion; prove recovery recognizes terminal state.

## Task 3: Independent-worker and stale-writer races

- [x] Start two distinct supervised worker processes simultaneously against one queue; assert exactly one durable claim and at-most-once dispatch.
- [x] Hold an old worker across lease/generation retirement, let a new worker claim, then release the old worker; prove every stale mission/queue/effect write is rejected and the new claim is unchanged.

## Task 4: Ambiguous-effect restart and Owner authority

- [x] Kill after the local ledgered side effect has committed but before a terminal outcome is recorded; restart and prove the effect remains ambiguous, is not replayed, and the local side-effect count remains one.
- [x] Revoke the pre-crash Owner session and reject its resume; create a fresh active test Owner session, reauthorize through MissionService, and prove only the exact renewed snapshot can requeue.
- [x] Map test assertions to the relevant V0–V9 durability/fence/evidence/effect boundaries; do not treat exception failpoints as process-death coverage.

## Task 5: Phase gates and checkpoint

- [x] Run the process-death matrix repeatedly, then the full repository suite; preserve exact exit codes, signal, and durable post-crash state.
- [x] Run compileall, py_compile, diff hygiene, dispatch/recovery/worker-ID static scans, secret-pattern scan, protected-ref comparison, and an independent read-only review.
- [x] Commit V10 helper/tests and the narrowly required runtime/CLI identity change locally; update `docs/M3_STATE.md` and preserve `main`/M2D.
- [x] Keep all remote pushes and production deployment withheld; V6 Cloudflare production-associated check remains unresolved.

## V11 Implementation Checklist — Provider/Tool Hardening

### Task 1: Provider ingress limits

- [x] Define an immutable 1 MiB response-body ceiling and enforce it while reading, before JSON parsing.
- [x] Add fake-transport tests for boundary, overflow, misleading/missing content-length, malformed JSON, and redacted failure behavior.

### Task 2: Shared provider/model response contract

- [x] Apply text, call-count, identifier, usage-metadata, and argument-size limits consistently to OpenAI-compatible, typed, legacy, router, and NativeModel paths.
- [x] Reject duplicate/malformed model-turn identities before a mission turn is recorded.
- [x] Preserve typed `INVALID_MODEL_RESPONSE` handling without provider-secret/body leakage or silent fallback.

### Task 3: Exact tool-input schema enforcement

- [x] Enforce registered `ToolSpec` input shapes exactly at registry execution and `AgentTaskRuntime` parse boundaries, including extra/missing keys and `None`-argument tools.
- [x] Test unknown tools, malformed/oversized queries, and extra properties against the same production registry path.
- [x] Keep provider-facing schema definitions copy-isolated from canonical registry state.

### Task 4: Whole-turn and cumulative-budget preflight

- [ ] Apply Owner-configured cumulative `max_tool_calls` and exact-repeat signature budgets without inventing a lifetime cap below supported Owner settings; keep the provider's 10-calls-per-response and existing context-assembler ceilings, and enforce lower Owner context limits.
- [ ] Preflight every sibling before durable turn/proposal events, in-flight checkpoints, or effect-ledger reservations.
- [ ] Prove a valid state-writing call paired with one malformed sibling causes no handler call, evidence append, checkpoint, or ledger event; retain per-call authorization denials for structurally valid proposals.

### Task 5: Bounded tool-result persistence

- [ ] Bound per-result and total output persisted to MissionStore/provider context using existing result/output budgets.
- [ ] Preserve deterministic digest/truncation provenance and the exact durable external-effect outcome.
- [ ] Test oversized successful results and restart behavior to prove no ambiguous operation is replayed.

### Task 6: V11 verification and checkpoint

- [ ] Run focused provider/tool adversarial tests, then the complete repository suite.
- [ ] Run compileall, targeted py_compile, diff/secret/static bypass scans, protected-ref comparison, and independent read-only review.
- [ ] Commit the V11 implementation/tests locally and update `docs/M3_STATE.md`; do not retry remote writes or deploy without new authorization and all external safeguards.
