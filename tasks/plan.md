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


## V10 execution record

- Local implementation checkpoint: `28a24ed8911471a16461dea668e1a7cab9a9f109`.
- Local real-process harness/matrix checkpoint: `cc708643fe71d89d05c1e9df1a1b2eddacd39e1e`.
- Ten required process-death scenarios passed within a 15-test suite on three consecutive runs; final full regression: **946 passed, 1 skipped**.
- Independent-review cleanup finding was closed: no SQLite post-death checks run unless every child has been successfully waited/reaped. Negative tests cover wrong executable, non-temp DB, and reap timeout.
- Local protected refs stayed unchanged; remote main/M2D remain unchanged. Remote M3 remains at V6; no push/deploy or hosted CI claim. See `docs/M3_STATE.md` for full evidence and external-status disposition.

## V11 — Provider/tool hardening integrated with fence and effect ledger

### Objective

Treat provider responses and model-proposed tool calls as bounded, untrusted input. Reject malformed, oversized, stale, or schema-invalid proposals before a model turn is persisted or any tool/effect-ledger dispatch can begin. Preserve the existing Owner authorization, ExecutionFence, external-effect ambiguity, and no-automatic-replay contracts.

### Source findings

- `OpenAICompatibleProvider._request()` currently calls `response.read()` without a byte limit before JSON parsing. Typed, legacy, and router normalization reject several malformed shapes but do not impose shared byte/text/call-count limits.
- `ToolSpec.input_schema` advertises `additionalProperties: false`, but `ToolSpec.validate()` validates only the extracted scalar argument. The strict mission loop reads `proposal.arguments['query']` and can ignore extra keys; `MissionRuntime` currently records the model turn and may create an in-flight parallel checkpoint before every proposal has passed one complete schema preflight.
- `RuntimeLimits` already defines context/result/tool/output budgets (`max_context_chars=32000`, `max_result_chars=4000`, `max_tool_calls=10`, `max_same_tool_calls=5`, `max_total_output_chars=8000` by default); `tools.registry.MAX_ARG_LENGTH` is 256. MissionRuntime uses context compaction but does not currently enforce the complete tool-call budget at its dispatch boundary.
- The canonical `ToolRegistry` reserves and writes the external-effect ledger before dispatch and marks successful outcomes afterward. V11 must reject invalid *input* before reservation, and any post-dispatch bound/serialization failure must retain the existing succeeded/ambiguous durable outcome rather than enabling replay.

### Contract and architecture decisions

1. Add an immutable provider-body ceiling of **1 MiB** at the HTTP read boundary (read at most limit + 1 bytes to detect overflow). Apply the same bounded response contract to typed and legacy adapters, independent of provider-declared `Content-Length` or configurable Owner values.
2. Bound provider text and turn/tool-call metadata using both existing `RuntimeLimits` and hard ceilings: assistant text no more than the existing 32,000-character context maximum, tool calls per mission/turn no greater than the existing default 10, same-tool calls no greater than the existing default 5, and tool arguments must match their exact registered schema and existing 256-character scalar limit. Lower Owner Policy limits remain authoritative; policy changes must not raise the hard ceilings.
3. Preflight the complete model turn before adding it to durable progress, emitting accepted proposal events, writing an in-flight checkpoint, or calling the registry. If any proposal in one returned batch is malformed, unknown, oversized, or has an invalid schema/identity, reject the whole batch with a redacted typed `INVALID_MODEL_RESPONSE` failure and prove zero handler calls and zero effect-ledger rows/events. A valid but individually unauthorized proposal remains an authorization denial; it does not gain authority from batch membership.
4. Bound durable tool observations and total model-visible output to the existing result/output budgets. Preserve a compact digest/length/explicit-truncation record when required; do not treat truncation as proof of success or failure, and never overwrite a known effect outcome or silently replay a dispatched operation.
5. Add no provider/service infrastructure, dependencies, credentials, live provider calls, or deployment changes. The canonical strict registry and existing fence/effect ledger remain the sole dispatch path.

### Ordered tasks and acceptance

1. **Provider ingress limits** — enforce the body-byte ceiling before JSON parsing and add adversarial fake-transport tests for exact-boundary, overflow, missing/incorrect length metadata, malformed JSON, and redacted failure behavior. Files: `agent/providers.py`, `agent/provider_api.py`, `tests/test_v12_provider_failure_boundary.py`.
2. **Shared response/model-turn validation** — make typed, legacy, and router-normalized responses share text, usage, tool-count, call-name/ID, and argument-size limits; reject duplicate IDs and malformed turns before orchestration. Tests cover direct `ProviderResponse`, legacy dict, OpenAI-compatible payload, and custom `NativeModel` values. Files: `agent/provider_api.py`, `agent/model_router.py`, `agent/model_protocol.py`, provider-boundary tests.
3. **Exact registered tool-input contracts** — enforce each `ToolSpec.input_schema` at runtime, including no extra/missing properties, registered tool names, `None`-argument tools, and the 256-character scalar cap. Apply the same contract before the alternate `AgentTaskRuntime` parser flattens arguments, and keep provider-facing schema copies detached from canonical registry state. Add positive/negative tests for all current tool argument forms. Files: `tools/registry.py`, `agent/task_runtime.py`, `tests/test_v11_provider_tool_hardening.py`, and focused registry/fence tests.
4. **Atomic turn and cumulative-budget preflight** — enforce per-mission/per-turn Owner Policy budgets with immutable ceilings, validate all proposals before persistence/checkpoint/dispatch, and prove a valid state-writing proposal paired with one malformed sibling creates no handler call, evidence, in-flight checkpoint, or ledger reservation. Preserve valid sequential/parallel behavior and per-proposal authorization semantics. Files: `agent/mission_runtime.py`, focused native-model tests, and a V11 adversarial test module.
5. **Bounded result persistence** — ensure tool observations and total output persisted to MissionStore/provider context obey the existing result/output budgets while retaining a deterministic digest and the exact external-effect state; test an oversized successful result and verify no replay after restart. Files: MissionRuntime/context boundary and focused effect-ledger integration tests; update the ledger only if source evidence shows the current hash path itself needs bounded streaming.
6. **V11 verification/checkpoint** — focused adversarial suite, complete repository regression, `compileall`, targeted `py_compile`, diff/secret/static dispatch/fence/effect scans, protected-ref comparison, and independent read-only review. Commit locally and update the state ledger; do not retry a remote push or deploy while external prerequisites remain unresolved.

### Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Provider libraries return arbitrarily large bodies or nested JSON | Memory/CPU amplification before validation | Enforce the byte ceiling while reading, then shared typed validation before model-loop use |
| One valid sibling executes before another sibling's malformed schema is noticed | Partial unauthorized or unintended side effects | Whole-turn preflight before durable turn/checkpoint/effect reservation; adversarial mixed-batch test asserts zero dispatch |
| Output bounding is applied after a side effect | False failure or duplicate replay | Preserve the authoritative effect-ledger outcome, store only bounded digest/metadata, and require reconciliation for genuinely ambiguous outcomes |
| Existing tests rely on loose legacy proposal shapes | Compatibility regressions | Inventory fixtures, update only test-only adapters to the explicit contract, and retain additive provider/tool API behavior where safe |

### Phase gate

V11 is complete only when oversized/malformed provider data and tool proposals fail closed across every production adapter; all current tool schemas are enforced before dispatch; no-effect assertions pass for malformed mixed batches; successful effects remain durable and non-replayed when outputs are bounded; the full local suite and independent review pass; and the local checkpoint is recorded without protected-ref changes or remote writes.
