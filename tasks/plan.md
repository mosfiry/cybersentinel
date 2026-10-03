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
- `RuntimeLimits` already defines context/result/tool/output/step/time budgets (`max_context_chars=32000`, `max_result_chars=4000`, `max_tool_calls=10`, `max_same_tool_calls=5`, `max_execution_steps=20`, `max_execution_time_seconds=300`, `max_total_output_chars=8000` by default); `tools.registry.MAX_ARG_LENGTH` is 256. The current mission loop does not enforce several of these at its provider or parallel dispatch boundaries.
- `AgentTaskRuntime._guard_call` treats `max_tool_calls` as cumulative but counts repeated exact `(name, arguments)` signatures. That permits a model to evade `max_same_tool_calls` by varying arguments to the same expensive tool. V11 will interpret the Owner field literally as a per-tool-name count across all arguments and turns; values above defaults remain Owner-configurable. The provider response retains its separate immutable 10-calls-per-response ceiling.
- `ContextAssembler.build(max_chars=...)` defaults to 24,000 but accepts an explicit target. MissionRuntime must pass and enforce the exact Owner-configured `max_context_chars` for model input; 32,000 is a separate provider-returned assistant-text limit. The supported long-horizon fixture uses a 64,000-character Owner input-context setting.
- MissionRuntime's `max_turns` argument is currently caller-controlled and not clamped to `max_execution_steps`; it also does not charge model text/tool results against `max_result_chars` or `max_total_output_chars`, and parallel dispatch does not preflight remaining steps or propagate a time/result budget to each worker.
- The canonical `ToolRegistry` reserves and writes the external-effect ledger before dispatch and marks successful outcomes afterward. Any post-dispatch output bound/serialization failure must retain the existing succeeded/ambiguous durable outcome, store a bounded digest/summary, and never enable replay.

### Contract and architecture decisions

1. Add an immutable provider-body ceiling of **1 MiB** at the HTTP read boundary (read at most limit + 1 bytes to detect overflow). Apply the same bounded response contract to typed and legacy adapters, independent of provider-declared `Content-Length` or configurable Owner values.
2. Bound provider text and turn/tool-call metadata using both existing `RuntimeLimits` and hard ceilings: assistant text no more than 32,000 characters and provider tool calls no more than 10 per response. Mission-wide `max_tool_calls` counts every accepted call; `max_same_tool_calls` counts each tool name across distinct arguments and turns, using the configurable Owner values (defaults 10 and 5) without an invented lower cap. Clamp persistent model-turn consumption to `max_execution_steps`; count turns from durable progress across restarts. Context input enforces exactly Owner `max_context_chars`; the 24,000 value is only an assembler compaction default. Enforce an Owner monotonic execution deadline with checks before/after provider calls and before dispatch. Every native proposal must echo exact `mission_id`, `run_id`, `turn_id`, and `plan_version`; runtime derives `action_id`, binds request/step/auth/scope identity from trusted state, and rejects supplied mismatches. Provider/model/capability provenance must match the selected configured adapter; direct NativeModels cannot assert provider labels. Tool arguments must match exact registry schemas and the 256-character scalar limit.
3. Preflight the complete model turn before adding it to durable progress, emitting accepted proposal events, writing an in-flight checkpoint, or calling the registry. Reject the complete model-call proposal list unless every provider-facing definition exactly equals the canonical registry schema; reject duplicate/unknown/malformed definitions before calling the model. If any proposal in one returned batch is malformed, unknown, oversized, or has an invalid schema/identity, reject the whole batch with a redacted typed `INVALID_MODEL_RESPONSE` failure and prove zero handler calls and zero effect-ledger rows/events. A valid but individually unauthorized proposal remains an authorization denial; it does not gain authority from batch membership.
4. Bound every durable tool result/observation to `max_result_chars` and cumulative model-visible assistant/tool output to `max_total_output_chars`. Stream-measure and hash serialized results; when a completed effect's output exceeds its bound, persist a compact digest/length/explicit-truncation record, do not add completion evidence from truncated content, preserve the effect ledger's succeeded/ambiguous state, and block further model/side-effect work as appropriate. Recompute usage from durable progress after restart.
5. Add no provider/service infrastructure, dependencies, credentials, live provider calls, or deployment changes. AgentCore, MissionRuntime, and AgentTaskRuntime must share registry-derived provider schemas. `RouterNativeModel` must reject unsupported native tool-calling by default; any generate-mode fallback is available only by explicit opt-in and must retain its capability provenance. The canonical strict registry and existing fence/effect ledger remain the sole dispatch path.

### Ordered tasks and acceptance

1. **Provider ingress limits** — enforce the body-byte ceiling before JSON parsing and add adversarial fake-transport tests for exact-boundary, overflow, missing/incorrect length metadata, malformed JSON, and redacted failure behavior. Files: `agent/providers.py`, `agent/provider_api.py`, `tests/test_v12_provider_failure_boundary.py`.
2. **Shared response/model-turn validation** — make typed, legacy, and router-normalized responses share text, usage, tool-count, call-name/ID, and argument-size limits; reject duplicate IDs and malformed turns before orchestration. Tests cover direct `ProviderResponse`, legacy dict, OpenAI-compatible payload, and custom `NativeModel` values. Files: `agent/provider_api.py`, `agent/model_router.py`, `agent/model_protocol.py`, provider-boundary tests.
3. **Exact registered tool-input contracts** — enforce each `ToolSpec.input_schema` at runtime, including no extra/missing properties, registered tool names, `None`-argument tools, and the 256-character scalar cap. Apply the same contract before the alternate `AgentTaskRuntime` parser flattens arguments, and keep provider-facing schema copies detached from canonical registry state. Add positive/negative tests for all current tool argument forms. Files: `tools/registry.py`, `agent/task_runtime.py`, `tests/test_v11_provider_tool_hardening.py`, and focused registry/fence tests.
4. **Atomic turn and Owner-budget preflight** — enforce cumulative total/per-tool call budgets, persistent turn limits, exact Owner context limits, and time budget. Validate canonical provider-facing tool definitions and every proposal before persistence/checkpoint/dispatch. Reject malformed siblings before any effect reservation, and enforce step limits before a sequential or parallel batch. Test changing-argument same-tool evasion, oversized caller `max_turns`, one-message contexts, stale identity, and zero side effects for malformed batches. Files: `agent/mission_runtime.py`, `agent/model_protocol.py`, canonical registry schema builder, and adversarial MissionRuntime tests.
5. **Bounded output/result persistence** — enforce per-result and cumulative output limits across provider text, results, observations, and context. Stream-measure/hash handler output without unbounded JSON duplication; save a compact digest/truncation record after a completed oversized result, avoid claiming verification from truncated content, preserve the exact ledger outcome, and block later model/side-effect work when exhausted. Test across sequential, parallel, and restart paths. Files: MissionRuntime, registry/effect digest only if needed, and focused effect-ledger integration tests.
6. **Parallel/time-budget enforcement** — calculate one Owner monotonic deadline per model-loop slice; propagate remaining timeout into provider and bounded handler paths; preflight step/tool/result capacity before parallel checkpoint or dispatch, and give each worker a capped output allowance. If an already-dispatched worker's outcome cannot be confirmed by the deadline, retain ambiguity and require reconciliation rather than replay. Add slow-worker, parallel step-boundary, and oversized-parallel-result tests.
7. **V11 verification/checkpoint** — focused adversarial suite, complete repository regression, `compileall`, targeted `py_compile`, diff/secret/static dispatch/fence/effect scans, protected-ref comparison, and independent read-only review. Commit locally and update the state ledger; do not retry a remote push or deploy while external prerequisites remain unresolved.

### Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Provider libraries return arbitrarily large bodies or nested JSON | Memory/CPU amplification before validation | Enforce the byte ceiling while reading, then shared typed validation before model-loop use |
| One valid sibling executes before another sibling's malformed schema is noticed | Partial unauthorized or unintended side effects | Whole-turn preflight before durable turn/checkpoint/effect reservation; adversarial mixed-batch test asserts zero dispatch |
| Turn, time, or output budgets are only checked after a provider call or parallel side effect | Unbounded cost, storage, or work; replay ambiguity | Clamp from Owner limits before dispatch, pass remaining deadlines to bounded handlers, persist digest/truncation while preserving ledger state |
| Output bounding is applied after a side effect | False failure or duplicate replay | Preserve the authoritative effect-ledger outcome, store only bounded digest/metadata, and require reconciliation for genuinely ambiguous outcomes |
| Existing tests rely on loose legacy proposal shapes | Compatibility regressions | Inventory fixtures, update only test-only adapters to the explicit contract, and retain additive provider/tool API behavior where safe |

### Phase gate

V11 is complete only when provider/tool inputs, provenance, turn/step/time/output budgets, and all current schemas fail closed across production dispatch paths; malformed mixed batches create no side effects; parallel boundaries are bounded; oversized results retain durable effect outcomes without replay; the full local suite and independent review pass; and the local checkpoint is recorded without protected-ref changes or remote writes.


## V12 — Deployment Target Implementation (COMPLETE; 2026-10-03)

### Source findings verified

- The application entrypoint is `bridge.py`, which uses `http.server.ThreadingHTTPServer`; durable mission processing is a separate supervised process started by `python -m scripts.run_mission_worker`.
- Writable SQLite state is spread across `DB_PATH` and its mission/evidence/queue siblings, task and memory databases, knowledge/scope stores, and mutable Owner policy state. Task, memory, and Owner-policy paths now accept environment overrides while preserving their local defaults; knowledge/scope already had path overrides. Compose maps every identified database/state path under the one persistent volume.
- `core/config.py` intentionally rejects non-loopback bridge binds. A container needs an explicit opt-in to listen on its private interface; Compose must publish the API only on host loopback by default.
- `firebase.json` configures static hosting of `web/` only. No backend domain/project or ingress rewrite is configured. The observed Cloudflare Worker build uses `npx wrangler preview` but fails because its Wrangler configuration has no `previews` block.
- Current official Cloudflare Python docs describe a Pyodide/V8 Worker runtime; `threading` and `multiprocessing` are nonfunctional and the filesystem is ephemeral. This conflicts with the actual threaded HTTP server, separate worker process, and durable SQLite-file design. Do not add `previews: {}` or attempt to force the backend into Workers. References: [Python Workers](https://developers.cloudflare.com/workers/languages/python/), [supported standard library](https://developers.cloudflare.com/workers/languages/python/stdlib/), and [how Python Workers work](https://developers.cloudflare.com/workers/languages/python/how-python-workers-work/).
- Docker's official port-publishing documentation warns that Engine releases older than 28.0.0 may allow same-layer-2 peers to reach localhost-published ports; the runbook therefore requires Engine 28.0.0 or newer and keeps the host mapping on `127.0.0.1`. Reference: [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).

### Architecture decisions

1. Implement a portable single-host OCI/Docker Compose target: one image, a non-root one-shot `workspace-init` service, separate `bridge` and `mission-worker` services, and one stable logical worker. Keep every writable database/policy file and workspace in the existing `cybersentinel-state` volume at the unchanged `/var/lib/cybersentinel/workspace` path. Run the initializer first and wait for successful completion so Docker never concurrently creates the nested working directory for the two services. Keep SQLite rollback-journal files on the same local host; do not scale the worker horizontally or put the state volume on an unverified network filesystem.
2. Keep the bridge loopback-only by default. Container mode may opt in to `0.0.0.0` only with an explicit non-loopback-bind flag and a non-placeholder strong bridge secret; Compose publishes `127.0.0.1:${BRIDGE_PUBLISHED_PORT:-8787}:8787`. Do not configure a public listener, domain, TLS proxy, or production secrets.
3. Use a non-root, read-only-root container with a writable persistent state volume and temporary mount, signal forwarding, restart policy, and liveness health checks. Provide interactive Owner account bootstrap using the existing `security.owner_password_bootstrap` flow; do not treat the unused `OWNER_TOKEN` sample variable as Owner identity.
4. Preserve `firebase.json` and all external service settings. The application image serves the existing frontend and backend together; public Firebase/Cloudflare split routing is not configured because no backend origin/authority is known.
5. Do not deploy. Production host/domain/credentials are unknown, so the production deployment gate remains separate. The local container target and no-provider rehearsal are the implementation/test scope.

### Ordered implementation tasks and acceptance

1. Add environment-overridable paths for task, memory, and Owner policy state stores; preserve existing defaults and verify all stores can initialize under an isolated state directory.
2. Add fail-closed container bind opt-in and bounded graceful SIGTERM/SIGINT shutdown for the bridge; test local defaults, allowed/denied bind cases, and bridge health/shutdown with only a temporary database.
3. Add runtime-only requirements, Dockerfile, `.dockerignore`, and Compose configuration with the existing state volume, serialized workspace initialization, single worker, loopback host publish, required bridge secret, optional provider env passthrough, non-root/read-only hardening, restart behavior, and explicit Owner bootstrap/volume-retention upgrade instructions.
4. Extend existing GitHub Actions CI (no publish/deploy) to build and run the container target, assert API/worker liveness, UID, read-only root, volume mount identity, path-preserving workspace writes, and loopback publish, then restart the worker and verify the same state volume retains monotonically increasing generations. Use only CI-only credentials and an isolated compose project/volume.
5. Run focused tests and the full suite, inspect the Docker build/Compose smoke result on exact pushed SHA `8e84268a4574d697cbde20029d308cd86d9f87f7`, scan secrets/static dispatch paths, obtain independent read-only review, and close the phase. Hosted smoke and audit passed; the known Cloudflare preview-config failure remains read-only and no production deploy occurred.

### Risks and non-goals

| Risk | Impact | Mitigation |
|---|---|---|
| Writable state is split across fixed paths | Read-only images fail or data silently resets on restart | Route every identified DB/state file to the named volume; assert paths in an isolated subprocess test |
| Container bind accidentally becomes public | Exposes an authenticated local-only bridge without ingress hardening | Require an explicit bind opt-in and publish only on host loopback; no public port mapping |
| Cloudflare preview failure tempts a config-only workaround | Produces a green build for an incompatible runtime without fixing the architecture | Record the missing `previews` block, but keep Cloudflare Worker out of the backend target |
| No Docker/Podman engine is installed on the active computer | Local image build cannot be claimed | Verify container build/runtime smoke in the existing GitHub-hosted Linux CI, without pushing an image |
| Bridge and worker concurrently create a nested workspace path in one fresh shared state volume | Docker rejects initial container creation with a `file exists` race | Add a read-only non-root initializer as the sole first creator; gate both services on its successful completion and verify on a new normal exact-SHA CI run |
| Source package omitted from Docker build context | Container starts but runtime module imports fail | Keep tracked app packages such as `workspace/` in the context and verify `from workspace import Workspace` after `USER 10001:10001`; test the ignore rule |
| Production endpoint/authority is absent | Cannot prove or authorize production cutover | Keep `PRODUCTION_DEPLOYMENT_BLOCKED`; continue V13–V16 non-production verification/rehearsal |

## V13 — Reproducible Production-Like End-to-End (in progress; 2026-10-03)

### Scope and design decisions

- Use only temporary state: a loopback-only live bridge, isolated SQLite databases, isolated workspace, a real temporary Owner account/session, real mission HTTP routes, and the production MissionService/MissionQueue/MissionWorker/MissionRuntime/effect-ledger path. Do not use saved production credentials, public listeners, external providers, or network tools.
- Use a fixed explicit two-step plan: `run_project_tests` over a tiny controlled workspace fixture, followed by the local `watch` state-write effect. This supplies deterministic execution, durable evidence, and a local effect-ledger record without external service dependencies.
- Treat a `Finding` as an explicit `FindingClaim` validated by the existing `VerificationEngine` against persisted mission evidence and the isolated fixture. There is no first-class mission Finding-approval API in the current contract; do not invent one for V13.
- Exercise the existing typed Owner approval path for an intentionally ambiguous post-dispatch effect: after verifying the first-step finding, crash a disposable worker after the local effect handler but before effect success is durably recorded; require exact-effect `OWNER_CONFIRM_APPLIED`, then a fresh Owner login/revalidation and resumed completion. This tests the existing authorization/reconciliation contract rather than adding a generic approval endpoint.
- Use a test-only worker child hook guarded by a dedicated argument/environment and temporary DB paths. It may terminate only its own disposable subprocess. Normal execution uses the existing supervised worker entrypoint; the hook is absent from production code.
- Compare deterministic canonical projections across repeated success runs; explicitly normalize only session identifiers and wall-clock metadata that are intentionally generated. Verify hashes and causal links inside each run rather than assuming random identifiers are byte-identical.
- V13 exposed an authorization-history defect: Owner reauthorization replaced the current snapshot needed to inspect an effect dispatched under the earlier snapshot. Preserve prior snapshots in the mission integrity payload, validate their owner/mission/version/time ordering, and bind an effect to the latest snapshot active at its recorded creation time; missing or malformed history fails closed.

### Ordered implementation tasks and acceptance

1. [x] Add a V13 fixture/harness that redirects `DB_PATH`, mission/queue/scheduler sibling stores, and Owner policy state into `tmp_path`; creates the temporary Owner account; serves the bridge only on `127.0.0.1`; and provides bounded HTTP/process cleanup.
2. [x] Traverse Owner login → explicit Owner instruction → authorization snapshot → persisted mission → queue enqueue/claim/fence → real worker execution → evidence/result/effect ledger → verified FindingClaim → `GOAL_COMPLETED`; assert every transition and read it back through Owner-authenticated APIs.
3. [x] Add a real disposable worker-crash case at the local effect transition; verify restart quarantines unresolved work, preserves prior finding evidence, performs no automatic replay, permits only exact typed Owner reconciliation, requires a fresh Owner session, and completes after worker restart with one effect application.
4. [x] Exercise stale-worker (with a deterministic pre-claim barrier), expired-session, worker-restart, ambiguous-effect, and concurrent-worker variants from the same isolated mission setup; assert no stale or unauthorized dispatch, one queue claim, and no duplicate effect.
5. [x] Run the successful scenario repeatedly and compare canonical result/finding/evidence/effect projections; assert every DB, workspace file, and subprocess is isolated and cleaned up.
6. [x] Complete focused/full suites, Python compile, YAML/shell parse, secret/diff hygiene, child cleanup, and independent read-only reviews; no remaining findings.
7. [x] Commit the production recovery fix (`2729fb5`) and live E2E harness (`ac85df7`) as separate local checkpoints; prepare the reviewed phase-ledger update.

### V13 risks and explicit boundaries

| Risk | Impact | Mitigation |
|---|---|---|
| No first-class Finding-approval endpoint exists | A generic approval workflow would invent product behavior and broaden the API | Verify `FindingClaim` from durable mission evidence; use only the existing typed Owner effect-reconciliation decision followed by fresh reauthorization; record this scope boundary in the ledger |
| Owner reauthorization renews the current snapshot while an older effect is still pending | The Owner cannot safely inspect or resolve the existing effect if the historical binding is lost | Persist prior snapshots inside the mission integrity hash; validate identity/version/time order and match the effect to the latest snapshot active at `effect.created_at`; fail closed on absent/malformed history |
| Child crash leaves live lease/effect records | Could poison shared state or cause duplicate dispatch | One test-owned worker subprocess, per-test temp DBs, bounded exit code, restart/recovery assertions, and fixture cleanup; never signal unrelated PIDs |
| Real providers/network could make results nondeterministic | External effects or credential leakage | Use only local `run_project_tests` and `watch`; explicit plan; fail if model/provider routing is invoked |
| Legacy effect rows have an empty Owner identity | Mission identity alone cannot prove which Owner was immutably bound to the effect at creation | New fenced reservations persist the nonempty identity from the validated authorization snapshot; inspection and transition require exact equality; migrated blank-owner rows fail closed and require a separate explicit repair/migration before any cutover |
8. [ ] Non-force push the reviewed commits only to the existing M3 branch and verify exact-SHA CI before V14.
