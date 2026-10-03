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

### Task 4: Whole-turn and Owner-budget preflight

- [x] Apply Owner-configured cumulative `max_tool_calls` and per-tool-name `max_same_tool_calls` across all argument values and turns (not per exact signature), preserving supported Owner increases; align AgentTaskRuntime's counter semantics.
- [x] Clamp `max_turns` to the Owner's `max_execution_steps`, count accepted turns from durable history across restarts, and block before another provider call at the limit.
- [x] Enforce one monotonic `max_execution_time_seconds` deadline per model-loop slice; check before/after provider calls and before dispatch, and pass remaining time into router/provider and tool execution.
- [x] Require exact, nonempty `mission_id`, `run_id`, `turn_id`, and `plan_version` on native proposals; derive `action_id` from mission/turn/call identity, bind request/step/auth/scope from trusted state, and reject supplied mismatches.
- [x] Enforce the actual assembled message count against the exact Owner limit with no hardcoded two-message minimum; prove one message is accepted when one is configured and the assembled request fits, and preserve the long-horizon run under an explicit supported 64K Owner input-context budget.
- [x] Bind nonempty provider/model/capability provenance to the configured router adapter; reject arbitrary or mismatched labels before durable turn recording.
- [x] Require supplied provider-facing tool definitions to equal the canonical registry schemas exactly; reject altered, duplicate, unknown, or extra-metadata definitions before calling the model.
- [x] Disable silent `CapabilityUnsupported` → `generate` fallback by default; permit only an explicit opt-in and persist the actual capability used.
- [x] Preflight every sibling against remaining Owner step/tool/time/result budgets before durable turn/proposal events, in-flight checkpoints, or effect-ledger reservations; give parallel workers bounded deadlines and result allowances.
- [x] Prove a valid state-writing call paired with one malformed sibling causes no handler call, evidence append, checkpoint, or ledger event; retain per-call authorization denials for structurally valid proposals.

### Task 5: Bounded tool-result persistence

- [x] Enforce `max_result_chars` per serialized observation/result and `max_total_output_chars` across accepted model text plus tool results; recompute usage from persisted progress after restart.
- [x] Stream-measure/hash raw handler results, then persist only bounded output or a compact digest/length/truncation summary; reject/block before dispatch when a result record cannot fit at all.
- [x] If a completed side effect has oversized output, preserve the effect ledger's exact outcome, do not add success evidence based on truncated content, save the summary, and block later work as appropriate.
- [x] Test cumulative model text, oversized sequential/parallel results, storage bounds, and restart/no-replay behavior.

### Task 6: Parallel/time-budget enforcement

- [x] Prove parallel batches cannot exceed remaining call/step/time/output allowances; no worker starts after deadline or when its bounded result slot cannot be persisted.
- [x] Test slow/timed-out workers and step-boundary batches; ambiguous post-dispatch outcomes remain recovery-required and cannot be replayed.

### Task 7: V11 verification and checkpoint

- [x] Run focused provider/tool adversarial tests, then the complete repository suite.
- [x] Run compileall, targeted py_compile, diff/secret/static bypass scans, protected-ref comparison, and independent read-only review.
- [x] Commit the V11 implementation/tests locally and update `docs/M3_STATE.md`; do not retry remote writes or deploy without new authorization and all external safeguards.


## V12 Implementation Checklist — Deployment Target

### Task 1: Source-compatible target decision

- [x] Inspect the bridge, supervised mission worker, SQLite stores, runtime defaults, existing static-host configuration, and current Cloudflare build evidence.
- [x] Verify official Cloudflare Python runtime limitations against the actual thread/process/filesystem needs; reject a Worker backend and do not alter external Cloudflare settings.
- [x] Select a host-agnostic, single-machine container model; keep production hosting blocked until an exact authorized host is known.

### Task 2: Durable container state and bind safety

- [x] Make task, memory, and Owner-policy state paths environment-overridable while preserving local defaults; route all production writable stores to one persistent state volume.
- [x] Keep loopback the default bind; allow container-interface binding only with an explicit opt-in and a non-placeholder strong bridge secret.
- [x] Add regression tests for default/invalid/explicit bind cases and isolated state-path initialization.

### Task 3: Container and operations configuration

- [x] Add a non-root Python 3.12 runtime image, a `.dockerignore` that excludes credentials, local DBs, caches, tests, and diagnostics, and a runtime-only dependency file.
- [x] Add Compose services for the HTTP bridge and one supervised worker, sharing the named state volume; bind the host port to 127.0.0.1, disable public web mode by default, and pass provider secrets only as runtime environment.
- [x] Configure read-only root, writable state/workspace and `/tmp` mounts, process initialization, restart policy, bounded stop grace, log rotation, and liveness checks.
- [x] Require Docker Engine 28.0.0+ for the documented localhost-publish boundary and link its upstream version caveat.
- [x] Document interactive Owner-password bootstrap, safe start/stop/restart/health commands, state-volume retention/backup cautions, and no production public-ingress claim.

### Task 4: Lifecycle and CI verification

- [x] Test bridge health, active-request drain, and graceful SIGTERM using a disposable child process and temporary DBs only; prove cleanup and reopened state.
- [ ] Extend the existing GitHub Actions workflow to build/run the container without publishing; verify bridge/worker health, worker restart/generation advancement, and state-volume persistence.
- [x] Run focused tests and the full local suite; 1,027 passed and 1 skipped after an isolated retry of one intermittent V10 child-identity failure.
- [ ] Inspect exact-SHA GitHub checks and the related Cloudflare check, with no redeploy/rebuild retry or service-setting mutation.
- [x] Obtain an independent read-only review; after Compose corrections, it found no remaining actionable V12 issue.
- [ ] Record the unavailable local Docker engine, inspect exact-SHA CI/external checks, update `docs/M3_STATE.md`, and checkpoint V12 before starting V13.

### V12 guardrails

- [x] No production deployment, public host bind, domain/project/secret invention, Cloudflare setting change, or Firebase rewrite.
- [x] No worker horizontal scaling or shared network-filesystem SQLite assumption.
- [x] Keep the existing frontend/static configuration and M3 protected branches unchanged.

### Preliminary V12 evidence (2026-10-03)

- [x] Focused V12 bridge/state/shutdown, API-boundary, supervisor, and V10 process-death regression set: 62 passed.
- [x] Modified Python modules pass `py_compile`.
- [x] Full repository suite: 1,027 passed, 1 skipped. One prior V10 child-PID identity check failed in a full run, then passed in isolation and on the complete rerun.
- [ ] Docker Compose build/restart smoke on GitHub CI and exact-SHA external checks remain pending; no local Docker engine is installed.
- [x] Independent re-review after the Compose fixes: no remaining actionable findings.
