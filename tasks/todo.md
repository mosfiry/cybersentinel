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

- [x] Make task, memory, and Owner-policy state paths environment-overridable while preserving local defaults; route all production writable stores to a persistent local state volume.
- [x] Keep loopback the default bind; allow container-interface binding only with an explicit opt-in and a non-placeholder strong bridge secret.
- [x] Add regression tests for default/invalid/explicit bind cases and isolated state-path initialization.

### Task 3: Container and operations configuration

- [x] Add a non-root Python 3.12 runtime image, a `.dockerignore` that excludes credentials, local DBs, caches, tests, and diagnostics, and a runtime-only dependency file.
- [x] Add Compose services for a non-root one-shot workspace initializer, HTTP bridge, and one supervised worker using the existing single state volume/path; bind the host port to 127.0.0.1, disable public web mode by default, and pass provider secrets only as runtime environment.
- [x] Configure read-only roots, one-time path initialization, writable state and `/tmp` mounts, restart policy, bounded stop grace, log rotation, and liveness checks.
- [x] Require Docker Engine 28.0.0+ for the documented localhost-publish boundary and link its upstream version caveat.
- [x] Document interactive Owner-password bootstrap, safe start/stop/restart/health commands, state-volume retention/backup cautions, and no production public-ingress claim.

### Task 4: Lifecycle and CI verification

- [x] Test bridge health, active-request drain, and graceful SIGTERM using a disposable child process and temporary DBs only; prove cleanup and reopened state.
- [x] Extend the existing GitHub Actions workflow to build/run the container without publishing and assert bridge/worker health, UID, read-only root, shared-volume identity, workspace writes, and loopback host binding, plus worker restart/generation persistence.
- [x] Fix the exact-SHA 52b2803 first-start race (`_data/workspace: file exists`) with a non-root serialized initializer completed before either service; retain the existing workspace path and files.
- [x] Verify bridge/worker health, UID/read-only/mount/loopback contract, workspace writes, and worker generation advancement on exact SHA `8e84268a4574d697cbde20029d308cd86d9f87f7`; hosted smoke passed.
- [x] Run focused tests and the full local suite after the Docker source-inclusion correction: V12 suite 22 passed; full suite 1,040 passed, 1 skipped.
- [x] Inspect exact-SHA GitHub and Cloudflare checks read-only. SHA `52b2803924e9f88af7c0513d03e5f2e62baf76ee`: audit passed; test failed before service startup at the known workspace-volume `file exists` race; Cloudflare check `111242158919` failed for the known missing Wrangler `previews` block; no preview or setting change.
- [x] Inspect current exact-SHA run `37138760819` on `bc65e8272f9b230f428060a11fa998962fdc0258`: audit passed, compileall/pytest passed, but container smoke failed because `.dockerignore` omitted tracked `workspace/` source; the earlier `file exists` race did not recur.
- [x] Recheck Cloudflare build `aefd2931-0b83-4ddc-b961-5516e75ad5a8` read-only: status `stopped`; logs confirm missing Wrangler `previews` block; no changes made.
- [x] First independent review found no critical/high findings, one medium false-positive health probe and a low same-volume symlink TOCTOU; exact init-child/worker-ID matching, fake-`/proc` negatives, CI health waiting, and an explicit trust-boundary caveat address them.
- [x] Second independent review found stopped/traced (`T`/`t`) processes could still appear healthy; restrict accepted states to `R`/`S`/`D` and add parameterized regression cases.
- [x] Further independent review found suffix-only argv comparison; require exact full Compose argv and add wrong-executable, changed-poll-interval, and extra-argument negatives.
- [x] Final independent review of the prior exact-argv snapshot confirmed command identity and corrected the LOW stale two-volume operations sentence.
- [x] Independent read-only review of the current `.dockerignore`/Dockerfile correction found no material issues; the static guard is not a live image build, so exact-SHA CI remains required.
- [x] Confirm local Docker Engine is unavailable (no Docker binary); do not claim a local container smoke test.
- [x] Commit and push the reviewed source-inclusion correction non-force to the existing M3 branch; exact SHA `8e84268a4574d697cbde20029d308cd86d9f87f7` is the remote head and hosted smoke passed before V13.

### V12 guardrails

- [x] No production deployment, public host bind, domain/project/secret invention, Cloudflare setting change, or Firebase rewrite.
- [x] No worker horizontal scaling or shared network-filesystem SQLite assumption.
- [x] Keep the existing frontend/static configuration and M3 protected branches unchanged.

### V12 current evidence (2026-10-03)

- [x] Final V12 bind/store/bridge-shutdown/workspace-initializer, source-inclusion, and exact-worker-health tests: 22 passed; adjacent API-boundary, supervisor, and V10 process-death regression set: 62 passed in the earlier focused regression.
- [x] Modified Python modules pass `py_compile`.
- [x] Full repository suite after the Docker source-inclusion correction: 1,040 passed, 1 skipped (29.82 seconds). One earlier full attempt failed before signal at the V10 child-PID identity guard; `/proc` inspection found no live harness child, the case passed in isolation, and the full rerun passed.
- [x] GitHub audit on exact SHA `52b2803924e9f88af7c0513d03e5f2e62baf76ee` succeeded.
- [x] Container smoke on that SHA built the image but failed at simultaneous first creation of the nested workspace path in the shared volume; a non-root one-shot initializer now creates that existing path before the bridge/worker.
- [x] Cloudflare build for the same SHA failed at `npx wrangler preview` due missing `previews` configuration; no preview artifact was produced.
- [x] Final exact-SHA V12 run `37139297002` on `8e84268a4574d697cbde20029d308cd86d9f87f7` passed compileall, pytest, Compose build/health, UID 10001, read-only root, shared mount/workspace writes, loopback publish, and worker generations 1→2→3; no local Docker engine is installed. The trusted-volume TOCTOU remains documented.

- [x] Final exact-SHA audit run `37139297065` / check `111250214581` passed; V12 tests run `37139297002` / check `111250214523` passed. The earlier race and omitted-source failures are historical and did not recur on this final SHA.
- [x] Reverify Cloudflare Workers Builds check `111250300538` read-only: build `54f66543-87fe-45aa-967e-31a73dacd405` stopped at the known missing Wrangler `previews` block; no Cloudflare setting/resource changed.
- [x] Confirm remote M3 head equals V12 SHA `8e84268a4574d697cbde20029d308cd86d9f87f7`; protected `main=8a3fd109c0e586db13ed48a7371ac9ad06465b74` and M2D `task/m2d-cutover-20261002=9bf91ea37748a239e6a6e3b6327706fa614232cd` unchanged; no production deployment/public bind.

### V13 — Reproducible production-like E2E (complete)

- [x] Build an isolated harness using a loopback-only live bridge, temporary SQLite/state/workspace paths, a real temporary Owner login, real mission HTTP routes, and production worker/queue/runtime classes; fail on any provider call.
- [x] Run the deterministic two-step Owner mission (`run_project_tests` plus local `watch`), assert the snapshot, queue/fence, persisted evidence/effect/result, verified `FindingClaim`, completion, and Owner-authenticated API readback.
- [x] Use a bounded disposable worker crash after local effect application but before its success transition; assert restart quarantine, ambiguous effect visibility, no auto-replay, exact typed Owner reconciliation, fresh Owner login/revalidation, and one effect at completion.
- [x] Cover stale worker generation with a barrier proving generation 1 attempts only after generation 2 is registered; it cannot claim or dispatch. Cover expired-session denials and competing workers claiming/applying once.
- [x] Run repeated successful scenarios and compare canonical result projections; all test-owned DBs, files, and subprocesses are isolated under each temporary root.
- [x] V13 revealed a real recovery bug: Owner reauthorization replaced the snapshot required to inspect an already-dispatched effect. Persist snapshots in the mission integrity payload and match the effect digest to the latest valid snapshot active at `effect.created_at`; malformed, missing, wrong-owner, and wrong-time history fails closed.
- [x] Focused V13 E2E: 4 passed; effect reconciliation: 40 passed; full suite: 1,048 passed, 1 skipped.
- [x] First independent security review found that legacy rows with an empty effect Owner identity could be inspected/approved by deriving the mission Owner; both paths now require exact nonempty identity equality, and legacy blank-owner rows fail closed without mutation. New fenced reservations persist the Owner identity from the authorization snapshot.
- [x] Final independent review confirmed strict Owner binding and snapshot-history validation; its low crash-projection concern was fixed by deriving approval status, Owner event count, dispatch count, and uniqueness from the HTTP response and post-resume ledger history. No remaining finding; focused/full tests reran successfully.
- [x] Final compile, YAML/shell syntax, secret-pattern, `git diff --check`, protected-ref, and V13 child-cleanup checks passed.
- [x] Non-force push to the existing M3 branch; exact remote read-back `8d32d79fc4ebeb75205af8e0ef5f26434e57afdb` matches local HEAD. Protected `main`/M2D unchanged.


#### V13 regression/closeout evidence (2026-10-03)

- Regression reproduced after queue start/resume renewed Owner authority: the effect row retained the dispatch-time hash, but readback compared it only with the new current snapshot. The live crash scenario could not inspect its `DISPATCHED` effect after restart.
- Fix is confined to Mission snapshot serialization/history, the shared execution-fence validator, AgentCore reauthorization, effect reconciliation/ledger authorization, and isolated tests. The current test matrix verifies exact historical snapshot acceptance and fail-closed missing/wrong-owner history.
- V13 exact-SHA CI is green for `8d32d79fc4ebeb75205af8e0ef5f26434e57afdb`: GitHub tests run `37142559205` and audit `37142559226` succeeded; Compose smoke passed. Cloudflare check `111259925397` failed; exact check metadata contains no cause, while the earlier V12 read-only build log identified the missing preview config. No external settings were changed. This completes V13; no production deployment was attempted.


### V14 — Cutover candidate + final verification (complete)

- [x] Create `docs/M3_CUTOVER_CANDIDATE.md` as a non-deployment readiness artifact with exact branch/SHA and CI evidence, the Compose target, known limitations, and explicit `PRODUCTION_DEPLOYMENT_BLOCKED` status.
- [x] Run the full repository suite and focused V14 groups: integration/auth/fence/evidence 70 passed; process/multi-worker/recovery/effects 119 passed; provider-boundary 65 passed/1 credential-gated skip; full suite 1,048 passed/1 skip.
- [x] Linter discovery: no repository or CI lint configuration exists. Temporary Ruff `E4,E7,E9,F` checks pass on all eight V13-touched Python files; the same baseline reports 291 findings repository-wide, so whole-repository lint is not green. No project config/dependency was added.
- [x] V14 `compileall`, Compose/workflow YAML parse, container shell syntax, high-confidence secret/sensitive-file scan, and `git diff --check` pass. No diagnostic/temp artifacts were found in the repository.
- [x] Protected `main` and M2D refs were unchanged; the V14 candidate diff was confined to the candidate record, M3 ledger/checklists, and narrowly scoped lint cleanup. The candidate checkpoint had no diagnostic/temp artifacts and a clean post-commit tree before the later V15/V16 planning edits.
- [x] Non-force push candidate SHA `c0982051dccc4425aadba4da154d951a52e9ed63`; remote readback matched; exact-SHA GitHub tests/Compose smoke and Owner Charter audit passed, Workers Builds failed without a detailed diagnostic; post-commit tree was clean.
- [x] No Cloudflare settings were changed, no public listener was published, and no production deployment was performed in V14.


### V15 — Real cutover decision gate (complete; CUTOVER_BLOCKED)

- [x] Score all 17 required conditions against source, test, and exact-SHA evidence; do not infer readiness from the Compose smoke alone.
- [x] Record `CUTOVER_BLOCKED` and `PRODUCTION_DEPLOYMENT_BLOCKED`: exact-SHA Workers Builds checks failed and no production-specific configuration/target is established; no production or Cloudflare mutation.
- [x] Non-force push the V15 gate decision to the existing M3 branch; verify exact-SHA tests/audit passed, record Workers Builds failure, and transition to V16.

### V16 — Actual non-production cutover rehearsal (in progress; hosted isolated project only)

- [x] **Task 1 — Test-only overlay and hook** (`tests/compose.m3-rehearsal.yaml`, `tests/m3_rehearsal/sitecustomize.py`, `tests/m3_rehearsal/hook.py`, `tests/test_m3_rehearsal_hook.py`). Acceptance: provider router is fail-closed; after the exact local `watch` effect is durably DISPATCHED, the read-only-mounted hook writes an in-volume barrier and waits no more than 45 seconds for host release before exiting 73; all DB/marker paths are fixed under the ephemeral volume; production Compose/runtime files are unchanged. Verification: `tests/test_m3_rehearsal_hook.py` (13 passed); Ruff E/F and compileall passed. Docker CLI is unavailable locally, so hosted CI must provide the actual Compose proof.


- [x] **Task 2 — Host-side runner (5 files)** (`scripts/rehearse_nonproduction_cutover.py`, `scripts/m3_rehearsal/__init__.py`, `scripts/m3_rehearsal/host.py`, `scripts/m3_rehearsal/runner.py`, `tests/test_m3_rehearsal_runner.py`). Acceptance: argv-only Compose commands pinned to the local ephemeral Docker socket with an empty per-run Docker config, unique project/image/volume, loopback port, synthetic Owner and Bridge credentials, twelve ordered secret-free stage results, and unconditional cleanup assertions for containers/volume/network/temp directory. Verification: 11 focused runner tests and 24 combined hook/runner tests pass; full suite 1,072 passed/1 skipped; Ruff E/F, compileall, YAML parsing and direct CLI help pass. Docker is unavailable locally; the actual Compose lifecycle is proven by the exact-SHA hosted rehearsal below.
- [x] **Task 3 — Hosted CI integration** (`.github/workflows/tests.yml`). The exact pushed SHA `909890e26670707acaf8d88f5586267d83859e8a` passed tests run `37148322727` (1,072 passed/1 skipped) and audit run `37148322822`; rehearsal job `111277017437` passed all 12 stages and cleanup in artifact `11282123873`. The artifact shows provider isolation, one dispatch, controlled exit 73, same-identity generation 1→2, one Owner-confirmed reconciliation, no duplicate dispatch, and zero leftover resources. Earlier failed attempts and fixes remain recorded in `M3_STATE.md`. Separate Workers Builds check `111276801695` failed without a diagnostic; production remains blocked and no Cloudflare action/deploy occurred.
- [x] **Checkpoint after Tasks 1–3:** the exact-SHA hosted rehearsal proved all twelve ordered stages and cleanup; its artifact verifies provider isolation, queue quarantine, Owner reauthorization/reconciliation, evidence/effect counts, graceful shutdown and complete cleanup. Final M3 documentation may proceed; production deployment remains blocked.
- [x] **Task 4 — Architecture/runtime docs** (`docs/M3_ARCHITECTURE.md`, `docs/M3_RUNTIME_CONTRACT.md`): documented source-verified contracts, strict `AgentCore → MissionWorker → MissionRuntime` dispatch, persistent stores, and explicit deployment boundaries.
- [x] **Task 5 — Recovery/effects/process docs** (`docs/M3_RECOVERY_MODEL.md`, `docs/M3_EXTERNAL_EFFECTS.md`, `docs/M3_PROCESS_FAILURE_TESTS.md`): documented restart quarantine, Owner reconciliation, transaction boundaries, process-death and concurrency evidence, and external-provider non-claims.
- [x] **Task 6 — Rehearsal/final audit docs** (`docs/M3_CUTOVER_REHEARSAL.md`, `docs/M3_FINAL_AUDIT.md`): recorded and revalidated the twelve-stage rehearsal plus cleanup on exact documentation SHA `cba7de93dfc5ee1f7ae450ab28468a504657bd28`, artifact `11282434212`, and mapped all five M2E blockers using the required table/status format.
- [x] **Task 7 — Closeout:** non-force pushed only to the existing M3 branch; final verified closeout head `8eb2d00c6d140a64810f38c5bc31e26c64ab3cfd`. Exact-SHA tests (`1,072 passed, 1 skipped`), Owner Charter audit, 12-stage rehearsal (artifact `11283661808`), and cleanup passed. Workers Builds check `111281965139` failed without diagnosis. Main/M2D unchanged; all five blockers remain `PARTIALLY_RESOLVED`; final status `PARTIALLY_VERIFIED`, cutover and production remain blocked. No production or Cloudflare mutation.

The exact required order is: 1) deploy/build, 2) startup, 3) health, 4) Owner login, 5) mission, 6) worker, 7) queue, 8) evidence, 9) crash, 10) same-identity restart, 11) recovery, 12) shutdown; then cleanup. Every stage must emit explicit evidence. No production credentials, production database, external provider/target, public bind, or Cloudflare mutation may be used.
