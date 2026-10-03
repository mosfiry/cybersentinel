# CyberSentinel M2E Architecture Map

**Source-audit baseline:** initial inventory at `e3c75688584dece1cb71393a884a63dfbecb4613`; V3 queue-fencing checkpoint `38f784e7f247906ffa2368332262a4c072ca11dd` is pushed to the M2E branch. V4 remains `BLOCKED / OWNER DECISION REQUIRED` for Mission/Queue atomicity. This map does not claim a running production service, an out-of-band deployment, or any production outcome.

## Runtime and request path

CyberSentinel is currently a local Python application. `README.md:3-20` and `docs/OPERATIONS.md:1-14` describe the localhost quick start; `core/config.py:11-18,33-34` defaults to and rejects any bridge bind other than `127.0.0.1`. `bridge.py:416-426` requires `BRIDGE_TOKEN`, constructs `ThreadingHTTPServer`, and blocks in `serve_forever()`. There is no repository-owned process supervisor, shutdown/restart service, platform adapter, or Worker/Pages entrypoint.

```mermaid
flowchart TD
    owner[Owner client on same device]
    bridge[bridge.py HTTP handler\n127.0.0.1 only]
    gates[Bridge token + live username/password Owner session\nfor mission HTTP routes]
    chat[api.chat.chat]
    core[AgentCore]
    reauth[AgentCore.prepare_mission_for_queue]
    service[MissionService]
    runtime[MissionRuntime]
    queue[MissionQueue\nmission_queue.sqlite3]
    worker[MissionWorker.run_once\nseparate callable; not wired into bridge startup]
    sched[MissionScheduler\nmission_scheduler.sqlite3]
    store[MissionStore\nmissions.sqlite3]
    tools[Tool Registry / deterministic authorization]
    effects[Local tools, provider HTTP, threat-intel/network effects]
    evidence[Mission evidence + separate EvidenceChainStore]

    owner --> bridge --> gates
    gates -->|/api/chat create/resume| chat --> core --> runtime
    gates -->|/api/missions create/start/resume| service
    service -->|create| runtime
    service -->|fresh Owner session| reauth -->|renewed proof and snapshot| service
    service -->|revalidated start/resume| queue
    sched -->|dispatch_due enqueues| queue
    queue --> worker --> runtime
    runtime --> store
    runtime --> tools --> effects
    runtime --> evidence
    effects --> evidence
```

The diagram’s queued worker is an available code path, not an active service proven by this checkout. `bridge.py:82-87` constructs a `MissionRuntime`, `MissionQueue`, and `MissionScheduler`; it does not construct `MissionWorker`, call `run_once()`, or run `dispatch_due()`. The only server entrypoint calls `serve_forever()` (`bridge.py:416-426`).

The chat API’s `mission_id` path calls `AgentCore.resume_mission()` (`api/chat.py:90-108`), which authenticates the supplied Owner session against the mission request, renews the authorization snapshot and policy/context, persists revalidation, and then runs the runtime (`agent/agent_core.py:333-391`). V2 closes the corresponding request-time gap for HTTP queueing: `/api/missions/{id}/start` and `/resume` require the bridge token and a live username/password Owner session (`bridge.py:89-97,268-285`), pass its server-side session ID to `MissionService`, and invoke the same AgentCore authentication/snapshot-renewal path before enqueue (`api/missions.py:29-53,84-111`). The prepare-only method persists the renewed proof/context without running a mission slice (`agent/agent_core.py:378-385`). Missing, invalid, or unbound proof fails closed; `RECOVERY_REQUIRED` and other terminal missions are rejected before queueing. No production worker is wired into bridge startup, so this does not establish an active background service or resolve authority for unattended scheduler dispatch or worker restart.

## State, leases, effects, and recovery

| Component | Current boundary | What it proves—and does not prove |
|---|---|---|
| Mission truth | JSON payloads in SQLite; integrity hash, trajectory hash checks, optimistic stale-write rejection (`agent/mission.py:129-189`). | Detects payload tampering and stale/concurrent mission saves; the save carries no queue worker or lease epoch. |
| Queue | SQLite queue rows; aware UTC timestamps are normalized and legacy time fields migrated before lexical SQL comparisons; `BEGIN IMMEDIATE` claims return their own transaction snapshot, and every worker update/release/heartbeat requires the current live owner and epoch (`agent/mission_worker.py:39-110,136-174,176-310`; adversarial coverage in `tests/test_lease_fencing.py:211-387`). | Fences queue-row mutations against offset-format expiry errors, stale claim refetch, and unfenced state changes. It still does not fence MissionStore, evidence, or provider effects. |
| Worker | `run_once()` validates the claimed lease before runtime construction and again before dispatch, then passes a fenced heartbeat into runtime slices; ambiguous exceptions park in `WAITING_FOR_TOOL` (`agent/mission_worker.py:345-404`; integration tests in `tests/test_autonomous_foundation.py:180-250`). | Queue lease is checked at the worker boundary, but no startup loop or process-level operational test is present; a separate mission/effect fence is still absent. |
| Scheduler | Schedule times are normalized/migrated to UTC before due-time comparison (`agent/mission_worker.py:418-472`). `dispatch_due()` still enqueues and advances the separate schedule database in separate writes. | Offset-formatted due times compare correctly; a crash between queue enqueue and schedule advancement can still leave a mismatch, with no dispatch idempotency marker (V4 follow-up). |
| Evidence | Mission evidence is stored inside the mission payload. `EvidenceChainStore` separately serializes a sequence and previous/current SHA-256 hashes (`agent/evidence.py:61-99`). | The local chain detects accidental/tampered records unless the entire database is rewritten and rehashed. It is not signed, not lease-bound, and is not atomic with mission or queue state. Native tool results are not automatically appended to this chain. |
| External effects | Registry tools and providers can perform local writes and outbound HTTP. Runtime writes an `in_flight` checkpoint before dispatch and records returned observations after it (`agent/mission_runtime.py:329-375,503-525`). | An exception/timeout may be ambiguous; the code avoids inferring “not executed” from a crash. There is no provider receipt/idempotency ledger or exactly-once guarantee. |
| Reconciliation | `MissionRuntime.reconcile_in_flight()` accepts `executed` plus an optional observation and persists a resolution (`agent/mission_runtime.py:193-239`). | No HTTP reconciliation endpoint or Owner-session parameter was found. Who may attest executed/not-executed remains an Owner decision; the runtime does not independently verify an external receipt. |

The queue, mission, scheduler, and evidence stores are separate persistence boundaries. Consequently, queue acknowledgement, mission-state save, evidence append, schedule advancement, and an external provider effect cannot be claimed as one atomic transaction. Queue fencing must not be described as unified mission/effect fencing. The runtime’s in-flight checkpoint/reconciliation behavior prevents blind replay but does not provide exactly-once execution.

## Authorization and model/tool boundary

Owner username/password sessions are server-side records with expiry and revocation (`security/owner_password.py:142-211`). Mission HTTP routes check both bridge authentication and a valid Owner session (`bridge.py:89-97,162-175,244-290`). The application has one canonical Owner account; the checked-in routes do not establish a multi-tenant mission-owner model. Structured-plan mission creation still uses the literal `owner-password-session` identity reference and route snapshot factory (`bridge.py:259-260,99-106`), but V2 now rebinds queue start/resume to a fresh session proof and policy snapshot before enqueue. `MissionService.create_mission()` supplies a server-generated UUID request ID when one is absent, matching the existing chat path convention (`api/missions.py:29-32`; `api/chat.py:102-106`).

`AuthorizationContext` requires typed, request-bound Owner evidence and a policy snapshot (`security/authorization_context.py:23-52`). `AuthorizationDecision` is HMAC-signed and binds tool, request ID, expiry, and argument fingerprint (`security/authorization_context.py:122-177`); `tools.registry.execute()` is the deterministic execution boundary. `MissionRuntime` checks authorization snapshots against mission/owner/target/version/action/tool and scope boundaries (`agent/mission_runtime.py:36-62`). V2 uses fresh Owner revalidation for the synchronous chat resume and authenticated HTTP queue start/resume paths; scheduled dispatch and a worker process resuming independently still have no source-established live Owner authority model.

The provider adapter currently normalizes malformed JSON tool arguments to `{}` and silently skips calls with non-string tool names (`agent/providers.py:62-86`). Native execution extracts only `arguments.query` and records success evidence without an execution-proof object or a durable link to the authorization decision and queue claim (`agent/mission_runtime.py:335-365`). Plan metadata is serialized, but the native model loop does not enforce proposal plan-version/step identity against the active step. There is no `ExecutionProof` type, verifier, or durable proof schema in this checkout; the trust model and required proof fields need an explicit design before adding one.

## CI and deployment boundary

`.github/workflows/tests.yml:1-60` is Python test/compile/secret-scan CI. At the initial source baseline, the isolated local run completed **718 passed, 1 skipped**. V2 completed **723 passed, 1 skipped**; the locally validated V3 worktree over e926 completed **732 passed, 1 skipped in 9.83s**, with focused V3 regressions **63 passed in 1.61s**, `compileall`, and `git diff --check` passing. V3 remains local and has no hosted exact-SHA CI result yet. At V2 commit `4e7a70ad986f0cf150a7a659e1646b1f3b97900b`, exact-SHA GitHub Actions `tests` run `37084032848` (check `111090497325`) and `owner-charter-audit` run `37084032823` (check `111090497193`) both completed `success`. `.github/workflows/github-only-poc.yml:1-105` is a manually dispatched, bounded Python job with an optional real-provider run and non-secret artifact; `docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md:69-92` explicitly describes it as a batch/POC, not a public backend.

The repository inventory and source audit found no `wrangler.toml`, `wrangler.json/jsonc`, Cloudflare Worker module, Pages Functions tree, Workers Builds deployment workflow, or Cloudflare deployment command. The checked-out dependencies and workflows are Python-only. The Cloudflare preview build `a4800e34-d7dd-45e6-94b2-1d73018617c2` for SHA `e3c75688584dece1cb71393a884a63dfbecb4613` failed at the Wrangler configuration check with `preview_url=null`; that attempt remains failed. A push-triggered V1 Cloudflare check `111087253066` for SHA `0aa4f5de6a40285d1ec9ce247dee4d535ea87c44` completed as `failure` (external build `78383d09-1a63-4449-84c9-767dd22d7b50`) without a preview URL or cause. V2 code SHA `4e7a70ad986f0cf150a7a659e1646b1f3b97900b` check `111090499896` remained `in_progress`, `conclusion=null` at the independent 03:31:16 +02:00 query (external build `947628a8-a733-4c4e-8660-707aee088686`). The separate V2 state checkpoint SHA `e9265647cb469150ad813657be4bab3d9ba9550a` passed exact-SHA GitHub Actions `test` (run `37085180611`, check `111093865980`) and `audit` (run `37085180635`, check `111093866140`); its Workers check `111093936774` completed `failure` (external build `5f7643af-2d11-496d-a00b-26e571bc926e`) with no cause or preview URL. Both Workers summaries give only build/script links; paths under `/production/builds` do not prove a production deployment. GitHub deployments queries returned no records for `4e7a70a` or `e926564` at 03:13:19 +02:00; that evidence is limited to GitHub and does not establish Cloudflare state. External effect remains `UNKNOWN`; no Cloudflare configuration, settings, direct build/deployment API, cancellation, or retry was used. Do not overlap a new remote M2E push with the still-in-progress `111090499896`; independent local V3 work is checkpointed but not pushed.

## Decisions that cannot be inferred safely

The code does not choose whether the canonical runtime should remain the localhost Python bridge, move to Workers/Pages, or use another persistent backend. It also does not define a durable state migration, an unattended worker/scheduler ownership model or its fresh Owner authority, who may reconcile ambiguous external effects, whether execution proof is tamper-evident or adversary-resistant, or whether cross-store consistency must be atomic. Those choices remain `BLOCKED / OWNER DECISION REQUIRED`; this map does not invent platform, approval, credential, or deployment semantics.

### Terminal result for prior V2 Workers check — 2026-10-03 03:48 +02:00

Owner-supplied independent read-only Cloudflare API evidence reports exact V2 code SHA `4e7a70ad986f0cf150a7a659e1646b1f3b97900b`, branch `task/m2e-cutover-20261002`, build `947628a8-a733-4c4e-8660-707aee088686`: terminal `fail`, command `npx wrangler preview`, cause missing top-level `previews` configuration, `preview_url=null`. The branch Preview record has `auto_build=true`; the queried Preview deployments endpoint returned `total_count=0`. Classification is confirmed preview-build failure; zero records is limited to that endpoint query and does not establish overall production state. No retry or Cloudflare mutation was performed.

First-parent boundaries are V3 checkpoint `38f784e7f247906ffa2368332262a4c072ca11dd`, V4 blocked-state commit `a79773e1c0fd7162df5e21a43760f1bd0a9158a1`, and V5 code commit `435ddcfa9c1dbf938bc1d3c58aa9c6d85436b749` (latest local state/map descendant `df455fb7782e480ba7723a5fa6935502e1d90469`). The V3 push must target 38f only; V4 and V5 remain separate later checkpoints. No production-state claim is made.


### V3 exact-SHA hosted checks — 2026-10-03 03:51 +02:00

After non-force push of V3 checkpoint `38f784e7f247906ffa2368332262a4c072ca11dd`, GitHub confirmed that exact remote M2E head. Exact-SHA `owner-charter-audit` run `37087663916` passed; `tests` run `37087663913` / check `111101185308` and the naturally triggered Workers check `111101190438` were still `in_progress` at 03:51:36. The Workers external build ID is `5dadb20d-402d-46e9-a97b-0ce7ef23e39f`; no final result or preview URL was yet available. The V3 preview remains unknown/nonterminal; no manual trigger or retry occurred.

The separate previous V2 code-SHA build `947628a8-a733-4c4e-8660-707aee088686` is confirmed failed by the owner's independent read-only Cloudflare API evidence: command `npx wrangler preview`, missing top-level `previews` config, `preview_url=null`, and queried Preview deployments endpoint `total_count=0`. This is a confirmed preview-build failure and no-preview-record result for that query, not a conclusion about overall production state. V4 and V5 remain separate later checkpoints.


### V3 CI follow-up — 2026-10-03 04:24 +02:00

The exact-SHA `tests` run `37087663913` / check `111101185308` and `owner-charter-audit` run `37087663916` completed successfully for V3 SHA `38f784e7f247906ffa2368332262a4c072ca11dd`. A direct read-only GET by Workers check ID `111101190438` at 04:24:31 confirmed `status=in_progress`, `conclusion=null`, external build `5dadb20d-402d-46e9-a97b-0ce7ef23e39f`; no terminal result or preview URL was reported. The V3 preview/build outcome remains `UNKNOWN` while nonterminal. No V4/V5 push, manual build, Cloudflare mutation, retry, or production operation occurred.

The preceding bounded monitor timed out after 30 minutes because its filtered check-list responses included the test check but omitted the Workers check; the direct exact-ID query resolved its current status without inferring the final result. This monitoring failure is recorded in `docs/M2E_STATE.md` and must not be conflated with the prior V2 preview build, which independently failed for missing top-level `previews` configuration.


### V3 terminal preview observation and V4 boundary — 2026-10-03 04:26–04:27 +02:00

The Owner's independent Cloudflare API evidence reports V3 build `5dadb20d-402d-46e9-a97b-0ce7ef23e39f` for SHA `38f784e7f247906ffa2368332262a4c072ca11dd` as terminal `fail` under `npx wrangler preview` because the existing Python repository has no Wrangler `previews` block. The branch preview-deployments API returned `total_count=0` and `preview_url` was absent. This is classified as a confirmed preview-build failure; the API result is limited to the queried preview endpoint and does not establish production state. No retry or Cloudflare API call was made by this agent.

For the same V3 SHA, GitHub Actions `tests` run `37087663913` / check `111101185308` and `owner-charter-audit` run `37087663916` / check `111101185368` are successful. A separate GitHub GET at 04:27:54 still showed Workers check `111101190438` as `in_progress` with no conclusion. Both provider-build and GitHub-check observations are preserved separately; no success or production inference is made from the GitHub check's nonterminal state.

V4 remains a documentation-only `BLOCKED / OWNER DECISION REQUIRED` checkpoint for unresolved Mission/Queue atomicity authority. No source/owner decision was supplied, so no architectural change is made. V4 is pushed as the next M2E checkpoint before V5; V5/V6 code is excluded from this V4 tip.

### V4 exact-SHA checks terminal — 2026-10-03 04:32 +02:00

For V4 SHA `a5cbb828cc59d816a1845ae8edf8dcb6477bfc08`, GitHub audit run `37090085541` / check `111108378136` and test run `37090085552` / check `111108378436` completed successfully. The naturally triggered Workers check `111108436527` completed `failure`, external build `fa23f980-a3f7-4683-99ae-5b2f9e0cd43f`; GitHub reported no cause or preview URL. This confirms a failed Workers Build check, not a production outcome or any specific preview artifact state.

The separate GitHub commit-status endpoint returned `pending` with no status records at 04:32:43, although exact check-run records were terminal. The check-run statuses are kept explicit and separate. V4 remains a docs-only `BLOCKED / OWNER DECISION REQUIRED` checkpoint; no V4 architecture/code choice was made.

## V5 evidence append serialization checkpoint

`EvidenceChainStore.append()` now begins with SQLite `BEGIN IMMEDIATE` before reading the current chain head, assigning the sequence/previous hash, and inserting the rehashed record (`agent/evidence.py:69-83`). This serializes concurrent appenders at the chain-position boundary. The focused tests verify rehashing, 64 concurrent appends across eight store instances with one valid sequence, detection of payload tampering, and rollback after non-JSON serialization failure (`tests/test_evidence_chain_store.py:8-84`).

This is a narrow V5 integrity improvement, not full worker-lease fencing or adversary-resistant authenticity. The chain remains unkeyed SHA-256, can be recomputed by a database writer, is stored separately from mission/queue state, and native mission evidence is not automatically appended to it. Binding evidence writes to a live worker claim still depends on the unresolved V4 storage/transaction decision; do not claim unified mission, queue, evidence, or external-effect atomicity.

### Historical read-only CI observation — 2026-10-03 03:45 +02:00

At 03:45:01, GitHub check `111090499896` for V2 code SHA `4e7a70ad986f0cf150a7a659e1646b1f3b97900b` was `in_progress`, `conclusion=null` (external build `947628a8-a733-4c4e-8660-707aee088686`). This is the status of that GitHub check at the query time, not a preview/deployment result. The Owner later supplied independent terminal Cloudflare failure evidence for this exact build, recorded above. The old local branch-tip and push-gating instructions from this snapshot are superseded by the verified V4 and current V5 checkpoints.
