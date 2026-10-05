# CyberSentinel Architecture Gap Analysis

**Audited base:** `9b21361a685f9eb5c491dffc57ff5b6ab901d256`  
**Audit result:** eight completed domain audits; no audit failures were reported.  
**Release constraint:** this analysis does not modify or propose touching v5.1.0, and it does not create or claim a final v5.2.0 release.

CyberSentinel has a credible, security-conscious single-owner mission execution core. The strongest implemented path is **Owner → authorization snapshot → scope → validated tools → fenced effects/evidence → deterministic verification/reporting**. Durable missions, leases, checkpoints, recovery quarantine, owner revalidation, append-only knowledge, evidence-chain integrity, and a hardened desktop/web boundary are real implementation capabilities, not merely design claims.

The central gap is breadth rather than absence of a foundation. The repository does not yet demonstrate a production multi-agent graph, procedural skill lifecycle, browser/MCP integration, complete knowledge/evaluation product surface, or broadly portable provider/hardware runtime. The safe strategy is additive: preserve MissionRuntime and its fences as the canonical execution path, add thin versioned services around it, and keep compatibility paths explicitly non-authoritative.

## Audit methodology and evidence standard

This synthesis consolidates the eight completed domain records against the audited commit. Findings were accepted as current capability only where the records identified concrete source paths and/or passing targeted tests. Historical documents, release notes, branch-specific workflow claims, compatibility shims, placeholders, and declarations in configuration were not treated as implementation evidence. The distinction is material: for example, web search is explicitly unavailable, MCP is documented as future work, and Windows/local-inference acceptance is not demonstrated by this audit.

The analysis groups each domain into five questions: what exists and is tested; what is missing; which components should be reused; what minimal additive implementation is warranted; and which security, persistence, migration, and test controls must accompany it.

## Eight-domain capability table

| Domain | Current tested capability | Missing capability / architecture gap | Minimal additive direction | Acceptance posture |
|---|---|---|---|---|
| Agent runtime, task model, planning, delegation, task graph | AgentCore → MissionRuntime is canonical; durable Mission payloads, checkpoints, authorization snapshots, execution fences, restart quarantine, and a compatibility TaskManager exist. | No agent registry, child lifecycle, parent-child edges, graph scheduler, joins, cancellation propagation, delegated-scope derivation, quota aggregation, or cross-agent evidence lineage. | Add versioned delegation/edge records and a thin prerequisite scheduler over existing Plan metadata; derive child authority as a non-expanding subset of the parent snapshot. | Single-mission execution is demonstrated; multi-agent execution is not. |
| Mission persistence, workers, recovery, resume | SQLite MissionStore, queue leases, worker generations, strict claim binding, scheduler handoff, checkpoint WAL, recovery-required states, and RuntimeSupervisor are implemented and tested. | No migration registry, independent scheduler/HA service, recurring schedules, cross-file backup contract, or automatic reconciliation of ambiguous effects. | Add explicit migrations, an optional durable poller/watchdog, documented reconciliation, and coordinated backup/restore tests. | Worker polling and conservative recovery are demonstrated; unattended scheduling and multi-host HA are not. |
| Memory and long-context management | Typed memory, provenance fields, conversation SQLite storage, trust-aware context composition, deterministic compaction, bounded retrieval, and append-only knowledge integrity exist. | New `domain`/`request_id` fields are not durably round-tripped; retrieval is unfiltered by query/scope; consolidation is a placeholder; required context can exceed budgets; vector retrieval is unimplemented; MissionContext is not durable. | Version memory schema, preserve provenance, add optional authorization-aware filters, transactional/versioned summaries, and explicit global/token budgets. | Core context and knowledge tests pass; durable migration, isolation, and token-budget behavior are not demonstrated. |
| Evidence, validation, reporting, skills, learning | Hash-linked evidence and trajectory helpers, fenced EvidenceChainStore, deterministic verification, trusted/unverified report labeling, and learning-adjacent critic/gate tests exist. | No procedural Skill registry, revision/approval/revocation lifecycle, durable trajectory/repair store, authenticated provenance, or promotion loop from learning output to executable procedure. | Add owner-scoped immutable skill revisions and approval audit events; treat learning output as a candidate only and require independent validation. | Evidence integrity and reporting are demonstrated; authenticated provenance and skill execution are not. |
| Tool registry, search/web, browser, MCP | ToolSpec is the canonical allowlist and dispatch boundary; search abstractions, local/GitHub/NVD/MITRE providers, SSRF helpers, fences, and secure web UI transport exist. | Web provider is explicitly unavailable; no browser automation or MCP transport/capability lifecycle exists; cache/rate limits are process-local; structured remote capability persistence is absent. | Implement web first through existing pinned-HTTP/SSRF and SearchProvider contracts; later map MCP/browser calls to ToolSpec and persist connector evidence. | Secure web UI is demonstrated; web search, browser automation, and MCP are blockers, not passes. |
| Owner authority, authorization, scope, isolation | Password/session auth, typed authorization context, mission snapshots, scope matching, owner revalidation, strict evidence fencing, and adversarial tests exist. | Structural-only compatibility authorization and legacy evidence remain permissive; process-local secrets impede portable decisions; scope expiry/mediation is distributed; hashes do not prove owner provenance. | Reject compatibility forms at every effect boundary, require active scope/expiry checks immediately before effects, and define deployment-safe secret continuity. | Strong tested security boundary exists on canonical paths; universal runtime mediation is not proven. |
| LLM providers, local model manager, hardware | OpenAI-compatible adapter, router fallback/deadlines, pinned CPU llama.cpp manager, model catalog/download integrity, loopback key, and desktop integration exist. | No native vendor integrations, truthful capability operations, retry/circuit breaker, durable provider schema, backend/GPU adaptation, or broad CI coverage; runtime/model acceptance is incomplete. | Keep the generic adapter honest, version manager state, serialize router replacement, and connect hardware claims only to real runtime selection. | Local CPU plumbing is implemented, but real local inference acceptance and Windows acceptance are blockers unless separately demonstrated. |
| Desktop/API, knowledge, evaluation, packaging, CI | Hardened Electron/web boundaries, mission/report routes, scheduler backend controls, append-only knowledge and benchmark contracts, and packaging checks exist. | No complete scheduler UI/API CRUD, owner knowledge surface, authenticated evaluation product, coordinated desktop DB migrations, signed release, or branch-independent Windows validation. | Add owner-scoped routes/UI, knowledge and evaluation surfaces, migration fixtures, and release gates without changing legacy contracts. | Candidate packaging and Linux/source checks exist; final release and Windows real acceptance are not demonstrated. |

## Domain findings and reusable architecture

### 1. Agent runtime, planning, delegation, and task graphs

The production path already has the right parent execution boundary: AgentCore emits ordered tool-backed `PlanStep` objects, Mission persists progress and authorization state, and MissionRuntime validates owner, tools, scope, workspace, network, and credential boundaries before dispatch. TaskManager and MissionTaskAdapter should remain compatibility seams, not become a second source of scheduling or authorization truth.

The missing layer is a durable graph model. Plan prerequisites and dependencies are strings with no cycle or unknown-reference validation, and there is no parent/child identity, delegated authority, fan-out/fan-in, cancellation, quota, or child evidence lineage. The minimum safe addition is a versioned edge/delegation record containing parent and child IDs, owner identity, narrowed authorization/scope digest, dependency state, budget, status, and result/evidence references. A scheduler can select ready nodes and persist transitions while falling back to the existing linear behavior when graph metadata is absent. Every child must be owner-scoped and fenced, and its tool/action set must be a strict subset of the parent snapshot.

Required tests include forged ownership, broader child scope, stale versions, cycles, unknown prerequisites, joins, orphan recovery, cancellation propagation, retry exhaustion, and exclusion of failed or unauthorized child evidence. No new graph work should attach directly to legacy AgentTaskRuntime.

### 2. Mission persistence, worker scheduling, recovery, and resume

MissionStore, MissionQueue, MissionScheduler, checkpoints, lease epochs, worker generations, and RuntimeSupervisor form a substantial durable execution substrate. Crash-injection tests correctly quarantine in-flight effects instead of replaying them; strict mode binds mission and queue state through rollback-journal transactions. This is the strongest reusable foundation in the repository.

The practical gaps are operational. Scheduling is polled by a live worker, one-shot only, and has no external watchdog or high-availability ownership protocol. The stores use `CREATE TABLE` and ad hoc `ALTER TABLE`/normalization rather than a migration registry. Four SQLite files participate in operational consistency, but backup/restore and journal-mode requirements are not a documented product contract. Recovery requires authenticated reconciliation or owner reauthorization and can remain blocked indefinitely by design.

Add explicit schema versions and idempotent migrations, define a coordinated backup/restore procedure, and—only if unattended execution is required—place a small durable poller/watchdog around existing dispatch methods. Test downtime, clock skew, duplicate polls, multi-process failover, old fixtures, malformed rows, and partial upgrades. Preserve strict fences and never turn ambiguous effects into automatic replay.

### 3. Memory and long-context management

The context subsystem has a sound trust ordering: system and owner policy precede execution context, tools, conversation, memory, knowledge, and tool results. Memory and knowledge are typed and marked untrusted, and the knowledge store's exact integrity and append-only patterns are suitable models for improving memory.

However, the memory schema silently loses newer `domain` and `request_id` fields; hashes are compatibility-strength prefixes; relevant-memory retrieval ignores its query and scope; consolidation writes a placeholder summary and deletes older rows without one transaction; and required context can exceed configured character/message limits. Context hashes omit important provenance and tool-schema identity. MissionContext is serializable in memory, not durable recovery state.

The minimal implementation is a versioned additive schema migration, full hashes for new rows with explicit legacy handling, optional caller-supplied trust/domain/request/mission filters, and transactional or append-only superseding summaries carrying source IDs and hashes. Define deterministic overflow behavior and preserve provenance through context adapters. Tests must cover old DBs, interrupted migration/consolidation, cross-mission isolation, full-hash tampering, required-content overflow, tool-call continuity, and every knowledge filter.

### 4. Evidence, validation, reporting, skills, and learning

Evidence chains, deterministic verification, and mission reports provide useful integrity and trust labeling. The report deliberately preserves arbitrary caller-provided material as `UNVERIFIED_PROVENANCE`, while the learning pipeline caps reference-derived confidence and keeps external material non-authoritative. These are valuable safety primitives.

They do not constitute a procedural learning system. There is no Skill registry or revision identity, approval/revocation state, dependency policy, signing, execution history, or promotion path. SHA-256 chains prove self-consistency, not authorship; validator callables and report authority fields are caller-controlled unless strict mission/fence checks are applied. Trajectory and repair records are not durable.

Add an owner-scoped immutable Skill revision table with content hash, required tools/scope, status, approver, and append-only approval events. A candidate generated by learning must pass existing verification, critic, and gate checks and remain non-executable until owner approval and current-scope validation. Add optional report skill fields without changing report v1. If durable telemetry is needed, add a versioned event store tied to mission and evidence heads. Test approval forgery, revocation, stale revisions, content tampering, report trust forgery, and crash recovery.

### 5. Tool, search, web, browser, and MCP boundaries

ToolSpec/build_registry/core engine are the correct host boundary: tools have schemas, effects, risk, authorization, timeout, idempotency, and evidence declarations. SearchProvider and SearchService already establish bounded, provenance-bearing untrusted results. The web UI is an untrusted client with session and CSRF controls.

The important negative finding is explicit: web search is unavailable, browser automation is absent, and no MCP transport or runtime capability lifecycle exists. Namespaces and documentation do not change that. SSRF utilities are only a safe starting point until every future request path proves DNS pinning, redirect revalidation, response limits, and destination checks.

Implement web by replacing only the unavailable provider through the existing SearchResponse and pinned-HTTP contracts. Add MCP/browser adapters only after persisting server identity and capability revisions and mapping every remote operation to a ToolSpec, owner scope, fence, and evidence receipt. Treat descriptions, prompts, resources, and returned content as untrusted. Test private-range blocking, redirects, malformed content, cancellation, timeout races, restart/idempotency, and unknown capabilities.

### 6. Owner authority, authorization, mission scope, and isolation

Owner authentication, policy snapshots, mission authorization snapshots, target/scope matching, session revocation, and adversarial fail-closed tests are implemented. The design principle should remain explicit: compatibility APIs may parse old callers, but they must not authorize effects.

The remaining risk is mediation consistency. `authorize_tool` can accept a structural-only context-less form; legacy evidence can be appended without a fence; process-local HMAC/decision secrets are not portable across workers unless session fallback remains live; and scope expiry and matching are distributed among callers. Plain hashes bind fields but do not prove that the Owner issued them.

At each effect boundary require typed authorization, current active session, fresh scope/expiry resolution, mission identity, and a strict execution fence. Define shared-secret continuity for restart and multi-worker deployments. Test every compatibility form against effectful tools, cross-process decisions, expired/revoked sessions, encoded paths, malformed scope timestamps, forged owner approvals, and legacy evidence that must remain readable but cannot authorize new effects.

### 7. LLM providers, local model management, and hardware

The generic OpenAI-compatible provider and ModelRouter are real boundaries, with typed responses, deadlines, fallback ordering, and traces. The local manager has meaningful lifecycle and supply-chain controls around pinned CPU llama.cpp artifacts, manifests, hashes, loopback authentication, and model restoration.

Environment labels are not native vendor integrations, and capability flags do not prove streaming, structured output, vision, parallel tools, or reasoning. GPU detection is informational; it does not select an accelerated backend. Provider state is not versioned, malformed persisted values can fail startup, and background provider mutation can race missions. The available audit does not prove real model activation/inference or Windows acceptance.

Keep the adapter generic rather than inventing fake providers. Make capability declarations truthful, version manager state and catalog identity, parse defensively, atomically replace provider sets, and claim CPU-only behavior until backend selection is implemented. Add direct adapter contract tests, corrupt-state migration tests, concurrent swap tests, executable/runtime identity checks, and Linux/Windows acceptance evidence before changing the blocker status.

### 8. Desktop/API, knowledge, evaluation, packaging, and CI

Electron hardening, bridge tokens, HttpOnly/CSRF sessions, workspace boundary checks, mission/report routes, scheduler backend operations, knowledge integrity, and benchmark contracts are implemented. These provide reusable product boundaries, but not a complete product surface.

There is no full scheduler list/get/update/delete UI/API, owner-scoped knowledge ingestion/query surface, authenticated evaluation run/artifact product, coordinated cross-database desktop migration, signed installer release, or branch-independent Windows proof. Existing release/version notes are historical or candidate evidence and must not be treated as a final release claim.

Add owner-authenticated scheduler CRUD and renderer controls, then a narrowly scoped knowledge API that returns source hashes and provenance but never execution authority. Add immutable, owner-scoped evaluation artifacts and report linkage. Keep Electron and backend changes additive, and add legacy DB upgrade/crash/restart and installer upgrade fixtures. Preserve the existing web and workspace security contracts.

## Phased incremental implementation plan

**Phase 0 — Freeze the baseline and constraints.** Tag the audited commit internally, record the current compatibility contracts, and establish that v5.1.0 is not to be touched and no final v5.2.0 release is to be created. Add migration fixtures and effect-boundary tests before feature work. Treat Windows real acceptance and local inference as blockers until demonstrated by executable code and acceptance tests.

**Phase 1 — Persistence and authority hardening.** Introduce version tables and idempotent migrations for memory, mission/schedule additions, and any new desktop records. Preserve unknown fields where safe, support old rows, define coordinated backup/restore, and require typed authorization plus active scope/expiry checks at every effectful boundary. Establish shared-secret continuity and reject structural-only forms in production dispatch.

**Phase 2 — Graph-ready mission execution.** Add agent identity and delegation/edge records, strict subset scope derivation, dependency validation, ready-node scheduling, budgets, join state, cancellation, and evidence producer lineage. Route execution through MissionRuntime, MissionQueue, checkpoints, and existing recovery quarantine. Keep linear plans and compatibility adapters unchanged when graph metadata is absent.

**Phase 3 — Durable context and learning controls.** Repair memory round-trip loss, add filtered retrieval and provenance-preserving adapters, replace placeholder consolidation with versioned transactional summaries, and make budget overflow deterministic. Add the owner-approved Skill registry as a non-authoritative candidate-to-approved lifecycle guarded by independent verification and current authorization.

**Phase 4 — External capability adapters.** Implement web search through existing pinned-HTTP/SSRF primitives and only then consider browser/MCP adapters. Persist provider identity, capability version, target, request/response hashes, redirects, and replay status through mission/evidence stores. Unknown remote capabilities and untrusted remote text must fail closed and remain data-only.

**Phase 5 — Product surfaces and acceptance gates.** Add scheduler CRUD, knowledge, evaluation, and report-export surfaces with owner scope and provenance. Add provider/runtime contract tests, real Windows install/upgrade/uninstall evidence, and a genuine local inference acceptance run. Until those artifacts exist, report Windows and local inference as blockers. Only after all gates pass should release planning be revisited; this document itself authorizes neither v5.1.0 changes nor a final v5.2.0 release.

## Cross-cutting dependencies and risks

The dependencies are intentionally modest: existing SQLite/dataclasses/pytest infrastructure, MissionRuntime and fences, authorization/scope resolvers, ToolSpec, EvidenceChainStore, knowledge integrity primitives, and current Electron/bridge contracts. The main architectural dependency is not a new framework; it is preserving one execution truth while adding versioned records around it.

The highest risks are authority escalation through child delegation or future skills, replay or divergence across separate stores, untrusted remote/model content being mistaken for instruction, stale or out-of-scope memory injection, and false confidence from declarations or historical documentation. Full-blob mission state and ad hoc migrations also create contention and upgrade hazards. Any new feature must fail closed on unknown schema/capability/revision, preserve old linear behavior, and leave ambiguous effects in recovery rather than replaying them.

## Required persistence, migration, and test gates

Every new durable record needs an explicit schema version, idempotent migration, backward-load behavior, owner filtering, integrity fields, and crash/restart tests. Cross-file mission/queue/scheduler changes need a documented transaction or reconciliation contract; backup and restore must cover all participating databases together. Legacy TaskManager and non-strict evidence remain readable compatibility paths but cannot become authorization or scheduler truth.

The minimum security suite should cover cross-owner reads and writes, forged owner/session and approvals, child scope expansion, stale authorization/version/fence, scope expiry and path canonicalization, revoked skills/providers, unknown capabilities, SSRF redirects/private ranges, prompt-injection content, secret redaction, and no replay of ambiguous effects. The minimum persistence suite should cover old fixtures, interrupted migrations, duplicate/idempotent migrations, malformed JSON/enums/timestamps, concurrent writers, lease expiry, orphan children, joins, cancellation, consolidation rollback, and coordinated restore. Existing targeted tests are regression baselines, not substitutes for these new gates.

## Tested code versus historical or documentary claims

The audited implementation and targeted tests support the canonical mission lifecycle, strict worker fencing, crash quarantine, owner/session controls, evidence-chain integrity, deterministic reporting, typed knowledge integrity, secure web UI boundaries, and CPU-oriented local runtime management. They do **not** support claims that CyberSentinel currently has multi-agent delegation, a procedural Skill system, browser automation, MCP, production web search, recurring unattended scheduling, high-availability scheduling, a complete knowledge/evaluation product surface, native vendor providers, GPU adaptation, Windows real acceptance, or proven end-to-end local inference.

Historical docs, release notes, branch-scoped workflows, configuration labels, compatibility modules, placeholders, and planned namespace entries must remain clearly labeled as such. In particular, Windows workflows tied to other branches and documentation mentioning installer versions do not establish acceptance for this base commit; environment labels do not establish provider integrations; and a model catalog or llama.cpp manager does not establish a successful local inference run. The honest current conclusion is a strong, tested single-owner mission foundation with substantial additive architecture work required before claiming Hermes-level multi-agent, learning, external-tool, or cross-platform production completeness.

## Current task-branch delta (2026-10-05)

The audit above describes the audited base commit, not the present task branch. Subsequent work on `work/hermes-level-agent-intelligence` has added memory provenance/migration/filtering and fail-closed context budgeting; owner-approved declarative Skill and candidate pipelines; bounded artifacts; durable events and veto hooks; evaluation records; and a pinned-HTTP web-search implementation. These are incremental source changes with targeted test suites, not proof of complete product or external acceptance.

Most importantly, the task graph is now integrated with the canonical `AgentCore`/`MissionRuntime` path as a **single-coordinator, dependency-gated plan-step scheduler**. Graph state is embedded in the integrity-covered Mission payload and saved with its checkpoint/action history. Claims still pass through the existing Owner snapshot, mission authorizer, execution fence, executor, ToolRegistry, and recovery quarantine. See `docs/architecture/MISSION_TASK_GRAPH_DISPATCH.md` and `tests/test_mission_graph_runtime.py`.

This closes the gap of having only an isolated graph control-plane in code. It does **not** close independent child-agent execution, fan-out/fan-in, parallel model/tool workers, child evidence lineage, production Skill dispatch, browser automation, MCP, authenticated evaluation/knowledge/scheduler product surfaces, real endpoint acceptance for web search, Windows installer acceptance, or real local-model inference. The new graph does not alter the evidence trust boundary. Full Hermes-level parity and the broader definition of done remain unmet.
