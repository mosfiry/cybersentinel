# CyberSentinel X Agent Architecture

CyberSentinel X is a local defensive agent. The browser and internal-client paths converge on the same server-side Owner session and authorization code:

```text
Browser: public CSRF session + username/password login
  -> HttpOnly Owner-session cookie
  -> POST /api/public/chat (CSRF + Owner session validation)
Internal client: X-CyberSentinel-Token + X-CyberSentinel-Owner-Session
  -> POST /api/chat
Both paths
  -> api.chat.chat -> AgentCore -> MissionRuntime
  -> ModelRouter proposal -> deterministic authorization
  -> bounded tool execution -> evidence and audit response
```

`BRIDGE_TOKEN` authenticates only the internal/local HTTP transport. Owner authority comes from a valid server-side session issued by `security/owner_password.py`; internal clients pass its ID using `X-CyberSentinel-Owner-Session`, while the browser receives that ID only inside an HttpOnly cookie. A public CSRF session is not Owner authority, and browser access remains disabled unless `PUBLIC_WEB_ENABLED=true`.

Browser `/api/public/chat`, internal `/api/chat`, the legacy-named `/api/command` handler, and mission-backed `/api/tasks` all reach the same `api.chat.chat -> AgentCore -> MissionRuntime` execution path. `/api/tasks` keeps a compatibility `Task` envelope but stores and controls the canonical mission; it is not a second execution runtime. `core.engine.handle()` and `agent/runtime.py` remain historical/direct compatibility APIs with no current bridge route caller. A model can propose a plan, but it cannot execute tools or authorize itself. `tools/registry.py` is the single source of tool metadata, handlers, risk classes, and argument schemas; `security/authorization.py` applies the registry policy, maximum argument length, and maximum plan size before execution.

All bridge chat paths pass the authenticated Owner session into the canonical mission facade, where typed authorization snapshots, mission/run/tool-call identity, and one-use execution proofs are validated before dispatch. Planner responses remain untrusted proposals; the model cannot authorize itself or create Owner identity.

Audit event IDs link authentication, policy, plan, authorization, execution, and response. Evidence objects carry the same request ID and a tamper-evident chain of `sequence`, `previous_hash`, and `current_hash`; `verify_chain()` detects later modification.

V4.6 persists one execution lifecycle per request ID: `created`, `planned`, `validated`, `authorized`, `executing`, `succeeded` or `failed`, and `completed`. SQLite uniqueness and an atomic claim prevent concurrent duplicate execution. A completed request is replayed rather than executed again. Requests left in an active state by a process crash are recovered as failed, never successful. Each tool has a bounded timeout; cancellation is cooperative at tool boundaries and records cancellation as a failure, not a success. The authenticated `/api/execution/<request_id>` endpoint exposes the durable lifecycle and request-scoped audit events for reconstruction.

V4.7/V4.8 add an Owner-only `red_team_assess` capability for defensive adversarial analysis. It accepts an observation and returns competing hypotheses, supporting and contradicting evidence, alternative explanations, required next evidence, confidence rationale, limitations, and provenance. It cannot exploit, scan, execute shell, retrieve credentials, or authorize another tool. Knowledge objects are normalized, deduplicated, quality-filtered, hashed, and retrieved locally; external source text is treated as untrusted data and never as policy or execution instructions.

If all configured model providers fail or return invalid JSON, the runtime uses its deterministic defensive fallback. Provider name and model are retained as provenance in plans, execution events, and responses. No provider credential is returned to the client.


## Agent Core Fusion — adaptive intelligence path

The current long-horizon path is now:

```text
Owner Instruction
  -> MissionRuntime persistent state
  -> typed KnowledgeRetriever / RetrievalResult
  -> ContextEngine with provenance and untrusted-data labels
  -> ModelRouter planning proposal
  -> plan/objective/scope/authorization enforcement
  -> Tool Registry handler
  -> Observation normalization
  -> ObservationInterpreter
  -> HypothesisEngine
  -> StrategyDecision
  -> continue / request evidence / replan / scope block
  -> trajectory + SQLite persistence
  -> GoalVerification
```

`agent/observation_intelligence.py` defines a closed observation-interpretation proposal. It can summarize observations, add evidence references, identify contradictions, update hypotheses, change confidence only with evidence and rationale, recommend another strategy, and request missing evidence. It cannot change Owner Instruction, policy, identity, authorization, scope, objective, or tool handler behavior. A malformed or overreaching model proposal is rejected and replaced by deterministic observation analysis.

`agent/hypotheses.py` stores typed `HypothesisState` objects with supporting evidence, counter-evidence, required evidence, confidence, status, and provenance. Confirmation is not model-controlled; it requires both deterministic validation and goal verification. `agent/strategy.py` produces typed decisions such as `CONTINUE_PLAN`, `REPLAN`, `ADD_EVIDENCE`, `WAIT_FOR_DEPENDENCY`, `SCOPE_BLOCKED`, and `VERIFY_GOAL`. A successful action can therefore still cause a replan when the resulting information materially changes the reasoning state.

`agent/knowledge_context.py` adapts the append-only typed knowledge store and BM25 retriever to `RetrievalResult`. Results include source ID, source type, content hash, trust class, transformation policy, relationship metadata, attribution status, and explicit `authority: null`. Knowledge is context, not policy. The model sees it as untrusted data and cannot use retrieved text to grant permission or expand scope.

### Authority rule

> **The authenticated Owner is the highest authority inside the application policy domain.** The Owner writes the mission objective, Owner Instruction, protection policy, privacy policy, scope, and operating rules. The model is subordinate to that Owner policy and may propose reasoning only. A separate immutable platform/safety boundary remains above application policy: no Owner Instruction, model output, knowledge object, or tool result may disable authentication, audit integrity, credential separation, or deterministic authorization.

This is not a claim that the model is the owner. The Owner identity is established outside the model, carried in `ExecutionContext`, persisted in mission provenance, and checked by authorization. Every adaptive decision is subordinate to that authenticated Owner context.

## Agent Core Fusion — failure and recovery behavior

The adaptive loop is fail-closed. Provider failure, invalid JSON, identity mismatch, unknown fields, missing evidence provenance, invalid hypothesis confirmation, out-of-scope targets, malformed observations, and ambiguous external effects do not become successful actions. The MissionRuntime records the rejection, recovery event, or scope block and persists the state. Replanning must preserve the original Owner objective; an attempted objective change is a safety block. Completed actions remain idempotent and are not replayed merely because a later strategy was generated.

The stable CVE fixture at `knowledge/fixtures/incident_cve_x.json` contains a primary advisory, counter-evidence showing a patched asset version, a low-confidence IOC report, and an unverified public claim. It is used only for defensive hypothesis evaluation and does not grant exploit or network-execution authority.


## Owner authority tiers — binding semantics (2026-09-22 audit)

The internal authority hierarchy of CyberSentinel X is fixed:

```text
OWNER_INSTRUCTION (800)
  > SYSTEM_PLATFORM (700)
  > OWNER_POLICY (600)
  > DETERMINISTIC_ENFORCEMENT
  > AUTHORIZATION_SCOPE
  > TOOL_RUNTIME
  > MODEL_OUTPUT
  > EXTERNAL_DATA
```

Semantics that remove a historical ambiguity:

- `SYSTEM_PLATFORM` names the **internal CyberSentinel platform layer** — the
  process boundary, credential separation (bridge transport token vs
  username/password-backed Owner session),
  lifecycle persistence, audit-chain integrity, and deterministic enforcement.
  It is an application-internal tier, **not** the external hosting or runtime
  constraints of the machine/network the service happens to run on.
- External platform constraints that CyberSentinel does not control (OS
  sandbox, host network policy, provider-side limits) are **outside** this
  hierarchy. No code path may claim to override them, and no Owner Instruction
  can be interpreted as overriding them.
- `OWNER_INSTRUCTION` is the highest **application** authority. It is never
  re-ordered below `SYSTEM_PLATFORM`, and `SYSTEM_PLATFORM` is never used to
  synthesize a competing application objective.
- Components that read `AuthorityTier` values must treat them as
  documentation of this ordering, not as an execution input. A clearer name
  (for example `INTERNAL_PLATFORM_LAYER`) may be introduced only if this
  documented order is preserved exactly.

## Runtime inventory — canonical vs compatibility status (2026-09-29 review)

The audit established the live call graph (bridge → api → agent → tools) by
reading every entrypoint. Status:

| Module | Role | Live reachability |
| --- | --- | --- |
| `agent/mission_runtime.py` (`MissionRuntime`) | Canonical persistent mission engine | Owner chat through `api.chat.chat` and `AgentCore.run_owner_mission` / `resume_mission` |
| `agent/agent_core.py` (`AgentCore`) | Facade/orchestration boundary over `MissionRuntime` | Every `/api/chat` request, including browser `/api/public/chat` |
| `agent/mission_task_adapter.py` (`MissionTaskAdapter`) | Compatibility Task envelope over canonical missions | `/api/tasks`; creation persists via AgentCore before supervised queueing, reads hydrate from MissionStore, and resume/pause/cancel/ownership delegate to AgentCore/MissionService |
| `agent/task_runtime.py` (`AgentTaskRuntime`) | Legacy task runtime retained for compatibility/tests | No current bridge/API production caller |
| `agent/runtime.py` (`AgentRuntime`) | Legacy planner for direct command-engine callers | No current bridge `/api/command` caller |
| `agent/loop.py` (`AgentLoop`) | Legacy conversational loop retained for compatibility/tests | Not the `/api/tools` source; that authenticated route reads `tools.registry.tool_definitions()` directly |
| `agent/conversation.py` (`ConversationParser`) | Deterministic intent baseline for legacy direct callers | `core/engine.py` `_handle_once()` |
| `agent/conversation_provider.py` | Model adapter for the conversation schema | Tests only (not imported by bridge/api/engine) |
| `agent/model_intelligence/conversation.py` | Live NLU (`NaturalLanguageUnderstanding` → `MissionIntent`) | `AgentCore.understand_mission_intent` / `run_owner_mission` |

Honest remaining gaps against the full workspace architecture goal:

1. `/api/tasks` remains a compatibility API envelope, though its mission-backed
   execution and lifecycle use the canonical MissionRuntime. `AgentTaskRuntime`,
   `AgentRuntime`, `AgentLoop`, and `core.engine` remain compatibility/test
   surfaces rather than the browser/API mission execution path.
2. `PlanStep` DAG prerequisites are validated and block execution until
   predecessors finish. Non-empty top-level `Plan.dependencies` are rejected;
   cross-mission dependency scheduling is not implemented. The runtime also does
   not spawn independent specialist agents; `core.expert_modes` are deterministic
   analysis templates, not provider-backed experts.
3. General-web search is unavailable. SearchService registers an explicit
   unavailable web provider, and both exported WebSearchProvider names fail
   closed without network or CLI calls. GitHub search is a separate provider
   scope; it is not reported as general web search.
4. No `owner_authenticated=True` trust path exists anymore:
   `security/authorization.py` explicitly rejects a bare boolean
   ("typed Owner authentication evidence required") and forbids mixing legacy
   evidence arguments with a typed `AuthorizationContext`.

## Natural Language Understanding vs final assistant response

`agent/model_intelligence/conversation.py` is the **understanding** layer:

```text
Natural Language → MissionIntent (objective, intent_type, constraints,
requested_artifacts, verification_criteria, scope_references,
authorization_requirements, entities, ambiguities, semantic_fingerprint, source)
```

It is **not** the response generator: a `MissionIntent` or tool proposal is
always an untrusted model proposal. Final assistant text is produced only after
deterministic verification, and mission completion is decided by
`GoalVerification` over persisted evidence, never by the model's own claim.

Do not confuse the three similarly named modules:

- `agent/conversation.py` — deterministic `ConversationParser` intent baseline
  used by the command engine (live, no authority).
- `agent/conversation_provider.py` — model adapter producing validated
  untrusted proposals (tests only today).
- `agent/model_intelligence/conversation.py` — live NLU for owner
  instructions in the mission path.

## Web search provider status — no synthetic success

The `web` search scope is **explicitly unavailable**. SearchService uses
`WebSearchProviderUnavailable`, and the exported `WebSearchProvider` compatibility
class now also raises `ProviderUnavailableError` without probing the network or
invoking a CLI. It cannot return a fabricated empty-success response or label
GitHub repository search as general web search. The `search` tool's automatic
scope is local events/intelligence; no general-web connector is configured.

## SSRF protection and residual risk

`search/ssrf.py` validates scheme, host, port, length, blocked suffixes, and
blocked ranges (loopback, RFC1918, link-local, IPv6 link-local, IPv6
unique-local `fc00::/7`, `0.0.0.0/8`, IPv4-mapped IPv6 ranges, cloud
metadata IPs), and fails closed on hostnames that do not resolve. These are
validation helpers only: no active generic-web provider makes an HTTP request
or follows redirects. A `RedirectPolicy` is available for any future caller
that implements HTTP fetching.

**Residual risk (documented, not fixed):** DNS TOCTOU / rebinding.
`check_url_ssrf()` resolves the hostname and validates the resolved IPs, but
an HTTP client performs its own resolution at connect time, so an attacker
with control of authoritative DNS could present a public IP at validation
and a private IP at connection. Full mitigation requires **IP pinning**
(resolve → validate → connect to the validated IP with SNI/Host handling);
this is not implemented. The current generic-web provider makes no request,
so this is a conditional residual risk for any future caller that combines
URL validation with a separate HTTP connection; it is not evidence of a live
general-web capability. Constrain egress at the platform layer as well.


## Product Workspace, authorization proofs, and durable recovery (2026-09-29)

The public browser workspace is a view/controller over server-owned mission state; browser state is not mission truth. Its flow is:

```text
Public CSRF session + authenticated Owner cookie
  -> owner-scoped mission list/status/timeline/evidence/artifact/log APIs
  -> exact mission-bound workspace snapshot
  -> Owner-authorized mission start/pause/resume/cancel
  -> durable queue lease + one bounded runtime slice
  -> signed action/criterion evidence
  -> deterministic goal verification + signed completion proof
  -> persisted result displayed after reload
```

Mutating public calls remain same-origin, Owner-session authenticated, and CSRF checked. New browser missions bind to the server's fixed repository workspace; the request cannot select an arbitrary file root. Mission ownership is the stable authenticated account identity rather than a bearer session ID. Conversations are account-scoped; a different account cannot adopt an existing conversation by guessing its ID. Raw Owner-session identifiers are excluded from the public serializers.

The workspace presents backend mission status, current action/checkpoint, queue state, timeline, evidence, artifacts, logs, file contents, repository identity, and read-only Git status/log/diff. Mission state and evidence are reloaded from the service rather than inferred from JavaScript defaults. The Findings tab is deliberately derived only from existing signed system criterion-evidence records, with criterion/action/verification links; there is no separate persisted finding object, and the UI says so explicitly. Empty evidence is displayed as no signed evidence—not as a passing finding. The page may persist one non-secret, Owner-tagged conversation pointer for transcript restoration; the pointer is not authentication or mission authority. Transcript and Task records are fetched from the server only after the live Owner session is validated, and foreign-owner records are filtered out. Session credentials and mission authority are not stored in browser storage.

File reads are mission-root-relative, bounded, UTF-8 checked, and reject absolute paths, traversal, symlink escapes, secret/database patterns, and missing/out-of-scope missions. Git access is read-only; credential-bearing remote userinfo and case-insensitive nested environment, cloud, container, SSH, key, state-file, and database paths are omitted from reads/listings/diffs. Neither browser workspace nor Git view offers a write or deploy control.

### Owner authority and one-use execution proofs

The current registered tool surface is intersected with the explicit captured Owner tool budget. Model proposals cannot widen that budget. Unavailable tools are exposed with status only in the authenticated internal catalog and are omitted from every model-facing schema; final execution also rejects them. Production tool execution is routed through an Owner-direct or mission execution boundary carrying a typed Owner authorization decision, canonical request/mission/tool/argument/action binding, and a one-use signed proof. The final registry validates and consumes that proof before invoking a handler; missing, forged, modified, replayed, wrong-call, wrong-mission, and out-of-budget requests fail closed.

System completion requires nonempty required criteria, unambiguous verification, independently checked criterion evidence, and a system-signed completion proof bound to the mission state. A model statement, tool-returned `success`, Owner-supplied recovery narrative, boolean `verified`, or frontend fallback is not sufficient. The supported automatic checks are intentionally narrow (such as an independent current core-status read and an exact successful locally recorded project-test event); other criteria remain unverified until an independent verifier exists.

### Queue and restart behavior

The bridge starts one worker and the persistent scheduler from `bridge.main`. The durable queue caps active work at ten missions by default; scheduled retry counts and recurring schedules are rejected until those semantics are implemented. A queue lease is not the mission result: the worker renews it during runtime construction and blocking actions, executes bounded slices, releases nonterminal work, recovers expired leases while the process is running, and requeues interrupted leases after restart. A stale worker cannot overwrite a lease it no longer owns. An ambiguous `in_flight` checkpoint is never retried silently; it is shown for explicit Owner reconciliation, with the retry consequence disclosed. Owner reauthentication renews the existing account-bound snapshot and does not bypass mission scope or proof verification. Pause, cancellation, authorization failure, and queue status remain distinct from goal completion.

Owner, mission, queue/scheduler, and evidence data use private local storage files; Owner and system-evidence keys are persistent, local, and separate from model credentials. Back up the matching databases and signing keys together. The bridge binds to loopback only; no production reverse proxy or external hosting target is configured by this repository.


## Operational hardening and browser restoration (2026-09-29)

The durable worker caps active queue entries at 10 using an atomic enqueue check and returns `mission_queue_full`/HTTP 429 on overflow. A heartbeat renews the lease while a model or tool call blocks; ambiguous in-flight parallel tool results remain in `RECOVERY_REQUIRED` until Owner reconciliation. The scheduler accepts one-time dispatch only and explicitly rejects recurring schedules and scheduled retries that are not implemented. `PlanStep` prerequisites are enforced, while top-level cross-mission dependencies remain unsupported.

The `run_project_tests` registry capability is exposed only when `bubblewrap` and `prlimit` pass the startup sandbox check. Test code executes from a bounded, read-only, secret-filtered snapshot with cleared credentials and network isolation; a missing sandbox makes the tool unavailable rather than falling back to an ordinary subprocess. `scoped_http_probe` and general-web search are likewise marked unavailable and fail closed.

Browser persistence is server-authoritative. The client retains only a non-secret Owner/conversation pointer; the transcript and Owner-filtered Task records are restored through the authenticated conversation endpoint. Local acceptance verified the Owner session and transcript after page reload and after the 15-second reconnect poll following a localhost bridge restart. It did not call a live model provider. The exact local suite result and the separately observed Cloudflare build/deployment limits are recorded in [Current Runtime Truth](CURRENT_RUNTIME_TRUTH.md).
