# CyberSentinel X Agent Architecture

CyberSentinel X is a local defensive agent. The active request path is:

```text
Bridge authentication
  -> Owner authentication
  -> current Owner policy
  -> AgentRuntime planner
  -> ModelRouter / provider fallback
  -> JSON extraction and schema validation
  -> deterministic tool authorization
  -> bounded tool execution
  -> evidence and audit response
```

The bridge accepts `X-CyberSentinel-Token` only for the local HTTP channel. Owner authority requires `X-CyberSentinel-Owner-Token`, which is checked against `OWNER_TOKEN`. There is no fallback between the two credentials.

`AgentRuntime.plan()` is the only planner entry point. It supplies the authenticated Owner policy context to an optional OpenAI-compatible model. A model can propose a plan, but it cannot execute tools or authorize itself. `tools/registry.py` is the single source of tool metadata, handlers, risk classes, and argument schemas; `security/authorization.py` applies the registry policy, maximum argument length, and maximum plan size before execution.

Each accepted request receives an `ExecutionContext` containing the request ID, authenticated Owner identity, policy fingerprint, and provider/model provenance. Planner responses use a closed schema and accepted plans are canonicalized and hashed before execution. The same hash is checked immediately before each handler call. Every tool receives an explicit authorization decision record containing its risk class, Owner requirement, policy version, and decision reason.

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
  process boundary, credential separation (bridge token vs Owner token),
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

## Runtime inventory — canonical vs compatibility status (2026-09-22 audit)

The audit established the live call graph (bridge → api → agent → tools) by
reading every entrypoint. Status:

| Module | Role | Live reachability |
| --- | --- | --- |
| `agent/mission_runtime.py` (`MissionRuntime`) | Canonical persistent mission engine | `AgentCore.run_owner_mission` / `resume_mission` — mission mode of `/api/chat` |
| `agent/agent_core.py` (`AgentCore`) | Facade/orchestration boundary over `MissionRuntime` | `api/chat.py` mission mode |
| `agent/task_runtime.py` (`AgentTaskRuntime`) | Live compatibility task engine | `api/chat.py` **default** mode (`create_task` / `run_to_completion`); each step routes through `core.engine.handle()` |
| `agent/runtime.py` (`AgentRuntime`) | Planner for the command engine | `core/engine.py` `handle()` (`/api/command`), also the planner under the task path |
| `agent/loop.py` (`AgentLoop`) | Legacy conversational loop | Not reachable from bridge/api except `tool_definitions()` imported by `bridge.py` for `/api/tools`; still imported by legacy tests |
| `agent/conversation.py` (`ConversationParser`) | Deterministic intent baseline (not dead) | `core/engine.py` `_handle_once()` |
| `agent/conversation_provider.py` | Model adapter for the conversation schema | Tests only (not imported by bridge/api/engine) |
| `agent/model_intelligence/conversation.py` | Live NLU (`NaturalLanguageUnderstanding` → `MissionIntent`) | `AgentCore.understand_mission_intent` / `run_owner_mission` |

Honest gaps against the "one canonical runtime" goal:

1. `/api/chat` in **default** (non-mission) mode executes through
   `AgentTaskRuntime` + `core.engine.handle()`, **not** `MissionRuntime`. The
   directive target (chat → AgentCore → MissionRuntime only) is therefore
   **not yet satisfied**; mission mode is opt-in via `{"mission": true}` or
   `mode: "mission"`.
2. `agent/loop.py` still contains an independent conversational loop
   (`AgentLoop.run`). It holds no independent security authority —
   `authorize_tool(item)` there is a structural preflight and real
   authentication happens inside `core.engine.handle()` via typed
   `OwnerAuthenticationEvidence` — but it remains a second loop that legacy
   tests depend on. Removing it requires migrating those tests, moving
   `tool_definitions()` into `tools/registry.py`, and updating the
   `bridge.py` import.
3. No `owner_authenticated=True` trust path exists anymore:
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

The `web` search scope is **explicitly unavailable**: the web provider raises
`ProviderUnavailableError` ("web search provider is not configured") instead
of fabricating results. `_search_with_http()` is a stub that returns an empty
list and never pretends to be a real search. Tool metadata
(`tools/registry.py`) describes the `search` tool as a local events/intel
search; the model must not assume a general web capability.

## SSRF protection and residual risk

`search/ssrf.py` validates scheme, host, port, length, blocked suffixes, and
blocked ranges (loopback, RFC1918, link-local, IPv6 link-local, IPv6
unique-local `fc00::/7`, `0.0.0.0/8`, IPv4-mapped IPv6 ranges, cloud
metadata IPs), and fails closed on hostnames that do not resolve. Redirects
are not followed by the web provider (`follow_redirects=False`) and a
`RedirectPolicy` exists for callers that follow redirects manually.

**Residual risk (documented, not fixed):** DNS TOCTOU / rebinding.
`check_url_ssrf()` resolves the hostname and validates the resolved IPs, but
an HTTP client performs its own resolution at connect time, so an attacker
with control of authoritative DNS could present a public IP at validation
and a private IP at connection. Full mitigation requires **IP pinning**
(resolve → validate → connect to the validated IP with SNI/Host handling);
this is not implemented. Until then, treat the SSRF check as a strong filter
with a known rebinding residual risk, and constrain network egress at the
platform layer.
