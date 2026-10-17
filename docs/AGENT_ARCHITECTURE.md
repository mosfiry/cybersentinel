# CyberSentinel X Agent Architecture

CyberSentinel X is a local defensive agent. The active chat request path is:

```text
Bridge authentication
  -> Owner authentication
  -> api.chat.chat()/stream()
  -> AgentCore and live MissionIntent understanding
  -> MissionRuntime
  -> Owner policy, authorization, and explicit scope checks
  -> registered tool schema and bounded execution
  -> evidence, verification, and audit response
```

`X-CyberSentinel-Token` authenticates only the local bridge transport. Owner identity is established through the username/password bootstrap and login flow and a server-managed session. Protected internal mission routes revalidate that session through `X-CyberSentinel-Owner-Session`; the Desktop/public API uses HttpOnly session cookies and CSRF protection for writes. There is no runtime `OWNER_TOKEN` credential, and bridge transport authentication never grants Owner authority.

`AgentCore` and `MissionRuntime` use the configured model router to propose mission reasoning and actions. A model can propose a plan, but it cannot execute tools, authenticate an Owner, or authorize itself. `tools/registry.py` is the single source of tool metadata, handlers, risk classes, and argument schemas; deterministic authorization and scope checks apply before execution.

Each current mission preserves its request ID, authenticated Owner identity, policy and scope snapshots, and provider/model provenance. Tool proposals are schema-validated and authorized before execution; evidence and verification are persisted with the mission. The separate legacy `core.engine.handle()` path maintains its own `ExecutionContext` and plan-integrity checks but is not the current `/api/chat` or `/api/command` entrypoint.

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


## Owner instruction precedence and execution gates (updated 2026-10-17)

The normative instruction-source order reflects the Owner's explicit direction:

```text
OWNER_INSTRUCTION (900)
  > SYSTEM_PLATFORM (800)
  > OWNER_POLICY (600)
  > DETERMINISTIC_ENFORCEMENT
  > AUTHORIZATION_SCOPE
  > TOOL_RUNTIME
  > MODEL_OUTPUT
  > EXTERNAL_DATA
```

Semantics and hard boundaries:

- `OWNER_INSTRUCTION` is the highest normative instruction source; `SYSTEM_PLATFORM` is second. The numeric order is descriptive precedence metadata only, not an execution input or grant of permission.
- Authentication, explicitly Owner-selected scope, tool authorization, process sandbox, cancellation fencing, and evidence integrity are separate unconditional execution gates. Every applicable gate must pass; no instruction may bypass or relax a failed gate.
- OS sandbox capabilities, host/network policy, and provider-side limits are enforced as execution facts, not silently changed by a policy rank. There is no runtime `OWNER_TOKEN` credential.
- `security/authority.py` publishes the closed tier order and explicitly reports that Owner rank grants no execution permission; the live authorization code does not use tier numbers to permit tools.

## Runtime inventory — canonical vs evaluation-only status (verified 2026-10-17)

The audit established the live call graph (bridge → api → agent → tools) by
reading every entrypoint. Status:

| Module | Role | Live reachability |
| --- | --- | --- |
| `agent/mission_runtime.py` (`MissionRuntime`) | Canonical persistent mission engine | `AgentCore.run_owner_mission` / `resume_mission` — `/api/chat` and mission routes |
| `agent/agent_core.py` (`AgentCore`) | Facade/orchestration boundary over `MissionRuntime` | `api/chat.py` chat/mission entrypoints |
| `agent/task_runtime.py` (`AgentTaskRuntime`) | Compatibility task runtime | No current `api.chat` caller; `api.chat._runtime()` returns `MissionTaskAdapter` |
| `agent/runtime.py` (`AgentRuntime`) | Planner/status component retained by `core.engine` | `core.engine` uses its `RUNTIME` for status and the legacy handler; `/api/command` routes through `api.chat.chat()` |
| `agent/loop.py` (`AgentLoop`) | Removed from the product tree | Historical implementation is retained only as `evaluation/legacy_agent_loop.py` for tests; the file is excluded from release/Docker artifacts |
| `agent/conversation.py` (`ConversationParser`) | Removed from the product tree | Legacy deterministic contract moved to `evaluation/legacy_conversation.py` for tests and benchmarks; the file is excluded from release/Docker artifacts |
| `agent/conversation_provider.py` | Removed from the product tree | Legacy schema adapter moved to `evaluation/legacy_conversation_provider.py` for contract tests; the file is excluded from release/Docker artifacts |
| `agent/model_intelligence/conversation.py` | Live NLU (`NaturalLanguageUnderstanding` → `MissionIntent`) | `AgentCore.understand_mission_intent` / `run_owner_mission` |

Verified path and compatibility notes:

1. `/api/chat` and `/api/command` both use the current `api.chat` entrypoint,
   which delegates chat requests through `AgentCore` and `MissionRuntime`.
   `core.engine.handle()` has no in-repository production caller.
2. The old `AgentLoop`, parser, and provider implementations are no longer
   under `agent/`; only explicitly named evaluation copies remain for historical
   tests/benchmarks and are excluded from runtime artifacts.
3. No `owner_authenticated=True` trust path exists:
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

Do not confuse the live mission NLU with the legacy evaluation contract:

- `agent/model_intelligence/conversation.py` — live NLU for owner
  instructions in the mission path.
- `evaluation/legacy_conversation.py` and
  `evaluation/legacy_conversation_provider.py` — historical parser/provider
  contracts for tests and benchmarks only; not imported by product runtime.

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
