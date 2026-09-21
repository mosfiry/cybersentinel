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
