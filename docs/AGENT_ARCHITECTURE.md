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
