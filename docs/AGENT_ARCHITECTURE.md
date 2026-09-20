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

`AgentRuntime.plan()` is the only planner entry point. It supplies the authenticated Owner policy context to an optional OpenAI-compatible model. A model can propose a plan, but it cannot execute tools or authorize itself. `security/authorization.py` applies the fixed allowlist, argument schemas, maximum argument length, and maximum plan size before execution.

If all configured model providers fail or return invalid JSON, the runtime uses its deterministic defensive fallback. Provider name and model are retained as provenance in plans, execution events, and responses. No provider credential is returned to the client.
