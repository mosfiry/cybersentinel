# Context Engine

`agent/context.py` builds provider context from authoritative policy/security material and untrusted conversation, memory, knowledge, tool results, and bounded Mission state. It validates roles, sanitizes sensitive tool-result keys, records provenance, hashes the context, deduplicates repeated content, and deterministically truncates optional material.

## Required and optional context

Required items are preserved during compaction:

- system instructions;
- Owner policy snapshot;
- security/execution context;
- current Owner objective/message;
- the canonical tool schemas sent to a tool-calling provider.

For initial AgentCore tool calls, schemas are charged to the budget as a separate provider payload; the duplicate textual tool list is omitted from the prompt. Generate-only observation analysis does not charge schemas that are not sent. Generic ContextEngine calls retain the textual tool summary by default. Conversation history, memory, knowledge, tool results, and Mission observations are untrusted and lower priority. Optional content that cannot fit is removed in deterministic priority order. Current Owner text is digest-marked if character truncation is needed; if required context or schemas still exceed the configured token ceiling, `ContextBudgetExceeded` is raised before the provider call rather than sending a partial policy or security context.

## Provider-window budgeting

When `AgentCore`'s configured `ModelRouter` exposes a context length, it sets a rough estimated-token ceiling at 80% of the window, reserving the remainder for generation and framing variance. The estimate includes message framing and, on tool-calling paths, canonical function schemas. Provenance records the estimate, limit, removed-token estimate, and estimator version (`utf8_heuristic_v1`). This is a rough deterministic heuristic that may undercount; it is **not** a guaranteed upper bound, model-native tokenizer, or measured provider token count.

The `ModelRouter` can read explicit window sizes from `LOCAL_LLM_CONTEXT_LENGTH`, `COLAB_LLM_CONTEXT_LENGTH`, and `HF_LLM_CONTEXT_LENGTH`; a generic provider uses `LLM_CONTEXT_LENGTH`. Values must be positive ASCII integers. The router uses the minimum declared window only across providers reachable under the active deployment policy (same deployment as the primary provider by default). Unknown primary locality restricts routing to that provider alone. If any reachable provider lacks a valid size, `context_length` is unknown and the estimated-token ceiling is disabled, while existing character, message, and schema caps remain. Explicit cross-deployment fallback makes those additional providers relevant to the window calculation. Configure the context size for each reachable provider according to its actual model deployment.

## Persistence and limitations

`AgentCore` invokes the engine before initial planning and during observation analysis/replanning. The context hash and truncation metadata are persisted in surrounding task/Mission provenance where available. No raw chain-of-thought is persisted as authority state; Mission state stores objective, plan, observations, evidence, failures, verification, recovery, and provenance instead.

The engine does not use an exact tokenizer, receive provider-side token usage feedback, summarize old context semantically, or create a durable recoverable context artifact. Long-term retrieval of evidence/artifact references and context hydration after restart remain separate gaps. When provider context metadata is absent, the engine cannot claim a provider-aware token budget.
