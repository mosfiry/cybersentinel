# Context Engine

`agent/context.py` builds provider context from authoritative policy/security material and untrusted conversation, memory, knowledge, and tool results. It validates roles, sanitizes sensitive tool-result keys, records provenance, hashes the context, deduplicates repeated content, and deterministically truncates optional material.

Required items are preserved during compaction:

- system instructions;
- Owner policy snapshot;
- security/execution context;
- current Owner objective/message;
- validated tool definitions.

Conversation history, memory, knowledge, and tool results are marked untrusted and are lower priority. `AgentCore` invokes this engine before initial planning and during replanning with observations. The context hash and truncation metadata are persisted in the surrounding task/mission provenance where available.

No raw chain-of-thought is persisted as authority state. Mission state stores objective, plan, observations, evidence, failures, verification, recovery, and provenance instead.
