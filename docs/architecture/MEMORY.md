# Memory and Context

`agent/memory.py` remains the durable structured-memory implementation. Its additive schema upgrade preserves owner, mission, agent, scope, domain, request, confidence, sensitivity, validation state, source, trust classification, and content hashes. Existing rows load with conservative defaults; new writes use full SHA-256 digests. Retrieval can filter by these identity and trust dimensions and ranks matching query terms deterministically without treating confidence as authorization.

Compaction is extractive and transactional. It writes a summary with source identifiers and hashes, then marks originals superseded rather than deleting them. A failed later group rolls back the entire compaction batch. Summaries do not cross owner, mission, agent, scope, or sensitivity boundaries, and their trust/confidence remains conservative.

`DurableMemoryProvider` preserves this metadata when projecting records into context. Memory and web results are still data, not instructions. Only the current authorized caller should supply owner/mission/request filters; unfiltered legacy APIs remain for compatibility and must not be used as a cross-owner retrieval path.

## Context limits

`ContextBudget` separately bounds messages and canonical tool-schema JSON. It retains system, Owner-policy, security, and the current user request as required content. If those protected instructions cannot fit, `ContextBudgetExceeded` fails closed. Oversized user text is shortened only with a visible marker containing the SHA-256 of the full original text; optional history, memory, tool summaries, and other context are dropped deterministically under the remaining budget.

The context hash includes complete tool definitions, schemas, and authorization metadata as well as message hashes. Tool schemas have their own default cap of 16,000 characters; this is a serialized-character budget, not a model-token estimator. Accurate provider-specific token accounting and durable `MissionContext` recovery remain unimplemented.

## Verification

`tests/test_memory_versioning.py` covers legacy migration, round trips, identity/trust filters, ranking, compaction and rollback. `tests/test_phase3_context.py` covers overflow, request preservation, message caps, tool-schema limits, context hashing, and secret non-disclosure. The new schema does not claim vector search or automatic memory promotion.