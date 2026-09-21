# Phase 6K.6 Implementation Record

## Unified authorization chain

The implementation now creates an immutable `AuthorizationContext` after Owner authentication and policy snapshot capture. The context is request-bound, validates typed Owner evidence, carries the immutable policy snapshot, optionally carries a persisted `ScopeSnapshot`, and records fingerprints for evidence, instruction, policy, and scope. A separate immutable `AuthorizationDecision` is issued only from this context and binds the request, tool, risk class, decision timestamp, policy/evidence fingerprints, and argument hash.

`core.engine` uses the context for plan authorization and passes the resulting decision to the registry. `tools.registry.execute` no longer accepts `owner_authenticated` as an execution capability; Owner-only and scope-bound tools require a valid `AuthorizationDecision`, and argument tampering is rejected before the handler runs. The legacy boolean remains only in non-execution compatibility and audit fields, never as the sensitive execution authority.

## Task and crash-recovery binding

`AgentTaskRuntime.create_task` accepts an `AuthorizationContext`, derives the request ID from it, binds the generated task ID into a replacement immutable context, and serializes that context in the task execution state. On resume, the runtime reconstructs and validates the context rather than re-reading current policy. A missing or invalid context prevents sensitive model proposals from reaching execution. A persisted context whose evidence secret is no longer valid after a process restart is denied deterministically instead of being silently re-authorized.

Scope-bound task execution requires both a persisted scope snapshot ID in the task scope context and the same snapshot in the AuthorizationContext. The model cannot provide a scope string, target, policy flag, or authority field that becomes trusted state.

## Conversation provider and benchmark

`LocalModelConversationProvider` is an adapter for a local/router model. It validates a strict JSON response schema, rejects unknown fields and authority-like fields, validates known intent values, and returns an explicitly untrusted `ConversationActionProposal`. The provider does not issue tool calls or authorization decisions. The contract benchmark reports explicit `PASS`/`FAIL` records with `EXPECTED`, `ACTUAL`, and per-check details rather than placeholder quality scores.

## Verification

The Phase 6K.6 tests cover immutable context binding, forged boolean rejection, argument-bound decisions, persisted-context round trips, deterministic post-restart denial, raw scope confusion, parallel A/B request isolation, strict conversation output, task serialization, sensitive-task denial without context, core end-to-end provenance, and scope/red-team registry enforcement. The full project suite is run after the final changes; its result is recorded in the delivery report and commit metadata.
