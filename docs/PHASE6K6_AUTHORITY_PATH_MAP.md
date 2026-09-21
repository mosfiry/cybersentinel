# Phase 6K.6 Authority Path Map — Initial Audit

**Baseline:** `33f20a4`  
**Status:** initial code audit, before Phase 6K.6 modifications.

## Current request/chat path

```text
api/chat.py
  → core.engine.handle / _handle_once
  → owner token verification or owner-session evidence
  → capture_policy_snapshot
  → conversation parser / AgentRuntime planner
  → authorize_plan(owner_evidence, policy_snapshot)
  → scope context checks in core.engine
  → tools.registry.execute
  → core.db audit event + evidence
```

## Current persistent task path

```text
AgentTaskRuntime.create_task
  → TaskManager.create_task
  → Task persisted in SQLite
  → task objective stored in ConversationMemory

AgentTaskRuntime.run_slice
  → _valid_owner_session re-verifies token or active session
  → _context calls current_owner_policy_context()
  → model output parsed into ToolCall
  → _run_one
      → authorize_tool(item)  [STRUCTURAL-ONLY; no evidence]
      → scope resolver for scope-required tools
      → executor / tools.registry.execute(owner_authenticated=True)
      → Task.record_tool_call
      → tool result stored in memory
```

## Findings

1. `AuthorizationResult` is not a full immutable `AuthorizationDecision`: it lacks request ID, evidence fingerprint, policy fingerprint, scope fingerprint, timestamp, and decision source.
2. `authorize_tool()` still supports structural-only mode and legacy boolean parameters. It is suitable for schema preflight but not as the final authorization boundary.
3. `AgentTaskRuntime._run_one()` uses structural-only authorization and then reaches execution through a separate boolean path. This is the central confused-deputy gap for Phase 6K.6.
4. `AgentTaskRuntime._context()` reads `current_owner_policy_context()` on resume instead of consuming a serialized request-bound policy snapshot.
5. `Task` persists request/session IDs but not an `AuthorizationContext`, policy snapshot, scope snapshot fingerprint, or authorization decision provenance.
6. `TaskRuntime._valid_owner_session()` re-authenticates a token/session at resume. This creates a second authority path; it must validate the context supplied by the upper boundary instead.
7. `tools.registry.execute()` accepts `owner_authenticated: bool`; this must become an internal execution capability derived from a validated authorization context/decision, not model or task input.
8. `ScopeSnapshot` is immutable and persisted separately, but there is no immutable bridge binding it to Owner evidence, request ID, policy snapshot, and task.
9. `ConversationProvider` exists only as a protocol-like shape in the parser module. There is no strict schema parser or LocalModelConversationProvider adapter.
10. The conversation benchmark has fixed/placeholder metrics such as `evidence_grounding=0.0`, `memory_resistance=0.0`, and `recovery=0.0`; it is not yet a PASS/FAIL/EXPECTED/ACTUAL benchmark.

## Required unified target

```text
OwnerAuthenticationEvidence
  → OwnerInstruction
  → OwnerPolicySnapshot
  → ConversationContext
  → Untrusted Model Proposal
  → AuthorizationContext (immutable)
  → AuthorizationDecision (immutable)
  → ScopeSnapshot binding
  → Task persisted context
  → Tool Firewall
  → Execution capability
  → Evidence/provenance
```

No model output, memory item, RAG result, expert statement, tool output, bare token boolean, or free-form scope string may construct the authorization context or decision.
