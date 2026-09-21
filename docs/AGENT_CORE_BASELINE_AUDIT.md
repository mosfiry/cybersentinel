# CyberSentinel X Agent Core Baseline Audit

**Baseline:** `0aa3848` — `Refactor owner authority and remove model policy veto`

## Executive classification

The baseline contains several strong deterministic components, but it is not yet a single native long-horizon execution core. The most important boundary is that `api/chat.py` currently routes provider-backed conversations through `AgentTaskRuntime`, while `MissionRuntime` is a separate durable loop. The `create_from_owner_instruction()` helper is therefore useful but, before this phase, was **PARTIAL / UNWIRED** from the production chat path.

| Subsystem | Classification | Evidence | Finding |
|---|---|---|---|
| Owner authentication and policy snapshot | STRONG / IMPLEMENTED | `security/owner_policy.py`, `security/authorization_context.py`, `core/engine.py` | Typed evidence, immutable snapshots, policy provenance, and request binding exist. |
| Deterministic authorization and scope | STRONG / IMPLEMENTED | `security/authorization.py`, `security/scope.py`, `security/scope_resolver.py`, `tools/registry.py` | Tool authorization, schema validation, scope checks, and decision binding are present. |
| Conversation understanding | PARTIAL | `agent/conversation.py`, `agent/conversation_provider.py` | Typed intent and untrusted proposals exist, but the deterministic parser remains a baseline and is not a complete TaskProfile extractor. |
| Model routing | IMPLEMENTED / PARTIAL | `agent/model_router.py`, `agent/providers.py`, `agent/provider_api.py` | Provider-agnostic generation and tool-call capability reporting exist; streaming and broad structured-output normalization are incomplete. |
| Context budgeting and compaction | STRONG / IMPLEMENTED | `agent/context.py` | Required authority/security items are preserved; optional context is deduplicated and deterministically truncated. Mission-specific relevance selection remains PARTIAL. |
| Task execution loop | IMPLEMENTED | `agent/task_runtime.py` | Durable task loop supports model calls, tool dispatch, retries, duplicate call guards, persistence, and read-only parallel calls. |
| Mission execution loop | IMPLEMENTED / PARTIAL | `agent/mission_runtime.py` | Durable plan/observation/recovery/verifier loop exists; before this phase it was not the `/api/chat` production path. |
| Mission persistence | IMPLEMENTED | `agent/mission.py` | SQLite-backed JSON payload with checkpoint, plan history, action history, and authorization provenance. |
| Event/trajectory stream | PARTIAL | `core/db.py`, task events in `agent/task_runtime.py` | Task event lists exist; typed immutable Mission trajectory is being added in this phase. |
| Evidence chain | IMPLEMENTED | `agent/evidence.py`, `core/engine.py` | Hash-linked evidence records and verification are present. Mission evidence integration is PARTIAL before this phase. |
| Goal verification | IMPLEMENTED | `agent/planning.py`, `agent/mission_runtime.py` | Required criteria block premature completion. |
| Failure taxonomy and recovery | IMPLEMENTED / PARTIAL | `agent/planning.py`, `agent/mission_runtime.py` | Typed classes and bounded recovery exist; diagnosis, dead-loop strategy changes, and malformed model-call repair are being strengthened. |
| Replanning | PARTIAL | `agent/mission_runtime.py`, `agent/planning.py` | Replanning preserves objective and can replace steps; model-driven dynamic decomposition and rejected-plan history need integration. |
| Memory | PARTIAL | `agent/memory.py`, `agent/context.py` | Durable memory is separated and marked untrusted; mission memory/evidence memory/knowledge are not yet one unified typed state projection. |
| `/api/chat` integration | PARTIAL | `api/chat.py` | Existing path uses `AgentTaskRuntime` or legacy engine. Native `AgentCore` mission routing is being wired with backward compatibility. |
| Crash recovery | PARTIAL | `agent/mission.py`, `agent/task_manager.py`, `core/lifecycle.py` | Durable state and idempotency exist; process-crash and in-flight Mission recovery need explicit end-to-end coverage. |
| Observability | PARTIAL | `core/db.py`, task events | Structured metadata exists, but Mission-level event types and metrics are being standardized. |
| Open-source fusion | NOT INTEGRATED | External archaeology pending | No external code is copied. Concepts will be rewritten natively after license/source audit. |

## Strong boundaries that must remain

Model output is a proposal and cannot create Owner identity, policy, authorization, or scope. External data, memory, RAG, tool output, and prior model reasoning are untrusted data. Authorization, scope, tool schema validation, evidence validation, idempotency, audit, and resource limits are deterministic enforcement and must not be replaced with model refusal.

## Baseline risks

The largest architectural risk is duplicated execution authority: `AgentTaskRuntime`, `AgentRuntime`, `core.engine`, and `MissionRuntime` each own parts of planning or execution. The target phase must establish one CyberSentinel-native Agent Core while preserving compatibility adapters. A second risk is that context compaction is strong at the generic context layer but not yet explicitly driven by MissionState fields such as active plan, failure state, verification criteria, and next action.
