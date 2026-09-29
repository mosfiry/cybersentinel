# CyberSentinel Native Agent Core

`AgentCore` is the canonical Owner-instruction facade over durable `MissionRuntime`. Browser chat, internal chat, `/api/command`, and mission-backed `/api/tasks` all converge on this path; the task endpoint retains a compatibility `Task` envelope rather than a competing task execution engine.

```text
Owner chat
  -> owner authentication / challenge
  -> OwnerPolicySnapshot
  -> AuthorizationContext
  -> AgentCore
      -> ContextEngine
      -> provider tool proposal
      -> typed Plan / PlanStep
      -> MissionRuntime
          -> authorization and scope
          -> tool execution
          -> Observation
          -> Evidence
          -> verification / recovery / replanning
          -> durable MissionStore
  -> mission status + trajectory
```

The model has high agency to analyze and propose plans, but zero authority to create Owner identity, policy, authorization, or scope. External data, memory, tool output, and previous reasoning are untrusted context. Deterministic enforcement remains in the authorization, scope, registry, and runtime layers.

`MissionTaskAdapter` is the compatibility boundary for existing task API records. It binds records to stable Owner account identity, persists the canonical mission before any work is queued, reauthorizes resumes through `AgentCore`, delegates pause/cancel to canonical mission state, and refreshes task reads from `MissionStore`. The `run` request flag starts work by enqueueing it for the supervised worker; task creation never executes the long mission inline. `AgentTaskRuntime` is retained for legacy tests/callers but has no current bridge/API production caller. The canonical `PlanStep` prerequisite DAG validates missing, duplicate, and cyclic edges before execution, and the runtime refuses deterministic or model-proposed work whose predecessors are incomplete. Independent provider-backed specialist agents are not implemented; current expert-mode functions are deterministic analytical templates, not separate agents or authorities.
