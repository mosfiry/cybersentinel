# CyberSentinel Native Agent Core

The native Agent Core introduced in this phase is a compatibility-preserving facade over the durable `MissionRuntime`. The production mission path is `api/chat.py` with `mode=mission` or `mission=true`; the existing task path remains available for non-mission chat.

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

`AgentTaskRuntime` remains a backward-compatible task runtime for the existing chat contract. It already provides provider tool calls, bounded read-only parallelism, task events, and durable task persistence. It is not silently presented as the native Mission Core.
