# Agent Loop

`AgentCore.run_owner_mission()` authenticates the Owner, captures a policy snapshot, builds a model proposal through `ContextEngine`, converts valid tool proposals into a typed `Plan`, persists a Mission, and calls `MissionRuntime.run_to_completion()`.

Each Mission slice performs the following durable sequence:

1. Load Mission from `MissionStore`.
2. Enforce iteration and dead-loop budgets.
3. Select and record the next `PlanStep`.
4. Validate authorization and scope before execution.
5. Persist an in-flight checkpoint.
6. Execute the injected tool/runtime boundary.
7. Convert the result to an `Observation`.
8. Persist observation, action history, evidence, and trajectory events.
9. Classify failures through `FailureClass` and choose `RecoveryAction`.
10. Retry, request Owner input, block scope, replan, or fail explicitly.
11. Verify required criteria only after all plan steps are observed.
12. Persist `GoalVerified` and `MissionCompleted` only when evidence satisfies the criteria.

The loop is bounded by `max_iterations`, retry policy, idempotent action IDs, and dead-loop detection. It does not treat a provider response or a tool result as authorization.
