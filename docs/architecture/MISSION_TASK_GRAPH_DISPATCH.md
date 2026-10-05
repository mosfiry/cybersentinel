# Mission-Atomic Task-Graph Dispatch

## Status

`AgentCore` now enables a bounded `MissionTaskGraphAdapter` for both newly created and resumed missions. Direct `MissionRuntime` users can opt in with an `AgentGraphPolicy`; the compatibility default remains unchanged when no policy is supplied. The graph is an execution-order guard for the existing plan, not a source of authority or a second executor.

## Dispatch and persistence

The adapter deterministically maps each current `PlanStep` to one task node, maps prerequisite step IDs to graph edges, and activates one coordinator agent. The default AgentCore policy permits one running task at a time. It does not create child model sessions or perform parallel execution.

For each step, the canonical path is:

1. `MissionRuntime` validates the persisted current `MissionAuthorizationSnapshot` and its ordinary mission/action/scope rules.
2. The adapter validates graph identity, plan fingerprint, policy, authorization binding, dependencies, lifecycle, and revision. It will not widen or synthesize Owner permissions.
3. `MissionRuntime` runs its existing step authorizer and checks that strict executors accept the current execution fence.
4. The graph task is claimed using the typed current mission snapshot. That task state and the existing in-flight checkpoint are saved together in the integrity-covered `MissionStore` record before the executor is called.
5. AgentCore's existing executor and `ToolRegistry` remain the only tool/effect path; existing tool authorization, scope, event/hook, and fence checks still apply.
6. A returned result is recorded in the Mission action history and the graph node is completed or failed. The graph state, action history, checkpoint, and Mission cursor are saved together through `MissionStore`.

Graph node results contain a bounded result digest and are explicitly marked `UNVERIFIED`; they are not evidence or goal-verification proof. The adapter does not bypass the existing verification/evidence chain.

The graph envelope uses schema version 1 and is stored inside the Mission payload, so its graph revision and integrity hash are committed atomically with Mission state. Older Mission payloads load with an empty graph field; the next graph-enabled MissionRuntime creation initializes it. The standalone `TaskGraphStore` remains available for domain use but is not a second persistence authority for graph-backed mission dispatch.

## Recovery, refresh, and cancellation

- A graph task is never retried merely because it is `RUNNING` or a worker restarted. An unresolved in-flight Mission remains quarantined by the existing recovery path.
- After authenticated reconciliation records a canonical completed/failed action, the graph can be reconciled from that action history. An Owner-confirmed `reconciled_no_effect` checkpoint is the only path that permits rebuilding a changed plan while discarding its old running node.
- A fresh authorization snapshot may rebind a graph for the same plan while preserving completed/failed task states; it does not change MissionRuntime authorization.
- If graph identity, revision, dependencies, current plan, or recovered action state conflict, MissionRuntime safety-blocks before dispatch.
- Owner cancellation marks pending graph nodes cancelled. For a running or ambiguous effect it records `cancel_requested` and leaves the node running; cancellation does not claim that the external effect stopped. Recovery-required Mission status remains authoritative.

## Evidence and remaining limits

The graph schedules plan steps for one coordinator only. It does **not** launch independent child agents, call separate models, fan out or join parallel workers, create child-specific evidence chains, or make graph results authoritative evidence. `SkillExecutor` is still not the canonical production plan-step dispatcher. Browser automation, MCP transport, authenticated graph/evaluation APIs, Windows acceptance, and real-model/local-inference acceptance are not provided by this integration.

Focused integration tests live in `tests/test_mission_graph_runtime.py`; they cover dependency rejection before executor dispatch, persistence, authorization refresh/expiry, bounded retries, crash quarantine, and Owner cancellation semantics. Existing MissionRuntime, execution-fence, recovery, and authorization suites remain regression gates.
