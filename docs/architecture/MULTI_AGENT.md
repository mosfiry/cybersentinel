# Multi-Agent and Task Graphs

`agent/intelligence_layer/models.py` and `graph.py` provide typed agent/task records, a deterministic prerequisite scheduler, bounded retries/results, cancellation semantics, and delegated-scope checks. The standalone `TaskGraphStore` persists owner/mission-bound graph revisions. The graph itself never grants authority.

## MissionRuntime integration

`AgentCore` now enables graph-backed dispatch for new and resumed missions through `MissionTaskGraphAdapter`. The adapter maps the existing linear `PlanStep` sequence and prerequisite metadata into a single coordinator's bounded task graph. `MissionRuntime` must claim the dependency-ready node after the existing authorization checks and immediately before saving the in-flight checkpoint. The graph state is stored inside the same integrity-covered Mission record as the checkpoint/action history, so task claims and reported outcomes share the MissionStore transaction.

The graph does not replace `MissionRuntime`, `MissionQueue`, `ToolRegistry`, the authorization snapshot, execution fence, or evidence verification. A graph node is only eligible work. AgentCore's existing executor remains the only path to model-proposed/canonical tools. Graph results are unverified digests, not evidence.

## Multi-agent status

This is operational **single-coordinator task-graph scheduling**, not a parallel multi-agent runtime. It does not launch child agents or separate models, perform fan-out/fan-in, aggregate child quotas, or issue child-specific evidence. The default parallel-task limit is one. A process crash leaves an in-flight node quarantined with the Mission; it is not replayed based on graph readiness. Owner-confirmed effect reconciliation and cancellation preserve the existing rules.

## Verification

`tests/test_mission_graph_runtime.py` covers MissionRuntime dispatch gating, durable state, dependency rejection, bounded retry, authorization refresh/expiry, crash quarantine, and cancellation semantics. `tests/agent_intelligence/test_graph.py` covers lifecycle, DAG validation, least-privilege delegation, retries, cancellation, owner binding, bounded concurrency, and the standalone graph store. Cross-process parallel fan-out, child execution, joins, child evidence lineage, and production independent-agent acceptance remain open.
