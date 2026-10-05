# Multi-Agent and Task Graphs

`agent/intelligence_layer/models.py` and `graph.py` add typed agent/task records and a deterministic prerequisite scheduler without replacing the existing mission runtime. The graph rejects cycles and unknown dependencies, enforces bounded nodes/results/retries, orders ready tasks deterministically, propagates failures, and records cancellation requests. `TaskGraphStore` persists owner/mission-bound revisions and detects stale writes and tampering.

A child `DelegationScope` is derived from a typed `MissionAuthorizationSnapshot`. Its tools, actions, target, scope, network, credential, workspace, and budgets cannot exceed the parent grant. Empty or missing child permissions do not become wildcards, and graph permission checks can only narrow—not replace—current runtime authorization.

## Execution status

This is a tested graph control plane, not a parallel multi-agent runtime. It does not launch agents, call models, dispatch tools, join results into a mission, or make graph results valid evidence. A production executor still needs to claim graph work through the existing durable MissionQueue/MissionRuntime path, preserve execution fences and recovery quarantine, and bind evidence to its producing agent/task. No new code bypasses those existing boundaries.

## Verification

`tests/agent_intelligence/test_graph.py` covers lifecycle transitions, DAG validation, least-privilege delegation, retries, cancellation, owner binding, bounded concurrency, and persistence. End-to-end multi-process fan-out, joins, restart reconciliation, and real parallel tool execution remain open acceptance gates.