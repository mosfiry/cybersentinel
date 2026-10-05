# Agent Intelligence Layer

`agent/intelligence_layer` is an additive control-plane package. It preserves the existing `Mission`, `MissionStore`, and canonical `MissionRuntime` path while adding typed agent/task graph, declarative skill, and artifact services.

The graph model validates lifecycle transitions, dependencies, cycles, retry bounds, deterministic ready-node ordering, concurrency capacity, and failure/cancellation propagation. Standalone graph persistence uses an owner-and-mission-bound SQLite store with schema version 1, optimistic revisions, and integrity checks. For canonical mission dispatch, `AgentCore` now enables `MissionTaskGraphAdapter`: it maps the Mission's current plan into a single coordinator graph and stores graph state inside the same integrity-covered Mission payload as checkpoints and action history. The default runtime concurrency is one; this is not child-agent or parallel-model execution. See [Mission-Atomic Task-Graph Dispatch](MISSION_TASK_GRAPH_DISPATCH.md).

The skill registry stores declarative, immutable revisions rather than executable code. A learning candidate requires a completed verified mission trajectory, independent critic acceptance, verification evidence, and deterministic no-side-effect fixtures. Owner approval, revocation, rollback, and current authorization remain explicit. The SkillExecutor still uses an injected dispatcher and is not integrated as the production MissionRuntime plan-step dispatcher.

`ArtifactStore` adds bounded opaque BLOB storage for reports, screenshots, sources, evidence, code, findings, and extracted data. Rows are append-only, owner/mission/task scoped, and protected by both a content digest and a manifest digest. Artifact bytes are not automatically executed, parsed, or inserted into model context.

`EventStore` adds append-only owner/mission timelines with idempotent writes, secret redaction, and verifiable hash-chain integrity. `EventBus` commits events before notifying observers. `HookRegistry` supports trusted host callbacks, rechecks its authorization adapter on every invocation, lets before-hooks veto only, and fails closed when pre-effect hooks or audit writes fail. Opt-in events/hooks reach canonical `ToolRegistry.execute` through `AgentCore`/`MissionRuntime`; other mission lifecycle, provider, evidence, and after-hook phases remain unintegrated. The evaluation package adds ten independent quality dimensions and owner-scoped immutable records; it has no authenticated product surface.

## Authority and integration boundary

> An agent, graph, skill, artifact, memory record, model proposal, or stored scope is not Owner authority.

The Mission authorization snapshot, `ToolSpec` registry, execution fence, and evidence validator remain the authoritative effect path. A graph node can gate existing plan-step order but cannot authorize a tool or convert a result into evidence. Skills cannot execute without their externally supplied dispatcher, and they are not the canonical mission-step dispatch path. Artifact, event, evaluation, and other auxiliary databases retain separate transactions; cross-store recovery, reconciliation, and coordinated backup are not claimed. Hashes do not prove Owner authorship.

## Verification

Targeted tests cover graph lifecycle/delegation and the integrated MissionRuntime path; skill candidate gates/revisions/revocation; artifact isolation/integrity; event-chain validation and canonical tool hooks; and evidence-gated evaluation. See `tests/agent_intelligence/`, `tests/test_mission_graph_runtime.py`, and `tests/test_agent_evaluation.py`. These establish bounded single-coordinator task scheduling and tested domain contracts, not production multi-agent execution, end-to-end Skill dispatch, universal hook coverage, or an evaluation product surface.
