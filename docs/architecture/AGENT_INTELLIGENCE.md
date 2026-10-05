# Agent Intelligence Layer

`agent/intelligence_layer` is an additive control-plane package. It keeps agent identity, task graphs, procedural skills, and artifacts separate from the existing `Mission`, `Task`, `MissionStore`, and canonical `MissionRuntime` path.

The graph model validates lifecycle transitions, dependencies, cycles, retry bounds, deterministic ready-node ordering, concurrency capacity, and failure/cancellation propagation. Graph persistence uses an owner-and-mission-bound SQLite store with schema version 1, optimistic revisions, and integrity checks. Delegated scope records must remain narrower than the parent authorization snapshot.

The skill registry stores declarative, immutable revisions rather than executable code. A learning candidate requires a completed verified mission trajectory, independent critic acceptance, verification evidence, and deterministic no-side-effect fixtures. Owner approval, revocation, rollback, and current authorization remain explicit; candidates are not executable.

`ArtifactStore` adds bounded opaque BLOB storage for reports, screenshots, sources, evidence, code, findings, and extracted data. Rows are append-only, owner/mission/task scoped, and protected by both a content digest and a manifest digest that binds provenance, trust classifications, scope, and identity. Database files are created with owner-only permissions where the host supports them. Artifact bytes are not automatically executed, parsed, or inserted into model context.

## Authority and integration boundary

> An agent, graph, skill, artifact, memory record, model proposal, or stored scope is not Owner authority.

The graph scheduler does not dispatch tools. The skill executor uses an injected dispatcher and rechecks revision and authorization before each step, but this repository has not yet wired that dispatcher through `MissionRuntime`, the execution fence, and evidence chain. Artifact storage is available as a service but is not yet transactionally coupled to mission completion or exposed through an Owner-facing artifact API.

The existing mission authorization snapshot, `ToolSpec` registry, execution fence, and evidence validator remain the authoritative effect path. The new graph, skill, and artifact databases are separate stores; cross-store recovery, reconciliation, and coordinated backup are not claimed.

## Verification

Targeted tests cover graph lifecycle, scope narrowing, scheduling and persistence; skill candidate gates, revisions, revocation, dispatch and audit events; and artifact owner isolation, append-only rows, payload/manifest tampering and size bounds. See `tests/agent_intelligence/`. These tests establish the new domain contracts, not production multi-agent execution or end-to-end skill dispatch.