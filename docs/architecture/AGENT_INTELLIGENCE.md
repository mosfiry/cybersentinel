# Agent Intelligence Layer

`agent/intelligence_layer` is an additive control-plane package. It keeps agent identity, task graphs, procedural skills, and artifacts separate from the existing `Mission`, `Task`, `MissionStore`, and canonical `MissionRuntime` path.

The graph model validates lifecycle transitions, dependencies, cycles, retry bounds, deterministic ready-node ordering, concurrency capacity, and failure/cancellation propagation. Graph persistence uses an owner-and-mission-bound SQLite store with schema version 1, optimistic revisions, and integrity checks. Delegated scope records must remain narrower than the parent authorization snapshot.

The skill registry stores declarative, immutable revisions rather than executable code. A learning candidate requires a completed verified mission trajectory, independent critic acceptance, verification evidence, and deterministic no-side-effect fixtures. Owner approval, revocation, rollback, and current authorization remain explicit; candidates are not executable.

`ArtifactStore` adds bounded opaque BLOB storage for reports, screenshots, sources, evidence, code, findings, and extracted data. Rows are append-only, owner/mission/task scoped, and protected by both a content digest and a manifest digest that binds provenance, trust classifications, scope, and identity. Database files are created with owner-only permissions where the host supports them. Artifact bytes are not automatically executed, parsed, or inserted into model context.

`EventStore` adds append-only owner/mission timelines with idempotent writes, secret redaction, and verifiable hash-chain integrity. `EventBus` commits events before notifying observers. `HookRegistry` supports trusted host callbacks, rechecks its authorization adapter on every invocation, lets before-hooks veto only, and fails closed when pre-effect hooks or audit writes fail. The evaluation package adds ten independent quality dimensions and owner-scoped immutable records; acceptance requires independent validation of evidence.

## Authority and integration boundary

> An agent, graph, skill, artifact, memory record, model proposal, or stored scope is not Owner authority.

The graph scheduler does not dispatch tools. The skill executor uses an injected dispatcher and rechecks revision and authorization before each step, but this repository has not yet wired that dispatcher through `MissionRuntime`, the execution fence, and evidence chain. Artifact storage is available as a service but is not yet transactionally coupled to mission completion or exposed through an Owner-facing artifact API. Events and hooks are not yet installed at every runtime boundary, and evaluation is not yet exposed through an authenticated product surface.

The existing mission authorization snapshot, `ToolSpec` registry, execution fence, and evidence validator remain the authoritative effect path. The new graph, skill, artifact, event, and evaluation databases are separate stores; cross-store recovery, reconciliation, and coordinated backup are not claimed. Event hashes and evaluation records do not prove Owner authorship.

## Verification

Targeted tests cover graph lifecycle, scope narrowing, scheduling and persistence; skill candidate gates, revisions, revocation and dispatch; artifact isolation/integrity; event-chain validation and hook authority; and evidence-gated evaluation. See `tests/agent_intelligence/` and `tests/test_agent_evaluation.py`. These tests establish domain contracts, not production multi-agent execution, end-to-end skill dispatch, universal hook coverage, or an evaluation product surface.
