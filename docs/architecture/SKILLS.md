# Procedural Skills

## Implemented boundary

`agent.intelligence_layer.skills` stores bounded, declarative procedures rather than executable Python, shell, prompts, or arbitrary callbacks. Definitions have immutable version IDs, schemas, tool/scope declarations, ordered steps, test fixtures, provenance, confidence, and a content hash. SQLite stores owner-keyed revisions and append-only candidate/approval/revocation/deprecation/rollback events; run outcomes are also recorded as append-only events.

Candidates enter through `SkillLearningPipeline`: a canonical mission-owner resolver must match the selected owner; the completed Mission trajectory hash chain must include `MissionStarted`, `GoalVerified`, and terminal `MissionCompleted`; a separate critic must accept; and the existing `VerificationEngine` must return `PASS` for the evidence referenced by the candidate. The final immutable content hash, mission/trajectory, critic, validator and evidence IDs are stored in the append-only candidate event. The registry also requires current ToolSpec checks, deterministic no-side-effect fixture binding tests, and declared output validation. Candidates are not executable. Promotion, deprecation, rollback, and revocation require a configured trusted owner-authorization adapter that issues a typed grant matching the exact owner, action, skill, and version. With no adapter the operation fails closed. A rollback is an explicit owner action; approving a revision never silently selects an older revision.

Execution requires an active approved revision, a current typed `MissionAuthorizationSnapshot`, and a `DelegationScope` bound to the same owner, mission, target, and authorization hash. Required tools must be explicitly present in both mission and delegated grants; an empty tool set is not treated as a wildcard for skills. Skill scope is bounded by both mission and child scope. The active revision is re-read before every dispatch, and the dispatcher receives the exact immutable skill ID/version/hash to recheck at the effect boundary. Each step checks the snapshot action/tool/target and canonical ToolSpec argument schema, honors cancellation between steps, enforces bounded JSON/step/timeout limits, and requires evidence references when declared.

## Important integration boundary

This module never invokes tool handlers. The injected dispatcher is a host integration seam and **must** reauthorize current MissionRuntime, scope, ToolRegistry, effect fence, and EvidenceChain for every tool call and honor the step timeout. A dispatcher that does not do this is not a production-safe integration. End-to-end MissionRuntime skill execution is not claimed until such a dispatcher is wired and independently acceptance-tested.

Memory, examples, external sources, learning output, and skill text remain untrusted data. Confidence is metadata, not authorization or evidence. Test fixtures validate the procedure deterministically without executing side effects; separate integration tests are still required for actual tool behavior and evidence validation. Revocation removes a revision from the active head immediately. Content hashes detect modification but do not prove authorship; the owner approval adapter is the authority source.

## Schema and tests

Skill storage uses explicit schema version 1 in its own SQLite database. Existing Mission/Task/ToolSpec schemas are unchanged. Tests cover owner isolation, candidate gating, malformed/tampered revisions, required tool and scope limits, deterministic fixtures, immutable versioning, rollback, revocation, execution dispatch, evidence requirements, cancellation, and audit events.
