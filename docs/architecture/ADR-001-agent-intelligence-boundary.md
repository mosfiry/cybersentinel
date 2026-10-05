# ADR-001: Additive Agent Intelligence Boundary

- **Status:** Accepted for the first implementation slice
- **Date:** 2026-10-05
- **Base:** `9b21361a685f9eb5c491dffc57ff5b6ab901d256`

## Context

CyberSentinel already has a durable `MissionRuntime`, `MissionStore`, `MissionQueue`, typed Owner authorization, target/scope enforcement, tool registry, execution fences, evidence chain, and validator. It has no production agent identity/child delegation graph. Replacing or bypassing the mission runtime would duplicate security and recovery authority.

## Decision

Add `agent/intelligence_layer` as a separate domain/control-plane package. It defines agent/task records and deterministic lifecycle transitions; validates a bounded DAG; selects dependency-ready tasks with a concurrency cap; stores owner/mission-scoped graph snapshots in a versioned SQLite table using CAS revisions and SHA-256 integrity; and derives explicit child constraints from a typed mission authorization snapshot.

This is a **graph and state-control layer only**. It does not execute a tool, contact a provider, authenticate an Owner, or issue mission authorization. A task claim requires the caller to supply and revalidate the exact current `MissionAuthorizationSnapshot`; its tool/action/target constraints are additionally checked against a derived child scope. The canonical executor remains `MissionRuntime`.

## Alternatives considered

1. **Extend the legacy `Task`/`TaskManager`:** rejected because the legacy task lifecycle is not the canonical mission execution or recovery source and has separate persistence.
2. **Add child state to `Mission` JSON directly:** rejected for this slice because adding an unsigned-payload field changes existing mission hashes and requires a carefully versioned migration of deployed records.
3. **Create a second autonomous tool runner:** rejected because it would split authorization, fencing, evidence, and recovery boundaries.

## Consequences

- Existing APIs and old mission/task payloads remain unchanged.
- Graph snapshots are durable but separate from MissionStore; callers must coordinate mission references and must not treat separate SQLite commits as atomic with mission/evidence writes.
- SHA-256 detects accidental/tampered payload changes but does not authenticate Owner authorship; active authorization is revalidated at claim time.
- Workspace, network, credential, action, and tool requests must be explicit and narrowed. A graph record or LLM proposal is never permission.
- Results and evidence references are pending validation or `UNVERIFIED`; graph completion does not imply a mission finding or success.

## Verification

The first slice is accepted only after lifecycle, DAG/cycle, scope narrowing, resource-limit, Owner revalidation, persistence/CAS, tamper, cancellation, retry, and compatibility regression tests pass. Real provider inference, browser, MCP, Windows GUI, and full multi-agent Mission acceptance remain separate gates.
