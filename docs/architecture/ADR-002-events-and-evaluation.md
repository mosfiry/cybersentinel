# ADR-002: Durable Events, Veto-Only Hooks, and Multidimensional Evaluation

- **Status:** Accepted for the current additive implementation.
- **Date:** 2026-10-05.

## Context

CyberSentinel already records mission trajectories and contains benchmark/critic code, but it lacks a shared owner-scoped timeline, general hook contract, and durable evaluation-run record. Replacing the mission runtime or existing trajectory chain would risk breaking recovery and evidence fences.

## Decision

Keep `agent/trajectory.py`, MissionRuntime, and existing benchmarks intact. Add a separate versioned SQLite event journal with per-owner/mission ordering, idempotency, secret redaction and hash-chain verification. Event subscribers observe persisted events; they do not authorize or perform effects. Hooks are trusted host callbacks bound to an Owner, mission and phase, and recheck current authority on each invocation. Before-hooks can veto only and fail closed when authorization, handler behavior or audit persistence fails; after-hooks cannot reverse completed work.

Add owner-scoped immutable evaluation records with independent metrics and thresholds. Acceptance requires every required dimension and trusted evidence validation. Missing or unavailable evidence validation is indeterminate; safety failures and unsupported evidence reject. There is no single aggregate quality score and no authority is granted by a benchmark result.

## Consequences

The changes are independently testable and do not change mission, trajectory, or tool schemas. Separate databases mean no cross-store transaction is implied. Event hooks and evaluation storage are not yet wired into every runtime/UI boundary; full timeline, replay and product acceptance require later integration. SHA-256 provides integrity checking, not a signature or proof of Owner authorship.