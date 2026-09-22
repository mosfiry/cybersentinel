# Manus Integration Requests — Cyber Intelligence Layer (Expert 1)

Date: 2026-09-22
Author: Expert 1 (Cyber Intelligence & Adversary Emulation)
Audience: Expert 2 (Manus — architecture, runtime, authorization)

## Principle

The cyber layer NEVER modifies Expert 2 files. Integration is composition:
`cyber/mission_adapter.py` consumes runtime artifacts read-only and produces
case DATA (`cyber/case_engine.py`). Runtime events can never grant or restore
authority: authority-bearing keys are stripped before ingestion (tested in
`tests/test_cyber_case_engine.py::TestMissionAdapter`).

## Implemented integration points

| # | FILE | FUNCTION | REASON | STATUS |
|---|------|----------|--------|--------|
| 1 | `cyber/mission_adapter.py` | `build_case_from_mission(mission, events)` | Build a CyberCase (observations/evidence/hypotheses/unknowns) from MissionRuntime events | IMPLEMENTED (defensive: unknown event types recorded as unknowns, never dropped) |
| 2 | `cyber/case_engine.py` | `CyberCase.add_conclusion` | Conclusions must be traceable to non-contradicted evidence | IMPLEMENTED |
| 3 | `cyber/case_engine.py` | `add_vulnerability / add_technique` | Structural validation of CVE / ATT&CK ids (anti-hallucination gate) | IMPLEMENTED |

## Required changes (Expert 2 owned files — DO NOT apply without Manus)

| FILE | FUNCTION | REASON | REQUIRED CHANGE | DEPENDENCY |
|------|----------|--------|-----------------|------------|
| `agent/mission_runtime.py` | `run_model_loop` | The cyber layer currently receives events only via test fixtures; there is no public read API on the runtime event log | Expose a read-only event-log accessor per mission/run (e.g. `list_events(mission_id, run_id)`) or persist the in-memory event list in the mission store | `cyber/mission_adapter.build_case_from_mission` (already tolerant to any event shape) |
| `agent/mission.py` | `Mission` | `mission.scope` is not a standard field today; the adapter falls back to `None` | Optional: add a typed `scope` reference (ScopeSnapshot id) on Mission so the case can carry scope provenance | `security/scope.py::ScopeSnapshot` |
| `agent/mission_runtime.py` | model loop observation handling | Known residual: a tool result with NEITHER `success` nor `ok` key is counted as success (fail-open edge, documented in round-2 proofs) | Gate observation success on explicit key presence; return RECOVERY_REQUIRED on ambiguous tool results | Round-2 residual-risk list; `agent/observation_intelligence.py` |

None of these are blocking for the cyber layer: the adapter degrades safely
(records unknowns) with today's runtime.
