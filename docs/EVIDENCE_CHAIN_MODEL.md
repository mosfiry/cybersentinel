# Evidence Chain Model — V6 Hardening Record

Status: VERIFIED at 492a7d1c324be83ff62a48a6db6465940bbf5a8a (V6 CI green;
record carried forward; re-verified green through 2eeefc2d).

## Chain invariants (source: agent/evidence.py + tests)

- Every evidence record is bound to mission, operation, tool_call_id and
  request_id; record hash is content-bound over the canonical record payload.
- Chain linkage: sequence position + previous-record hash + recomputed record
  hash. V6.2 FIX (7bae762): EvidenceChainStore.append drops any
  caller-supplied current_hash and recomputes it AFTER the chain position is
  assigned — chains built through observed()+append could previously never
  verify (silent integrity failure).
- Tamper resistance: direct database payload tampering rejected on load
  (verify_integrity raises); reordering, replay, and middle-record removal
  rejected by chain linkage; duplicates receive unique sequence slots with
  correct linkage; per-request isolation enforced.
- Authorization binding: unsigned evidence never supports a completion proof;
  substituted system evidence (action-binding forgery, signature forgery)
  rejected; evidence transplant across missions rejected (binding payload
  mismatch); workspace event evidence carries mission/operation chain binding.
- Completion: a mission completion proof requires deterministic verification
  evidence from the persisted verified state; a model final claim without
  evidence never completes (pinned across test_mission_state_machine_hardening,
  test_failure_recovery_replan, test_provider_failure_model).

## Honest limits

- The chain protects integrity of stored evidence; cross-mission E2E over real
  HTTP is covered by the public boundary battery, not by a dedicated
  evidence-over-HTTP test (routes verified read-only in
  docs/DESKTOP_BACKEND_CONTRACT.md).
- Evidence completeness for a SECURITY REPORT remains BLOCKED: no report
  backend exists in this lineage (V7 verdict, docs/VIBE_MISSION_STATE.md).

Tests: tests/test_evidence_chain_hardening.py (9 tests) + baseline
test_governed_execution.py evidence provenance assertions.
