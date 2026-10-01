# B3-C5 Session 8 Checkpoint — verification + single-use nonce proposal (2026-10-01)

- CURRENT_PHASE: B3 - four-layer intent + canonical execution boundary (post-completion review track)
- CURRENT_UNIT: C5-S8 (independent verification + Case 15 design proposal)
- CURRENT_STEP: session closed
- LAST_COMPLETED_STEP: (1) CI re-verified GREEN at the review head:
  diagnostics/ci-b1a805859da8.md = result SUCCESS (1315 passed / 1 skipped),
  and the Actions check-runs API shows "test (3.13)" success on the checkpoint
  commit 8c4521ca (run 36281417798). (2) Independent source re-verification of
  the four Mission-2 claims at the branch head, without relying on prior
  session records: cross-run proof binding (run_id is inside the signed
  binding payload AND the serialization AND checked at verify() with
  RUN_MISMATCH AND against the live mission in validate_against_mission) -
  PROVEN at source; OWNER_DIRECT typed-decision enforcement (registry raises
  PROOF_INCOMPLETE before any handler when the decision is absent, plus
  decision/policy fingerprint binding) - PROVEN at source; Owner budget
  narrowing-only (security/owner_budget.py: intersection order-preserving,
  widened declaration raises OwnerBudgetError, absent policy budget fails
  closed) - PROVEN at source. B3-H2/H3/H4 closure claims are consistent with
  the existing batteries and were not contradicted anywhere in this pass.
  (3) Verified that RejectionCode.PROOF_REPLAY is defined but emitted nowhere
  today. (4) Wrote docs/runtime/DESIGN_PROPOSAL_SINGLE_USE_PROOF_NONCE.md
  (Case 15): single-USE consumption via a server-side proof_use ledger keyed
  by execution_binding_hash, consumed atomically at the registry boundary
  immediately before the handler, fail-closed on ledger unavailability, with
  the mandatory 14-test adversarial battery enumerated. NO code changes; the
  semantics flip requires explicit Owner approval.
- NEXT_STEP: Owner decision on Case 15 (single-use proofs). If approved:
  implement per the proposal section 7 order. If declined: continue B3-scope
  review only.
- LAST_VERIFIED_COMMIT: 8c4521cac284 (test (3.13) success, run 36281417798);
  marker head 4658ab1b (diagnostics only)
- TEST_STATUS: 1315 passed / 1 skipped / 0 failed (diagnostics/ci-b1a805859da8.md);
  unchanged by this session (documentation only)
- CI_STATUS: GREEN at the verified head; this session's commit is docs-only
- OPEN_ISSUES: Case 15 (single-use proof semantics) - proposal now exists,
  awaiting Owner decision; diagnostics/wrap_probe*.py legacy debris unchanged
  (harmless, outside B3-C5 scope)
- INVARIANTS_PROVEN: unchanged full H1 set; cross-run proof binding
  re-verified independently this session at source level
- INVARIANTS_NOT_PROVEN: proof single-USE (Case 15) - now has a concrete
  implementable design pending Owner approval
- FILES_CHANGED (this session): docs/runtime/DESIGN_PROPOSAL_SINGLE_USE_PROOF_NONCE.md
  (new), this checkpoint file (new). Zero code deltas.
- NEXT_SESSION_FIRST_ACTION: read this file and the proposal; verify CI green
  on this docs commit; then await/act on the Owner Case-15 decision. Do NOT
  start B3-C6, Phase A, or R2 without explicit Owner approval.
