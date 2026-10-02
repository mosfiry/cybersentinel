# Release Readiness — V15 Matrix

Status vocabulary: VERIFIED / PARTIALLY VERIFIED / NOT VERIFIED / BLOCKED.
The words READY / PRODUCTION READY / FINAL are deliberately not used.

| Component | Source SHA | Tests | Security tests | Integration | Provider acceptance | CI | Deploy | Known blockers | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Mission lease/queue/scheduler (agent/mission_worker.py) | b58e432b | VERIFIED | VERIFIED (fencing matrix 13 tests; V12 injection battery) | VERIFIED (service facade tests) | N/A | VERIFIED (green runs above) | NOT VERIFIED | none new | tests/test_lease_fencing.py, tests/test_run_at_contract.py, tests/test_v12_adversarial_surface.py |
| Mission runtime / state machine (agent/mission_runtime.py, mission.py) | b58e432b | VERIFIED | VERIFIED (10-test hardening battery; GOAL_COMPLETED invariant) | VERIFIED | VERIFIED (failure model battery) | VERIFIED | NOT VERIFIED | none new | test_mission_state_machine_hardening, test_failure_recovery_replan, test_provider_failure_model |
| Evidence chain (agent/evidence.py) | b58e432b | VERIFIED | VERIFIED (9-test battery + V6.2 fix) | VERIFIED | N/A | VERIFIED | NOT VERIFIED | none new | docs/EVIDENCE_CHAIN_MODEL.md |
| Agent core (agent/agent_core.py) | b58e432b | VERIFIED | VERIFIED (request_id contract incl. V12.1 no-normalization hardening) | VERIFIED | VERIFIED | VERIFIED | NOT VERIFIED | none new | tests/test_request_id_contract.py, tests/test_v12_adversarial_surface.py |
| Bridge (bridge.py) | UNCHANGED from 71ce3c95 | VERIFIED (public boundary battery) | VERIFIED (CSRF/origin/session batteries) | VERIFIED | N/A | VERIFIED | NOT VERIFIED | BLOCKED: no security-report retrieval route; BLOCKED: no Owner approval route (Owner decision) | docs/DESKTOP_BACKEND_CONTRACT.md, VIBE_SECURITY_AUDIT.md |
| Knowledge fabric (knowledge/, cyber_data/) | b58e432b (no runtime change) | VERIFIED | VERIFIED (non-authority invariants pinned) | VERIFIED | N/A | VERIFIED | NOT VERIFIED | license gate; generator metadata; freshness policy (design gaps) | docs/KNOWLEDGE_SUPPLY_CHAIN.md |
| PoC validator (cyber_data/poc_validation.py) | b58e432b | VERIFIED (6 tests) | VERIFIED (no-upgrade invariants) | NEW (no consumers yet) | N/A | VERIFIED | N/A | validator only; actual training data NOT VERIFIED (absent) | tests/test_poc_validation.py |
| Desktop shell (desktop/, branch desktop/windows-exe) | 5dc5e1cb | VERIFIED (build run 36851558192, artifact produced) | VERIFIED (sandbox/contextIsolation config audited) | PARTIALLY VERIFIED | N/A | VERIFIED | NOT VERIFIED | Windows launch NOT EXECUTED; PR #18 open, unmerged | docs/DESKTOP_ARCHITECTURE.md, PR18_AUDIT.md |
| Full pytest suite | b58e432b | VERIFIED green | — | — | — | VERIFIED (5 green check runs) | NOT VERIFIED | vibe-diagnostics.yml must be removed at release gate | check runs 110849021668 / 110848999747 / 110849022006 / 110848999900 / 110849115268 |

Release blockers (BLOCKED on Owner decisions, per mission §26):
1. Owner approval route (authority-model change).
2. Security report retrieval route (report-generation backend does not exist;
   building it is new feature scope).
3. Knowledge licensing gate (policy decision).
4. Workers Builds pre-existing failure (infra, present on every branch).
