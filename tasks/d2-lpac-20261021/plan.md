# D2 investigation checkpoint plan

Base: `77515ed87435b051faf0d16a04ee89246eeff1aa` (D4). Isolated branch: `fix/blocker-d2-lpac-20261021`. Diagnostic commit: `feeb6236c70520931bb9e92c022b517aef77dd58`.

Existing incomplete repository plans were not overwritten. No main/tag/Skill Routing/Cloudflare/Workers Builds changes are permitted. No fallback, mock, non-equivalent LowBox or Job-only sandbox is permitted. Native CI is not interactive Windows acceptance.

## Ordered tasks

- [x] Verify HEAD, protected refs, existing CI logs/artifacts, device availability and failure stage directly.
- [x] Audit LPAC attributes, SID/capabilities, executable/cwd/environment, ACL/profile assumptions and Mission/Registry boundaries; obtain independent read-only root-cause and architecture reviews.
- [x] Add bounded failure-only diagnostics and portable source guards without changing native launch policy. Verify red phase, focused tests, cross-compile and native MSVC compile.
- [x] Run the existing strict Windows contract on this exact D2 branch. Preserve all four required LPAC tests and no-skip/missing-case rejection. LPAC remains red; Job and VHD primitives pass independently.
- [x] Run frozen D4 and final full local regressions, record every failure/warning/skip, inspect failing Linux CI and deterministically demonstrate its independent PID publication race without changing that test.
- [x] Verify D4 source blobs remain unchanged and record concrete backend design, acceptance matrix and native evidence limitations.
- [x] Commit and push the isolated diagnostic change only; preserve CI artifacts and logs on its exact SHA.
- [x] Save the final investigation/results/design checkpoint on this branch only; protected refs were rechecked unchanged before checkpoint publication.

## Open implementation/acceptance gates — not completed by this checkpoint

- [ ] Identify the exact missing Windows object via filtered trace/effective-access inspection, not merely Win32=2 or advisory NTSTATUS.
- [ ] Resolve profileless launch versus supported fully bounded profile storage without relaxing filesystem/registry/network permissions.
- [ ] Implement production LPAC+Job+bounded storage backend with atomic binding, handle/identity verification, network denial, resource accounting, cancellation/timeout/crash cleanup and authenticated start receipts.
- [ ] Pass all positive/negative native confinement tests and full regression without hiding Linux CI failures.
- [ ] Demonstrate real installed Windows local-model Mission GOAL_COMPLETED and restart/resume with current Owner authorization and unchanged strict D4 evidence gates.

**Stop condition:** overall D2 remains BLOCKED. Evidence and runnable diagnosis were improved, but no unverified backend is enabled. Full findings and exact test/CI outcomes are in `results.md`; the design is in `docs/architecture/D2_LPAC_ROOT_CAUSE_2026-10-21_AR.md`.
