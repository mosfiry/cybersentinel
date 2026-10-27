# Experimental task list

- [x] **1. Baseline and branch checkpoint.** Verify exact D2 HEAD, clean worktree, protected refs and available devices; create a separate experiment branch. Verify branch parent and preserve baseline.
- [ ] **2. Inspect and specify prototype contract.** Confirm only documented profile APIs are used; define unique run ID/profile name, durable ownership states, fail-closed duplicate/recovery behavior and redacted evidence schema.
- [ ] **3. Implement bounded native storage-gate fixture.** Use a new profile per run, obtain its actual storage path, bind a suspended trusted probe to a Job, validate actual LPAC token before resume, and make only bounded file/registry attempts. Ensure no mission dispatch.
- [ ] **4. Add lifecycle/evidence validation and Windows CI.** Add exact branch allowlisting without reducing test coverage; keep all four original native LPAC tests and their failures visible; upload evidence on failure and bind it to commit SHA/Windows build.
- [ ] **5. Execute and inspect hosted Windows run.** Preserve JUnit, redacted JSON and run URL. Do not call artifacts acceptance if the guard fails. Quarantine unclear cleanup.
- [ ] **6. Stop or continue at the gate.** If external profile writes are allowed or storage scope cannot be established, record `REGISTERED_LPAC_STORAGE_BOUNDARY_FAIL` or `INCONCLUSIVE` and stop before mission tests. Only if independently proven bounded, propose next isolation stages; no D2 closure without all task requirements.
- [ ] **7. Final review and checkpoint.** Run focused Linux checks, verify no skips were added, inspect all diffs, commit/push each logical slice, verify remote commit SHAs and protected refs, and report exact stage outcomes.
