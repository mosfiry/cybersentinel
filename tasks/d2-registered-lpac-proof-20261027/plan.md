# Plan: Registered-LPAC isolation proof (experimental)

## Purpose and safety boundary

Build and run a **separate, non-production Windows experiment** for a unique registered AppContainer profile per run. The first native gate is profile storage: establish the actual profile folder and whether the LPAC fixture can create a bounded file or registry entry there outside the designated workspace/VHD. If an out-of-bound write succeeds or the boundary cannot be established, stop at that gate, record `REGISTERED_LPAC_STORAGE_BOUNDARY_FAIL` or `INCONCLUSIVE` as appropriate, clean up only resources whose ownership is proven, and quarantine any ambiguous resource. Do not launch a Mission, alter `MissionRuntime`/`ToolRegistry`, enable a production backend, grant capabilities, loosen ACL/network policy, or modify D4 acceptance semantics.

## Architecture decisions

- Start from D2 commit `42b475b355f0537cb01b8f1efbe91dd17ba11f2a` on a new branch only.
- Use documented Windows profile APIs (`CreateAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`, `GetAppContainerFolderPath`, `DeleteAppContainerProfile`); never edit private registry mappings.
- Give each experiment a CSPRNG-derived profile name/Run ID; an existing name is not adopted. Record an fsync'ed append-only ownership/lifecycle record under a protected per-run temporary root before provisioning and mark unresolved states quarantined, never infer ownership from PID alone. This record is not proof of persistence across host reboot.
- A trusted, tiny Windows fixture may be launched solely to probe the registered token and profile-storage boundary. It must be created suspended, bound to a kill-on-close Job before resume, and have its actual token checked before resume. It is not a workload or Mission.
- Preserve the original four native LPAC test cases, failures, exact-SHA evidence and artifacts. A green job/VHD/Linux result is not LPAC acceptance.
- Keep raw ProcMon PML/CSV and sensitive Windows paths/SIDs out of Git/public artifacts; publish only bounded, redacted summaries and hashes where suitable.

## Ordered work and acceptance gates

1. **Baseline checkpoint** — verify clean D2 start SHA and protected refs; create this experiment branch; save and push baseline + task plan. No code changes in this checkpoint.
2. **Prototype lifecycle contract** — add isolated tooling/tests for unique run IDs and registered profile creation/ownership states; refuse pre-existing or ambiguous profiles; make cleanup/recovery conservative and document limits. No production integration.
3. **Native storage gate** — run on Windows, create a dedicated bounded workspace (prefer the existing fixed-capacity VHD primitive), register fresh profiles, capture before/after profile inventory and actual local-data path, and probe only bounded file/registry fixtures as an LPAC child. Validate token and Job membership before resuming the fixture. Confirm all profile handles/child processes are closed before cleanup. If the fixture can write outside the accepted workspace boundary, stop and record the exact failure code; do not continue to Mission or broader workload testing.
4. **Strict Windows CI and evidence** — use a hosted Windows runner tied to the exact commit SHA; run the original four LPAC tests and the new registered-storage gate together with no skip/xfail/soft-failed native cases; retain sanitized per-case results, allowlisted token/Job attestations and failure artifacts; record Windows build and run URL. Upload no raw JUnit, trace, path or SID data to public artifacts.
5. **Further stages only if gate 3 passes** — evaluate broader file/network denial, true simultaneous task execution, cancellation/timeout, crash recovery and Mission only after an independently reviewed boundary proof. Host reboot recovery requires a persistent Windows environment and remains unproven by a disposable hosted runner. Any unproven condition remains `BLOCKED`, `FAIL`, or `INCONCLUSIVE`; never close D2 on partial evidence.

## Verification

- Baseline remote refs and branch parent match the exact values in `baseline.md`.
- Focused portable tests verify lifecycle journal parsing, fail-closed ownership decisions, source/workflow exact-case guards, and non-production wiring.
- On Windows: exact native case inventory (four legacy tests plus the registered-storage gate), no skipped/xfail/soft-failed cases, actual child token verified before resume, actual profile folder resolved by a handle-based final path, before/after filesystem/registry/VHD inventory saved, and artifacts bound to `GITHUB_SHA`, run ID/attempt and Windows version/build.
- After every increment: inspect staged diff, scan for secrets and raw artifacts, run focused tests, commit atomically, push without force, verify remote SHA and protected refs.

## Risks and stop conditions

| Risk | Mitigation |
|---|---|
| No interactive Windows device is available | Use the hosted Windows Actions runner for the native cases; its disposable lifecycle cannot prove recovery after host reboot, which remains `BLOCKED` absent a persistent Windows environment. |
| Profile local storage may be writable outside the VHD | Test this first with a bounded native fixture; success of an out-of-bound write is a hard stop. |
| Create/Delete profile APIs may leave partial state or open-handle residue | Append-only fsync lifecycle states; cleanup only after process-tree and handle closure; quarantine ambiguity. Do not claim reboot durability from runner temp storage. |
| Profile name/SID reuse or concurrent races | Cryptographically random per-run names, unique SID checks and no adoption of existing names. |
| Public artifacts may disclose SID/paths | Redact raw values; preserve raw traces only in approved private evidence storage. |
| Baseline workflow branch allowlists may prevent experimental CI | Add only this exact branch to existing triggers/guards; do not alter test inventories or success policy. |

## Task list

See [`todo.md`](todo.md). This plan does not authorize production rollout or D2 closure.
