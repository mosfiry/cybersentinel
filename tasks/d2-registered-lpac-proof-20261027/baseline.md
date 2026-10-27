# Baseline snapshot — 2026-10-27

- Repository: `mosfiry/cybersentinel`, checkout `/workspace/cybersentinel-d2-lpac`.
- Starting branch: `fix/blocker-d2-lpac-20261021`.
- Starting HEAD and verified remote D2 head: `42b475b355f0537cb01b8f1efbe91dd17ba11f2a`.
- Starting worktree: clean.
- New authorized work branch: `experiment/d2-registered-lpac-proof-20261027`, created directly from the starting D2 SHA.
- Protected references read from `origin` before edits:
  - `main`: `8a3fd109c0e586db13ed48a7371ac9ad06465b74`.
  - D4 baseline: `77515ed87435b051faf0d16a04ee89246eeff1aa`.
  - `v5.1.0` tag object: `684b344c183da1dee8dfd229c93cef0fd29396a5`.
  - `v5.1.0` peeled commit: `26739d9b01b3b1ff492854e7e21789be20b1be0e`.
- Available execution device: Linux Sandbox only; no Windows desktop/VM is currently listed. The authenticated GitHub connector is available and the repository has `windows-sandbox-contract.yml` with a `windows-latest` native gate. Windows execution must therefore come from hosted Actions, if it can run for this experimental branch.
- Historical Windows acceptance remains red: prior exact-SHA records report all four original native LPAC cases failed at `CreateProcessW`, with the other 17 profileless workspace tests passing. This is historical evidence, not a result for this branch. See `tasks/d2-lpac-20261021/results.md` and the linked run records there.
- Initial prototype scope is tests/tools/workflow/documentation only. The product backend remains unavailable and fail-closed. `MissionRuntime`, `ToolRegistry`, production launch code, D4 contract, protected refs and release tags are out of scope.
- Official API references consulted: [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile), [GetAppContainerFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath), [DeleteAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deleteappcontainerprofile), and [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

The Windows registered-profile storage boundary has not yet been run or proven at this snapshot.


### Additional official registry API reference

[GetAppContainerRegistryLocation](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerregistrylocation) returns a registry-storage `HKEY` for the current profile and takes desired access; the documentation says access for another user requires impersonation. The prototype must not enumerate or write private AppContainer registry mappings as a provisioning interface. The native storage gate will treat registry storage as unresolved unless exercised inside the verified AppContainer context through this documented API.

### First Windows run and current debug checkpoint

- Exact-SHA Windows Actions run [`40471018156`](https://github.com/mosfiry/cybersentinel/actions/runs/40471018156) ran commit `fe60fd1afd0c849010a20faae6a3f77acb856b81` on runner image `win25-vs2026` / Windows build `10.0.26100`. The workflow uploaded both sanitized JSON artifacts; it did not publish private JUnit or raw stderr.
- All five expected native cases were collected with zero skips, but all five failed and the validation result was `INCONCLUSIVE`. The registered gate stopped at `post_exit_job_empty_attestation_missing`; it did not establish whether this reflects a failed CreateProcess/launcher step or missing/invalid post-exit output because the harness checked the attestation before surfacing launcher return details. Therefore this run is not evidence of a storage-boundary PASS or FAIL.
- The report did establish three distinct simultaneously existing registered profiles/storage paths, no reuse of a retired SID, and VHD cleanup. Two profiles were confirmed deleted; one was quarantined because Job emptiness was unproven. The fixture result had `mission_started=false`; network and broader host-file access were `NOT_RUN`/unvalidated.
- Local focused checks after adding diagnostic capture: `81 passed, 12 skipped` on Linux. The skips are Windows-native cases and are not acceptance evidence. MinGW cross-compilation produced a PE32+ x64 executable; native MSVC execution for the diagnostic correction is pending.
- A diagnostic-only code correction is in the working tree, not yet pushed: it records a sanitized launcher return code, fixed failure step, Win32 code and allowlisted broker facts, while keeping the Job/cleanup gate fail-closed. D2 acceptance remains `BLOCKED`; network denial, true simultaneous task execution, crash/host-reboot recovery, and production integration remain unvalidated. The ownership journal is per-run temporary storage, not reboot-persistent evidence.
