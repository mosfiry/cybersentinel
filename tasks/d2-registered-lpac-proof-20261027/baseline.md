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

### Experimental branch status before the first Windows run

- The branch now contains a tests-only registered-profile storage gate and an exact-branch Windows Actions workflow that runs the four original native acceptance cases plus the new registered-storage case. It publishes sanitized JSON only; private JUnit is removed after extracting per-case outcomes and allowlisted parent token/Job attestations.
- Local focused checks: `80 passed, 12 skipped` on Linux. The skips are Windows-native cases and are not acceptance evidence. MinGW cross-compilation produced a PE32+ x64 executable; MSVC compilation and native Windows runtime remain unverified.
- The Windows workflow has not yet run for this branch. D2 acceptance remains `BLOCKED` until the exact-SHA Windows run is inspected. Network denial, true simultaneous task execution, crash/host-reboot recovery, and production integration also remain unvalidated; the ownership journal is per-run temporary storage, not reboot-persistent evidence.
