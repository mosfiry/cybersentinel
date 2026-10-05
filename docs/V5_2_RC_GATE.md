# CyberSentinel v5.2 production-completion branch: release gate

## Final acceptance status

| Gate | Status | Evidence |
|---|---|---|
| Source integrity | PASS | Branch `work/v5.2-production-completion`; tested product/code SHA `103516c9b58cc37eaacda40c8d11ba6878ba64e9`; based on v5.1.0 source `26739d9b01b3b1ff492854e7e21789be20b1be0e`. The final branch update `019110ab4bd762490f2fc37d14cad16040dffbd0` changes only this gate document. |
| Python | PASS | 1,225 passed, 1 skipped on the branch. |
| Node | PASS | 5/5 Desktop tests passed. |
| Windows CI | PASS | [Windows regression run 37243749816](https://github.com/mosfiry/cybersentinel/actions/runs/37243749816); Windows unit/API and Desktop contract coverage only, not real model inference or GUI acceptance. |
| Windows install | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | Current device inventory contains only the Linux Sandbox; no installer run. |
| First Run | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No interactive Windows application run. |
| Owner login | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No interactive Windows application run. |
| Hardware detection | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No interactive Windows application run. |
| Qwen3 download | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | `scripts/windows_acceptance.ps1` was not run. |
| Qwen3 integrity | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No Windows download or local integrity check was performed. |
| Qwen3 activation | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No Windows activation was performed. |
| Qwen3 real inference | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | CI, Linux tests, and mock/unit coverage are not accepted as Windows inference evidence. |
| Real Mission | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No Windows Mission using the local Qwen3 runtime was executed. |
| Evidence/Validator | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No Windows real-Mission evidence chain was produced. |
| Close/Reopen | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No installed Windows application process was closed and reopened. |
| Persistence/Resume | NOT TESTED — NO WINDOWS INTERACTIVE ENVIRONMENT | No post-restart Windows Mission/model state was inspected. |
| Remote catalog update | NOT IMPLEMENTED | The application loads the bundled, versioned catalog; no remote catalog updater is shipped. |

**RC decision: NOT RC — BLOCKED BY WINDOWS INTERACTIVE ACCEPTANCE.** No `v5.2.0` tag or GitHub Release was created. The `v5.1.0` tag, release, and assets were not changed.

## Scope and release boundary

This work is based on the published `v5.1.0` source and belongs on `work/v5.2-production-completion`. The published `v5.1.0` tag, release, and every release asset remain immutable. This branch does **not** create a `v5.2.0` tag or final release, rebuild/re-sign/replace the `v5.1.0` installer, or claim Windows certification from Linux results. `desktop/package.json` intentionally remains at `5.1.0` until a separately approved RC packaging step.

The code changes in this branch are additive around the existing model manager, runtime, owner session, desktop renderer, and mission core; they do not replace the validated v5.1 behavior.

## Current implementation contracts

- **Catalog:** `agent/local_runtime/catalog.json` is a versioned, data-only manifest with pinned repository revision, file name, byte size, SHA-256, license URL, backend compatibility, context length, and RAM/VRAM/CPU requirements. `catalog.py` validates schema and path/source safety before exposing entries. This separates catalog data from manager logic and permits future catalog revisions without refactoring the runtime.
- **Current catalog update boundary:** the application loads the bundled catalog. A future downloaded catalog must be publisher-signature-verified before it is passed to `load_catalog`; this branch deliberately does not ship an online catalog updater or invent a publisher key. The bundled manifest is not itself a signature.
- **Model lifecycle:** existing pinned downloader and manifest verification remain authoritative. Models are stored under the desktop user-data `local-model-manager/models` directory, outside the installer and repository. Downloads verify size and SHA-256 before atomic install; activation re-verifies the installed file.
- **Runtime:** llama.cpp remains the existing pinned Windows CPU runtime, bound to loopback with a generated API credential. The new inference check invokes only the active `local_llama_cpp` provider and validates provider/model identity; it cannot silently fall back to a remote provider. The UI offers an explicit stop action and reports runtime cleanup status.
- **Recommendations:** the manager reports recommended, compatible-but-not-recommended, and too-large categories from actual RAM/CPU/VRAM/disk inventory. GPU discovery currently uses `nvidia-smi`; a missing result is reported as not detected, not as zero GPU capability. GPU acceleration remains unavailable in the pinned CPU runtime.
- **Authorization and mission safety:** test/activate/stop use the existing public-session CSRF guard and owner authorization when an Owner account exists. Model changes, runtime stop, and inference checks are blocked while a non-terminal mission is active. Mission execution, tool authorization, scope checks, evidence, and persistence continue through the existing AgentCore/MissionService path.

## Update architecture for later production work

Keep independently versioned payloads and state boundaries:

1. **Application:** stage a signed, versioned installer/update outside user data; validate compatibility; switch only after health checks; preserve a rollback version.
2. **Catalog:** stage a publisher-signed catalog; verify signature, schema, source allowlist, revision, file digest, and compatibility; atomically promote it only after validation. The current loader supplies structural checks, not cryptographic provenance.
3. **Models:** retain content-addressed/pinned artifacts in the user model store; stage downloads beside the destination; verify before atomic promotion; never overwrite mission, evidence, owner, or user settings data.
4. **Knowledge packs:** store separately with version, provenance, and digest; validate schema and retrieval compatibility before activation; retain previous version for rollback.
5. **Migrations:** use explicit schema versions, backups, and a tested rollback path. Update code must never migrate or delete user state implicitly as a side effect of refreshing model/catalog data.

These are compatibility boundaries for future update work, not claims that an updater or signed feed has already been implemented.

## Windows acceptance

Run from PowerShell on a real Windows x64 computer with at least 8 GiB RAM (12 GiB recommended), at least the catalog's required free disk, Python 3.11+, Node 22+, network access, and a supported CPU. The script installs the pinned llama.cpp runtime into a unique temporary folder, downloads the pinned Qwen3 4B Q4_K_M model into a separate temporary user-data root, verifies it through the production manager, starts the real Windows process, calls real local inference, creates a disposable Owner session in an isolated database, runs the existing AgentCore status-tool mission path, reopens the durable MissionStore to verify mission/evidence persistence, and shuts down the runtime. This is real backend/core acceptance, not automated Electron UI testing or a full application-process close/reopen test; a manual UI/restart pass remains required after an RC installer exists.

```powershell
./scripts/windows_acceptance.ps1
```

Add `-KeepArtifacts` to retain the isolated acceptance root/model and temporary runtime for inspection. The script never uses or modifies the installed app's Owner database or model directory. A machine rejected by the normal hardware guard is not force-run.

The separate `Windows Model Manager Regressions` workflow runs fast Windows unit/contract tests only; it does not fetch a multi-gigabyte model or claim real inference. Passing that workflow is not a substitute for the real-device acceptance script. After the RC installer exists, perform a short manual Electron UI pass as well: first-run owner setup, model download/verification, activation, the local inference button, stop, mission execution, restart, and mission/evidence recovery.

## Security and release checklist

- Re-run the full Python suite and Desktop Node suite on this branch.
- Run the focused Windows workflow; run `scripts/windows_acceptance.ps1` on a compatible Windows x64 device and archive its JSON output.
- Confirm model-switch/stop/test are blocked by live missions and protected by CSRF/owner authorization.
- Confirm no external-provider fallback occurs during the local inference check.
- Confirm the catalog SHA/revision and runtime archive hash remain pinned and the updater does not trust an unsigned catalog.
- Review the application boundary, loopback binding, generated credential handling, scope firewall, tool authorization, evidence integrity, and persisted mission recovery.
- Build/sign a **separately named release candidate** only after Windows acceptance. Do not publish or tag the final `v5.2.0` release as part of this branch-completion task.
