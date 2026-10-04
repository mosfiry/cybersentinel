# CyberSentinel Windows Desktop Architecture (5.1.0 work branch)

This document describes `work/windows-native-local-llm`, based on the published `v5.0.0` source. The work branch adds a Windows-first local application without changing `main`, the existing release branch, or the published tag. It does not create a GitHub Release, tag, package registry entry, or production deployment.

## Components and lifecycle

```text
NSIS Installer
  ├─ Electron shell (trusted main process + sandboxed renderer)
  ├─ PyInstaller onedir backend under resources/backend
  └─ pinned llama.cpp CPU runtime under resources/llama
       └─ LocalModelManager loads a verified GGUF through RuntimeAdapter
```

Electron selects an available ephemeral loopback port and starts the bundled `cybersentinel-backend.exe` directly. It never searches for Python or a checked-out repository in packaged mode. A random bridge token and one-time desktop setup capability are generated per app process and passed only to the backend. Child output is drained but not forwarded to the renderer or an external terminal. The backend binds to `127.0.0.1`, serves the existing same-origin web app, and starts the durable `RuntimeSupervisor` mission worker.

At first run, the user creates an Owner password in the app. Electron sends it over a private IPC channel and posts it to a loopback-only backend route with the unexposed setup capability. The route is disabled outside Desktop mode, rejects an existing Owner account, checks the expected Origin, and creates the one local Owner account. Subsequent sign-in uses the existing Owner authentication, HttpOnly cookies, and CSRF flow; no password, token, or session identifier is stored in renderer storage.

SQLite databases, owner policy, local secrets, downloaded models, and managed project directories are separated from the installed application under Electron `userData`. A project may use an app-managed directory or a folder chosen by the native Windows folder picker. The absolute selected path remains in local backend state and is omitted from the public project response. Mission creation resolves the selected owner/project mapping server-side and applies that project's root to its authorization snapshot and execution context; the renderer cannot submit a broader scope.

## Local model management and runtime abstraction

The bundled catalog is pinned to immutable Hugging Face revisions and LFS SHA-256 digests. This build supports:

| Model family | Quantization | Minimum RAM | Recommended RAM | Approx. model size |
| --- | --- | ---: | ---: | ---: |
| Qwen3 4B | Q4_K_M | 8 GiB | 12 GiB | 2.50 GB |
| Qwen3 8B | Q4_K_M | 16 GiB | 24 GiB | 5.03 GB |
| DeepSeek-R1-Distill-Qwen 7B | Q4_K_M | 16 GiB | 24 GiB | 4.68 GB |

Before an install or activation, the backend checks platform, RAM, and free disk space. Downloads are allow-listed to HTTPS Hugging Face hosts, use a `.part` file and HTTP Range resume, enforce expected length, verify SHA-256, and atomically replace the final file. The verified model manifest and current operation state are persisted below `userData/local-model-manager`.

`RuntimeAdapter` is the Core-facing lifecycle protocol; `LlamaCppRuntime` is the current implementation. It launches the bundled CPU `llama-server` hidden, binds it to loopback only, creates a random per-process API key, checks runtime health, and exposes an OpenAI-compatible provider to the existing `ModelRouter`. Switching is blocked while nonterminal missions remain active. On app restart, the manager checks the persisted model metadata and restores the selected local runtime. After a model and runtime have been installed, inference does not need an Internet connection; online model discovery is not required because the catalog is bundled.

The bundled Windows runtime pins upstream `b11146`, the binary build referenced by the latest stable llama.cpp `v0.5.0` release notes; GitHub labels the binary build itself prerelease. Its exact archive size and digest, plus the pinned model revisions/digests, are recorded in [`LOCAL_MODEL_ARTIFACTS.md`](LOCAL_MODEL_ARTIFACTS.md).

The installer and user data are intentionally separate: future signed installers can replace the app/runtime while keeping databases, projects, and model files. This work does not enable auto-update or configure an update server; upgrades remain explicit versioned installers with SHA-256 manifests.

## Existing mission and safety architecture

The local UI calls the existing owner-authenticated mission APIs. It does not replace Owner authorization, mission isolation, Tool Registry, `ExecutionContext`, Scope Firewall, Target Identity, bounded execution/testing, deterministic Validator, evidence-chain integrity, provenance, reporting, durable queue fencing, checkpoints, or resume. Mission state, timeline, Evidence, Findings, reports, and pause/resume/cancel operations remain backend-owned. Core remains routed through `ModelRouter`; the local provider is selected only through the manager.

The inspected `v5.0.0`, Vibe, Workspace, and IDE branches did not expose durable per-mission sub-agent identities or a distinct child-agent run schema. The current interface therefore surfaces persisted plan steps, queue/worker lease state, and recorded tool results; it does not fabricate individual agent runs. A future child-agent ledger should be added in Core with authorization, budget, checkpoint, and evidence lineage before a per-agent UI is claimed. The existing multi-worker supervisor and bounded tool execution remain intact.

## Security boundary

- Renderer runs with `contextIsolation`, `sandbox`, and `nodeIntegration: false`; preload exposes only retry, Owner-bootstrap, and native-folder-picker methods. It exposes no filesystem, process, bridge token, setup capability, or direct IPC handle.
- Packaged mode passes only the required OS environment and generated process-scoped credentials to the child; it does not read `.env` or import arbitrary developer provider secrets.
- All public mission/project changes require the server-managed Owner session and CSRF. Native folder import additionally requires a main-process capability; path roots are validated on the backend.
- GGUFs are checked against a pinned digest on download and again before activation. The llama.cpp Windows archive is pinned by release tag, exact size, and SHA-256 during the build.
- Local inference listens only on loopback with a random API key. Runtime output is discarded by the child process.
- Findings remain provenance-aware: model proposals are marked unverified, and the report builder's deterministic evidence rules govern any `VERIFIED` result.
- The existing Windows fail-closed behavior for filesystem/Git views is retained where secure handle-relative/no-follow access is not available; it is not silently weakened to ordinary path traversal.

## Build and validation boundary

The full Python regression/security suite runs in the Ubuntu `tests.yml` workflow. The Windows x64 NSIS workflow runs a Windows-portable API/project/model/security subset, then locked npm install/audit, JavaScript syntax checks, icon/ICO validation, Desktop contract tests, verified runtime download and Windows CLI smoke, PyInstaller bundle smoke, Installer build, and SHA-256 manifest generation. The manifest records the full source commit SHA and installer digest. It runs on `windows-latest` for the dedicated work branch. Its artifact is attached to the Actions run and expires after 90 days. The repository is public, so branch/CI/artifact access follows GitHub's public-repository visibility; this is not a GitHub Release, package-registry publication, or production deployment. Signing-identity auto-discovery is disabled; the installer is unsigned.

Hosted CI can build and smoke-test the bundled backend, but this computer has no native Windows GUI or Wine. Therefore CI does not prove an interactive Windows install, SmartScreen flow, or first-run window behavior. API first-run and the package's backend resource tests are exercised separately; actual Windows interactive rehearsal remains an explicit limitation.
