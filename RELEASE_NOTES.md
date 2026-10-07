# CyberSentinel X 5.2.0-rc1 — Unpublished Release Candidate

**Status:** Candidate artifacts only. No final v5.2.0 Git tag, public release, or production deployment has been created.

## Scope

The supported deployment target is a single-host Linux Docker Compose installation using a rootful Docker Engine 28 or newer and Compose plugin. The bridge is published only on loopback; one separately supervised worker shares the local named SQLite state volume. This is not a multi-host, high-availability, or public-internet deployment claim.

## Included hardening

- Owner-bound mission authorization, restart revalidation, independent deterministic completion verifiers, and integrity-linked reporting.
- Fenced worker execution and durable recovery behavior for process crashes, ambiguous effects, provider timeouts, response loss, and scheduler races.
- SHA-256 session references, descriptor-relative filesystem/process protections, and DNS-pinned outbound provider requests.
- Non-root container execution, read-only application filesystem, bounded logs, file-backed Compose secrets, isolated workspace initialization, and loopback-only host publishing.
- Versioned SHA-256 state backup/verification/restore that rejects symlinks and path traversal and refuses non-empty restore targets; the clean-environment rehearsal also checks representative legacy schema migrations.
- Optional Electron Desktop shell for Windows x64, using the same loopback Python bridge and Owner-authenticated API. The renderer gets no bearer token; packaged launches require a separately provisioned backend repository via `CYBERSENTINEL_REPO`. The executable does not bundle Python, the repository, state, or backend secrets. Workspace file/Git views fail closed on Windows until secure handle-relative path access is implemented.

## Verification and limits

The release candidate is generated from an exact source commit and its Docker image, bundle, checksums, and installer manifest are verified before candidate artifacts are retained. The project CI includes the complete Python suite, Docker build/smoke checks, and the isolated M3 lifecycle, migration, backup, restore, and cleanup rehearsal. The live-provider long-horizon test is skipped when no provider credential/factory is configured; no live provider is contacted. The Linux Docker target is validated in hosted CI, not on the local development computer.

The Windows x64 Desktop installer and portable executable are built by a separate branch-scoped workflow. Linux-side packaging and static checks are not Windows interactive acceptance. Installation, GUI launch/close/reopen, local model inference, and the full desktop Owner flow are only claimed when they are actually exercised in a Windows interactive environment.

The workflow disables signing-identity auto-discovery and supplies no code-signing identity; the Windows executables are unsigned candidates. Windows may show publisher or SmartScreen warnings.

Acceptance status is determined only by the fresh evidence package bound to the exact candidate source commit. Historical audits do not establish current results, and a test Owner fixture is not the user's final Owner approval. No final tag `v5.2.0`, public release, registry publication, or production deployment has been created. Do not treat these files as a public release or as publication approval.
