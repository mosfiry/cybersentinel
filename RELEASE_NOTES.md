# CyberSentinel X 5.0.0 — Unpublished Release Candidate

**Status:** Candidate artifacts only. No final Git tag, public release, or production deployment has been created.

## Scope

The supported deployment target is a single-host Linux Docker Compose installation using a rootful Docker Engine 28 or newer and Compose plugin. The bridge is published only on loopback; one separately supervised worker shares the local named SQLite state volume. This is not a multi-host, high-availability, or public-internet deployment claim.

## Included hardening

- Owner-bound mission authorization, restart revalidation, independent deterministic completion verifiers, and integrity-linked reporting.
- Fenced worker execution and durable recovery behavior for process crashes, ambiguous effects, provider timeouts, response loss, and scheduler races.
- SHA-256 session references, descriptor-relative filesystem/process protections, and DNS-pinned outbound provider requests.
- Non-root container execution, read-only application filesystem, bounded logs, file-backed Compose secrets, isolated workspace initialization, and loopback-only host publishing.
- Versioned SHA-256 state backup/verification/restore that rejects symlinks and path traversal and refuses non-empty restore targets; the clean-environment rehearsal also checks representative legacy schema migrations.

## Verification and limits

The release candidate is generated from an exact source commit and its Docker image, bundle, and checksums are verified by CI before upload as an unpublished workflow artifact. CI runs the complete test suite, Docker build/smoke checks, and the isolated M3 lifecycle, migration, backup, restore, and cleanup rehearsal. The live-provider long-horizon test is skipped when no provider credential/factory is configured; no live provider is contacted. The Linux Docker target is validated in hosted CI, not on the local development computer.

The final V14 release gate remains outstanding. Do not treat these files as a public release or create a final tag until the owner separately confirms the exact proposed tag and artifact hashes.
