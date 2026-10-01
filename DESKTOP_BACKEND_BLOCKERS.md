# Desktop Mission — Backend Blockers (observed, not fixed)

Backend is read-only for the desktop mission. The items below were observed
during the Phase 0-3 audit and were deliberately not modified. Each item
includes file, location, observed vs expected behavior, evidence, and
impact on the desktop application.

## B-1 — Mojibake in the max-steps chat message

- File: `agent/loop.py`
- Location: the `run()` method's max-steps fallback answer string (final
  Arabic sentence of `agent/loop.py` in PR #17 / branch
  `work/arabic-auth-ci-docs-20260929`).
- Observed behavior: the Arabic message contains literal bullet characters
  where Unicode escapes are expected, producing garbled output resembling
  "...أفصى للخطوات •u0627لمسموحة بها. يرجى إعادة صياغة طلبك أو •u062a•u0642سيمه •u0625•u0644ى •u0623•u062c•u0632•u0627•u0621 •u0623•u0635•u0631."
- Expected behavior: properly escaped Arabic text identical to the other
  Arabic literals in the same file.
- Evidence: PR #17 diff hunk for `agent/loop.py` (the answer string), read
  from the PR files API on 2026-10-01.
- Impact on Desktop: cosmetic only — a garbled chat message when the agent
  reaches max steps. No functional or security impact. Not fixed (backend
  freeze).

## B-2 — Runtime prerequisites are Owner responsibilities, not shell features

- File: `.env.example`, `bridge.py`, `security/owner_password_bootstrap.py`
- Observed behavior: the public web boundary returns
  `404 public_boundary_disabled` unless the Owner sets
  `PUBLIC_WEB_ENABLED=true` in `.env`, and Owner login requires an account
  bootstrapped locally (`python -m security.owner_password_bootstrap`).
- Expected behavior: this is by design (server-side authority, loopback
  binding, no browser-managed credentials).
- Evidence: `bridge.py` `_public_enabled`/`_public_guard` at the PR head;
  `.env.example` in the PR diff.
- Impact on Desktop: the packaged application cannot enable the backend or
  create the Owner account itself. The shell detects this state and shows a
  "backend disabled" screen with the exact remediation steps instead of any
  bypass. Recorded as a deployment prerequisite, not a defect.

## B-3 — Raw channel truncation is an audit-tooling hazard, not a repository defect

During the audit, fetching `bridge.py` (>32 KB) through the raw content
channel produced a truncated, reordered copy. The authoritative contract
was instead read from the PR files API and the complete diff. This affects
tooling choices for future audits, not the repository or the desktop
application.
