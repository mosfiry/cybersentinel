# CHECKPOINT — Owner Authentication Migration, Session 11 (final in-scope hardening)

Branch: security/owner-password-auth-migration
Date: 2026-10-04
Prior checkpoints: docs/CHECKPOINT_OWNER_AUTH_MIGRATION.md (session 7),
docs/CHECKPOINT_OWNER_AUTH_MIGRATION_SESSION8.md,
docs/CHECKPOINT_OWNER_AUTH_MIGRATION_SESSION9.md,
docs/CHECKPOINT_OWNER_AUTH_MIGRATION_SESSION10.md

## SESSION 11 RECORD (unit X-K: last in-scope engineering closures)

1. Executed session 10's NEXT_SESSION_FIRST_ACTION: confirmed CI green on the
   docs commit 00edf2acfd65 (diagnostics/ci-00edf2acfd65.md = SUCCESS; commit
   checks page shows "test succeeded Oct 3, 2026").
2. X-K.1 (commit 5132aec9bda5): removed the inert legacy OWNER_TOKEN-era
   policy schema keys (require_owner_token / owner_phrase) from
   security/owner_policy.py and security/owner_policy.json — zero consumers,
   no fallback, no compatibility mode — plus guard test
   tests/test_owner_policy_legacy_keys_removed.py. This completes the
   repository-wide OWNER_TOKEN removal inside the policy schema.
3. X-K.2 (commit 03aa7265f6ac): atomic login throttle — each
   login/reset_password attempt consumes its failure slot inside a single
   BEGIN IMMEDIATE transaction BEFORE any KDF work, closing the documented
   check-then-record overshoot race. Removed _lockout_active /
   _record_login_failure entirely. New adversarial battery
   tests/test_owner_throttle_atomicity.py (concurrent bursts, locked
   correct-credential burst, unknown-username burst, reset slot accounting).
4. Byte-exact editing discipline maintained: base files verified via decoded
   b64 integrity exports with locally computed git blob SHAs equal to the
   GitHub-reported SHAs (owner_password.py 9e3d0d91..., owner_policy.py
   63db0f03..., owner_policy.json 24c8b08d..., core/db.py 28d45388...) before
   any modification.
5. Second-pass attacker review documented in
   docs/OWNER_AUTH_AUDIT_2026-10-04.md section 3.

## CHECKPOINT FIELDS

- CURRENT_PHASE: Mission 1 (owner password auth migration) — ENGINEERING
  COMPLETE + SESSION-11 FINAL IN-SCOPE HARDENING
- CURRENT_UNIT: X-K (legacy policy keys removal + atomic throttle)
- CURRENT_STEP: units X-K.1 and X-K.2 complete; CI verification in progress
  on 03aa7265 / 5132aec9 at session close
- LAST_COMPLETED_STEP: commits 03aa7265f6ac (atomic throttle + battery) and
  5132aec9bda5 (legacy keys removal + guard test)
- NEXT_STEP: confirm CI green on 5132aec9bda5 (write the diagnostics marker
  if the workflow did not run), then Owner-only steps
- LAST_VERIFIED_COMMIT: 00edf2acfd65 (CI SUCCESS, marker
  diagnostics/ci-00edf2acfd65.md); session-11 commits pending CI verdict
- TEST_STATUS: session-10 full suite GREEN at 5b1f13e1a818; session-11 adds
  tests/test_owner_throttle_atomicity.py and
  tests/test_owner_policy_legacy_keys_removed.py (CI verdict pending at
  session close)
- CI_STATUS: GREEN through 00edf2acfd65; 03aa7265 / 5132aec9 pending
- OPEN_ISSUES: (1) OWNER-LOCAL STEP NOT YET RUN:
  python -m security.owner_password_bootstrap (username mosfiry);
  (2) merge of the session-6..11 commits into main is an Owner decision;
  (3) documented residual tradeoff in docs/OWNER_AUTH_AUDIT_2026-10-03.md
  section 1 (transport-token holder can keep the Owner locked out) —
  fail-closed availability, not an authentication bypass; the overshoot
  race residual is now CLOSED by X-K.2; the inert-keys open issue is now
  CLOSED by X-K.1
- INVARIANTS_PROVEN: all prior invariants unchanged and green
  (username+password-only Owner auth on all live Owner-controlled paths;
  scrypt verifier-only; server-side session lifecycle; removed legacy token
  mechanisms stay removed with no fallback/compat mode — now including the
  policy schema keys; recovery fails closed; MODEL_OUTPUT/EXTERNAL_DATA
  non-authoritative; docs pinned by guard test; adversarial batteries
  green) — PLUS session-11: throttle slot consumption is atomic (no
  threshold overshoot under concurrent bursts, zero sessions minted on any
  rejection path, unknown usernames never create rows, window never
  extended during lockout); legacy policy keys can never reappear (guard
  test)
- INVARIANTS_NOT_PROVEN: none within Mission 1 scope
- FILES_CHANGED (session 11): 03aa7265f6ac (security/owner_password.py,
  tests/test_owner_throttle_atomicity.py), 5132aec9bda5
  (security/owner_policy.py, security/owner_policy.json,
  tests/test_owner_policy_legacy_keys_removed.py), this commit
  (docs/OWNER_AUTH_AUDIT_2026-10-04.md,
  docs/CHECKPOINT_OWNER_AUTH_MIGRATION_SESSION11.md)
- NEXT_SESSION_FIRST_ACTION: verify CI green on 5132aec9bda5 (and
  03aa7265f6ac) — read the commit checks; if a failure exists, diagnose and
  fix it (never hide it). If green, Mission 1 has NO remaining engineering
  work: direct the Owner to (1) run python -m security.owner_password_bootstrap
  locally (username mosfiry) and confirm owner_account_created, and
  (2) decide on merging the session-6..11 commits into main (ordinary
  merge, no force/squash). Only after that merge does Mission 2 (B3-C5)
  resume on security/b3-four-layer-intent. Do NOT start B3-C6, Phase A, or
  R2.
