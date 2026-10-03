# Owner Authentication Audit — Session 10 Addendum (2026-10-03)

Branch: security/owner-password-auth-migration (engineering head 5b1f13e1a818)

Purpose: close the three actionable accepted risks recorded in
docs/OWNER_AUTH_AUDIT_2026-10-02.md section 2 with engineering that requires
no Owner decision. The inert config schema keys (require_owner_token /
owner_phrase) remain unchanged per the session-2 decision; they still have zero
consumers and never influence authentication.

## 1. X-J.1 Login throttling (closes: "no login throttling")

- security/owner_password.py now enforces a DB-backed, deterministic,
  fail-closed lockout: LOGIN_FAILURE_THRESHOLD = 5 consecutive failures,
  LOGIN_LOCKOUT_SECONDS = 300, stored in the new owner_login_throttle table
  (core/db.py SCHEMA, CREATE IF NOT EXISTS — existing databases migrate
  automatically on next connect).
- Keying: only the canonical username can ever create or move a throttle row.
  Failures with any other client-supplied username are dummy-verified and
  rejected without touching the table, so the table cannot be flooded (at most
  one row exists).
- During lockout, login runs the dummy scrypt verifier (timing-equalized) and
  rejects with the generic invalid_credentials error; the real verifier is
  never consulted while locked, so repeated attempts cannot mount a KDF
  oracle. Even CORRECT credentials are rejected until the window elapses.
- The reset_password current-password check is the same class of KDF oracle;
  it shares the same lockout (locked resets reject with the generic error and
  record nothing).
- Successful login or reset clears the counter. Attempts made during lockout
  do not extend the window (nothing is recorded while locked). After expiry,
  the next failure starts a fresh window (a counter at/above the threshold
  resets to 1), so a sustained lockout requires continuous attack traffic.
- Documented tradeoff (accepted): a caller holding only the transport
  BRIDGE_TOKEN can deliberately keep the Owner locked out (availability,
  fail-closed, never an authentication bypass). Residual race: the
  lockout-check and failure-record are separate statements, so a burst of
  concurrent attempts can overshoot the threshold slightly before the lock
  engages — impact is a few extra scrypt verifications, no authorization
  impact, local single-user tool.

## 2. X-J.2 Bootstrap atomicity (closes: "check-then-insert race")

- create_owner_account computes the verifier before opening the transaction,
  keeps the friendly existence pre-check, and treats the UNIQUE constraint on
  owner_accounts.username as the authoritative guard: sqlite3.IntegrityError
  on the INSERT is rolled back and converted to the same generic
  PermissionError (owner_account_already_exists). A concurrent double
  bootstrap can never produce a duplicate Owner row.

## 3. X-J.3 Authenticated logout (closes: "unauthenticated logout revocation DoS")

- bridge /api/auth/logout now requires proof of possession of the live session
  token itself (the X-CyberSentinel-Owner-Session header, resolved
  server-side with status, expiry, account-status, and auth_method checks).
  A body-supplied session_id is never consulted. Without a live session the
  endpoint fails closed with 403; replaying a revoked token also yields 403
  because the revoked session no longer resolves. The route remains behind the
  transport BRIDGE_TOKEN check.
- In-process idempotent revocation by token remains available via
  security.owner_password.logout (callers necessarily hold the token).

## 4. Adversarial battery (tests/test_owner_auth_hardening.py, 11 tests)

- Lockout rejects CORRECT credentials fail-closed with zero sessions minted.
- Lockout expiry restores correct-credential login.
- Successful login resets the counter.
- Attempts during lockout do not extend the window.
- Twenty unknown-username failures create zero throttle rows and do not
  affect the canonical account.
- Forged claims (magic strings, role/boolean JSON) mint nothing during
  lockout.
- reset_password failures drive and share the lockout.
- Bootstrap race: stale-SELECT simulation forces the INSERT path onto the
  UNIQUE constraint; generic PermissionError, exactly one account row, and
  the original verifier intact.
- Bridge logout: no header -> 403 with the session still resolvable; forged
  header -> 403 with the session still resolvable; proof of possession ->
  200 and revoked; replay -> 403; naming another session in the body never
  revokes it.

## 5. Verification

- Base files were verified byte-exact before editing: computed git blob SHAs
  matched the GitHub-reported SHAs for security/owner_password.py,
  core/db.py, and bridge.py at c8bc416eb5c9.
- Commit 5b1f13e1a818 CI verdict (read from the check-runs API): test (3.13)
  SUCCESS, test SUCCESS, export SUCCESS. The Cloudflare Workers Builds
  failure is the long-documented pre-existing check that fails on every
  branch and is unrelated to this work.
- Second-pass attacker review: no alternate path added (module-level logout
  requires the token itself); no legacy bypass or compatibility mode; the
  throttle only ever rejects (no widening, no fresh identity minting); the
  schema change is additive; no password material appears in the new code or
  tests (isolated test password only).

## 6. Remaining Owner-only steps (unchanged)

1. python -m security.owner_password_bootstrap locally (username mosfiry).
2. Owner merge decision for the session-6..10 commits (ordinary merge, no
   force/squash).
