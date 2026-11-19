# Owner Authentication Audit — Session 11 Addendum (2026-10-04)

Branch: security/owner-password-auth-migration (engineering heads 03aa7265,
5132aec9)

Purpose: close the last two engineering-actionable items inside Mission 1
scope that require no Owner decision. After this session the only remaining
Mission 1 steps are Owner-only: local bootstrap and the merge decision.

## 1. X-K.1 Legacy OWNER_TOKEN-era policy schema keys removed (completes the
repository-wide OWNER_TOKEN removal)

- The inert dataclass fields require_owner_token / owner_phrase in
  security/owner_policy.py and their defaults in security/owner_policy.json
  were the last OWNER_TOKEN-era remnants anywhere in the repository's
  policy schema. The 2026-10-02 audit had classified them as inert (zero
  consumers in live code, never consulted by any authentication path), and
  the 2026-10-03 addendum left them "unchanged per the session-2 decision".
  That decision predates the session-8 engineering-complete closure of the
  OWNER_TOKEN removal contract ("remove completely, no fallback, no
  compatibility mode"); keeping dead legacy-authentication schema keys in
  the canonical policy serves no consumer and re-exposes deprecated
  terminology, so they are now removed outright.
- Removed everywhere they existed: the frozen OwnerPolicy dataclass fields
  and the owner_policy.json keys. The .env example files were re-checked and
  already contain no legacy terminology. No code path referenced either key
  (verified by repository occurrence classification), so removal is a pure
  dead-schema elimination; load_policy() and every snapshot/fingerprint
  consumer continue to work, and the policy fingerprint simply advances with
  the deliberate schema change.
- Guard test: tests/test_owner_policy_legacy_keys_removed.py asserts the
  fields and JSON keys can never reappear and that the canonical schema
  still loads with its security-critical values intact (model_authority
  "none", external_content_authority "none", system_safety_boundary
  "immutable").

## 2. X-K.2 Atomic login throttle (closes the documented check-then-record
residual race)

- The 2026-10-03 addendum documented a residual race: the lockout check and
  the failure recording were separate statements, so a burst of concurrent
  attempts could overshoot LOGIN_FAILURE_THRESHOLD slightly before the lock
  engaged. security/owner_password.py now consumes each attempt's failure
  slot ATOMICALLY, BEFORE any KDF work: the lockout check and the counter
  update run inside a single BEGIN IMMEDIATE transaction
  (_reserve_login_attempt). Concurrency can therefore never overshoot the
  threshold — the attempt that would exceed it is rejected before any real
  verifier runs — which also bounds the worst-case KDF work per lockout
  window to exactly the threshold.
- Semantics preserved from session 10 (all covered by the existing battery
  tests/test_owner_auth_hardening.py, which exercises only the public API):
  fail-closed rejection of CORRECT credentials while locked; timing-equalized
  dummy verification on every locked path (no KDF oracle); window never
  extended by attempts made during lockout; fresh window after expiry
  (counter resets to 1); successful login/reset clears the counter; only the
  canonical username can ever create a throttle row (unknown usernames are
  never recorded, so the table cannot be flooded); reset_password shares
  the same atomic lockout.
- The removed helpers (_lockout_active, _record_login_failure) have no
  fallback, no compatibility shim, and no remaining callers.
- New adversarial battery: tests/test_owner_throttle_atomicity.py —
  concurrent burst of threshold+4 wrong-password attempts asserts the stored
  counter never exceeds the threshold and correct credentials are then
  rejected with zero sessions minted; a concurrent burst of CORRECT-password
  attempts while locked asserts zero sessions minted and the recorded window
  unchanged; a concurrent burst of unknown usernames asserts zero throttle
  rows; reset_password slot accounting asserts exactly threshold recorded
  failures and a locked correct-current-password attempt that records
  nothing new.

## 3. Second-pass attacker review (session 11)

- No new authentication path was introduced; _reserve_login_attempt only
  ever REJECTS (it can consume a slot or deny an attempt, never widen
  authorization, never mint identity, never emit a session).
- No alternate path to the throttle: login() and reset_password() are the
  only callers of the reserve; both fail closed on False.
- No oracle regression: locked attempts still run the dummy scrypt verifier
  only; the real verifier is consulted only after a slot was consumed and
  the account row exists.
- Unreadable/corrupted last_failure_at timestamps fail closed (locked) rather
  than open.
- No password material appears in code, tests, or docs (isolated per-run test
  passwords only).
- The DB-backed lockout remains fail-closed availability behavior, not an
  authentication bypass; the documented tradeoff that a transport
  BRIDGE_TOKEN holder can keep the Owner locked out is unchanged and
  accepted (it can only deny, never grant).

## 4. Remaining Owner-only steps (unchanged)

1. python -m security.owner_password_bootstrap locally (username mosfiry).
2. Owner merge decision for the session-6..11 commits (ordinary merge, no
   force/squash).
3. Only after that merge does Mission 2 (B3-C5) resume on
   security/b3-four-layer-intent (open item: the Owner decision on the Case
   15 single-use-proof proposal).
