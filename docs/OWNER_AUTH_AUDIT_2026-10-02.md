# Owner Authentication Audit — Session 9 Addendum (2026-10-02)

Branch: security/owner-password-auth-migration (head 01aef91fcc0f + diagnostics-only markers
f1c2afdbc473 / eb1d868f6976 — zero live-code deltas after 01aef91fcc0f, proven by commit stats)

Purpose: independent session-9 re-verification of Mission 1 closure. Session 8 closed the
engineering; its single open question was the final CI verdict on the checkpoint commits.
This addendum records: (1) that CI verdict, (2) a fresh source-level attacker review of the
live auth stack at HEAD, and (3) a fresh repository-wide occurrence classification.

## 1. CI verdict (the session-8 NEXT_SESSION_FIRST_ACTION)

- diagnostics/ci-01aef91fcc0f.md = "result: SUCCESS" (full pytest suite + compileall +
  secret-scan + git diff --check) for the migration-branch checkpoint commit 01aef91fcc0f.
- diagnostics/ci-346a6f0890ad.md = "result: SUCCESS" (full pytest output attached) for the
  B3-branch session-8 checkpoint commit 346a6f0890ad (branch security/b3-four-layer-intent).
- The two commits after 01aef91fcc0f on the migration branch (f1c2afdbc473,
  eb1d868f6976) touch ONLY diagnostics/ exports and markers (commit stats verified);
  no workflow re-run is required for them and no live file changed.

## 2. Source-level attacker review (fresh, at HEAD via CI b64 exports)

Reviewed files: security/owner_password.py, security/owner_password_bootstrap.py,
bridge.py (both export parts), api/chat.py, agent/mission_task_adapter.py,
agent/agent_core.py (auth-relevant paths), security/owner_policy.py, security/owner_policy.json.

Findings — CONFIRMED SOUND:
- scrypt verifier-only storage (N=16384, r=8, p=1, dklen=32, 16-byte random salt);
  plaintext password never stored, logged, or returned.
- Timing-equalization dummy verifier: unknown-username / disabled-account paths run a
  real scrypt pass before the generic invalid_credentials failure; wrong-password runs
  the real verifier. Enumeration via timing is not practical.
- Sessions: server-side only, minted with secrets.token_urlsafe(32), 8h TTL, status
  checked (active/revoked/expired), account status re-checked at resolve time.
- authenticated_owner() accepts ONLY a server-side session reference; there is no
  parameter through which a client boolean/role/token/magic string could authenticate.
- resolve_session additionally requires auth_method == "username_password" at every
  call site (bridge._owner_session and api.chat._owner_session).
- Deep-path check of the suspicious-looking resume path: bridge /api/session/<id>/task
  resume and task_stream pass the raw header token, but AgentCore.resume_mission calls
  authenticate_owner(owner_session_token, mission.request_id) server-side (agent_core.py
  line ~336) BEFORE any mission mutation; pause/cancel additionally enforce
  task.owner_session_id == owner["session_id"]. No unauthenticated resume path found.
- reset_password requires the CURRENT password and revokes all active sessions after
  rotation. Bootstrap: getpass only, idempotent, --reset requires current password.
- BRIDGE_TOKEN is checked only as a transport credential and never confers Owner identity.

Accepted risks (documented, no code change without an Owner decision):
- /api/auth/logout revokes by session_id without an authenticated session (idempotent,
  deliberate; gated behind the transport BRIDGE_TOKEN and localhost-only bridge; worst
  case is a revocation DoS, which is fail-closed, not an auth bypass).
- No login attempt throttling (mitigated: memory-hard KDF per attempt, bridge bound to
  127.0.0.1, single canonical account).
- create_owner_account uses check-then-insert; a concurrent double bootstrap could race
  (local single-user tool; benign failure mode is a duplicate row for the same username).
- Inert config schema keys require_owner_token / owner_phrase (owner_policy.py dataclass
  fields + owner_policy.json defaults) have ZERO consumers in live code; they were
  classified as inert in the session-6 audit and remain unchanged per the session-2
  decision. They never influence authentication.

## 3. Repository-wide occurrence classification (fresh)

Note: GitHub code search indexes the DEFAULT branch (main). Main has not received the
session-6/7/8 commits (merge is the Owner's pending decision), so main still shows the
pre-reconciliation residue. On the migration branch HEAD the classification is:

- Live code: only the inert config schema fields require_owner_token / owner_phrase in
  security/owner_policy(.py/.json). No OWNER_TOKEN / verify_owner / owner_challenge
  symbol exists in any live authentication path.
- Tests: OWNER_TOKEN and magic-string literals appear only as ATTACKER PAYLOADS in the
  rejection batteries (test_owner_password_auth.py, test_owner_mission_path_auth.py,
  test_v50_owner_session.py, test_active_docs_terminology.py and legacy phase tests),
  asserting they are rejected with handler_calls == 0 where applicable.
- Docs: active docs use only canonical terminology, enforced by
  tests/test_active_docs_terminology.py; dated historical audit/checkpoint documents
  legitimately mention the removed mechanisms as history.
- Diagnostics: immutable historical legacy-auth inventories and CI markers.

## 4. Conclusion

Mission 1 (owner password authentication migration) remains ENGINEERING COMPLETE and
CI-GREEN at the branch head. The only remaining steps are Owner-only and unchanged:
(1) python -m security.owner_password_bootstrap locally (username mosfiry);
(2) Owner merge decision for the session-6/7/8/9 commits (ordinary merge, no force/squash).
