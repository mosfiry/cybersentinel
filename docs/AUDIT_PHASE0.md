# PHASE 0 — Fresh Main Audit Record (X-T Track)

Method: direct source inspection on `main` (raw.githubusercontent fetches + GitHub code search), NOT prior agent reports or checkpoints. Each finding below cites the file and line region verified. Anything not inspected is listed as UNVERIFIED at the bottom.

- main HEAD at audit time: `8ff36c72719ff59a6fb0061ff0c966b7a4bed189` (CI marker commit; parent `4edba71b02e8d91a0602cc23d0d305dd7eb28eba` = merge of PR #16, owner password auth migration).

## CONFIRMED findings (verified against source)

### F1 — CI whitespace check inspects the wrong thing (defect)
`.github/workflows/tests.yml`, step "git diff check": runs `git diff --check` against the WORKING TREE after checkout. The checked-out working tree equals the commit, but the step proves nothing about the pushed commit range; on `pull_request` events the checkout is a merge commit, on `push` it is HEAD. Required fix: diff explicit commit ranges (push: `github.event.before`..HEAD; PR: base..HEAD) with sufficient fetch depth, and fail on a nonzero exit of the RANGE diff.

### F2 — GET /api/execution/{request_id} authorization defect
`bridge.py` `do_GET`, branch `self.path.startswith("/api/execution/")`: requires only `_bridge_auth()` (X-CyberSentinel-Token == BRIDGE_TOKEN). No owner session check, no request ownership binding. BRIDGE_TOKEN is transport authentication only; it must never act as Owner identity.

### F3 — POST /api/cancel has NO authentication at all
`bridge.py` `do_POST`, branch `self.path == "/api/cancel"`: reads JSON, calls `request_cancel(request_id)`, returns 200. No bridge auth, no owner session, no ownership. Any local caller can cancel any request.

### F4 — executions table records no owner binding
`core/db.py` `CREATE TABLE executions` and `core/lifecycle.py` `begin(request_id, source)`: no `owner_session_id` column, no ownership recorded at begin(). F2/F3 ownership checks therefore need a schema addition + migration (pattern exists: `ALTER TABLE executions ADD COLUMN cancel_requested` in db.py migration block).

### F5 — Web UI is misleading: chat always fails
`web/app.js` calls only `/api/*` public endpoints; `/api/public/chat` is hardwired (api layer) to return 403 `owner_authorization_required` (deliberate: no public identity-to-Owner mapping). The UI renders a functional-looking chat; every send errors. No login UI exists (app.js never calls `/api/auth/login`, which exists in bridge.py behind bridge auth).

### F6 — ProcessManager is dead code with a latent authorization bypass
`workspace/environment.py`: `ProcessManager.start()` calls only `workspace.policy.authorize("process", ...)` — NOT `workspace._authorize(...)` — so a process started through it would bypass the mission authorization snapshot check, the audit trail (`_record`), and evidence persistence that `Workspace.run_process` enforces. Reachability: code search finds `ProcessManager` only in `workspace/environment.py` and `workspace/__init__.py` (export). No production or test callers. Classification: DEAD CODE (exported, unused) with a latent second-execution-engine bypass. Decision per mandate item 13/22: REMOVE (with regression test asserting absence), consistent with the earlier `owner_session.py` removal pattern.

### F7 — SSRF/DNS TOCTOU is a CONDITIONAL risk, not a proven exploit
`search/ssrf.py`: `validate_url` performs hostname/blocklist checks; `get_ip_addresses` resolves at validation time; a code comment acknowledges a hostname may resolve differently between validation and connection. Current provider endpoints are code/config-fixed (not model-controlled URLs). CONDITIONAL RISK: if any URL becomes request-controlled, the resolve-then-connect gap must be closed (resolve → validate IP → connect to validated IP). No claim of "SSRF exploitable" is made — UNPROVEN.

### F8 — Stale OWNER_TOKEN terminology in active documentation
Live runtime uses username/password + server-side owner sessions (`security/owner_password.py`); OWNER_TOKEN removed from live path by PR #16. Stale mentions remain in active docs/config: `README.md` ("Set different random BRIDGE_TOKEN and OWNER_TOKEN values"), `docs/SECURITY_MODEL.md` ("requests that also carry the separate OWNER_TOKEN are instruction authority" — WRONG for current runtime), `.env.example` (`OWNER_TOKEN=...`). Full classification sweep (LIVE CODE / ACTIVE DOC / TEST NEGATIVE CASE / HISTORICAL RECORD / MIGRATION NOTE) pending in PHASE 9.

### F9 — Password security gaps
`security/owner_password.py`: scrypt verifier-only, constant-time compare, dummy-verify timing equalization, generic errors, TTL 8h sessions, revocation — VERIFIED GOOD. GAPS: no rate limiting / failed-attempt lockout on `login()`; no password policy check in `create_owner_account`/`reset_password`. To be fixed in PHASE 1/12.

### F10 — No truthfulness/anti-hallucination architecture exists on main
No EvidenceStatus/ClaimStatus machine-readable states, no completion gates, no claim→evidence provenance records. (Code search for truthfulness modules: none found.) This is the core PHASE 3/4 build.

## UNVERIFIED / NOT YET INSPECTED (no claims made)
- b3 branch (`security/b3-four-layer-intent`, now at `4658ab1b`) state: NOT audited in this pass. Module-by-module port evaluation pending PHASE 2; nothing merged from it.
- Full docs sweep beyond the files named in F8: NOT RUN yet.
- `search/web_provider.py` connect-time resolution behavior: NOT fully traced yet (F7 is conditional).
- Web login UI implementation feasibility (F5 fix choice): decided at PHASE 6.

## NEXT_ACTION
PHASE 1: fix F2/F3/F4 — bridge token + owner session + request ownership binding on GET /api/execution/{id} and POST /api/cancel; add `owner_session_id` to executions with migration; add explicit HTTP tests for the 8 named cases.
