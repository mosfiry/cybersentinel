# Truthfulness Overhaul — Session Checkpoint

Branch: security/truthfulness-overhaul (from main 8ff36c72719f)
NEVER: reset / rebase / squash / force-push / touch main.
CI oracle: tests.yml "test (3.13)" check-run on the exact commit SHA.
api.github.com (unauth, 60/hr) exhausts quickly; the commit checks page
(https://github.com/mosfiry/cybersentinel/commit/<sha>/checks) renders
step verdicts and "Invalid workflow file" annotations without the API.

## Verified commit chain (all CI green, evidence recorded)
- 370bada47512 — PHASE 0 audit record (docs/AUDIT_PHASE0.md, findings F1-F10)
- ea69d1db6834 — PHASE 1: owner-session + request-ownership binding on
  GET /api/execution/{id} and POST /api/cancel (bridge token + owner session +
  ownership, fail-closed 401/403/404); owner_session_id column on executions
  with ALTER migration; lifecycle bind_owner()/release_unclaimed();
  tests/test_execution_ownership.py (12-case HTTP battery).
  CI: workflow run 36339132634-series predecessor run, "test (3.13)" success.
- f0d876ef75dc — PHASE 3/4: security/truthfulness.py (EvidenceStatus states
  OBSERVED/VERIFIED/INFERRED/PLANNED/CLAIMED/UNVERIFIED/FAILED/NOT_RUN/
  INTERRUPTED/UNKNOWN/NOT_APPLICABLE; TRUSTED_EVIDENCE_ORIGINS without
  model_output; EvidenceRecord/ExecutionRecord/Claim with provenance;
  classify_claim/verify_test_claim/verify_ci_claim; 9 completion gates,
  evaluate_completion -> COMPLETE only with authoritative evidence)
  + tests/test_truthfulness.py (15 adversarial tests).
  CI VERIFIED: workflow run 36339132634, "test (3.13)" conclusion=success,
  all steps success incl. pytest (18:02:09-18:02:40Z).
- 03b8132dbb93 — PHASE 5a (F1): tests.yml now fetches full history
  (fetch-depth: 0) and the whitespace check runs git diff --check between the
  push before-SHA (or PR merge-base) and the current SHA — NOT the working
  tree. + tests/test_ci_workflow_range.py (4 validation tests).
  CI VERIFIED: "test (3.13) succeeded Sep 27, 2026 in 28s" on the commit
  checks page; no failures.
- 936b3e9533b8 — PHASE 5b (NEW finding): pytest-diagnostics.yml was failing
  at STARTUP on every branch push since 4cd056ec ("Invalid workflow file
  #L1"). Root cause: the only non-ASCII bytes in the file were a
  double-encoded em-dash (c3 a2 c2 80 c2 94) introduced by the mojibake
  edit in 4cd056ec. Rewrote the file pure ASCII (em-dash -> " - "), and
  its whitespace check is now also commit-range based.
  CI VERIFIED: "test (3.13) succeeded in 30s" AND the pytest-diagnostics
  workflow now parses and RUNS (published its export marker commit
  60956dd3249d and diagnostics/ci-936b3e9533b8.md "result: SUCCESS").
- 60956dd3249d — CI-published diagnostics marker (NOT authored by the agent;
  preserved per parallel-agent safety rule).

## Engineering rules re-confirmed this session
- Byte-exact remote reconstruction: contents API base64 (decode in TS) is the
  trusted channel; byte count must match the API size field. The raw
  raw.githubusercontent wrap-repair channel has a SECOND corruption mode
  (a newline can be swallowed into spaces around boundaries) — never use it
  for byte-exact edits; use it only for cross-checking.
- The local sandbox sha1 implementations tried this session were BOTH wrong
  (self-test against known vectors failed) — do NOT trust hand-rolled sha1;
  verify round-trip by re-fetching pushed content instead.

## Remaining phases
- PHASE 2: b3 module-by-module port evaluation (b3 HEAD 4658ab1b3202) — NOT STARTED.
- PHASE 6 (F5): web owner login (login form -> server-side auth -> HttpOnly
  owner session; NO bridge token in browser) or visibly disable chat — NOT STARTED.
- PHASE 7 (F6): remove dead ProcessManager/ProcessHandle from
  workspace/environment.py (+ regression test) — NOT STARTED (next).
- PHASE 8 (F7): SSRF/DNS TOCTOU boundary documentation — NOT STARTED.
- PHASE 9 (F8): OWNER_TOKEN terminology sweep + CI guard — NOT STARTED.
- PHASE 10/11: full regression + evidence-first final report — NOT STARTED.
- F9 gaps (rate limiting / password policy) remain open.

## NEXT_ACTION
PHASE 7: fetch workspace/environment.py via contents-API b64 channel, confirm
ProcessManager/ProcessHandle are dead code (no callers), remove them, add a
regression test asserting absence, push, verify CI on the exact SHA.
