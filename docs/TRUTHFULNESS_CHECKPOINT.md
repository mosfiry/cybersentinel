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

## UPDATE 2026-09-27 — PHASE 7 (F6) COMPLETE (VERIFIED)

- f8e07736fb8c (PHASE 7 attempt) and 2e20acb78047 (fix attempt) were BOTH BROKEN:
  the diff reconstruction of workspace/environment.py deleted LIVE code
  (resolve() logic, _hash, edit(), create()/delete() bodies, run() call,
  ProcessResult fields) and mangled indentation -> IndentationError line 80.
  Evidence: diagnostics/ci-2e20acb78047.md "result: FAILURE" (compileall exit 1,
  pytest exit 2). Both commits remain in history (fix-forward, no revert).
- Root cause identified by replaying the f8e07736 unified diff (all 7 hunks
  matched the TRUE pre-F6 state line-for-line): the pushed file diverged from
  the intended minimal dead-code removal.
- 13c6a74652ec (fix-forward): workspace/environment.py REBUILT from the
  verified pre-F6 state (raw fetch at 8a697ef22aab + wrap-repair, validated by
  exact context match of all 7 f8e07736 hunks) with ONLY the intended change:
  subprocess import reduced to "from subprocess import CompletedProcess, run";
  ProcessHandle + ProcessManager classes removed (dead code, no callers);
  __all__ updated. workspace/__init__.py exports updated accordingly.
  Round-trip re-fetch verified content. Live Workspace logic (resolve/_authorize/
  _record/list/read/write/edit/create/move/delete/run_process/run_shell/develop,
  ProcessResult) fully preserved.
- tests/test_no_process_manager.py (3 regression tests) unchanged and passing.
- CI VERIFIED on 13c6a74652ec: workflow "test" succeeded Sep 27, 2026 in 33s;
  diagnostics/ci-13c6a74652ec.md "result: SUCCESS" (published by marker commit
  a257a3269f34 — CI-authored, preserved).
- HEAD after this checkpoint push: see the commit containing this update.

## NEXT_ACTION (supersedes previous)
PHASE 9 (F8): OWNER_TOKEN terminology reconciliation in active docs
(README.md, docs/TESTING.md, docs/OPERATIONS.md, docs/SECURITY_MODEL.md,
.env.example, .env.agent.example) + classification of the remaining
occurrences (tests = negative cases, historical records stay) + CI guard
against legacy terminology re-entering active docs. Then PHASE 6 (F5), PHASE 8
(F7), PHASE 2, PHASE 10/11.
