# M2.d Cutover State

## V0 — forensic inventory

**Status:** inventory recorded; this first checkpoint is documentation-only. No production code, application data, or protected branch has been changed.

**Task branch:** `task/m2d-cutover-20261002`
**Base:** `main` / `origin/main` at `8a3fd109c0e586db13ed48a7371ac9ad06465b74`
**Base parent:** `be24ae326c710145d192f13e167ef02bf2f51792`
**Initial checkout:** `main` at the same SHA, clean worktree. The task branch was created from that exact commit after rechecking the worktree. GitHub reports the repository default branch is `main`; its current SHA matched the local ref. The repository is public. Its API-reported branch-protection flag is false, but this task still treats `main` as protected and will not push to or modify it.

### Relevant branch provenance

- `origin/main` — `8a3fd109c0e586db13ed48a7371ac9ad06465b74`, parent `be24ae326c710145d192f13e167ef02bf2f51792`; the initial task branch starts here.
- `origin/manus/durable-runtime-fencing` — `71299521ae2ed986e0d8748e00ac475629e13a04`, 14 commits after this `main`. It contains the lease/evidence fencing, external-effect intent work, `agent/mission_supervisor.py`, and associated tests. Its own `docs/MANUS_M2D_CUTOVER_EVIDENCE.md` records a cutover blocker. Current-source checks below independently confirm the authorization/restart mismatch. This branch is not merged into the task branch.
- `origin/vibe/principal-engineering` — `9364caf0f35c008ca86976706f35fa5aa6dced71`, 41 commits after the same `main` base. It is a separate sibling implementation: it does not contain the Manus supervisor or effect-intent module at that ref. The two lineages have a common base at `8a3fd10`; neither is merged into the other or into this task branch.
- `origin/engineering/mission-orchestration` and `origin/engineering/mission-orchestration-live-integration` diverge from the older merge base `4889f69d5d5e1f172cbdbbd7b0a6ed1abcd7d98d` (96 commits unique to current `main`; 4 and 7 commits unique to those refs respectively). They are not used as a base.
- `origin/engineering/agile-runtime` (`71536e2175ed14def01aac48e909999bcf991fb1`), `origin/engineering/agile-runtime-crash-reconcile` (`dcc982c8c8bec0847249ebc1eb963db9691bd4bb`), and `origin/engineering/agile-runtime-lease-fencing` (`3b7b29653769dd7c8061616f8ce6fe18fd58ab9`) are additional descendants of current `main` with their own commits. They remain untouched pending source review.
- `origin/work/desktop-client` (`08a87cf3db7d489c7773fc497c16a45fecd92dff`) is six commits after `main` and carries a separate desktop/backend implementation. It is not part of this checkout or task branch. No Vibe, desktop, other Manus, or unrelated engineering branch has been checked out or modified.

### Production call graph on the selected base

```text
README.md: python bridge.py
└── bridge.main()
    └── ThreadingHTTPServer(..., Handler).serve_forever()
        ├── POST /api/chat
        │   └── Bridge-token + Owner-session checks
        │       └── api.chat.chat()
        │           └── AgentCore.run_owner_mission() / resume_mission()
        │               └── MissionRuntime.run_model_loop() or run_to_completion()
        │                   (runs inline in the HTTP request)
        └── /api/missions routes
            └── Handler._mission_service()
                ├── MissionStore at missions.sqlite3
                ├── MissionQueue at mission_queue.sqlite3
                ├── MissionScheduler at mission_scheduler.sqlite3
                └── MissionService
                    ├── create/status/timeline/evidence/artifacts/logs
                    ├── start/resume -> queue.enqueue()
                    └── schedule -> persistent schedule record
```

The exact source paths are `bridge.py`, `api/chat.py`, `api/missions.py`, `agent/agent_core.py`, `agent/mission_runtime.py`, and `agent/mission_worker.py`. `MissionService.start_mission()` only enqueues. In the selected `main` tree, `MissionWorker` and `MissionSupervisor` are not constructed by production code; `agent/mission_supervisor.py` is absent. No production caller invokes `MissionWorker.run_once()`, `MissionQueue.recover_expired()`, or `MissionScheduler.dispatch_due()`. Scheduler records therefore have no production dispatch loop in this tree. `MissionRuntime` is used by `AgentCore` for synchronous Owner mission requests and by the bridge facade for mission storage/API operations; a separate audit script also constructs it.

`bridge.main()` requires `BRIDGE_TOKEN`, creates a `ThreadingHTTPServer`, and calls `serve_forever()`. No application lifespan, worker startup hook, signal-driven cooperative supervisor stop, or managed scheduler lifecycle is present. `BRIDGE_HOST` defaults to `127.0.0.1`; `core/config.py` raises if it is set to another host. There is no production worker identity or duplicate-supervisor protection because no production supervisor is wired.

### Queue, restart, and authority facts

- `MissionQueue.claim_next()` uses `BEGIN IMMEDIATE` and stores `lease_owner` / `lease_expires_at`. The selected `main` queue has no `lease_epoch` field (`lease_epoch` search: no matches); its lease updates are not epoch-fenced. `MissionStore` has payload integrity and stale-payload write checks, but that is not a queue-lease fencing protocol.
- `MissionQueue.recover_expired()` requeues expired executing leases. `recover_after_restart()` resets executing/planning/waiting rows without checking lease expiry. Neither is called by production lifecycle code in this checkout.
- `MissionStore`, queue, and scheduler are constructed with three separate SQLite files under `DB_PATH` (`missions.sqlite3`, `mission_queue.sqlite3`, `mission_scheduler.sqlite3`). There is no single atomic transaction spanning those files.
- Mission records include serialized `authorization_context`; `AuthorizationContext.to_dict()` includes `session_id`, and Owner authentication evidence also serializes its session identifier. `MissionStore.save()` stores the serialized mission payload in SQLite. The session identifier is a bearer credential in the current auth design, so a background worker must not be introduced by simply replaying the stored context.
- Owner evidence is signed using `_EVIDENCE_SECRET = secrets.token_bytes(32)` when `security.owner_policy` loads, and evidence has a 300-second lifetime. A restarted process does not have the old signing key. `AgentCore.resume_mission()` explicitly takes a fresh Owner session and renews authorization evidence before resuming. **Automatic durable-worker continuation after restart is BLOCKED pending an Owner decision on the reauthorization/approval contract; no key persistence, token forwarding, or authority bypass is being designed by assumption.**
- `ContextAssembler`'s over-budget fallback includes `mission.authorization_context` and `mission.scope_snapshot` in its assembled mission sections. This is an additional redaction/provenance review item before any persistent worker or provider-facing background path is enabled; no claim is made here that the conditional path has been exercised in production.

### API, desktop, and backend boundary

- Mission endpoints in `bridge.py` are guarded by bridge authentication and an Owner password session. `POST /api/missions` can create a mission; `/start` and `/resume` enqueue; status/timeline/evidence/artifacts/logs are reads; pause/cancel update mission state; schedule records a schedule. The queue path does not currently have a consumer.
- `/api/public` is disabled by default (`PUBLIC_WEB_ENABLED=false`). If enabled, `/api/public/chat` still returns `403 owner_authorization_required`; the code explicitly does not treat public-session identity as Owner authority. The current `web/app.js` uses only `/api/public/*`, so public chat does not reach Owner mission execution. Any identity-to-Owner mapping is an **OWNER DECISION**, not a gap to fill silently.
- A separate local command cancellation route, `POST /api/cancel`, is governed by the shared bridge-token check in `Handler.do_POST` before its handler runs, so it is not unauthenticated. It does not require an Owner session, unlike `/api/command`, `/api/tasks`, and mission actions. `core.lifecycle.request_cancel()` checks only that the request ID exists, with no Owner identity binding. The repository does not specify whether bridge-token authority is sufficient for this fail-safe operation or an Owner session must also be required; classify this as **REVIEW / OWNER DECISION**, not a confirmed authentication bypass. Loopback binding limits network exposure. No legitimate caller of `/api/cancel` was found in `web/`, `scripts/`, or tests.
- Current `main` contains no desktop/Electron packaging tree, Cloudflare Worker, `wrangler` config, Dockerfile, or production deployment manifest. It serves `web/` from the local Python bridge. Desktop implementation files exist on separate branches such as `origin/work/desktop-client`; those branches are not evidence of a deployed runtime for this base. `.github/workflows/github-only-poc.yml` is manually dispatched and runs a bounded job, not a persistent backend. **DEPLOYMENT = NOT VERIFIED.**

### CI and test baseline

The tracked test workflow is `.github/workflows/tests.yml`: `push` and `pull_request`, Python 3.13, dependency installation, `compileall`, `pytest -q`, whitespace and secret-file checks. The current run list showed `tests` run `36357709260` succeeding for parent commit `be24ae326c710145d192f13e167ef02bf2f51792`; this is not a run for base HEAD `8a3fd10`. The latest observed run for base HEAD `8a3fd109c0e586db13ed48a7371ac9ad06465b74` is `pytest-diagnostics` run `36429488651`, conclusion `failure`; its failure cause still needs inspection. The V0 task commit `7476c36db75b58016f137fae88770add8e25fa3e` was remotely verified and its `tests` workflow run `37031411904` completed successfully: Python 3.13, `compileall`, `pytest -q` (**704 passed, 1 skipped in 13.47s**), `git diff --check`, and the secret/sensitive-file scan all passed. No CI success is claimed for the base commit `8a3fd10`.

`.github/workflows/pytest-diagnostics.yml` runs on pushes to non-`main` branches, grants `contents: write` to the job that executes repository tests, base64-exports selected `origin/main` and branch source files into `diagnostics/`, excludes `diagnostics/` from its secret scan, and pushes diagnostics back to the branch. The current tree has 199 tracked diagnostics files totaling 1,495,992 bytes. This creates a source-secret scan blind spot and can produce an automatic branch commit after a push; no secret value is asserted to have been leaked. `.github/workflows/tests.yml` also grants `contents: write` to the test job and publishes diagnostics only on `main`. Treat these as V14 CI-boundary findings; any remediation must keep write credentials out of test execution and must not push to `main`.

Relevant existing test modules include `tests/test_autonomous_foundation.py` (queue/worker), `tests/test_governed_execution.py` (mission store and queue), `tests/test_crash_restart_resume.py`, `tests/test_phase6k7b_mission_runtime.py`, `tests/test_tool_continuity.py`, `tests/test_native_model_protocol.py`, and `tests/test_owner_authority_refactor.py`. The selected `main` has no dedicated `test_mission_supervisor.py` or `test_mission_queue_fencing.py`. In an isolated archive of V0, `python -m compileall -q .` passed, but `python -m pytest -q` could not start because the sandbox Python 3.12.3 has no `pytest` module installed; this is not a test failure. The task-branch GitHub run above is the verified full-suite evidence. The separate read-only review reported the same pass/skip count on Python 3.12.3.

The requested repository-wide searches for `MissionWorker(`, `MissionRuntime(`, `MissionQueue(`, `MissionSupervisor(`, `run_once`, `recover_expired`, `recover_dispatching`, `heartbeat`, `claim_next`, `release`, `update`, `lease_owner`, `lease_epoch`, `request_id`, `DISPATCHING`, `UNKNOWN`, `RECOVERY_REQUIRED`, and `GOAL_COMPLETED` were run from this checkout. Their detailed output is outside the repository at `/tmp/m2d-v0/`; targeted source/caller results are summarized above. `MissionSupervisor(`, `recover_dispatching`, `DISPATCHING`, and `lease_epoch` have no matches in the selected `main` source.

## Next action

1. V0 is committed and pushed as `7476c36db75b58016f137fae88770add8e25fa3e`; remote `task/m2d-cutover-20261002` was verified at that SHA. Do not amend or rewrite this checkpoint.
2. Inspect the base diagnostics failure `36429488651`. The task-branch diagnostics run `37031410210` also concluded `failure`, but its REST record has no jobs and the log endpoint reports `log not found`; no diagnostics commit was made. Establish why it has no job before claiming a repaired workflow.
3. Continue V1/V7/V14 with source-backed findings. Harden the diagnostics/test workflows so they do not export unchecked source into `diagnostics/`, do not grant write credentials to code-under-test, and cannot silently turn test failures into green results. Push only the task branch. Treat `/api/cancel` as **REVIEW / OWNER DECISION**: the shared bridge-token guard is present; do not add an Owner-session gate unless source evidence resolves the policy.
4. Keep M2.d production lifecycle cutover **BLOCKED / OWNER DECISION** until queued missions have a safe, explicit reauthorization contract across process restart. In parallel, finish queue/fencing and crash evidence only on the task branch, without enabling a worker that can act on stale authorization.

No merge, deployment, or external provider execution has been performed.
