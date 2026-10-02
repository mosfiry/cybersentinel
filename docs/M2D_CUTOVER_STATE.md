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

The tracked test workflow is `.github/workflows/tests.yml`: `push` and `pull_request`, Python 3.13, dependency installation, `compileall`, `pytest -q`, whitespace and secret-file checks. The selected base HEAD `8a3fd109c0e586db13ed48a7371ac9ad06465b74` had a `pytest-diagnostics` failure (run `36429488651`); no CI success is claimed for base `8a3fd10`. The V0 task commit `7476c36db75b58016f137fae88770add8e25fa3e` was remotely verified and its `tests` workflow run `37031411904` completed successfully (**704 passed, 1 skipped in 13.47s**). The corrected V0-inventory commit `ea10cca67a9687cb0eb044f11b3e79d29072ba97` was also remotely verified; `tests` run `37031851052` completed successfully (**704 passed, 1 skipped in 11.74s**). Both used Python 3.13 and passed `compileall`, `git diff --check`, and the secret/sensitive-file scan. Run links: [V0 tests](https://github.com/mosfiry/cybersentinel/actions/runs/37031411904), [inventory-correction tests](https://github.com/mosfiry/cybersentinel/actions/runs/37031851052).

V14 CI boundary finding and remediation: the baseline `.github/workflows/pytest-diagnostics.yml` had `contents: write` while running tests, exported selected source files and a charter audit as base64 under `diagnostics/`, excluded that directory from secret scanning, and auto-pushed diagnostics. Baseline `.github/workflows/tests.yml` also ran tests with write permission and auto-pushed a status file on `main`; `.github/workflows/docs-export.yml` exported selected source files as base64 and pushed them. Baseline diagnostics contained 199 tracked files (1,495,992 bytes). A read-only scan reconstructed 102 base64 groups and found **zero matches** for common GitHub, OpenAI-style, Hugging Face, bearer-token, and private-key patterns; this heuristic is not proof that no sensitive content exists or ever existed. Hardening commit `b2496aa13b7df8ef530c9307904082ec3c99cdbe` changes all three workflows to `contents: read`, sets `persist-credentials: false`, removes raw source/base64 exports and repository pushes, and reports a run summary or file hashes only. Secret scans no longer exclude `diagnostics/`. `tests/test_ci_security_contract.py` adds two static regression checks for these boundaries. Both workflows actually ran and passed on that exact SHA: `tests` run `37032464144` and `pytest-diagnostics` run `37032464131`, each reporting **706 passed, 1 skipped**. Links: [tests run](https://github.com/mosfiry/cybersentinel/actions/runs/37032464144), [branch diagnostics run](https://github.com/mosfiry/cybersentinel/actions/runs/37032464131). The branch-specific `docs-export.yml` workflow was not triggered by this task branch; its shell blocks passed `bash -n`, and its workflow is covered by the static guard, but no executed run is claimed for it.

The old diagnostics workflow failed with no job/log records on V0 run `37031410210` and inventory-correction run `37031849798`; GitHub reported `total_count: 0` jobs and `log not found`. No diagnostics commit was made. Its precise pre-hardening cause was not established. The replacement workflow has a real job and passed on `b2496aa` (run `37032464131`), so the no-job symptom no longer reproduces on the current task branch. Do not describe the old no-job events as pytest failures; the workflow redesign is verified on the new run.

Relevant existing test modules include `tests/test_autonomous_foundation.py` (queue/worker), `tests/test_governed_execution.py` (mission store and queue), `tests/test_crash_restart_resume.py`, `tests/test_phase6k7b_mission_runtime.py`, `tests/test_tool_continuity.py`, `tests/test_native_model_protocol.py`, `tests/test_owner_authority_refactor.py`, and the new `tests/test_ci_security_contract.py`. The selected `main` has no dedicated `test_mission_supervisor.py` or `test_mission_queue_fencing.py`. In an isolated archive of V0, `python -m compileall -q .` passed, but `python -m pytest -q` could not start because sandbox Python 3.12.3 lacks the `pytest` module; this is not a test failure. The GitHub runs above are the verified full-suite evidence. The separate read-only review reported the same pass/skip count on Python 3.12.3.

The requested repository-wide searches for `MissionWorker(`, `MissionRuntime(`, `MissionQueue(`, `MissionSupervisor(`, `run_once`, `recover_expired`, `recover_dispatching`, `heartbeat`, `claim_next`, `release`, `update`, `lease_owner`, `lease_epoch`, `request_id`, `DISPATCHING`, `UNKNOWN`, `RECOVERY_REQUIRED`, and `GOAL_COMPLETED` were run from this checkout. Their detailed output is outside the repository at `/tmp/m2d-v0/`; targeted source/caller results are summarized above. `MissionSupervisor(`, `recover_dispatching`, `DISPATCHING`, and `lease_epoch` have no matches in the selected `main` source.

## Next action

1. Continue V1/V2 architecture analysis from source: compare bridge/process host, queue/scheduler lifecycle, and mission authorization/restart semantics. Record an explicit production-lifecycle decision or **BLOCKED / OWNER DECISION** without starting a worker.
2. Inspect the exact lease/fencing commits and tests on the Manus and Vibe sibling branches without checking out or merging them. Determine whether an isolated queue/store fencing change can be safely ported to this task branch without taking broader policy, desktop, or API changes.
3. If that bounded change is safe, implement it with adversarial stale-worker tests and small commit/push checkpoints; otherwise document the source-backed blocker and continue safe crash/evidence analysis. Never claim exactly-once or successful external-effect replay.
4. Keep `POST /api/cancel` as **REVIEW / OWNER DECISION**: the shared bridge-token guard is present; do not add an Owner-session gate unless repository evidence resolves the policy. Keep production lifecycle cutover **BLOCKED / OWNER DECISION** until queued missions have an explicit, safe reauthorization contract across process restart.

No merge, deployment, or external provider execution has been performed.
