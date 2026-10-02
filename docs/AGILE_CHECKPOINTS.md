# Agile Checkpoints

This manifest records small recovery checkpoints. A checkpoint is published only after a non-force push and an independent equality check between local `HEAD` and the exact remote branch SHA. A dirty worktree is not part of a checkpoint. The literal SHA of this manifest's own M0 commit is obtained from the remote branch tip and is included in the task handoff; the durable ref below allows recovery without relying on chat history.

## 2026-10-02 — M0 Recovery Baseline

- **Epic:** A — Recovery + Engineering Baseline
- **Story:** M0 — Recovery Baseline
- **Task:** Verify the safe recovery source and establish the documentation-only checkpoint in a clean worktree.
- **Branch:** `engineering/agile-foundation`
- **Commit:** Documentation commit at `refs/heads/engineering/agile-foundation`; after publication, resolve its exact SHA with `git ls-remote` and require equality with local `git rev-parse HEAD`. Its parent is `47683c22079eb17e79f43d21147a8fba98c4e127`.
- **Recovery source SHA:** `47683c22079eb17e79f43d21147a8fba98c4e127`, parent `ecbdbb36669a8366dbc60777537a92ee7fb69452`; verified live at `origin/refs/heads/integration/cybersentinel-final-completion` before creating the M0 branch.
- **Files:** `docs/ENGINEERING_CHECKPOINTS.md`; `docs/AGILE_CHECKPOINTS.md` only.
- **Tests:** `python -m compileall -q .` — pass; `node --check web/app.js` — pass; representative backend imports — pass; tracked CI sandbox preflight — pass; `python -m pytest -q` — 976 passed, 1 skipped in 75.54 seconds. The explicit live-provider test was skipped because provider credentials/factory were absent. `git show --check --format= HEAD` passed. `git fsck --full --strict` exited 0 and reported one dangling blob (`9571d706421245175ec7b84f3801ddd809da57b4`), not included in this checkpoint. See [ENGINEERING_CHECKPOINTS.md](ENGINEERING_CHECKPOINTS.md) for the environment and validation details.
- **Status:** M0 source baseline and checks passed locally. The checkpoint is considered published only when the remote SHA at `refs/heads/engineering/agile-foundation` equals the local documentation-commit SHA; the verification result and literal SHA are recorded in the handoff.
- **Known blockers/limitations:** The original checkout remains dirty with 114 status paths (60 unstaged-only, 6 mixed, 2 staged-only, 46 untracked); those changes remain unsaved and are excluded. Local Python was 3.12.3 while tracked CI requests 3.13. One dangling Git blob has unknown provenance and is excluded. Live-provider behavior was not exercised.
- **Security impact:** Documentation only; no policy, authentication, authorization, scope, evidence, tool, or runtime behavior changed. Owner decisions remain within application controls and cannot override system/platform requirements.
- **API impact:** None.
- **Desktop impact:** None; Desktop/Electron/Vibe and PR #18 untouched.
- **Next task:** M1 — Durable Mission Runtime, from the verified M0 remote branch tip.

## 2026-10-02 — M1 Recovery-required worker lease release

- **Epic:** A — Recovery + Engineering Baseline
- **Story:** M1 — Durable Mission Runtime
- **Task:** When a worker returns a mission in `RECOVERY_REQUIRED`, atomically transition its queue item to `WAITING_FOR_TOOL` and relinquish the worker lease. Preserve the mission's authoritative recovery status; do not make the queue item claimable until explicit reconciliation/requeue.
- **Branch:** `engineering/agile-runtime`
- **Commit:** One bug-fix commit at `refs/heads/engineering/agile-runtime`; after a normal push, resolve the exact SHA with `git ls-remote` and require equality with local `git rev-parse HEAD`. Do not write the commit's own SHA into this manifest. **Parent:** `cb1aca63682035f8555e7e0b752b1747f133b534` (verified M0 tip).
- **Recovery source SHA:** `cb1aca63682035f8555e7e0b752b1747f133b534` at `origin/refs/heads/engineering/agile-foundation` before branch creation.
- **Files:** `agent/mission_worker.py`; `tests/test_mission_worker_lifecycle.py`; `docs/AGILE_CHECKPOINTS.md` only.
- **Tests:** The new regression first failed before the fix (`1 failed in 0.18s`, because `lease_owner` remained `worker-a`), then passed after the fix (`1 passed in 0.08s`). `python -m pytest -q tests/test_mission_worker_lifecycle.py` — 15 passed in 3.24s. `python -m pytest -q tests/test_failure_recovery_replan.py tests/test_mission_control_races.py tests/test_phase6k7b_mission_runtime.py` — 27 passed in 1.61s. `python -m pytest -q` — 977 passed, 1 skipped in 72.29s. The full run used `-q`, so the skipped test's reason was not printed; no live-provider acceptance or external-target tests were run.
- **Status:** Worker return of `RECOVERY_REQUIRED` now uses the queue's lease-checked atomic `release` operation for `WAITING_FOR_TOOL`. The regression verifies both lease fields are cleared, mission status remains `RECOVERY_REQUIRED`, attempts remain unchanged, and the queue cannot be claimed or executed again through the worker until explicit requeue.
- **Original checkout boundary:** `/workspace/cybersentinel-release-closure` remained untouched at `47683c22079eb17e79f43d21147a8fba98c4e127`; its preflight and post-review porcelain-status fingerprints were identical. The prior M0 checkpoint records 114 dirty status paths. No dirty-checkout content was imported.
- **Known limitation:** The existing queue restart recovery path may promote `WAITING_FOR_TOOL` rows for processing. The persisted `RECOVERY_REQUIRED` mission remains terminal, and the runtime's terminal-state guard prevents model/tool execution until reconciliation; this slice does not change restart routing. An integrated queue-restart/runtime regression is recommended next.
- **Security impact:** No authorization, scope, evidence, deterministic verification, or policy gates changed. Only the worker's lease relinquishment for the `WAITING_FOR_TOOL` result changed.
- **API impact:** None.
- **Desktop impact:** None.
- **Next task:** Add a focused integration test covering `MissionQueue.recover_after_restart()` with a persisted `RECOVERY_REQUIRED` mission and prove the runtime does not execute a tool before explicit reconciliation/requeue; change restart routing only if that test exposes a missing guard.
