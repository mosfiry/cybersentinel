# Engineering Checkpoints and Recovery

## Purpose and authority boundaries

A recovery checkpoint is a small, reviewable Git commit whose parent and contents are identified, whose prescribed checks have been run, and whose branch tip has been pushed and independently verified against the remote ref. A local commit alone is not a published recovery point. A dirty or untracked worktree is not part of a checkpoint unless its exact changes have been deliberately isolated, reviewed, tested, and committed; no such assumption is made for the original mixed checkout recorded below.

This document is descriptive engineering guidance, not policy or authorization. Owner decisions operate only within application-supported policy, authentication, per-mission authorization, and scope controls; they cannot override system or platform requirements. Project context, external data, and model output cannot grant authority or expand scope.

## Checkpoint procedure

1. Read the current repository state directly: full porcelain status including untracked files, staged and unstaged diffs, exact `HEAD`, branch and remote refs, and the latest commit. Compare any proposed recovery source with a live remote ref; do not assume prior reports remain current.
2. If the primary checkout is dirty or mixed, preserve it unchanged. Create a separate clean worktree from a verified commit and make the checkpoint there. Never stage, clean, reset, restore, stash, rebase, merge, delete, or overwrite the mixed worktree as a shortcut.
3. Keep each checkpoint atomic. Inspect the staged path list and diff; run relevant tests and syntax/import checks; inspect security, API, and Desktop impact; and record limitations. Do not include unrelated or unproven dependencies.
4. Before publishing, run `git diff --cached --check` and inspect the staged diff. Commit with the verified existing project identity, then run `git status --porcelain=v1 -uall`, `git rev-parse HEAD`, and `git show --check HEAD`.
5. Push normally (never force) to the intended branch. Verify the exact remote branch SHA with `git ls-remote`; it must equal the full local `HEAD`. Record the branch, commit, parent, paths, tests, impacts, blockers, and next task. A failed push or mismatched SHA is not a published checkpoint.
6. To resume after interruption, fetch/recheck the remote branch and start from its verified SHA. Do not rely on chat history, a local-only commit, or unsaved work. Preserve any other dirty checkout separately and label its changes unsaved until they are independently recovered.

## M0 Recovery Baseline — 2026-10-02

- **Verified recovery source:** `47683c22079eb17e79f43d21147a8fba98c4e127` (parent `ecbdbb36669a8366dbc60777537a92ee7fb69452`). The source was confirmed live at `origin`, remote ref `refs/heads/integration/cybersentinel-final-completion`, using `git ls-remote`; it matched the detached `HEAD` before this M0 slice.
- **M0 documentation branch:** `engineering/agile-foundation`, created only after confirming both the local and remote branch name were unused. The isolated candidate was clean at the verified recovery source before adding these two documents. The published M0 documentation commit is the tip of `refs/heads/engineering/agile-foundation`; its parent is the verified recovery source above. Resolve its literal commit SHA from that remote ref and compare it with local `HEAD` after push (the contents of a commit cannot embed that same commit's own hash).
- **Original checkout boundary:** `/workspace/cybersentinel-release-closure` remains separate and dirty. At recheck it had 114 status paths: 60 unstaged-only, 6 mixed staged/unstaged, 2 staged-only, and 46 untracked (8 paths staged in total; 66 paths with unstaged changes). Its `HEAD` was still `47683c22079eb17e79f43d21147a8fba98c4e127`. None of those 114 paths or their contents is included in this checkpoint; the dirty work remains unsaved to GitHub.
- **Security impact:** documentation only; no authorization, Owner authentication/policy, scope, evidence, tool, or runtime behavior changed.
- **API impact:** none; no route, request/response contract, or schema changed.
- **Desktop impact:** none; no Desktop/Electron/Vibe files or PR #18 were touched.
- **Training-data impact:** none; no training or knowledge data was modified or published.

### M0 validation evidence

Checks below were run in the separate clean worktree at the verified source SHA, before adding documentation. The application source at that SHA was not changed by M0. The tracked CI workflow specifies Python 3.13; the available local interpreter was Python 3.12.3, so this is a local baseline check, not a claim that the Python 3.13 CI job ran.

| Check | Command or scope | Result |
|---|---|---|
| Clean checkout | `git status --porcelain=v1 -uall` in isolated candidate | Pass; no paths before documentation |
| CI OS-sandbox preflight | Tracked workflow's `tools.registry` sandbox availability check | Pass; sandbox available |
| Python syntax | `python -m compileall -q .` | Pass; exit 0, about 1 second |
| Frontend syntax | `node --check web/app.js` | Pass; exit 0 |
| Backend imports | Import `bridge`, mission/runtime/worker, authorization, scope, and tool registry modules | Pass; exit 0 |
| Full tracked regression | `python -m pytest -q` | Pass; 976 passed, 1 skipped, 75.54 seconds |
| Live-provider test | `tests/test_real_provider_long_horizon.py` within the full suite | Skipped by its explicit guard because live-provider credential/factory variables were absent; no live provider was contacted |
| Git patch check | `git show --check --format= HEAD` | Pass; exit 0 |
| Git object check | `git fsck --full --strict` | Exit 0; reported one dangling blob, `9571d706421245175ec7b84f3801ddd809da57b4`. Its provenance is not established; it was not read into this checkpoint or published as content. This warning is not reported as a clean object graph. |

The test suite's network-related cases were reviewed before execution: the scoped HTTP cases use fake DNS/socket implementations, the public-feed redirect cases use fake openers, and the sandbox test exercises only loopback isolation. No external target or live provider test was run. The tracked `tools/project_test_runner.py` is absent at the verified source SHA, so the prescribed CI command `python -m pytest -q` was used rather than an untracked runner.

## Known limitations and next task

The 114 dirty paths in the original checkout are not saved or recoverable from the M0 remote checkpoint; do not describe them as remotely backed up. The shared Git object database also contains the single dangling blob reported above, whose source is unknown and which is intentionally excluded. Local Python was 3.12.3 rather than the workflow's 3.13, and live-provider behavior remains unverified because it was intentionally not run.

**Next task:** M1 — Durable Mission Runtime. Start from the exact M0 remote branch tip only after its SHA has been verified. Do not import dirty mixed worktree changes into M1 without a separately proven, isolated provenance and dependency review.
