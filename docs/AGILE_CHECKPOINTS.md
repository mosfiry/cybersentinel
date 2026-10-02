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
