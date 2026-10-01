# PR #17 Audit — "Wire Arabic browser Owner auth and stop main CI diagnostics commits"

Audit date: 2026-10-01. Evidence: GitHub REST data for
`mosfiry/cybersentinel` PR #17 (metadata, files, commits, diff, comments,
check runs) read in full during the desktop mission. This document records
what the PR actually contains and how the desktop work relates to it.

## 1. Metadata

- PR: #17 — "Wire Arabic browser Owner auth and stop main CI diagnostics commits"
- Author: mosfiry
- State: open (not merged, not draft), mergeable_state: unstable
- Base: `main` @ `8a3fd109c0e586db13ed48a7371ac9ad06465b74`
- Head: `work/arabic-auth-ci-docs-20260929` @ `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`
- Created: 2026-09-28T22:24:55Z; updated: 2026-09-29T02:46:56Z
- Size: 77 changed files, +5591/−938, 6 commits

## 2. Commits

1. `ad5dd1517c13` — Wire browser Owner auth and artifact-based CI diagnostics
2. `2e24d9904920` — Harden mission execution and workspace authorization
3. `35585b14d039` — fix: enforce mission plan dependency order
4. `4b73d11a23b1` — fix: queue mission tasks through durable runtime
5. `fcad10f71b5d` — feat: make Arabic workspace natural language first
6. `71ce3c9550ad` — docs: record current runtime verification truth

## 3. CI / checks on head 71ce3c95

- `test (3.13)` (tests.yml): success
- `test` (pytest-diagnostics.yml): success
- `export` (docs-export.yml): success
- `Workers Builds: cybersentinel` (Cloudflare preview): failure — deployment
  of a preview unrelated to the desktop mission; the PR body explicitly
  scopes the bridge to loopback and does not claim production deployment.
- One comment, from the Cloudflare Workers deploy bot (build failed for the
  head commit).

## 4. What the PR actually changes (complete file list read)

- Browser Owner auth in `bridge.py`: `POST /api/public/auth/login`,
  `POST /api/public/auth/logout`, `GET /api/public/auth/session`,
  CSRF/Origin-checked `/api/public/chat`, owner session cookie
  (`cs_owner_session`), scoped `Path=/api/public` cookies, session rotation,
  anonymous sessions still denied Owner authority.
- Full Arabic workspace UI in `web/app.js` (+543/−27), `web/index.html`
  (+52/−15): missions list/create, start/resume/pause/cancel/reconcile,
  evidence/findings/timeline/logs/artifacts tabs, read-only file viewer and
  git views, status page.
- Mission/workspace backend hardening: `agent/mission.py` (PAUSED status,
  system-signed completion proofs, `to_public_dict` redaction),
  `agent/mission_runtime.py`, `agent/agent_core.py` (Owner tool budget,
  execution proof boundary), `agent/mission_worker.py`,
  `agent/mission_task_adapter.py`, `security/execution_proof.py` (new),
  `security/execution_boundary.py` (new), `security/owner_budget.py` (new),
  `security/truthfulness.py` (new), `tools/registry.py`,
  `workspace/environment.py`, `core/db.py`, `core/engine.py`,
  `api/chat.py`, `api/missions.py`.
- CI: `tests.yml`, `pytest-diagnostics.yml`, `docs-export.yml`,
  `github-only-poc.yml` converted from commit/push diagnostics to read-only
  artifact uploads (`contents: read`), secret-scan output no longer printed,
  `node --check web/app.js` added to CI.
- Docs: `docs/PRODUCT_WORKSPACE_API.md` (new), `docs/PROVIDER_CONTRACT.md`
  (new), plus README/OPERATIONS/SECURITY_MODEL/TESTING/AGENT_ARCHITECTURE/
  PUBLIC_WEB_ARCHITECTURE/CURRENT_RUNTIME_TRUTH updates and `.env` templates.
- Tests: new `tests/test_product_workspace_boundary.py` (290 lines),
  `tests/test_mission_worker_lifecycle.py` (179),
  `tests/test_task_mission_compatibility.py` (203),
  `tests/test_execution_proof_boundary.py` (87),
  `tests/test_ci_diagnostics_workflow.py` (19); PR body reports
  713 passed, 1 skipped.

## 5. Comparison with current repository state

- The PR is not merged; `main` still ends at `8a3fd109` and its bridge lacks
  the missions/workspace public routes (`/api/public/missions`,
  `/api/public/workspace/...`) and the full Arabic UI
  (main's `web/app.js` is about 4 KB vs about 25 KB at the PR head).
- Everything the PR adds still exists verbatim at its head branch; nothing
  in the PR was reverted.
- Backend changes in the PR are treated as read-only source of truth; the
  desktop mission merged nothing and modified none of them.

## 6. Desktop implications

- The desktop shell targets the PR head tree because that is where the
  existing web UI is complete and connected to real backend capabilities
  (Owner login, missions, evidence, workspace, git views) with green CI.
- The branch `desktop/windows-exe` was created from the PR head commit
  `71ce3c9550ad` and adds only desktop/packaging/docs files. PR #17 itself
  was not merged, rebased, or modified.
- Desktop uses: the shipped UI, the public API contract documented in
  `docs/DESKTOP_BACKEND_CONTRACT.md`, the Owner username/password
  authentication, and `GET /api/public/health` as its probe.
- Desktop deliberately does not modify: every backend file the PR touches,
  and every CI workflow the PR reworked. The desktop CI
  (`desktop-windows-build.yml`) is separate and read-only
  (`contents: read`).
- Known limitation observed in the PR (recorded, not fixed, backend freeze):
  the max-steps Arabic message in `agent/loop.py` contains mojibake bullet
  characters (see `DESKTOP_BACKEND_BLOCKERS.md`).
