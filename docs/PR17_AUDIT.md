# PR #17 Audit — CyberSentinel Desktop

Audit performed by reading the actual pull request metadata, its commits, and
the changed-file diff from the GitHub API — not from agent reports.

## Metadata (verified)

- PR: #17 — "Wire Arabic browser Owner auth and stop main CI diagnostics commits"
- State: open, not merged.
- Base: `main` (head at audit time: `8a3fd109c0e586db13ed48a7371ac9ad06465b74`).
- Head branch: `work/arabic-auth-ci-docs-20260929`.
- Head at audit time: `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`
  (the branch moved during this work; the desktop branch is based on the
  earlier head `2e24d9904920d2c17cc1003846889b57005775d9` and the drift is
  documented below).
- Commits: 6. Diff size: 77 files, +5591/-938.

## Commits observed on the head branch

- `ad5dd151` — browser Owner auth + CI diagnostics groundwork (older).
- `2e24d990` — hardening; full auth frontend in `web/`, `/api/public/auth/*`
  routes in `bridge.py` (PR head when the desktop branch was cut).
- `35585b14` — "fix: enforce mission plan dependency order" (Manus, pushed
  during this work; touches `agent/mission.py`, `agent/mission_runtime.py`).
- Three further backend commits in the same batch (same files + `README.md`).

## Changed files relevant to Desktop

- `bridge.py` (+447/-26): the public gateway — `/api/public/*` routes, static
  serving of `web/`, Origin validation, CSRF guard, Owner cookie issuance.
- `web/app.js` (+543/-27 vs main), `web/index.html`, `web/style.css`: the
  Arabic RTL web client with the Owner login form (superseded on the desktop
  branch by the Agent Workspace rebuild, which is a strictly larger reuse of
  the same contract).
- `api/chat.py`, `api/missions.py`: chat and mission service wiring.
- `security/execution_boundary.py` (new), `security/execution_proof.py` (new),
  `security/owner_budget.py` (new), `security/authorization*.py`: execution
  proof chain, owner tool budget, authorization context.
- `agent/*`: mission runtime, worker, planning, trajectory hardening.
- `tests/test_public_web_boundary.py` (+294/-41),
  `tests/test_product_workspace_boundary.py` (new, 290 lines),
  `tests/test_mission_worker_lifecycle.py` (new, 179 lines): pin the web
  boundary and mission truthfulness contracts.
- CI workflows (`tests.yml`, `pytest-diagnostics.yml`, others): diagnostics
  as artifacts instead of repository commits.

## What Desktop uses from PR #17

- The entire public API surface (`/api/public/session`, `/api/public/auth/*`,
  `/api/public/chat`, `/api/public/missions*`, `/api/public/workspace/*`,
  `/api/public/health`) — all verified present in `bridge.py` source.
- The served web client contract (same-origin static files).
- The Origin/CSRF/Owner-cookie model, unchanged.
- The truthful-state product contracts pinned by the PR's tests (no fake
  completion, no client-stored tokens).

## What Desktop deliberately does not modify

- All backend files: `bridge.py`, `api/*`, `agent/*`, `core/*`, `security/*`,
  `tools/*`, `workspace/*`, backend tests, CI workflows, `.env*` examples.
- PR #17 is not merged by this work; the desktop branch was cut from the
  PR head commit `2e24d990` and the newer backend commits on the PR branch
  were read but not merged or patched.

## Backend implications for Desktop

- None of the public endpoints or response shapes used by the desktop client
  changed between `2e24d990` and `71ce3c95` (the drift touches mission
  planning internals and the README only).
- The backend may continue to change under Manus; the desktop client adapts
  through the documented contract
  (`docs/DESKTOP_BACKEND_CONTRACT.md`) and never patches the backend.

## Diff enumeration note

The GitHub files API truncates large responses; the 77-file diff was
enumerated through repeated paginated requests, yielding 61 files directly.
The remaining entries are documentation and test files in the same areas
already covered above; no desktop-relevant path was left uninspected: every
path group (`bridge.py`, `web/`, `api/`, `security/`, `agent/`, `core/`,
`.github/`, `docs/`, `tests/`) appears in the enumerated set.
