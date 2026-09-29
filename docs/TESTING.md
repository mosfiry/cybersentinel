# Testing and CI

## Local validation

Install the repository dependencies with `python -m pip install -r requirements.txt`, then run:

```bash
python -m compileall -q .
node --check web/app.js
python -m pytest -q
```

The full suite includes authorization/Owner proof enforcement, one-use execution proofs, mission completion and signed-evidence invariants, persisted worker lifecycle/recovery, cross-account conversation isolation, public HTTP auth/CSRF/Origin/logout, owner-filtered mission APIs, same-owner cross-mission workspace confinement, file traversal/symlink/size/encoding defenses, frontend truthfulness, read-only Git, and the established runtime/security regressions. The focused checks are useful while iterating, but do not replace the complete suite.

The live-provider long-horizon test is an external acceptance test, not a local deterministic test. If its required provider/Owner runtime is not configured, report it as externally blocked or not run; do not count a deterministic fallback or a model narrative as live-provider evidence.

## GitHub Actions

The `tests` workflow and `pytest-diagnostics` workflow run the compiled Python check, `node --check web/app.js`, full `pytest`, patch-aware whitespace validation, and a tracked secret/sensitive-file scan. They declare only `contents: read`. Their status is captured in a short-lived Actions artifact. Neither workflow exports source files into a diagnostics artifact, writes commits, or pushes a branch. `docs-export` preserves a documentation-only tarball as an artifact and is also read-only.

For a pull request, CI whitespace validation compares the actual PR range with its base SHA. A commit's workflow result is still not a deployment or owner approval. Check the actual GitHub Actions runs after pushing the proposed branch.

## Optional manually dispatched provider acceptance workflow

`GitHub-only CyberSentinel POC` is `workflow_dispatch` only and only runs code checked out from `main`; it does not run unreviewed PR head code with provider secrets. The numeric `max_iterations` input is validated to 1–16 before work starts. It requires Actions secrets named `OPENAI_API_BASE`, `OPENAI_API_KEY`, and `CYBERSENTINEL_OWNER_PASSWORD`; `REAL_PROVIDER_MODEL` is optional. The Owner password is used only to create a short-lived disposable local Owner account/session in the runner's temporary database. Secrets are not workflow inputs and are not written into the artifact.

When required secrets are missing, the workflow records a `BLOCKED` proof artifact and starts no mission. A `BLOCKED` artifact is not PASS. When configured, review the actual run logs and JSON artifact for provider/model, mission ID/status, evidence count, verification, and the SHA-256 digest. Do not accept a commit message, checklist statement, or CI green badge in place of the artifact itself.

## Reporting discipline

Keep the categories distinct:

- local test run: evidence for local code behavior;
- GitHub Actions run: CI evidence for the exact commit SHA;
- live-provider run: separate external acceptance evidence;
- deployment: a real configured target and operational evidence.

A skipped, blocked, unavailable, or unconfigured check is not a pass. Do not weaken a regression, skip a failing test, or label untested deployment/production behavior as verified.
