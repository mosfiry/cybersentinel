# GitHub-Only CyberSentinel X POC Results

**POC branch:** `feature/github-only-poc`
**POC commit:** `276406d87a0a26af9ceb2e1296a83e81eeaaa21d`
**Main branch:** unchanged at `f1ed9ae21fe5ff9e806daebc76db8be549ccbe74`
**Remote branch:** `origin/feature/github-only-poc`
**Scope:** no Firebase, Cloud Run, VPS, Billing, provider credential, Owner credential, or self-hosted runner was used.

## Result summary

The GitHub-only result is **PARTIAL**:

- A static GitHub Pages UI is technically possible, subject to repository/project Pages configuration and public-asset limitations.
- GitHub Actions can run bounded Python tests and scripts.
- GitHub Actions artifacts can carry bounded non-secret proof files.
- GitHub REST `workflow_dispatch` is a control-plane trigger, not a persistent API server.
- GitHub alone did not provide a persistent public HTTPS CyberSentinel backend in this POC.
- A real LLM mission was **not executed** because no provider or Owner credentials were supplied.
- No fake provider, mock success, simulated MissionRuntime, or fabricated evidence was used.

## Architecture that was actually prepared

```text
Approved external dispatcher
    → GitHub workflow_dispatch
    → GitHub Actions hosted runner
    → bounded Python CyberSentinel process
    → REAL provider only when approved secrets exist
    → request_id / mission_id / evidence / verification JSON
    → SHA-256 proof hash
    → Actions artifact
```

The workflow is `.github/workflows/github-only-poc.yml`. It is deliberately bounded to 20 minutes, accepts a maximum iteration input, runs compilation and the existing test suite, and uploads only non-secret proof output.

When `OPENAI_API_BASE`, `OPENAI_API_KEY`, or `OWNER_TOKEN` is absent, the workflow writes exactly:

```text
NOT EXECUTED — credentials unavailable
```

It then uploads that non-secret status as proof. It does not call the provider and does not create a mission.

When all approved secrets are present, the workflow calls the existing `scripts/run_real_provider_mission.py` with a bounded iteration count. That existing runner uses the real configured provider path and now records `request_id`, `mission_id`, `evidence_count`, provider status/trace, verification, and mission status. A non-completed mission exits as failure rather than being converted to success.

## Practical execution evidence

### Local validation

Command:

```bash
.venv/bin/pytest -q
python3 -m compileall -q .
```

Result:

```text
542 passed, 1 skipped in 6.33s
local_validation=passed
```

The one skipped test is the existing live-provider acceptance test that requires provider configuration. It was not changed or converted into a success.

### GitHub Actions validation

The push to the feature branch automatically triggered the existing `tests` workflow:

| Field | Value |
|---|---|
| Workflow | `tests` |
| Event | `push` |
| Run ID | `35765478231` |
| Run URL | https://github.com/mosfiry/cybersentinel/actions/runs/35765478231 |
| Head SHA | `276406d87a0a26af9ceb2e1296a83e81eeaaa21d` |
| Job | `test (3.13)` |
| Status | `completed` |
| Conclusion | `success` |

This proves the existing CI test job completed successfully for the feature commit. It does **not** prove a CyberSentinel Mission completed.

### Workflow file publication

The POC workflow is present on the remote feature branch:

```text
.github/workflows/github-only-poc.yml
blob: a9d317e5c50f056f3d251d66a809d03cd635b72a
```

### Workflow dispatch attempt

The attempted command was:

```bash
gh workflow run github-only-poc.yml \
  --repo mosfiry/cybersentinel \
  --ref feature/github-only-poc \
  -f max_iterations=4
```

GitHub returned:

```text
HTTP 404: workflow github-only-poc.yml not found on the default branch
```

This is a real GitHub control-plane limitation for this experiment: the workflow is on the feature branch, but GitHub's dispatch API lookup requires the workflow to exist on the default branch. Moving it to `main` solely to enable dispatch would violate the explicit Git discipline for this POC, so it was not done.

Consequently:

| POC evidence field | Result |
|---|---|
| Workflow run ID for `github-only-poc.yml` | None — dispatch was rejected before a run was created |
| CyberSentinel request ID | None |
| Mission ID | None |
| Provider | Not executed |
| Model | Not executed |
| Execution status | `NOT EXECUTED — credentials unavailable` by workflow design; workflow itself was not dispatchable from the feature branch |
| Evidence count | 0 for the no-credential path; no mission was started |
| Verification result | None |
| Artifact hash | None — no POC workflow run/artifact was created |

## What GitHub can host

| Question | Evidence-based answer |
|---|---|
| Web UI | **Yes, static only.** GitHub Pages supports HTML/CSS/JavaScript and HTTPS. |
| Python | **Yes, bounded.** Actions and Codespaces can run Python; hosted Actions jobs are ephemeral. |
| Backend API | **Not as a GitHub Pages or hosted-runner service.** No persistent inbound API capability was established. |
| Persistent backend | **No, not from GitHub alone.** Codespaces is temporary development port forwarding; self-hosted runners are customer infrastructure. |
| REAL LLM | **Only through an external provider with Owner-supplied credentials.** GitHub does not provide an LLM service. |
| MissionRuntime | **Can be invoked by bounded Python code if the workflow runs, but GitHub does not host or guarantee MissionRuntime.** |
| 24/7 | **No documented support.** Actions jobs and Codespaces are bounded; Pages is static. |
| HTTPS | **Yes for Pages; temporary forwarded HTTPS for Codespaces.** Neither establishes a permanent CyberSentinel API. |
| Secrets | **Actions/Codespaces support secrets with restrictions.** Secrets must never enter Pages assets, logs, or artifacts. |
| Cost | **Free-tier quotas and plan limits apply.** Private Actions usage beyond quota can require billing; Codespaces is metered; self-hosted machine costs remain with the Owner. |

## Security outcome

The POC preserves the CyberSentinel security boundary conceptually and in the workflow design:

> `OWNER_INSTRUCTION → SYSTEM_PLATFORM → OWNER_POLICY → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`

The workflow does not:

- place a PAT in frontend JavaScript;
- publish `OWNER_TOKEN`, `BRIDGE_TOKEN`, API keys, provider keys, or HMAC secrets;
- treat workflow completion as mission completion;
- fabricate request IDs, mission IDs, evidence, or verification;
- convert missing credentials into provider success;
- create a self-hosted runner;
- use a public repository PR as a privileged self-hosted runner trigger.

The workflow has a proof-output scan that refuses artifact publication if common token/key patterns or secret variable names appear in the generated proof directory.

## Most important answer

**Can GitHub alone provide a persistent, public HTTPS CyberSentinel backend?**

**No.** GitHub Pages is static. GitHub-hosted Actions runners are bounded, ephemeral workers with no documented stable inbound HTTP endpoint. Codespaces can temporarily forward a port but stop on idle and are documented as development environments. A self-hosted runner is not GitHub-only infrastructure and carries documented persistent-compromise risks; it also does not automatically provide public HTTPS, TLS, DNS, monitoring, or durable storage.

The nearest GitHub-only arrangement is a **bounded batch POC**:

> authenticated workflow dispatch → Actions runner → real CyberSentinel process → optional real external provider → non-secret artifact

That arrangement is not a persistent backend and cannot claim 24/7 availability.

## Owner actions required

1. Add the POC workflow to the default branch only if the Owner explicitly accepts changing the default branch and wants a dispatchable workflow. This was intentionally not done in this phase.
2. Provide an approved, server-side workflow-dispatch credential if external triggering is required; never put it in Pages JavaScript.
3. Provide and approve `OWNER_TOKEN`, `OPENAI_API_BASE`, `OPENAI_API_KEY`, and optionally `REAL_PROVIDER_MODEL` as GitHub secrets if a real mission should run.
4. Decide whether the public Pages UI is acceptable given that all published assets are public.
5. Decide artifact retention and any durable evidence store beyond GitHub artifact retention.
6. Approve any external provider cost or any persistent runtime outside GitHub.
7. Approve a self-hosted runner only after threat modeling, patching, isolation, runner groups, and trust boundaries are documented.

No Owner action was taken automatically.
