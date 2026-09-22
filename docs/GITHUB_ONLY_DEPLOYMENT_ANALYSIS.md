# GitHub-Only Deployment Analysis — CyberSentinel X

**Baseline:** `feature/github-only-poc`, based on commit `846efa2aea5732ba6261832acf10d298015af3eb`
**Scope:** GitHub Pages, Actions, runners, Codespaces, API dispatch, artifacts, secrets, environments, and self-hosted runner constraints. No GitHub credential, provider credential, billing change, or external deployment was used.

## Executive conclusion

GitHub can provide a **static HTTPS Web UI** through GitHub Pages and can execute **bounded Python jobs** through GitHub Actions. It can also retain bounded proof files as Actions artifacts and start a configured workflow through an authenticated REST `workflow_dispatch` request.

GitHub alone cannot, on the official capabilities reviewed, provide a **persistent public HTTPS CyberSentinel backend**. GitHub Pages is static hosting and does not support server-side Python. GitHub-hosted Actions runners are ephemeral job workers, not inbound application servers. Codespaces can temporarily forward a running port over HTTPS, but stop after inactivity and are documented as development environments. Self-hosted runners are customer-managed infrastructure and carry explicit compromise risks; they are not GitHub-only hosting.

Therefore a GitHub-only POC can prove bounded execution and artifact generation, but it cannot honestly claim a 24/7 CyberSentinel API, persistent MissionRuntime, autonomous long-running agent, or GitHub-provided real LLM service.

## Capability comparison

| Capability | GitHub Pages | GitHub Actions / hosted runner | GitHub Codespaces | Self-hosted Runner |
|---|---|---|---|---|
| Static Web UI | **Yes.** Static HTML/CSS/JS publishing. | **Indirectly.** Can build/deploy to Pages; runner itself is not hosting. | **Not documented as hosting.** Development container only. | **Not documented.** Must add and operate a separate web server. |
| Python execution | **No.** Pages does not support server-side Python. | **Yes, bounded job.** `setup-python` and workflow scripts. | **Yes, in the development container.** | **Depends on operator image/setup.** |
| Persistent HTTP server | **No.** Static files only. | **No documented support.** Job process ends with runner/job lifecycle. | **Temporary forwarded port only.** | **Possible only as operator-managed infrastructure, not a GitHub guarantee.** |
| 24/7 runtime | **No.** | **No.** Jobs are bounded and cancelled at documented limits. | **No guarantee.** Idle timeout and metering apply. | **No GitHub guarantee; host must remain online and jobs have limits.** |
| HTTPS endpoint | **Yes for Pages.** HTTPS and enforcement are documented. | **No runner-hosted public endpoint.** Pages can provide the static endpoint. | **Temporary HTTPS forwarded port.** | **Operator must provide TLS, DNS, firewall, and uptime.** |
| Secrets | **No runtime secret store.** Published assets are public. | **Yes, repository/org/environment secrets with workflow restrictions.** | **Yes, Codespaces secrets as environment variables.** | **Workflow secrets can reach the host; compromise risk is higher.** |
| Real LLM | **No documented capability.** | **Only through an external provider and supplied secret.** | **Only through an external provider and supplied secret.** | **Only through an external provider and operator credentials.** |
| MissionRuntime | **No documented capability.** | **Can run bounded project code, but no GitHub guarantee of this runtime.** | **Can run project code while active; not a service guarantee.** | **Can run project code if configured; operator responsibility.** |
| Long-running Agent | **No.** | **No persistent agent guarantee.** | **No unattended-production guarantee.** | **Possible only as customer-managed compute; security and job limits remain.** |
| Cost | Static Pages has documented limits and policy constraints. | Public standard runners are free; private usage is quota/billing bound. | Metered compute/storage and included quotas. | GitHub Actions usage is free, but operator pays for machine/network/maintenance. |
| Security | Public output; HTTPS does not make assets private. | Ephemeral runner, but workflow/action supply-chain and secret risks. | Public forwarded ports can be reachable by anyone with the URL. | GitHub warns untrusted code can persistently compromise the host. |

## Evidence and official sources

The assessment is based on current GitHub documentation, including:

- [What is GitHub Pages?](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
- [Creating project Pages manually](https://docs.github.com/articles/creating-project-pages-manually)
- [Securing GitHub Pages with HTTPS](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https)
- [GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits)
- [About GitHub-hosted runners](https://docs.github.com/actions/using-github-hosted-runners/about-github-hosted-runners)
- [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Workflow syntax and limits](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Actions limits](https://docs.github.com/en/actions/reference/limits)
- [Actions billing and usage](https://docs.github.com/en/actions/concepts/billing-and-usage)
- [Actions secrets](https://docs.github.com/en/actions/reference/security/secrets)
- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Python setup action](https://github.com/actions/setup-python)
- [Codespaces overview](https://docs.github.com/en/codespaces/about-codespaces/what-are-codespaces)
- [Codespaces deep dive](https://docs.github.com/en/codespaces/about-codespaces/deep-dive)
- [Forwarding ports in Codespaces](https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace)
- [Codespaces timeout](https://docs.github.com/en/codespaces/setting-your-user-preferences/setting-your-timeout-period-for-github-codespaces)
- [Codespaces secrets](https://docs.github.com/en/codespaces/managing-your-codespaces/managing-your-account-specific-secrets-for-github-codespaces)
- [Codespaces security](https://docs.github.com/en/codespaces/reference/security-in-github-codespaces)
- [Create a workflow dispatch event](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)
- [Actions environments](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment)
- [Store and share data with workflow artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data)
- [Artifact and log retention](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization)
- [Self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
- [Security of self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Free included usage](https://docs.github.com/en/billing/reference/product-usage-included)

## CyberSentinel-specific security conclusion

The GitHub mechanism must not bypass the existing chain:

> `SYSTEM_PLATFORM → OWNER_POLICY → OWNER_INSTRUCTION → DETERMINISTIC_ENFORCEMENT → AUTHORIZATION_SCOPE → TOOL_RUNTIME → MODEL_OUTPUT → EXTERNAL_DATA`

A Pages asset cannot contain `OWNER_TOKEN`, `BRIDGE_TOKEN`, provider keys, session secrets, or HMAC material. An Actions secret can be used only within a bounded workflow and must never be emitted into logs, artifacts, generated JavaScript, or Pages output. A workflow completion is not a MissionRuntime completion; the proof must show the process, runtime, provider, tool execution, evidence, and verification independently.

## Closest executable architecture

The closest no-new-infrastructure architecture is:

```text
Operator / approved REST caller
    → authenticated workflow_dispatch
    → GitHub Actions hosted runner
    → bounded CyberSentinel Python process
    → REAL provider only when approved secrets exist
    → non-secret JSON proof artifact
    → optional static Pages dashboard
```

This is a **batch/POC architecture**, not a public backend. The current branch adds a workflow that fails closed when the provider and Owner credentials are unavailable and records `NOT EXECUTED — credentials unavailable` rather than fabricating a result.

## Owner decisions required

- Configure a secure workflow-dispatch caller credential; do not put it in frontend JavaScript.
- Supply and approve `OWNER_TOKEN` and real provider credentials if a real mission is to run.
- Decide whether a public Pages site is appropriate given that all published assets are public.
- Decide artifact retention and any durable evidence store beyond GitHub's retention window.
- Approve any private-repository Actions quota, billing, external provider cost, or separately managed persistent runtime.
- Approve any self-hosted runner only after a threat model, trust boundary, patching plan, and network isolation are documented.
