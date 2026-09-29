# CyberSentinel X 5.0.0

CyberSentinel X is a local, defensive cybersecurity agent for threat intelligence, local security checks, evidence, policy enforcement, and auditability. The model proposes; the registry and deterministic authorization code validate and execute the fixed defensive tools. The platform includes a persistent mission runtime, Owner-only reasoning memory, and defensive learning/evaluation paths. Historical attacks are analyzed as evidence-limited cases; no executable attack tools are added.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Set a fresh random BRIDGE_TOKEN in .env; browser UI access remains localhost-only.
python -m security.owner_password_bootstrap
python -m compileall -q .
node --check web/app.js
python -m pytest -q
python bridge.py
```

Open `http://127.0.0.1:8787/` locally and sign in with the Owner username/password created by the bootstrap command. The password is stored as a scrypt verifier in the local database; the browser receives only an HttpOnly Owner-session cookie, never the bridge token or a session ID in page storage. The mission workspace, evidence, activity, findings linked to signed evidence, file viewer, and read-only Git views are backed by authenticated APIs. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for configuration and backups, [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) for the canonical request path, [docs/PRODUCT_WORKSPACE_API.md](docs/PRODUCT_WORKSPACE_API.md) for the browser API/security contract, [docs/PROVIDER_CONTRACT.md](docs/PROVIDER_CONTRACT.md) for provider capabilities and limits, and [docs/TESTING.md](docs/TESTING.md) for validation guidance.

The bridge binds only to `127.0.0.1`. Browser API routes require `PUBLIC_WEB_ENABLED=true`, a short-lived CSRF-protected public session, and Owner login for protected workspace APIs; an anonymous public session does not grant Owner authority. `BRIDGE_TOKEN` remains a separate internal transport credential. Never commit `.env`, passwords, tokens, API keys, provider credentials, databases, or runtime state.

## Mission execution and evidence

The long-horizon mission path connects typed knowledge retrieval, provenance-labeled ContextEngine inputs, ModelRouter planning, observation interpretation, hypothesis state, information-gain classification, deterministic strategy decisions, persistent replanning, and GoalVerification. Every executed tool remains subject to the explicit Owner tool budget and the final proof-verifying registry boundary. Completion requires independent signed evidence for the required criteria and a system-signed completion proof; model text, tool booleans, CI badges, and UI state are not proof.

The authenticated Owner sets the actual mission objective, privacy/protection policy, and scope **inside the application policy domain**. Immutable platform boundaries such as authentication, credential separation, audit integrity, workspace confinement, and deterministic authorization remain enforced. Operational CI, provider acceptance, and deployment readiness are reported as separate evidence categories.
