# CyberSentinel X 5.0.0

CyberSentinel X is a local, defensive cybersecurity agent for threat intelligence, local security checks, evidence, policy enforcement, and auditability. The model proposes; the registry and deterministic authorization code validate and execute the fixed defensive tools. The platform includes a persistent mission runtime, Owner-only reasoning memory, and defensive learning/evaluation paths. Historical attacks are analyzed as evidence-limited cases; no executable attack tools are added.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Set a random BRIDGE_TOKEN in .env; the example enables the browser UI only on localhost.
python -m security.owner_password_bootstrap
python -m compileall -q .
pytest -q
python bridge.py
```

Open `http://127.0.0.1:8787/` locally and sign in with the Owner username and password created by the bootstrap command. The password is stored as a scrypt verifier in the local database; the browser receives only an HttpOnly session cookie, never the bridge token or a session ID in page storage. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for configuration and [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) for the request path.

The bridge binds only to `127.0.0.1`. Browser API routes require `PUBLIC_WEB_ENABLED=true`, a short-lived CSRF-protected public session, and Owner login for chat; an anonymous public session does not grant Owner authority. `BRIDGE_TOKEN` remains a separate internal transport credential. Never commit `.env`, passwords, tokens, API keys, provider credentials, databases, or runtime state.

## Agent Core Fusion

The long-horizon mission path now connects typed knowledge retrieval, provenance-labeled ContextEngine inputs, ModelRouter planning, observation interpretation, hypothesis state, information-gain classification, deterministic strategy decisions, persistent replanning, and GoalVerification. The model proposes; the Registry, Authorization layer, ExecutionContext, MissionRuntime, and evidence chain decide what can execute.

The authenticated Owner is the highest authority **inside the application policy domain** and writes the real policy, privacy rules, protection rules, scope, and Owner Instruction. This authority is carried outside model output and persists in mission provenance. It does not remove immutable platform safety boundaries such as credential separation, audit integrity, deterministic authorization, or scope enforcement.

See [`docs/AGENT_ARCHITECTURE.md`](docs/AGENT_ARCHITECTURE.md), [`docs/TESTING.md`](docs/TESTING.md), and [`docs/AGENT_INTELLIGENCE_AUDIT.md`](docs/AGENT_INTELLIGENCE_AUDIT.md) for the implemented path, test commands, and the latest real-provider/synthetic audit record.
