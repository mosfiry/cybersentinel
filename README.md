# CyberSentinel X 5.0.0

CyberSentinel X is a local, defensive cybersecurity agent for threat intelligence, local security checks, evidence, policy enforcement, and auditability. The model is a planner only; the registry and deterministic Python authorization code validate and execute the fixed defensive tools. V4.9 adds a safe Cyber Learning Loop: case generation, deterministic critique, Owner-only reasoning memory, and benchmark gates. Historical attacks are analyzed as evidence-limited cases; no executable attack tools are added.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Set different random BRIDGE_TOKEN and OWNER_TOKEN values in .env
python -m compileall -q .
pytest -q
python bridge.py
```

Open `http://127.0.0.1:8787/` locally. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for configuration and [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) for the request path.

The bridge binds only to localhost. Never commit `.env`, tokens, API keys, provider credentials, databases, or runtime state.

## Agent Core Fusion

The long-horizon mission path now connects typed knowledge retrieval, provenance-labeled ContextEngine inputs, ModelRouter planning, observation interpretation, hypothesis state, information-gain classification, deterministic strategy decisions, persistent replanning, and GoalVerification. The model proposes; the Registry, Authorization layer, ExecutionContext, MissionRuntime, and evidence chain decide what can execute.

The authenticated Owner is the highest authority **inside the application policy domain** and writes the real policy, privacy rules, protection rules, scope, and Owner Instruction. This authority is carried outside model output and persists in mission provenance. It does not remove immutable platform safety boundaries such as credential separation, audit integrity, deterministic authorization, or scope enforcement.

See [`docs/AGENT_ARCHITECTURE.md`](docs/AGENT_ARCHITECTURE.md), [`docs/TESTING.md`](docs/TESTING.md), and [`docs/AGENT_INTELLIGENCE_AUDIT.md`](docs/AGENT_INTELLIGENCE_AUDIT.md) for the implemented path, test commands, and the latest real-provider/synthetic audit record.
