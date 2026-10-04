# CyberSentinel X 5.0.0

CyberSentinel X is a local, defensive cybersecurity agent for threat intelligence, local security checks, evidence, policy enforcement, and auditability. The model is a planner only; the registry and deterministic Python authorization code validate and execute the fixed defensive tools. V4.9 adds a safe Cyber Learning Loop: case generation, deterministic critique, Owner-only reasoning memory, and benchmark gates. Historical attacks are analyzed as evidence-limited cases; no executable attack tools are added.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Replace BRIDGE_TOKEN with a private, random value of at least 32 characters
python -m security.owner_password_bootstrap
python -m compileall -q .
pytest -q
python bridge.py
```

Open `http://127.0.0.1:8787/` locally. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for configuration and [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) for the request path.

By default, the bridge binds only to localhost. Compose opts into the private container interface but publishes the service only on host loopback. `BRIDGE_TOKEN` is transport authentication; Owner identity is a username/password account initialized by the interactive bootstrap command above. Never commit `.env`, tokens, API keys, provider credentials, databases, or runtime state.

## Agent Core Fusion

The long-horizon mission path now connects typed knowledge retrieval, provenance-labeled ContextEngine inputs, ModelRouter planning, observation interpretation, hypothesis state, information-gain classification, deterministic strategy decisions, persistent replanning, and GoalVerification. The model proposes; the Registry, Authorization layer, ExecutionContext, MissionRuntime, and evidence chain decide what can execute.

The authenticated Owner is the highest authority **inside the application policy domain** and writes the real policy, privacy rules, protection rules, scope, and Owner Instruction. This authority is carried outside model output and persists in mission provenance. It does not remove immutable platform safety boundaries such as credential separation, audit integrity, deterministic authorization, or scope enforcement.

See [`docs/AGENT_ARCHITECTURE.md`](docs/AGENT_ARCHITECTURE.md), [`docs/TESTING.md`](docs/TESTING.md), and [`docs/AGENT_INTELLIGENCE_AUDIT.md`](docs/AGENT_INTELLIGENCE_AUDIT.md) for the implemented path, test commands, and the latest real-provider/synthetic audit record.

## Version 5.0.0 release-candidate architecture

The 5.0.0 candidate adds a durable supervised worker, fenced mission/effect recovery, independent completion verification, and a self-hosted Compose deployment with a non-root read-only bridge, loopback publication, and file-backed secrets. Backup archives are versioned and SHA-256 verified; the candidate bundle includes setup/backup/restore assets and checksums. Compose remains a single-host self-hosted target, not a hosted service or high-availability claim.

The optional Electron Desktop shell serves the same UI/API through the local Python bridge. Python, the repository, dependencies, and private backend configuration are provisioned separately; the executable is not a bundled backend. See [`desktop/README.md`](desktop/README.md), [`docs/DESKTOP_BACKEND_CONTRACT.md`](docs/DESKTOP_BACKEND_CONTRACT.md), and [`docs/DESKTOP_ARCHITECTURE.md`](docs/DESKTOP_ARCHITECTURE.md) for requirements, routes, security boundaries, and the Windows x64 validation limit. The Owner UI exposes only supported, read-only workspace/Git views and supported mission operations; it does not claim generic approvals, transcript persistence, or streaming chat.

**Release status:** this work is an unpublished release candidate. No final tag, public release, registry publication, or production deployment is made by these instructions. The generated `release-metadata.json`, inner `SHA256SUMS`, outer `.sha256` sidecar, and exact-commit CI run identify and verify each candidate; final tagging/publication requires a separate explicit confirmation after every release gate is verified.
