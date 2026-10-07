# CyberSentinel X 5.2.0-rc1

CyberSentinel X is a local, defensive cybersecurity agent for threat intelligence, local security checks, evidence, policy enforcement, and auditability. The model is a planner only; the registry and deterministic Python authorization code validate and execute the fixed defensive tools. V4.9 added a safe Cyber Learning Loop: case generation, deterministic critique, Owner-only reasoning memory, and benchmark gates. Historical attacks are analyzed as evidence-limited cases; no executable attack tools are added.

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

The long-horizon mission path connects typed knowledge retrieval, provenance-labeled ContextEngine inputs, ModelRouter planning, observation interpretation, hypothesis state, information-gain classification, deterministic strategy decisions, persistent replanning, and GoalVerification. The model proposes; the Registry, Authorization layer, ExecutionContext, MissionRuntime, and evidence chain decide what can execute.

The authenticated Owner is the highest authority **inside the application policy domain** and writes the real policy, privacy rules, protection rules, scope, and Owner Instruction. This authority is carried outside model output and persists in mission provenance. It does not remove immutable platform safety boundaries such as credential separation, audit integrity, deterministic authorization, or scope enforcement.

See [`docs/AGENT_ARCHITECTURE.md`](docs/AGENT_ARCHITECTURE.md), [`docs/TESTING.md`](docs/TESTING.md), and [`docs/AGENT_INTELLIGENCE_AUDIT.md`](docs/AGENT_INTELLIGENCE_AUDIT.md) for the implemented path, test commands, and the dated real-provider/synthetic audit record. Historical audit results do not establish acceptance for the current candidate.

## Version 5.2.0-rc1 candidate architecture

The v5.2.0-rc1 candidate carries forward the durable supervised worker, fenced mission/effect recovery, independent completion verification, and self-hosted Compose deployment with a non-root read-only bridge, loopback publication, and file-backed secrets. Backup archives are versioned and SHA-256 verified; the candidate bundle includes setup/backup/restore assets and checksums. Compose remains a single-host self-hosted target, not a hosted service or high-availability claim.

The current candidate branch `work/v5.2-final-completion` includes the unpublished Windows x64 Desktop Installer candidate with a bundled backend, first-run Owner setup, project workspace, and pinned local GGUF model manager. The Windows Actions artifact is SHA-256 manifested and is not a GitHub Release. The published `v5.1.0` tag, release, installer asset, and `main` are to remain unchanged. End users do not need Python, Node, Docker, WSL, Termux, a terminal, or a manually started bridge. Public workspace file/Git views continue to fail closed on Windows unless secure handle-relative access is available. See [`desktop/README.md`](desktop/README.md), [`docs/DESKTOP_BACKEND_CONTRACT.md`](docs/DESKTOP_BACKEND_CONTRACT.md), and [`docs/DESKTOP_ARCHITECTURE.md`](docs/DESKTOP_ARCHITECTURE.md) for installation, routes, security, and the Windows validation boundary.

**Release status:** this work is an unpublished release candidate. No final v5.2.0 tag, public release, registry publication, or production deployment is created by these instructions. The generated `release-metadata.json`, inner `SHA256SUMS`, outer `.sha256` sidecar, installer manifest, and exact-commit acceptance report identify and verify the candidate; final tagging/publication requires a separate release decision after every gate is verified.
