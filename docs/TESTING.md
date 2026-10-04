# Testing

Install development dependencies with `python -m pip install -r requirements.txt`. Run syntax checks with `python -m compileall -q .` and the default regression suite with `pytest -q`.

The regression tests cover bridge/Owner credential separation, missing Owner authentication, planner policy propagation, provider/model provenance, deterministic fallback, unknown tools, malformed arguments, argument length limits, duplicate/invalid registry entries, closed plan schemas, canonical plan hashes, provider metadata forgery, tampered evidence, bounded `run_project_tests` execution, duplicate request claims, crash recovery, cancellation persistence, replay of completed requests, and per-tool timeout behavior. HTTP and public-boundary tests exercise authenticated routes, request replay, CSRF/origin checks, workspace bounds, and redacted responses.

## Local smoke test

1. Set a private `BRIDGE_TOKEN` in an untracked `.env` file; do not commit it.
2. Initialize the Owner username/password account with `python -m security.owner_password_bootstrap`.
3. Start the bridge with `python bridge.py` and open `http://127.0.0.1:8787/` on the same device.
4. `GET /api/health` checks process liveness. `GET /api/health/ready` additionally requires `X-CyberSentinel-Token` and checks initialized state.
5. Sign in through the UI using the Owner username/password. The browser uses server-managed HttpOnly session cookies and CSRF protection for writes. Direct internal Owner routes require both the bridge transport header and an active Owner session via `X-CyberSentinel-Owner-Session`.

There is no runtime `OWNER_TOKEN` credential. `BRIDGE_TOKEN` authenticates the transport only and does not establish Owner identity. Never put real credentials in source control, CI logs, browser storage, or model prompts.

## Agent Core Fusion validation

The adaptive-loop regression file is `tests/test_agent_adaptive_loop.py`. It covers successful observations that trigger replanning, contradictory evidence that weakens one hypothesis and activates another, low/medium/high/critical information-gain classification, typed knowledge retrieval and ContextEngine routing, knowledge-injection resistance, Owner/objective/scope immutability, malformed model proposals, crash recovery, idempotent completed actions, deterministic dead-loop detection, a persisted 21-turn retention trajectory, and multilingual natural-language entrypoints. The stable CVE fixture is loaded through `KnowledgeObject`, `TypedKnowledgeRetriever`, `KnowledgeProvider`, and `ContextEngine` rather than being asserted as an isolated JSON file.

The complete deterministic validation command is:

```bash
python -m compileall -q .
python -m pytest -q
python -m pytest tests/test_agent_adaptive_loop.py -q
```

## Opt-in live-provider validation

`tests/test_real_provider_long_horizon.py` is skipped unless both `CYBERSENTINEL_LIVE_PROVIDER_KEY` and `CYBERSENTINEL_LIVE_ROUTER_FACTORY=module:function` are configured. The factory must return a router implementing `tool_calling(messages, tools)`; the harness makes at least 20 model turns. This is a live external-provider test, not a deterministic unit test. Run it only when the Owner has explicitly authorized the provider, test inputs, and usage budget. Do not supply credentials through source files or logs.

`scripts/run_agent_intelligence_audit.py` also makes live-provider requests when `LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` configure a provider; its real mission path may make additional requests. It is not part of the ordinary no-network test command. The checked-in `docs/AGENT_INTELLIGENCE_AUDIT.md` is a dated historical report and is not evidence for a later release SHA. For the 5.0.0 V14 candidate, the long-horizon test was skipped because its key and router factory were not configured; no live provider was contacted.
