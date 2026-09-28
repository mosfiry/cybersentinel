# Testing

Install development dependencies with `python -m pip install -r requirements.txt`. Run the syntax check with `python -m compileall -q .` and the regression suite with `pytest -q`.

The regression tests cover bridge/Owner credential separation, missing Owner authentication, planner policy propagation, provider/model provenance, deterministic fallback, unknown tools, malformed arguments, argument length limits, duplicate/invalid registry entries, closed plan schemas, canonical plan hashes, provider metadata forgery, tampered evidence, bounded `run_project_tests` execution, duplicate request claims, crash recovery, cancellation persistence, replay of completed requests, and per-tool timeout behavior. Browser-boundary integration tests exercise anonymous-session denial, CSRF and Origin checks, username/password login, HttpOnly Owner-cookie authentication, chat delegation through the canonical Owner session, generic login failure, and session revocation on logout.

V4.7 tests additionally verify that `red_team_assess` is inaccessible without Owner authentication, emits hypotheses and evidence requirements rather than attack instructions, rejects prompt-injection fields in knowledge objects, preserves source hashes during retrieval, and keeps external knowledge separate from authorization.

V4.9 tests verify safe case generation from reference knowledge, deterministic critic findings, benchmark-gate rejection when unsupported claims increase, Owner-only reasoning-memory access, and persistence of the case/critic record without adding executable attack capabilities.

For a local smoke test, configure `BRIDGE_TOKEN`, run `python -m security.owner_password_bootstrap`, and start `python bridge.py`. Open the local web page, sign in with the Owner username/password, and verify that status shows an authenticated session. Internal API clients use `X-CyberSentinel-Token` plus a valid `X-CyberSentinel-Owner-Session`; never place real credentials in GitHub Actions or source control.

The main CI workflow has read-only repository permissions. It uploads a compact run-status artifact and does not commit diagnostics; the existing tracked `diagnostics/` history is retained unchanged. Full step logs remain attached to the Actions run.


## Agent Core Fusion validation

The adaptive-loop regression file is `tests/test_agent_adaptive_loop.py`. It covers successful observations that trigger replanning, contradictory evidence that weakens one hypothesis and activates another, low/medium/high/critical information-gain classification, typed knowledge retrieval and ContextEngine routing, knowledge-injection resistance, Owner/objective/scope immutability, malformed model proposals, crash recovery, idempotent completed actions, deterministic dead-loop detection, a persisted 21-turn retention trajectory, and multilingual natural-language entrypoints. The stable CVE fixture is loaded through `KnowledgeObject`, `TypedKnowledgeRetriever`, `KnowledgeProvider`, and `ContextEngine` rather than being asserted as an isolated JSON file.

The complete validation command is:

```bash
python -m compileall -q .
python -m pytest -q
python -m pytest tests/test_agent_adaptive_loop.py -q  # 24 adaptive-loop tests, including dead-loop and 21-turn retention gates
```

The automated audit command uses the existing configured provider route when environment variables are present. It records both a safe synthetic multi-replan trajectory and a real AgentCore mission; it does not silently convert a provider failure into a real-model success:

```bash
LLM_BASE_URL="$OPENAI_API_BASE" \
LLM_MODEL="gpt-5-mini" \
LLM_API_KEY="$OPENAI_API_KEY" \
OWNER_SESSION_TOKEN="<authenticated-owner-session-id>" \
python scripts/run_agent_intelligence_audit.py
```

The generated `docs/AGENT_INTELLIGENCE_AUDIT.md` reports provider/model provenance, mission lifecycle, observations, interpretations, replans, verification, trajectory events, limitations, and the exact commit under test. The current audit must be interpreted narrowly: the real default/gpt-5-mini mission has been executed successfully through one defensive observation with typed CVE context and an `ObservationInterpreted` event; the multi-replan, counter-evidence scenario is validated through the actual persistent MissionRuntime with deterministic fixture observations. This is evidence of the implemented path, not a claim of unrestricted autonomy or super-intelligence.
