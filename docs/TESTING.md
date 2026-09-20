# Testing

Install development dependencies with `python -m pip install -r requirements.txt`. Run the syntax check with `python -m compileall -q .` and the regression suite with `pytest -q`.

The regression tests cover bridge/Owner credential separation, missing Owner authentication, planner policy propagation, provider/model provenance, deterministic fallback, unknown tools, malformed arguments, argument length limits, duplicate/invalid registry entries, closed plan schemas, canonical plan hashes, provider metadata forgery, tampered evidence, bounded `run_project_tests` execution, duplicate request claims, crash recovery, cancellation persistence, replay of completed requests, and per-tool timeout behavior. The HTTP smoke test also verifies that an identical request ID produces a replay instead of a second execution and that `/api/execution/<request_id>` reconstructs the durable record.

V4.7 tests additionally verify that `red_team_assess` is inaccessible without Owner authentication, emits hypotheses and evidence requirements rather than attack instructions, rejects prompt-injection fields in knowledge objects, preserves source hashes during retrieval, and keeps external knowledge separate from authorization.

V4.9 tests verify safe case generation from reference knowledge, deterministic critic findings, benchmark-gate rejection when unsupported claims increase, Owner-only reasoning-memory access, and persistence of the case/critic record without adding executable attack capabilities.

For a local smoke test, configure separate `BRIDGE_TOKEN` and `OWNER_TOKEN`, run `python bridge.py`, request `/api/health`, then call `/api/status` with the bridge header and `/api/command` with both headers. Never place real credentials in GitHub Actions or source control.
