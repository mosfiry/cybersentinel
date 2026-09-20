# Testing

Install development dependencies with `python -m pip install -r requirements.txt`. Run the syntax check with `python -m compileall -q .` and the regression suite with `pytest -q`.

The regression tests cover bridge/Owner credential separation, missing Owner authentication, planner policy propagation, provider/model provenance, deterministic fallback, unknown tools, malformed arguments, argument length limits, duplicate/invalid registry entries, closed plan schemas, canonical plan hashes, provider metadata forgery, tampered evidence, and bounded `run_project_tests` execution.

For a local smoke test, configure separate `BRIDGE_TOKEN` and `OWNER_TOKEN`, run `python bridge.py`, request `/api/health`, then call `/api/status` with the bridge header and `/api/command` with both headers. Never place real credentials in GitHub Actions or source control.
