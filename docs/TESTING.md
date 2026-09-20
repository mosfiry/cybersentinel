# Testing

Install development dependencies with `python -m pip install -r requirements.txt`. Run the syntax check with `python -m compileall -q .` and the regression suite with `pytest -q`.

The regression tests cover bridge/Owner credential separation, missing Owner authentication, planner policy propagation, provider/model provenance, deterministic fallback, unknown tools, malformed arguments, and argument length limits.

For a local smoke test, configure separate `BRIDGE_TOKEN` and `OWNER_TOKEN`, run `python bridge.py`, request `/api/health`, then call `/api/status` with the bridge header and `/api/command` with both headers. Never place real credentials in GitHub Actions or source control.
