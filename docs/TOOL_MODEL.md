# Tool Model

The tool registry is intentionally small and defensive. The current known tools are `status`, `latest_intel`, `refresh_intel`, `local_security_check`, `local_system_info`, `search`, `watch`, and `unwatch`.

Only `search`, `watch`, and `unwatch` accept arguments, and each argument must be a non-empty string no longer than 256 characters. A plan may contain no more than eight tools. Unknown tools, unexpected arguments, null values, malformed arrays, and oversized strings are rejected by deterministic code before execution.

The model is a planner, not an authorization authority. Tool execution is selected from the fixed Python implementation in `core/engine.py`; model output cannot create a new executable tool.
