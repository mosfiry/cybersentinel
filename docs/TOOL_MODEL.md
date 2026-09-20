# Tool Model

The tool registry in `tools/registry.py` is intentionally small and defensive. The current known tools are `status`, `latest_intel`, `refresh_intel`, `local_security_check`, `local_system_info`, `search`, `watch`, and `unwatch`. Each registry entry declares its description, risk class, Owner requirement, argument type, and handler.

Only `search`, `watch`, and `unwatch` accept arguments, and each argument must be a non-empty string no longer than 256 characters. A plan may contain no more than eight tools. Unknown tools, unexpected arguments, null values, malformed arrays, and oversized strings are rejected by deterministic code before execution.

The model is a planner, not an authorization authority. Tool execution is selected from the registry; model output cannot create a new executable tool. The engine no longer contains a second distributed tool dispatch table.

`run_project_tests` is deliberately bounded: its argument is a project directory confined below `CYBERSENTINEL_TEST_ROOT`, and the handler always runs `[sys.executable, "-m", "pytest", "-q"]` with a 60-second timeout and bounded output. It does not accept a command, executable, shell string, or arbitrary argv from the model.

`red_team_assess` is explicitly `owner_only` and has risk class `analysis`. It produces defensive hypotheses and required evidence for an Owner observation. It is not an exploit primitive, scanner, shell, credential, persistence, or network-action tool; any future active assessment must be a separately reviewed, bounded capability.
