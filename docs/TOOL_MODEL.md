# Tool Model

The canonical registry in `tools/registry.py` is intentionally small and defensive. This branch contains 13 tools: `status`, `latest_intel`, `refresh_intel`, `local_security_check`, `local_system_info`, `search`, `watch`, `unwatch`, `run_project_tests`, `red_team_assess`, `scoped_http_probe`, `browser`, and `browser.fill`. Each registry entry declares its description, risk class, Owner requirement, argument schema, handler, and any required scope/effect metadata. The registry, not this document or model output, is authoritative if the list changes.

| Tool | Risk class | Input and enforced boundary |
| --- | --- | --- |
| `status` | `read` | No arguments; reads service status and recent audit events. |
| `latest_intel` | `read` | No arguments; reads collected threat intelligence. |
| `refresh_intel` | `network-read` | No model-supplied arguments; collects defensive threat intelligence through its registered provider. |
| `local_security_check` | `read` | No arguments; inspects local TCP listeners. |
| `local_system_info` | `read` | No arguments; reads local system information. |
| `search` | `read` | One non-empty, bounded string query; schema-validated before dispatch. |
| `watch` | `state-write` | One non-empty, bounded string keyword; updates local watch state. |
| `unwatch` | `state-write` | One non-empty, bounded string keyword; updates local watch state. |
| `run_project_tests` | `bounded-exec` | One project-directory string confined below the configured test root; runs only `[sys.executable, "-m", "pytest", "-q"]` with a 60-second timeout and bounded output. It accepts no command, executable, shell string, or arbitrary argv. |
| `red_team_assess` | `analysis` | One bounded string; explicitly Owner-only and produces defensive hypotheses/evidence requirements, not active exploitation. |
| `scoped_http_probe` | `network-read` | One bounded URL string and a required Scope Snapshot/authorized target. The current handler is a metadata-only placeholder and does not issue a network request. |
| `browser` | `network-read` | Bounded structured action over pinned Chromium (open/navigate, extraction, links, DOM inspection, screenshot, inert download, close); requires exact Owner/Mission, target scope, signed decision, active execution fence, and evidence context. Page content and artifacts are untrusted. |
| `browser.fill` | `state-write` | Bounded structured local field fill only; separately authorized, non-sensitive input, network disabled during fill, no submit, session closed afterward. |

The six current string-input tools are `search`, `watch`, `unwatch`, `run_project_tests`, `red_team_assess`, and `scoped_http_probe`. Each uses the canonical JSON object schema with one required string field, no extra properties, and a maximum argument length of 256 characters; handlers and scope policies impose additional tool-specific constraints. `browser` and `browser.fill` are the only structured-object inputs and carry explicit, bounded per-tool schemas; custom schemas are rejected at registry construction unless that opt-in is set. The other five tools accept no arguments. A plan may contain no more than eight tools. Unknown tools, unexpected arguments, null values, malformed arrays, and oversized strings are rejected by deterministic code before execution.

The model is a planner, not an authorization authority. Tool execution is selected from the registry; model output cannot create a new executable tool. The engine no longer contains a second distributed tool dispatch table. Owner authentication, scope authorization, execution fences, and the per-tool risk policy are checked by the runtime, not inferred from the model's proposal.
