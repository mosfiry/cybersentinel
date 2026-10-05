# Tool Model

The canonical registry in `tools/registry.py` is authoritative. This branch **contains 16 tools**; each `ToolSpec` declares its input schema, risk class, Owner requirement, handler, and any scope/effect/evidence metadata. The registry—not this document or model output—defines executable capability.

| Tool | Risk class | Input and enforced boundary |
| --- | --- | --- |
| `status` | `read` | No arguments; reads service status and recent audit events. |
| `latest_intel` | `read` | No arguments; reads collected threat intelligence. |
| `refresh_intel` | `network-read` | No model-supplied arguments; collects defensive threat intelligence through its registered provider. |
| `local_security_check` | `read` | No arguments; inspects local TCP listeners. |
| `local_system_info` | `read` | No arguments; reads local system information. |
| `search` | `network-read` | One non-empty, bounded string query; uses registered search providers, whose external results remain untrusted. |
| `web_research` | `network-read` | Bounded structured search query and result count; Owner-only and Mission-scoped; fetches only independently ScopeResolver-authorized URLs through DNS-pinned `GET`, and records cited untrusted results in fenced Mission evidence. |
| `watch` | `state-write` | One non-empty, bounded string keyword; updates local watch state. |
| `unwatch` | `state-write` | One non-empty, bounded string keyword; updates local watch state. |
| `run_project_tests` | `bounded-exec` | One project-directory string confined below the configured test root; runs only `[sys.executable, "-m", "pytest", "-q"]` with a bounded timeout and output. It accepts no command, executable, shell string, or arbitrary argv. |
| `red_team_assess` | `analysis` | One bounded string; Owner-only and produces defensive hypotheses/evidence requirements, not active exploitation. |
| `scoped_http_probe` | `network-read` | One bounded URL string and a required Scope Snapshot/authorized target. The current handler is a metadata-only placeholder and does not issue a network request. |
| `browser` | `network-read` | Bounded structured action over pinned Chromium (open/navigate, extraction, links, DOM inspection, screenshot, inert download, close); requires exact Owner/Mission, target scope, signed decision, active execution fence, and evidence/artifact context. Page data and artifacts are untrusted. |
| `browser.fill` | `state-write` | Bounded structured local field fill only; separately authorized, non-sensitive input, network disabled during fill, no submit, session closed afterward. |
| `mcp.discover` | `network-read` | Owner-only and Mission-scoped. Uses HTTPS Streamable HTTP through DNS-pinned POST/no redirects; returns a bounded tool-name/schema-hash catalog, and retrieves only one normalized schema when `tool_name` is requested. Server descriptions/annotations are withheld. |
| `mcp.invoke` | `state-write` | Owner-only, Mission-scoped, execution-fenced and evidence-backed. Invokes exactly one currently present tool from a `TRUSTED` server only when the exact normalized schema revision is Owner-approved. Classified as state-write and not parallel-safe because arbitrary remote tools may mutate external state; MCP read-only annotations are not trusted. |

The six current string-input tools are `search`, `watch`, `unwatch`, `run_project_tests`, `red_team_assess`, and `scoped_http_probe`. Each uses a canonical JSON object schema with one required string field, no extra properties, and a maximum argument length of 256 characters; handlers and scope policies impose additional tool-specific constraints. The five structured-object tools are `browser`, `browser.fill`, `web_research`, `mcp.discover`, and `mcp.invoke`; they carry explicit bounded schemas. The other five tools accept no arguments. A plan may contain no more than eight tools. The 16,000-character context tool-schema budget measures `model_tool_definitions()`—the exact canonical function schemas sent to a provider—not the duplicated local `parameters`/`input_schema` aliases or policy metadata. Unknown tools, unexpected arguments, null values, malformed arrays, and oversized strings are rejected by deterministic code before execution. For `mcp.invoke`, the generic registry schema is followed by a second runtime validation against the exact freshly discovered remote input schema before any remote call.

MCP has only two canonical wrapper tools; remote server tool names are **not** added as arbitrary executable `ToolSpec`s. The Owner+Mission trust store and the per-tool schema approval gate decide which remote revision `mcp.invoke` may reach. Discovery, trust, and invocation constraints are documented in [`docs/architecture/MCP.md`](architecture/MCP.md).

The model is a planner, not an authorization authority. Tool execution is selected from the registry; model output cannot create a new executable tool. The engine does not use a second distributed dispatch table for these tools. Owner authentication, scope authorization, execution fences, effect-ledger reservations, and per-tool risk policy are checked by the runtime, not inferred from the model's proposal.
