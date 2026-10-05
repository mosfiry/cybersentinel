# Model Context Protocol (MCP)

## Status

CyberSentinel now contains a bounded **MCP client slice** for Streamable HTTP tool discovery and invocation. It uses the existing canonical `ToolRegistry` and `ExecutionContext`; it is not a general MCP host and has not been accepted against a live external MCP server. See `docs/HERMES_LEVEL_GAP_CLOSURE.md` for current test evidence and parity gaps.

## Protocol and transport

The client implements MCP protocol revision `2025-06-18` over **HTTPS Streamable HTTP** only. It sends JSON-RPC requests by HTTP POST, handles either JSON or Server-Sent Events responses, performs `initialize` and `notifications/initialized`, retains a bounded `Mcp-Session-Id` when supplied, and sends the negotiated `MCP-Protocol-Version` on later requests. Redirects are rejected by the existing transport. Requests go through `security.pinned_http.PinnedSession` and a fresh `ScopeResolver` decision for each POST; endpoints must be HTTPS, public-DNS-resolvable under the existing pinned transport rules, port 443, and contain no userinfo, query, or fragment. Message, schema, tool-count, argument, response, timeout, and pagination limits are enforced in code. Timeouts and cancellation are surfaced as ambiguous external outcomes; no automatic retry or replay is performed.

No authorization header, cookie, API key, or other stored credential is forwarded to MCP servers. The client does not start local stdio/subprocess servers, follow redirects, fetch resource links, process MCP resources/prompts, or subscribe to server notifications. Servers requiring OAuth or other credentials are not supported by this slice.

## Registration, trust, and approvals

The durable `MCPServerStore` is Owner+Mission keyed and uses `mcp_registry.sqlite3` beside the Mission database. Registration creates an `UNTRUSTED` endpoint record and does not contact the server; the transactional registry cap is eight servers per Mission; each server keeps at most 32 current tool schemas and absent names are pruned to prevent catalog-churn growth. A Mission may register only an endpoint allowed by its current Scope Snapshot for HTTPS POST. Management requests re-resolve the canonical Owner from the authenticated session, load only that Owner's Mission, verify Mission integrity and the signed authorization snapshot, require both `mcp.discover` and `mcp.invoke` grants, and require the exact Scope Snapshot fields. The public routes reuse the existing authenticated Owner session and CSRF checks:

| Route | Purpose |
| --- | --- |
| `GET /api/public/missions/{mission_id}/mcp` | List bounded server/tool name/hash/trust metadata. |
| `GET /api/public/missions/{mission_id}/mcp?server_id=…&tool_name=…` | Inspect one bounded normalized input/output schema and its approval status. |
| `POST /api/public/missions/{mission_id}/mcp` | Register an in-scope HTTPS endpoint as `UNTRUSTED`. |
| `POST /api/public/missions/{mission_id}/mcp/{server_id}/trust` | Explicitly set `TRUSTED`, `KNOWN`, `UNTRUSTED`, or `BLOCKED`. Lowering trust revokes stored tool approvals. |
| `POST /api/public/missions/{mission_id}/mcp/{server_id}/approve` | Approve one discovered tool's exact normalized schema digest. |

The states are deliberately distinct: `UNTRUSTED` can be discovered but not invoked; `KNOWN` is recognized but cannot be invoked; `TRUSTED` permits only individually approved present tool revisions; `BLOCKED` prevents discovery and invocation. A trusted server identity change automatically downgrades it to `KNOWN` and clears approvals. Every invocation rediscovers current server/tool identity and exact schema before checking approval and dispatch. A changed schema, missing tool, identity drift, revoked approval, blocked server, foreign Owner/Mission, or missing Mission grant fails closed.

The identity digest is derived from endpoint, server-declared name/version, protocol revision, and tool-capability flags. It is **not** a TLS certificate pin, code attestation, or proof of server behavior. An implementation change that preserves those fields and the approved schema cannot be detected by this digest alone. Schema digests bind the normalized JSON schema, not server-side implementation semantics.

## ToolRegistry and evidence path

The only model-visible MCP entry points are two canonical `ToolSpec`s:

- `mcp.discover` lists a bounded catalog of tool names, exact schema hashes, and approval flags. Passing an optional `tool_name` retrieves only that one normalized schema. Server descriptions, instructions, annotations, icons, and arbitrary metadata are withheld.
- `mcp.invoke` invokes one individually Owner-approved schema revision from a currently `TRUSTED` server. It is classified as **`state-write`** and is not parallel-safe because an arbitrary remote MCP tool may change external state even when the server labels it read-only. It requires Owner/Mission authorization, the exact live `ExecutionContext`, scope, execution fence, effect-ledger reservation, and fenced evidence store.

Remote schemas are reduced to a strict bounded JSON Schema subset; unsupported keywords such as `$ref`, combinators, patterns, or permissive extra properties fail closed. Arguments are checked against the exact freshly discovered schema. Text results are secret-scrubbed and prefixed as `UNTRUSTED_MCP_TOOL_OUTPUT`; structured results are schema-checked, bounded, and scrubbed, including values under sensitive field keys such as tokens, passwords, API keys, cookies, and private keys. Images, audio, resource links, and embedded resources are ignored rather than fetched or returned. No result, description, annotation, or server-provided instruction can authorize another tool, change Mission scope, or gain Owner authority.

Each discovery/invocation adds a fenced `UNTRUSTED_MCP_OBSERVATION` evidence record containing Owner/Mission/task/execution bindings, tool and endpoint identity hashes, request/response digests, and bounded safe content. Raw credentials, session IDs, server descriptions, and unbounded raw arguments are not persisted. The evidence explicitly states that any remote side effect is not independently verified. A failed/timeout/cancelled invocation, including server-declared tool errors, remains ambiguous in the effect ledger and is not retried automatically.

## Verification and limitations

MCP tests use deterministic Streamable HTTP transport doubles for protocol, JSON/SSE parsing, secret/description stripping, sensitive structured-result key redaction, schema rejection, trust transitions, schema and identity drift, tenant isolation, cancellation/no-replay, timeout, evidence lineage, bounded catalog/detail and server/tool count caps, and Owner/CSRF API controls. These are **control-plane and protocol tests**, not a live external MCP server acceptance. A localhost TLS MCP server, real OAuth integration, Windows packaged runtime, and authenticated Desktop UI acceptance have not been exercised. The Owner management surface is API-only; there is no MCP management panel in the Desktop UI yet.

The SQLite content-digest checks detect schema-record inconsistency and fail closed. They do not cryptographically authenticate the registry database against an attacker who can rewrite the database and all associated approval fields on the same host. Protect the application data directory with the operating-system account boundary; local privileged-database compromise remains outside the verified guarantee.

## Protocol references

- [MCP 2025-06-18 transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [MCP 2025-06-18 tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [Official Python SDK client documentation](https://py.sdk.modelcontextprotocol.io/client/) — consulted for the supported transport model; CyberSentinel uses its own DNS-pinned HTTP transport rather than adding the SDK dependency.
