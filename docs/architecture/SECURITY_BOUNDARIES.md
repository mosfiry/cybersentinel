# Security Boundaries

## Authority and effects

Owner authentication, mission authorization snapshots, scope checks, ToolSpec metadata, execution fences, and evidence validation remain the canonical route for effectful work. A plan, agent graph, skill candidate, memory item, artifact, tool description, or model response is not authority. Graph permission checks and skill revision checks are additional restrictions; they do not replace current authorization immediately before dispatch.

The `search` tool remains Owner-authorized and is recorded as network-read with a bounded search-provider boundary. Web-search output is explicitly `untrusted_data`. It is not an instruction source, not a validated finding, and not permission to access the URL it cites.

## Network boundary

The web provider sends requests only to its fixed HTTPS search endpoint through `security.pinned_http.PinnedSession`. That transport resolves once, rejects private/non-public destinations, connects to the pinned address, ignores ambient proxies, caps response bytes, and refuses redirects. Result URLs are validated as HTTP(S) citation metadata and are not fetched. A DuckDuckGo HTTP 202 challenge is reported as unavailable, never as a successful zero-result response.

## Data and persistence boundary

Memory is owner/mission/request/scope filtered when the caller supplies those constraints, remains untrusted context, and is compacted transactionally without deleting source records. Artifacts are opaque, bounded, append-only blobs; each stored record binds identity, scope, provenance, classifications, metadata, size, and payload hash into an integrity-checked manifest. Artifact reads require the matching owner identity.

Separate graph, skill, memory, and artifact databases are not a single transaction. Their hashes detect accidental or unsophisticated tampering but do not prove an Owner signature or authorship. Coordinated backup/recovery and universal mediation of legacy compatibility paths remain open.

## Residual controls

Browser automation and MCP are not implemented; no claim is made that their network, credentials, DOM, download, or remote-tool risks are covered. Full desktop/Windows acceptance, real local inference, and end-to-end graph/skill dispatch also remain separate gates.