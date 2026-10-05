# Provider System

The existing model side uses provider-neutral request/response types and the `ModelRouter`/OpenAI-compatible adapter. The local model manager provides guarded model lifecycle and supply-chain checks for its supported llama.cpp path. These are the reusable foundations; new product providers should implement the same interface rather than branch-specific execution behavior.

The search side uses `SearchProvider`, `SearchRequest`, `SearchResponse`, and `SearchService`. Local knowledge and the GitHub, NVD, and MITRE providers remain separate scopes. The `web` scope now has an anonymous read-only DuckDuckGo HTML adapter that uses `security.pinned_http.PinnedSession`, refuses redirects, bounds response bytes and results, hashes provenance, and labels returned material untrusted. Search integration routes through the canonical `search` ToolSpec, whose risk metadata now identifies network-read access.

The web adapter reports `IMPLEMENTED`; it does not claim that a third-party endpoint is reachable. In this environment the live DuckDuckGo probe returned HTTP 202 with an anti-automation page and no result markup, so the provider correctly reports a typed unavailable error for that response. Real live search acceptance is therefore blocked by the endpoint response, not inferred from mocked tests.

Native vendor integrations, truthful capability negotiation across all models, GPU/backend selection, durable provider configuration, and a real end-to-end local inference run remain unverified or unimplemented. Capability labels and model catalog presence are not acceptance evidence.
