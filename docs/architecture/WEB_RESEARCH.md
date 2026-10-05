# Mission-Scoped Web Research

## Status

The production ToolRegistry contains `web_research`, an Owner-only, Mission-scoped read-only research operation. It combines the existing `SearchService` web adapter with bounded extraction from a small number of source URLs that are independently authorized by the Mission's persisted Scope Snapshot. This implementation is **not** evidence that the public search provider is operationally available: the most recent live check received an HTTP 202 anti-automation response with no results. See [`PROVIDER_LIVE_CHECK.md`](PROVIDER_LIVE_CHECK.md).

## Dispatch and authority

`web_research` uses the canonical `ToolRegistry.execute` path. Dispatch requires a signed `AuthorizationDecision`, the current Mission authorization snapshot, the canonical authenticated Owner `ExecutionContext`, a strict Mission evidence store, and the active task-bound execution fence. The Mission must explicitly authorize this tool and its network boundary. Registry preflight checks the current Mission scope URL; every discovered source URL then undergoes a separate `ScopeResolver.resolve` check for the same persisted `scope_snapshot_id`, `target_id`, `program_id`, and `GET` method. A search result never widens target authority. Out-of-scope URLs are skipped before any fetch request, and sensitive or malformed URL-query values are rejected.

The search endpoint is the existing explicitly configured Web `SearchService` provider; this implementation has no search-engine fallback. Search queries are bounded to 512 characters, credential patterns are removed before the outbound search call, and query caching is disabled. Search result snippets are treated only as untrusted locator/provenance data; they are not adopted as findings.

## Fetch and extraction limits

| Boundary | Limit or policy |
|---|---|
| Search results | At most 3 per tool invocation |
| Search request timeout | 8 seconds |
| Page fetch timeout | 4 seconds per source |
| Fetched body | At most 512,000 bytes |
| Accepted content types | `text/html`, `application/xhtml+xml`, `text/plain` |
| HTTP methods | `GET` only |
| Redirects | Not followed; 3xx responses are not cited |
| Transport | Existing DNS-pinned `pinned_http_request`; public addresses required in production |
| Extracted text | At most 2,000 characters per source |

The extractor uses Python's `HTMLParser`; it never executes page scripts. It omits script, style, form, SVG, canvas, template, and noscript contents. Credential-like material is scrubbed from query, title, excerpt, and evidence text. The tool never forwards cookies, authorization headers, browser session state, or Owner credentials to the search or source sites.

Every returned excerpt is labeled `UNTRUSTED_WEB_CONTENT`; each batch/result carries `trust: untrusted_data` and `authority: none`. Confidence is explicitly `not_assessed` for factual validity. A content digest proves only which response bytes and sanitized excerpt were observed; it does not establish the truth of page claims.

## Evidence and provenance

Each successfully fetched source is appended through the existing strict `EvidenceChainStore` using the active execution fence. The record contains its canonical URL, retrieval time, raw-response SHA-256, sanitized-excerpt SHA-256, source-provider identity, query digest, exact Mission/Task/execution/target/scope provenance, and an explicit untrusted/retrieval-only verification classification. The raw query, raw provider response, unsanitized page bytes, and credentials are not persisted. Returned citations use stable batch-local labels (`[W1]`, `[W2]`, `[W3]`) and an opaque digest of the fenced evidence receipt.

Provider failure, no-result, no-in-scope-source, and fetch failure are distinct bounded status categories. Raw provider exceptions and page-controlled strings are not returned as error text. No evidence is written for a source that fails URL authorization, fetch, content-type validation, extraction, or active-context revalidation.

## Verification and remaining gaps

`tests/test_web_research.py` covers scrubbed search dispatch, exact Scope Resolver decisions, out-of-scope and secret-bearing URL refusal, real DNS-pinned HTTP to a controlled local fixture (with loopback permitted only by the test fetcher), safe extraction, secret scrubbing, evidence hashes/provenance, no raw provider error disclosure, cancellation-before-dispatch, and schema/fence rejection. The positive Registry/ExecutionContext integration also runs in the controlled local Browser integration test. These are deterministic provider/control-plane and localhost tests, not successful live-web or authenticated product acceptance.

Current gaps include the upstream anti-automation challenge, no successful live public search/fetch acceptance, no broad-source research outside explicitly authorized Mission targets, no independent factual cross-check or LLM synthesis, no citation-quality scoring, and no production evaluation-run creation. Live provider availability, Windows acceptance, and real local-Qwen/Mission acceptance remain unverified.
