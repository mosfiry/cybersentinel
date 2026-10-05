# Public Web Provider Live Check

- **Checked:** 2026-10-05 (UTC timestamp recorded by the implementation session).
- **Source endpoint:** [DuckDuckGo HTML search](https://html.duckduckgo.com/html/).
- **Method:** one low-impact, read-only request through the repository's existing DNS-pinned `PinnedSession`; no account, credentials, or writes were used.
- **Observed:** HTTP 202, an anti-automation/challenge response, and no parseable result entries.
- **Handling:** `WebSearchProvider` reports this challenge as provider-unavailable; it must not be interpreted as a successful zero-result search.

This is a single endpoint observation, not evidence that the service is permanently unavailable or that all production networks will receive the same response. Mocked provider/security tests remain the basis for deterministic code-path validation; live endpoint availability remains an external acceptance gate.

The later Mission-scoped `web_research` path reuses this exact SearchService provider and surfaces provider-unavailable status without falling back. Its search-to-fetch/extract tests use a deterministic searcher and a controlled localhost source; they do not replace this live check or demonstrate successful public search/fetch acceptance.
