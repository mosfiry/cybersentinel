# Browser Automation

CyberSentinel does not yet provide an in-process browser agent. The new web-search provider retrieves only a bounded search-results page; it does not navigate to result URLs, inspect live DOM, fill forms, click controls, take screenshots, or download files. The public search result URL is metadata only and is never fetched by that provider.

A future browser must use the canonical flow **Agent proposal → current authorization and scope check → registered browser ToolSpec → bounded browser action → evidence receipt**. Browsing and authorization must remain separate: page text, links, scripts, form labels, and downloads are untrusted observations and cannot grant permissions or alter Owner policy.

The browser boundary must enforce allowed origins and redirects at every navigation, prevent secret submission to unapproved destinations, require explicit authorization for destructive or state-changing actions, and restrict local-file access. Executables and other active downloads need a separate policy and must not be launched automatically. Timeouts, cancellation, response limits, download hashing, screenshot/DOM provenance, and prompt-injection tests are required for acceptance.

The existing desktop application's hardened renderer/preload boundary is not browser automation and is not evidence that these browser capabilities exist.