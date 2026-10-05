# Security Boundaries

## Authority and effects

Owner authentication, persisted Mission authorization snapshots, canonical scope snapshots, ToolSpec metadata, execution fences, and evidence validation remain the canonical route for effectful work. Context-required ToolRegistry dispatch validates the Mission authorization snapshot version against the persisted version and carries that exact version into the live `ExecutionContext`. A plan, agent graph, Skill, memory item, artifact, tool description, or model response is not authority. Some legacy tools still do not require an explicit `ExecutionContext`; uniform mediation remains an open gap.

## Network boundary

The `search` tool sends requests only to its fixed HTTPS provider through `security.pinned_http.PinnedSession`. That transport resolves once, rejects private/non-public destinations, connects to the pinned address, ignores ambient proxies, caps response bytes, and refuses redirects. Search-result URLs are untrusted citation metadata and are not fetched by `search` itself. A DuckDuckGo HTTP 202 challenge is reported as unavailable, never as a successful zero-result response.

The Owner-only `web_research` tool sends only a scrubbed query to that provider, then resolves each result against the exact persisted Mission Scope Snapshot before fetching. It uses DNS-pinned `GET` requests without redirects, accepts only bounded HTML/XHTML/plain text, extracts visible text without script execution, and records retrieved page content as explicitly untrusted, task-fenced evidence. Retrieval and content hashes establish which bytes were observed, not factual truth.

## Browser and MCP boundaries

Browser tools require the canonical Owner/Mission context, scope and target checks, a signed tool decision, an active execution fence, and fenced evidence/artifact handling. Navigation uses the DNS-pinned browser transport with redirects rechecked; Chromium runs with its OS sandbox and a dead proxy, and POSIX root launch is refused. Sessions are isolated to Owner, session, Mission, scope, and target. Page content and downloads are untrusted. `browser.fill` only fills a local non-sensitive field; it does not submit a form and blocks network use while filled.

MCP supports bounded HTTPS Streamable HTTP JSON/SSE `tools/list` and `tools/call` only. Requests are scope-checked and DNS-pinned without redirects. Invocation requires an Owner-approved TRUSTED server and exact normalized tool-schema approval; the client does not forward credentials. Server metadata and results are untrusted, bounded, and recorded with provenance. Timeout, cancellation, or an ambiguous remote result is not replayed automatically. OAuth, credentialed MCP, stdio/process transport, resources, prompts, and subscriptions are not implemented.

## Sandboxed project-test execution

`run_project_tests` is the only code-execution entry and is not a general terminal: it accepts only `python3 -m pytest -q --junitxml=/artifacts/pytest.xml`. Dispatch flows through the canonical ToolRegistry and requires the live `ExecutionContext`, the current persisted Mission authorization version, the authenticated Owner context bound to the exact persisted ScopeSnapshot, a Mission execution fence, and fenced evidence/artifact stores. The direct Mission API binds its authenticated Owner session and persisted scope when creating the Mission; client-provided Owner identity alone is not accepted.

On Linux, the runner requires a non-root process, usable namespaces, Bubblewrap, `prlimit`, and race-resistant directory handles; if a required boundary is unavailable, it fails closed without an unsandboxed fallback. Bubblewrap unshares user, network, PID, IPC, and UTS namespaces, drops capabilities, mounts the runtime/Python paths and authorized workspace read-only, and clears the host environment before setting a small fixed environment. `/tmp` is a 64 MiB tmpfs, `/artifacts` is a 4 MiB tmpfs, and only the individual pytest-report file is bound for capture—no writable host directory is exposed. `prlimit` caps CPU at 60 seconds, address space at 1 GiB, file size at 4 MiB, open files at 128, and child processes at 32. Output is bounded; timeout/cancellation terminates the process tree. Reports and process output are explicitly untrusted, and ambiguous timed-out effects require reconciliation rather than automatic replay.

The tested boundary is the Linux Bubblewrap namespace/mount/environment/resource-limit profile. It is not a general shell, does not include a seccomp or Landlock profile, and is not a formal claim of immunity to kernel vulnerabilities. Windows, macOS, and deployed-product sandbox acceptance have not been demonstrated.

## Owner UI workspace reads

The Desktop has separate Owner/Mission-protected APIs for listing workspace entries, reading a bounded file, and a fixed set of read-only Git queries. These are not model-facing ToolRegistry tools or general shell access. They require the active Owner session, Mission integrity and capability checks, and race-resistant workspace access; sensitive paths are hidden, file reads and listings are capped, and Git operations are fixed and time-limited.

## Data and persistence boundary

Memory is owner/Mission/request/scope filtered when the caller supplies those constraints, remains untrusted context, and is compacted transactionally without deleting source records. Artifacts are opaque, bounded, append-only blobs; each stored record binds identity, scope, provenance, classifications, metadata, size, and payload hash into an integrity-checked manifest. Artifact reads require the matching Owner identity.

Separate graph, Skill, memory, and artifact databases are not a single transaction. Their hashes detect accidental or unsophisticated tampering but do not prove an Owner signature or authorship. Coordinated backup/recovery and universal mediation of legacy compatibility paths remain open.

## Remaining controls

No general-purpose terminal, arbitrary shell command, or generic archive tool is exposed. The fixed pytest runner is Linux-specific; complete Desktop/Windows acceptance, real local inference, live external MCP, successful live public search, and end-to-end product acceptance remain separate gates. A portion of legacy tool dispatch still lacks explicit `ExecutionContext` enforcement.
