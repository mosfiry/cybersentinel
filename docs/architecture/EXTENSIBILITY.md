# Tool and Service Extensibility

`tools/registry.py` is the canonical allowlist and dispatch boundary. New capabilities should be represented by `ToolSpec` and use its input schema, risk class, owner/scope requirements, timeout, effect-provider identity, evidence requirements, and the existing execution/authorization path. Do not create a second registry for browser, MCP, filesystem, terminal, git, archives, model calls, or knowledge operations.

The web provider is integrated behind the existing SearchProvider/SearchService abstraction and invoked through the established `search` ToolSpec. Its fixed remote search endpoint is bounded and pinned; arbitrary result URLs are data and are not fetched. Skills contain declarative steps that refer to canonical tools and are dispatched only through an injected host seam that must reauthorize each effect.

`ArtifactStore` is a storage service, not an executable tool or a permission source. It can hold bounded outputs with owner/mission/task identity, content and manifest hashes, sensitivity, validation, confidence, scope and provenance. A future API or tool exposing artifacts must still apply Owner authorization and must not treat stored bytes as trusted code.

Every future adapter should fail closed on unknown or stale capabilities, preserve source provenance, treat remote output as untrusted, honor cancellation and size/time limits, and write evidence through the existing evidence boundary. Add tests at the ToolSpec and effect boundary—not only at the provider helper—before surfacing a capability to a model.