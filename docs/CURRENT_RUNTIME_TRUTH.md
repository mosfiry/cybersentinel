# CyberSentinel X — Runtime Reachability (verified 2026-10-17)

**Comparison baseline:** `main` at `8a3fd109c0e586db13ed48a7371ac9ad06465b74` and review branch `fix/blocker-d-review-20261010` at `98e298851fb17b343e2b2a9872623f71bee15758`. At that baseline, the three legacy modules discussed below were byte-identical on `main` and the review branch. The review-branch changes remove them from the product/runtime tree; `main` was not modified.

## Current request path

```text
bridge authentication
├── GET /api/tools
│   └── tools.registry.tool_definitions()
├── GET /api/status
│   └── core.engine.status()
├── POST /api/chat and chat stream
│   └── api.chat.chat()/stream()
│       └── AgentCore.run_owner_mission()/resume_mission()
│           └── MissionRuntime
│               ├── explicit Owner authorization and scope
│               ├── tools.registry.execute()
│               ├── external-effect ledger and cancellation fencing
│               └── evidence and deterministic verification
└── POST /api/command
    └── api.chat.chat() (same current chat entrypoint)
```

`core.engine` remains imported for runtime/status services, but the bridge's `/api/command` route calls `api.chat.chat()`; no in-repository production caller of `core.engine.handle()` was found. The handler's former eager dependency on the legacy parser has been removed. If the legacy handler is called directly, its provenance uses the live `NaturalLanguageUnderstanding` component lazily.

## Legacy module comparison and disposition

| Original product path | Baseline reachability on `main` and review branch | Review-branch disposition |
|---|---|---|
| `agent/loop.py` | No production importer or `AgentLoop` construction. `/api/tools` uses `tools.registry`, not its duplicate `tool_definitions()`. | Removed from `agent/`; the historical implementation remains at `evaluation/legacy_agent_loop.py` solely for compatibility tests. It is excluded from Docker context and source release payloads. |
| `agent/conversation.py` | Eagerly imported by `core.engine`, but its parser call existed only inside `core.engine.handle()`, which had no in-repo production caller. | Removed from `agent/`; its typed parser/contract is retained at `evaluation/legacy_conversation.py` for benchmarks and tests. `core.engine` no longer imports it. |
| `agent/conversation_provider.py` | No production importer, provider construction, plugin registration, or reflection-based loader found. | Removed from `agent/`; schema-validation behavior remains at `evaluation/legacy_conversation_provider.py` for contract tests. |

`agent/model_intelligence/conversation.py` is a different, active module: `AgentCore` uses its `NaturalLanguageUnderstanding` and `MissionIntent` in the mission path. It remains in the runtime package. Docker excludes the legacy loop/parser/provider and their benchmark files individually; it retains `evaluation.critic`, which `core.engine` imports. The existing standalone source-release selector excludes the `evaluation/` tree as a whole; that selector was not changed here.

The relocation preserves the old parser/provider benchmark and legacy-loop regression coverage without making those implementations part of the application runtime. The request behavior remains on the canonical `AgentCore`/`MissionRuntime` path; no user-facing route depended on `AgentLoop`.

## Scope URL canonicalization

The review branch also rejects raw or recursively percent-encoded `.`/`..` path segments, ambiguous encoded slash/backslash separators, malformed escapes, invalid path encodings, and control characters before scope-prefix evaluation. Resolver tests cover the `/api/%2e%2e/admin` bypass, and a local HTTP boundary test verifies WebResearchService dispatches no request for it. Ordinary percent-encoded path characters such as spaces remain valid.

## Other runtime facts

- `AgentCore` and `MissionRuntime` enforce Owner authentication, explicit authorization context, selected scope, tool schemas, cancellation fencing, and evidence integrity independently of language understanding.
- `agent/task_runtime.py` is not the current `api.chat` entrypoint; `api.chat._runtime()` returns `MissionTaskAdapter`, while chat uses `AgentCore` mission methods.
- No changes were made to `main`, tags, releases, or Cloudflare. This candidate is maintained on `fix/blocker-d-review-20261010` for review.

## Superseded documentation

Older phase and runtime-inventory documents may describe `AgentLoop`, `ConversationParser`, or `AgentTaskRuntime` as part of the default request path. Treat those statements as historical. This file records the reachability verified from current bridge/API call sites and the review-branch relocation described above.
