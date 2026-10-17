# CyberSentinel X — Runtime Reachability (verified 2026-10-17)

**Compared:** `main` at `8a3fd109c0e586db13ed48a7371ac9ad06465b74` and review branch `fix/blocker-d-review-20261010` at `d486742f41daf6cc2c38586f023a46162eab9ec5` (plus its current working tree). The three named modules are byte-identical between main and the review-branch HEAD. Conclusions below come from source imports/call sites; older runtime-truth notes were not used as evidence.

## Current request path

```text
bridge.py
├── GET /api/tools
│   └── tools.registry.tool_definitions()
├── GET /api/status
│   └── core.engine.status()             # imports core.engine and its globals
├── POST /api/chat / chat stream
│   └── api.chat.chat()/stream()
│       └── AgentCore.run_owner_mission()/resume_mission()
│           └── MissionRuntime
│               ├── authorization + explicit scope
│               ├── tools.registry.execute()
│               ├── external-effect ledger and cancellation fencing
│               └── evidence and deterministic verification
└── mission worker/API routes
    └── MissionRuntime / MissionService
```

The review branch also imports `core.engine.status` from a MissionRuntime status path. This loads `core.engine` and its top-level `ConversationParser` import, but does not call `core.engine.handle()` or the parser. The current `api.chat.chat()` implementation documents and implements all chat modes through `MissionRuntime`; no production caller of `core.engine.handle()` was found in bridge, API, agent, or core source. Likewise, no production importer or constructor of `AgentTaskRuntime` was found.

## Requested module-by-module comparison

| File | `main`: module import / behavior | Review branch: module import / behavior | Assessment |
|---|---|---|---|
| `agent/loop.py` | No production import or `AgentLoop` construction found / no loop execution | Same / same | The module and its duplicate `tool_definitions()` are internally unreachable from production. `/api/tools` imports `tools.registry.tool_definitions()`. Legacy tests still use `AgentLoop`; retain pending compatibility review rather than deleting feature code automatically. |
| `agent/conversation.py` | Eagerly imported by `core.engine` / parser call is inside `core.engine.handle()` and no production caller of `handle()` was found | Same / same | The module is loaded as an import side effect, but its parser behavior is not part of current request execution. Evaluation/tests also use it. Treat as legacy command-path code, not active chat NLU. |
| `agent/conversation_provider.py` | No production importer / no provider construction | Same / same | Test-only adapter/prototype. Its sibling import of `agent.conversation` is internal to the module and does not make the provider live. Keep until compatibility consumers are reviewed. |

The three target source files have no content delta between the compared main and branch revisions. The bridge in both uses `tools.registry.tool_definitions`; `core.engine` imports `ConversationParser`, but its `handle()` entry has no internal production caller. Unit tests and evaluation scripts are not counted as production reachability.

## Other runtime facts relevant to the comparison

- `agent.model_intelligence.conversation` is a separate, live MissionRuntime NLU component; it is not `agent.conversation` or `agent.conversation_provider`.
- `agent.loop.py` must not be confused with `agent/context.py` or with the canonical tool registry. A docstring reference to `AgentLoop` is not a call site.
- The legacy modules remain present because tests/compatibility consumers exist. This audit did not delete them or claim that external consumers are impossible.
- `OwnerAuthenticationEvidence`, explicit `ScopeSnapshot`, tool authorization, process sandboxing, cancellation fencing, and evidence integrity remain independent runtime controls. Instruction-order metadata does not grant access.

## Superseded documentation

The 2026-09-22 runtime inventory incorrectly described `AgentLoop` as imported by the bridge and `/api/chat` default mode as an `AgentTaskRuntime`/`core.engine.handle()` path. Current source shows the bridge imports tool metadata from `tools.registry` and chat enters `MissionRuntime`. This file supersedes those reachability statements; it does not claim the legacy files were removed.
