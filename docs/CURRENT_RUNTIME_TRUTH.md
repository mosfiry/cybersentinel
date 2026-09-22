# CyberSentinel X — Current Runtime Truth

**Audit date:** 2026-09-22  
**Starting commit:** `534e604`  
**Branch:** `main`  
**Basis:** direct inspection of the checked-out source, imports, entrypoints, and tests.

## Actual entrypoint graph

```text
bridge.py
├── GET /api/tools
│   └── agent.loop.tool_definitions()
├── POST /api/chat
│   └── api.chat.chat()
│       ├── mission=true or mode=mission
│       │   └── AgentCore.run_owner_mission()/resume_mission()
│       │       └── MissionRuntime
│       │           ├── persistent MissionStore (SQLite)
│       │           ├── typed authorization boundary
│       │           ├── model turn / native tool-call proposals
│       │           ├── deterministic authorization and replay checks
│       │           ├── tools.registry.execute()
│       │           ├── observations/evidence/trajectory
│       │           ├── recovery/reconciliation
│       │           └── deterministic goal verification
│       └── default mode
│           ├── configured provider
│           │   └── AgentTaskRuntime.create_task()/run_to_completion()
│           │       └── core.engine.handle()
│           │           └── AgentRuntime planner
│           │               └── tools.registry.execute()
│           └── no configured provider
│               └── core.engine.handle()
│                   └── AgentRuntime planner
│                       └── tools.registry.execute()
└── POST /api/command
    └── core.engine.handle()
        └── AgentRuntime planner
            └── tools.registry.execute()
```

## Runtime inventory

| Component | Current role | Status against one-runtime requirement |
|---|---|---|
| `agent/mission_runtime.py::MissionRuntime` | Durable mission lifecycle, native model loop, recovery, evidence, deterministic verification | Canonical mission engine |
| `agent/agent_core.py::AgentCore` | Mission orchestration facade | Active mission entry boundary |
| `agent/task_runtime.py::AgentTaskRuntime` | Durable compatibility task lifecycle for provider-backed default chat | **Still a second live execution path** |
| `core/engine.py` / `agent/runtime.py` | Command planner and local/default chat execution | **Still live for `/api/command` and default chat** |
| `agent/loop.py::AgentLoop` | Legacy conversational loop; also exports tool metadata | **Still present and independently executable** |
| `tools/registry.py` | Tool metadata, validation, authorization-decision revalidation, execution | Shared registry and execution boundary |
| `security/authorization.py` | Typed authorization and decision issuance | Active security boundary |
| `security/authorization_context.py` | Typed immutable context and signed decision | Active for sensitive mission execution |
| `security/scope*.py` | Scope snapshot persistence/resolution/firewall | Active for scope-bound tools |
| `core/lifecycle.py` | Request lifecycle persistence for command path | Active in compatibility path |
| `agent/mission.py::MissionStore` | Durable SQLite mission state and integrity hash | Active in canonical mission path |

## Security facts observed in source

The canonical mission loop does not accept a bare `owner_authenticated=True` as authority. Sensitive tools require an `AuthorizationContext` and `tools.registry.execute()` revalidates an `AuthorizationDecision` against tool name, request ID, and argument hash. Mission tool proposals carry mission/run/turn/tool-call identity and duplicate or stale identities are rejected.

The model cannot directly set completion status. `MissionRuntime` invokes deterministic verification and only then transitions to `GOAL_COMPLETED`. Crash recovery records an ambiguous in-flight side effect as `RECOVERY_REQUIRED`; it does not infer success or retry blindly.

## Remaining gaps observed in source

1. `/api/chat` still has a mission path and a default compatibility path; they do not share one canonical mission lifecycle.
2. `agent/loop.py::AgentLoop` still exists and is imported by `bridge.py` and `agent/context.py`; legacy tests also import it.
3. Live-provider acceptance is gated and currently skipped when credentials/factory are absent; deterministic long-horizon tests are not REAL-PROVIDER evidence.
4. The current checkout contains no CI run for `534e604` because the commit is a diagnostics-only commit covered by the workflow's `paths-ignore` rule. The latest successful GitHub Actions run observed before this audit was for `5d29375b1f35`.

## Deterministic local baseline

Executed from `/home/ubuntu/cybersentinel` in a fresh shell using the declared requirements:

```text
471 passed, 1 skipped in 9.14s
TEST_EXIT_CODE=0
```

The skipped test is the live-provider long-horizon acceptance test and is explicitly labeled unavailable when provider credentials/factory are absent. This baseline is not evidence that the remaining architecture gaps are complete.
