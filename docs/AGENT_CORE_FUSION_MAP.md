# Agent Core Fusion Map

The target is a **CyberSentinel-native Agent Core**, not a composition of OpenHands, LangGraph, AutoGen, SWE-agent, mini-SWE-agent, and Qwen-Agent frameworks. The table records concepts studied, their source paths, target modules, and the decision to rewrite them independently.

| External project | Component | Relevant source file | Concept | CyberSentinel target | Decision | Reason | License |
|---|---|---|---|---|---|---|---|
| OpenHands | Event/replay projection | `src/contexts/conversation-websocket-context.tsx`, `src/stores/use-event-store.ts`, event types | Correlated action/observation events, replay cursors, deduplication, confirmation statuses | `agent/trajectory.py`, Mission trajectory, future event store | REWRITE CONCEPT | Canvas delegates execution to Agent Server and is not an autonomous loop or checkpoint backend | MIT |
| mini-SWE-agent | Agent loop and interruptions | `src/minisweagent/agents/default.py`, `exceptions.py` | Explicit query/execute/observe cycle, typed flow interruptions, incremental trajectory save | `agent/mission_runtime.py`, `agent/observation.py`, failure engine | REWRITE CONCEPT | Bash/environment semantics and JSON trajectory are insufficient for security authorization and crash resume | MIT |
| SWE-agent | Typed steps and parser recovery | `sweagent/agent/agents.py`, `types.py`, `tools/parsing.py` | StepOutput/TrajectoryStep, corrective requery, history processors, bounded retry | `agent/planning.py`, `MissionState`, ContextEngine | REWRITE CONCEPT | Coding-agent and SWE-ReX assumptions must not become CyberSentinel security controls | MIT |
| Qwen-Agent | Function-call and context window | `qwen_agent/agents/fncall_agent.py`, `llm/base.py`, `tools/base.py` | Bounded tool loop, schema checks, token-aware message truncation | `AgentCore`, `ContextEngine`, `tools.registry` | REWRITE CONCEPT | Qwen has no durable checkpoint, authority model, or semantic loop detector | Apache-2.0 |
| LangGraph | Durable orchestration | `libs/langgraph/langgraph/pregel/_loop.py`, checkpoint base, `types.py`, `ToolNode` | State channels, checkpoint snapshots, interrupts/resume, bounded supersteps, parallel task concepts | `Mission`, `MissionStore`, `MissionRuntime`, `MissionState` | REWRITE CONCEPT | CyberSentinel needs its own serializer allowlist, evidence chain, policy state, idempotency, and scope enforcement | MIT |
| AutoGen | Async lifecycle/workbench | `autogen_agentchat/agents/_assistant_agent.py`, group chat, workbench, intervention | Correlated tool events, async cancellation, save/load contracts, explicit termination | `TrajectoryEvent`, tool boundary, Owner intervention | REWRITE CONCEPT | Generic model-driven dispatch and caller-driven snapshots are not sufficient security controls | MIT source / CC BY assets |

## Cross-cutting synthesis

The audited implementations agree on a useful separation between model proposal, tool dispatch, observation, state update, and termination. They differ in reliability: LangGraph provides the strongest checkpoint abstractions; SWE-agent and mini-SWE-agent provide clear step/trajectory bookkeeping; Qwen-Agent provides compact function-call patterns; OpenHands demonstrates replay and UI event correlation; AutoGen demonstrates async lifecycle and correlated tool results.

CyberSentinel therefore implements its own typed `Mission`, `MissionState`, `TrajectoryEvent`, `Observation`, `Plan`, `AuthorizationContext`, and `MissionStore`. The model remains a proposal source. The deterministic layers own authorization, scope, schema validation, idempotency, evidence, resource limits, and termination. No external framework is imported as a runtime control plane.

## Rejected patterns

The implementation rejects direct use of bash-only agent parsers, generic blocklists as security policy, UI replay as checkpointing, unversioned JSON trajectories as crash recovery, lossy context eviction as evidence memory, model-mediated authorization, and generic framework retries for non-idempotent security actions. It also rejects treating parallel completion order as a security ordering guarantee.
