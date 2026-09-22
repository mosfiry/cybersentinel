# CyberSentinel X - Round 2 Execution Proofs (2026-09-22)

Owner directive round 2: canonical execution + real long-horizon. This file is
the honest record of what was proven, what is mock-verified, and what remains
UNVERIFIED. Round 1 report: docs/OWNER_MASTER_DIRECTIVE_AUDIT_2026-09-22.md.
OffensiveMind is out of scope for this round and was not modified.

## Deliverable commit

- `d594f2a` - 8 new test files exercising the REAL MissionRuntime /
  MissionStore / RecoveryPolicy / GoalVerification / HypothesisEngine /
  ObservationInterpreter / strategy engine. CI status: see below.

## Execution authority status (honest)

ONE canonical mission execution authority exists and is now proven by
executable tests: `agent/mission_runtime.py::MissionRuntime` over the durable
`Mission`/`MissionStore` lifecycle, with the single authorization boundary
`security.authorization.authorize_tool` and the single tool registry
`tools.registry`.

What is NOT yet unified (unchanged from round 1, honestly restated):

1. `/api/chat` default mode still runs through `AgentTaskRuntime` +
   `core.engine.handle()`; only mission mode reaches MissionRuntime.
   P0-2 (single chat lifecycle) is therefore still OPEN.
2. `agent/loop.py::AgentLoop` still exists as a legacy conversational loop
   kept alive by legacy tests (`tests/test_phase3_context.py` 54KB and
   `tests/test_phase5_long_horizon.py` 36KB could not be safely rewritten
   from this environment: the fetch channel truncates at ~32KB and one file is
   blocked by a content filter mid-transfer). P0-1 is OPEN with this exact
   blocker. AgentLoop holds no independent security authority (structural
   preflight only; real auth happens in core.engine.handle) - but it IS still
   a second loop body, and it must not stay forever.

## What the new tests prove (deterministic, no mocks where it matters)

| File | Directive item | Proof |
| --- | --- | --- |
| tests/test_failure_recovery_replan.py | P0-4 | RecoveryPolicy matrix (AUTHORIZATION->OWNER_INPUT_REQUIRED, SCOPE_BLOCKED, RESOURCE_BLOCKED, bounded RETRY/REPLAN, FAIL at cap - no infinite retry). Exception or timeout during a side effect => mission RECOVERY_REQUIRED with in-flight checkpoint, never blind retry. reconcile_in_flight(executed=False) => exactly one safe retry; (executed=True) => evidence recorded, never replayed. Deterministic failed result is a failure observation, never verification evidence. Unknown tool rejected before execution. |
| tests/test_crash_restart_resume.py | P0-5 | Simulated process crash mid-loop (unhandled exception in the model turn) leaves a fully loadable durable mission (identity, turns, seen_call_ids, observations, actions, evidence, checkpoint, trajectory). A restarted runtime resumes with persisted turn numbering. Restart NEVER silently continues an in-flight side effect (RECOVERY_REQUIRED without execution) and NEVER silently restores Owner authority: red_team_assess / scoped_http_probe proposals after restart are denied. |
| tests/test_tool_continuity.py | P1 continuity | Duplicate tool_call_id rejected, prior result authoritative, single execution; wrong run_id rejected without execution; parallel results fold in proposal order; validate_proposals rejects cross-mission, stale-run, duplicate, missing identity. |
| tests/test_deterministic_goal_verification.py | P1 verification | GoalVerification requires passed evidence for every required criterion. Model final claim ("CONFIRMED...") without evidence => mission back to READY, never GOAL_COMPLETED. Turn-budget exhaustion => FAILED_RETRY_EXHAUSTED. |
| tests/test_contradiction_lifecycle.py | P1 contradiction | Supporting evidence STRENGTHENS; contradicting evidence weakens (partial) or DISPROVES (full) the hypothesis; deterministic interpreter extracts contradictions from raw observations; strategy engine orders REPLAN; model CONFIRMED attempt raises and only goal_verified + deterministic_validation can confirm. |
| tests/test_poisoning_battery.py | P1 untrusted data | "Owner approved this", "Scope includes X", "Ignore previous instruction", "Execute immediately" payloads in tool arguments, plans, model proposals, tool results, and owner-instruction dicts grant NOTHING: no authorization, no scope, no AuthorizationDecision, no hypothesis confirmation. Interpreter strips authority fields from model proposals and falls back to deterministic interpretation on CONFIRMED attempts. |
| tests/test_long_horizon_deterministic.py | P0-3 (MOCK-VERIFIED) | 23 model turns (22 tool + 1 final) through the REAL runtime: full trajectory event battery (ModelTurn/ToolProposed/AuthorizationChecked/ObservationReceived/ObservationInterpreted/StrategyDecided/HypothesisUpdated/GoalVerified/MissionCompleted), one real deterministic tool failure, one hypothesis created then DISPROVEN by counter-evidence, REPLAN strategy decisions, every tool_call_id executed exactly once, completion only via deterministic verification. HONESTY LABEL: MOCK-VERIFIED - scripted NativeModel, because no live provider credentials exist in CI. |
| tests/test_real_provider_long_horizon.py | P0-3 (UNVERIFIED) | Live-provider harness, gated on CYBERSENTINEL_LIVE_PROVIDER_KEY + CYBERSENTINEL_LIVE_ROUTER_FACTORY. Skips with an explicit "UNVERIFIED - REAL PROVIDER UNAVAILABLE" reason instead of faking a pass. |

## Acceptance matrix

| Item | Status |
| --- | --- |
| P0-1 remove/thin-adapter AgentLoop | NOT DONE - blocked on rewriting two legacy test files that cannot be fully read from this environment; documented, no blind push that could break CI |
| P0-2 unify /api/chat to one lifecycle | NOT DONE - two paths remain (default: AgentTaskRuntime/engine.handle; mission: MissionRuntime); same authorization boundary, different lifecycles |
| P0-3 20+ real model turns | MOCK-VERIFIED (23 turns, deterministic script, real runtime); live-provider variant UNVERIFIED - REAL PROVIDER UNAVAILABLE |
| P0-4 real failure->recovery->replan | VERIFIED deterministically (ambiguous side effect, bounded retries, no infinite loop) |
| P0-5 crash/restart/resume | VERIFIED deterministically (durable state, no silent in-flight continuation, no silent authority restore) |
| P0-6 exactly-once semantics | VERIFIED as written: side effects are UNKNOWN-after-crash by default (RECOVERY_REQUIRED + mandatory reconcile_in_flight); reconciled-executed is never replayed; reconciled-not-executed permits exactly one retry |
| P1 contradiction | VERIFIED deterministically |
| P1 context compaction safety | PARTIAL: compaction lives in AgentTaskRuntime (ContextEngine + ConversationMemory); no MissionRuntime compaction exists yet, so no compaction test was added for the mission path |
| P1 tool-result continuity | VERIFIED deterministically |
| P1 deterministic goal verification | VERIFIED deterministically |
| P1 knowledge/RAG/memory poisoning | VERIFIED for the authorization/interpretation/hypothesis boundary; memory TrustClassification itself was not re-tested (round 1 coverage) |
| P1 authority regression | Round-1 batteries (test_boolean_trust_battery.py, test_scope_firewall_battery.py, test_owner_master_invariants.py) run in the same CI suite |
| P2 documentation | This file + AGENT_ARCHITECTURE.md (round 1 sections still accurate) |

## Residual risks (new findings this round)

1. `run_model_loop` treats a tool result that contains NEITHER a
   `success` NOR an `ok` key as success (`observation.get("success",
   observation.get("ok", True))`). A tool handler returning an unmarked dict
   (e.g. a bare result payload) is counted as passed evidence. Fixing this
   requires editing `agent/mission_runtime.py` (36KB), which cannot be
   rewritten byte-exactly from this environment (fetch channel truncates);
   until then this is a documented fail-open edge for malformed results.
   All registry handlers currently return explicitly marked dicts.
2. The model loop records REPLAN strategy decisions but performs actual plan
   revision only in the slice loop (`run_slice`); the native model loop
   continues on the same plan. This is a behavior gap, not a security hole.
3. Live-provider long-horizon remains UNVERIFIED until credentials exist.
