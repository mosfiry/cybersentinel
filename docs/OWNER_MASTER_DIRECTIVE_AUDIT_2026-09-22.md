# CyberSentinel X — Owner Master Directive Audit (2026-09-22)

Auditor: EXPERT-A (automated, tool-driven static + CI-verified audit)
Branch: `main`
Baseline before this audit: `38328ddbab7f4157ac54ed24c9b3086dd4a415bc` (CI success, run 35707542167)

> **Honesty rule for this report.** Every claim below is labeled one of:
> `VERIFIED`, `INTEGRATION VERIFIED` (proven by the repository CI gate:
> `python -m compileall -q .` + `pytest -q` + secret scan on the pushed
> commit), `STATIC VERIFIED` (proven by reading the exact source, not by
> executing it), `MOCK-VERIFIED` (proven only against mock/fake providers in
> tests), `PARTIAL`, `UNVERIFIED`, `NOT IMPLEMENTED`.
> Nothing is claimed as REAL provider-verified: this audit ran from an
> environment with **no model-provider credentials and no Python runtime**,
> so no live 20-turn mission was executed here.

## 1. Executive Summary

- The audited codebase is a coherent, fail-closed defensive agent. The Owner
  authority model, typed authorization (`AuthorizationContext` /
  `OwnerAuthenticationEvidence`), scope snapshot binding, durable mission
  state, checkpointing with explicit reconciliation, and deterministic goal
  verification are implemented in the canonical path
  (`AgentCore` -> `MissionRuntime`).
- The historical `owner_authenticated=True` trust hole is **closed at the
  enforcement layer**: `security/authorization.py` rejects a bare boolean
  ("typed Owner authentication evidence required") and rejects mixed legacy
  evidence plus typed context.
- The canonical-runtime goal is **NOT met**: `/api/chat` in default mode runs
  `AgentTaskRuntime`, not `MissionRuntime`; `agent/loop.py` still contains a
  second conversational loop (live only through legacy tests and a
  `tool_definitions` import in `bridge.py`). Details and blockers in sections 3/4.
- The "314 passing tests" baseline is dominated by mock-provider tests. The
  long-horizon suite (`tests/test_phase5_long_horizon.py`) uses `MagicMock`
  routers. **No real-provider 20+ turn mission has been demonstrated anywhere
  in the repository history.**
- Fixes pushed by this audit (all CI-green on `main`):
  - `search/ssrf.py`: blocked IPv6 unique-local `fc00::/7` and `0.0.0.0/8`
    (previously allowed — a real redirect/probe gap).
  - `search/web_provider.py`: third-party `httpbin.org` availability probe
    replaced with a local capability check (no outbound request).
  - `tests/test_owner_master_invariants.py`: new deterministic invariant
    battery (boolean-auth rejection, stale-evidence rejection, sensitive-tool
    context requirement, scope-bound context requirement, plan size/integrity,
    16-case SSRF URL battery, unresolvable-host fail-closed).
  - `docs/AGENT_ARCHITECTURE.md`: binding authority-tier semantics, honest
    runtime inventory, NLU-vs-response clarification, web-provider stub
    status, SSRF residual-risk statement.

## 2. Owner Authority Verification — STATIC VERIFIED

- `security/authorization.py`: `authorize_tool(..., owner_authenticated=True)`
  -> denied ("typed Owner authentication evidence required"). Mixing
  `AuthorizationContext` with legacy evidence args -> denied ("mixed
  authorization inputs are forbidden"). Stale evidence
  (`is_valid(request_id)` false) -> denied.
- `core/engine.py` `_handle_once()`: Owner auth precedes any planning and
  tool execution; wrong/expired/missing token denies and completes the
  lifecycle with failure. `set_current_owner_instruction(...)` requires
  fresh authenticated evidence.
- `agent/agent_core.py` `_auth()`: challenge path via
  `consume_owner_challenge` (single-use, message-bound), token path via
  `authenticate_owner`; both produce typed evidence bound to `request_id`.
- Owner hierarchy `OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY > ...`
  is documented as binding semantics in `docs/AGENT_ARCHITECTURE.md`,
  including the clarification that `SYSTEM_PLATFORM` means the *internal*
  CyberSentinel platform layer, not external hosting constraints (which are
  outside the hierarchy entirely). No reordering was made anywhere.
- `AuthorityTier` is not used as an execution input in any path audited.

## 3. Runtime Architecture — PARTIAL (canonical not exclusive)

Established live call graph (read from source, every entrypoint):

```text
bridge.py
  |- POST /api/chat --> api.chat.chat
  |     |- mission mode --> AgentCore.run_owner_mission / resume_mission
  |     |                    \-> MissionRuntime (run_model_loop | run_to_completion)
  |     \- default mode --> create_task --> AgentTaskRuntime.run_to_completion
  |                          \-> core.engine.handle() (AgentRuntime planner,
  |                              typed auth, authorize_plan, tools.registry.execute)
  |- POST /api/command --> core.engine.handle() (same enforcement pipeline)
  \- GET  /api/tools --> agent.loop.tool_definitions (metadata listing only)
```

`MissionRuntime` is the canonical persistent mission engine: create ->
authorize per step -> checkpoint (`in_flight` -> `completed`) -> observation
-> interpretation (proposal only) -> hypothesis/strategy update -> replan
with objective-integrity guard -> deterministic `GoalVerification`. The
native model loop (`run_model_loop`) does: per-turn identity
(`run_id`/`turn_id`), duplicate/cross-mission/cross-run proposal rejection,
per-call `authorize_tool` with typed context, bounded parallel execution
with deterministic fold, in-flight ambiguity -> `RECOVERY_REQUIRED` (never
silently success), and model "final" accepted only when deterministic goal
evidence verifies.

Gap (honest): `/api/chat` default mode and the `/api/command` engine are a
second, independently executable runtime path. Both share the same
authorization/registry enforcement, so this is not a security bypass, but
the "single canonical runtime" requirement is not satisfied.

## 4. Dead / Legacy Code Status — STATIC VERIFIED

| Module | Status | Evidence |
| --- | --- | --- |
| `agent/loop.py` | Live but unreachable except `tool_definitions` import in `bridge.py` (`/api/tools`) and 4 legacy test files | No `owner_authenticated` trust remains; `authorize_tool(item)` there is structural-only; the executor delegates to `core.engine.handle()` for real auth |
| `agent/conversation.py` | **Not dead** — `core/engine.py` imports `ConversationParser` for the deterministic intent baseline | Live in `/api/command` and task path |
| `agent/conversation_provider.py` | Tests only | Not imported by bridge/api/engine; enforces the forbidden-authority-field schema (`FORBIDDEN_MODEL_FIELDS`) |
| `agent/runtime.py` | Live planner (command engine) | `core/engine.py`; deterministic fallback explicitly labeled `planner: local` |
| `agent/task_runtime.py` | Live (default chat mode) | `api/chat.py` |
| Deletion blockers documented | `AgentLoop` removal requires migrating `tests/test_agent_platform.py`, `test_phase5_long_horizon.py`, `test_phase3_context.py`, `test_message0003_auth.py` and moving `tool_definitions()` to `tools/registry.py` + updating `bridge.py` | This audit did **not** perform the deletion (unsafe without a local test runner); recorded as remaining work |

## 5. Authentication — STATIC VERIFIED + INTEGRATION VERIFIED (unit level)

`security/owner_session.py`: single-use, message-bound, HMAC-compared
challenges; TTL 10-900 s; expired/unknown/replayed/cross-session challenges
raise `PermissionError` before any provider/tool side effect
(`tests/test_v50_owner_session.py`, plus the new
`tests/test_owner_master_invariants.py` stale-evidence test). Sessions are
**in-memory** — a process restart invalidates live sessions (acceptable for
a local bridge; noted as a design constraint for crash/resume scenarios).

## 6. Authorization — STATIC VERIFIED + INTEGRATION VERIFIED

Typed `AuthorizationContext` (request_id + owner evidence + policy snapshot
+ optional scope snapshot + session id) is the only path to sensitive tools.
`tools/registry.execute()` re-checks the presented `AuthorizationDecision`
(is-instance, allowed, tool match, argument hash) at execution time —
decisions cannot be forged or replayed with different arguments. New CI-green
tests cover I1 (boolean is not authority), stale evidence, sensitive-tool
context requirement, plan size, and plan integrity hashing.

## 7. Scope — STATIC VERIFIED

`security/scope.py` builds immutable `ScopeSnapshot` (frozen dataclasses,
evidence-hashed `ProgramAuthorization`, canonical host/URL with IDNA and IP
normalization, wildcard/ports/paths matching). `tools/registry.execute()`
for scope-bound tools requires a complete scope context and calls
`security/scope_resolver.resolve()` for both the declared URL and the
argument URL. `MissionRuntime` blocks observations whose `target` falls
outside `scope_snapshot.allowed_targets` (`SCOPE_BLOCKED`), and
`decide_strategy` receives `scope_blocked`. Model, knowledge, or tool
success never mutates a scope snapshot; only a new Owner-authorized snapshot
can. (`scope_store.py`/`scope_resolver.py` were reviewed at signature level
only — flagged in section 20.)

## 8. Native Tool Calling — STATIC VERIFIED (runtime), MOCK-VERIFIED (end-to-end)

`agent/model_intelligence/tool_calls.py` provides `validate_proposals`
(identity: mission/run/duplicate/stale) and `execute_bounded_parallel`;
`MissionRuntime.run_model_loop` consumes typed proposals carrying
mission_id/run_id/turn_id/action_id/step_id/tool_call_id and per-call
authorization context references. Cross-mission and cross-run proposals are
rejected; duplicate `tool_call_id` is rejected with the prior result
authoritative. The continuation path stores `progress["tool_results"]` and
re-assembles context with them (`ContextAssembler.build(..., tool_results=...)`),
so the model sees prior calls, arguments, results, and observations.
End-to-end native calling is proven only against scripted routers in tests —
not with a live provider.

## 9. Observation -> Evidence -> Hypothesis -> Strategy — STATIC VERIFIED

`MissionRuntime._interpret_observation()` runs only when
`should_interpret_observation` fires; the interpreter output is a proposal;
`HypothesisEngine.apply(..., goal_verified=False, deterministic_validation=False)`
means a model can never confirm; strategy decisions are typed (`REPLAN`,
`CHANGE_HYPOTHESIS`, `ADD_EVIDENCE`, `SCOPE_BLOCKED`, ...) and emitted to
the durable trajectory. New evidence records always carry `authority: null`
provenance.

## 10. Replanning — STATIC VERIFIED

Replans trigger on typed strategy decisions (`REPLAN`/`CHANGE_HYPOTHESIS`/
`ADD_EVIDENCE`), not blind retries; `loop_signatures` counters abort a dead
loop after 3 repeats of the same plan/step/action; the replanner's plan must
preserve the Owner objective ("replanner attempted to change Owner objective"
-> `SAFETY_BLOCKED`); completed `action_id`s are idempotent-skipped.

## 11. Recovery — STATIC VERIFIED

Failure classification (`FailureClass` from observation `failure_class`),
`RecoveryPolicy.action_for(failure, retry_count)` selects typed
`RecoveryAction`s; `OWNER_INPUT_REQUIRED` transitions for authorization
gaps; recovery budget exhaustion ends in `FAILED_RETRY_EXHAUSTED`, never
silent success.

## 12. Context Compaction — STATIC VERIFIED (mechanism), UNVERIFIED (behavior)

`agent/context.py` `ContextEngine` + `agent/model_intelligence/context.py`
`ContextAssembler` build hashed, provenance-tagged, untrusted-labeled
contexts with `truncated` flags. **Behavior under long-horizon compaction was
not executed with a real provider here** — remains to be proven by the
acceptance run.

## 13. Crash / Restart / Resume — STATIC VERIFIED

Every state mutation goes through `MissionStore.save()` (SQLite); checkpoints
are written before/after each side-effecting action (`in_flight` ->
`completed`); on restart, `in_flight` -> `RECOVERY_REQUIRED` with
`reconcile_in_flight(executed=...)` as the only resolution (at-most-once
until reconciliation — exactly-once is NOT claimed, matching the
directive); `core/lifecycle.py` recovers interrupted request lifecycles as
failed, and completed requests replay idempotently. Mission identity, run
identity, authorization context, scope, evidence, hypotheses, strategy, and
pending action are all persisted fields of `Mission`.

## 14. SSRF — INTEGRATION VERIFIED (filters), PARTIAL (rebinding)

Fixed in this audit: `fc00::/7` (IPv6 ULA) and `0.0.0.0/8` added to blocked
ranges; third-party `httpbin.org` probe removed. CI-green test battery
covers localhost/127.0.0.1/::1/RFC1918/link-local/ULA/IPv4-mapped/metadata/
blocked port/blocked suffix/disallowed scheme, and fail-closed on
unresolvable hosts. Redirects: the provider sets
`follow_redirects=False`; a `RedirectPolicy` exists for manual redirect
handling. **Residual risk (documented, not fixed): DNS rebinding TOCTOU —
validation resolves DNS, the client re-resolves at connect; IP pinning is
not implemented.**

## 15. Knowledge — STATIC VERIFIED (invariants)

Knowledge retrieval carries `authority: null`, trust classes, and
transformation policy (`agent/knowledge_context.py`); observation
interpreter prompts explicitly forbid policy/authorization changes;
`conversation_provider` schema rejects any authority field from model
output. The corpus is a **fixture/synthetic corpus**
(`knowledge/fixtures/...`, `cyber_data/`, `cyber_knowledge/`) — it is NOT a
comprehensive real corpus and must not be described as one.
Knowledge is not authorization; a PoC is not permission.

## 16. Security Invariants — INTEGRATION VERIFIED (subset)

New `tests/test_owner_master_invariants.py` (CI green) proves I1, I5-shaped
(no-provenance authorization), I8, and an I15 subset deterministically.
Remaining invariants (I2-I4, I6-I7, I9-I14) are covered by existing suites
(`test_phase6c_scope_firewall`, `test_phase6k4_deep_hardening`,
`test_phase6k6_unified`, `test_phase6k7b_mission_runtime`) at
MOCK/INTEGRATION level — see section 20.

## 17. Real Long-Horizon Test — NOT PERFORMED (the decisive gap)

No environment available to this audit could run a real provider (real API
credentials + Python runtime + crash injection). The repository's
long-horizon tests are mock-router tests (`MagicMock`, scripted routers).
Therefore: **20+ real model turns, real crash/restart/resume with a live
provider, and real failure recovery remain UNPROVEN.** This is the single
largest acceptance gap and is explicitly not claimed.

## 18. Evidence Package

| Item | Value |
| --- | --- |
| Baseline commit | `38328ddbab7f4157ac54ed24c9b3086dd4a415bc` (CI success, run 35707542167) |
| Audit commit 1 | `9945f0dc26f957169f9d1371793d63b2ee2bf07c` — SSRF ranges + invariant tests + architecture docs (CI success, run 35716643299) |
| Audit commit 2 | `93246fb2abd8a2b77ec42e657a0da8fd43656b13` — web provider local availability check (CI success, run 35716973065) |
| Test commands (CI gate) | `python -m pip install -r requirements.txt`; `python -m compileall -q .`; `python -m pytest -q`; `git diff --check`; secret scan |
| New tests | `tests/test_owner_master_invariants.py` — 12 tests (incl. 16-case parametrized SSRF battery) |
| Files read in full (exact bytes) | `security/scope.py`, `security/owner_session.py`, `security/authorization.py`, `tools/registry.py`, `search/ssrf.py`, `search/web_provider.py`, `agent/conversation.py`, `agent/conversation_provider.py`, `api/chat.py`, `bridge.py`, `core/engine.py`, `agent/agent_core.py`, `agent/runtime.py`, `agent/loop.py` |
| Files read at 91-100% (raw fetch truncation on the largest file) | `agent/mission_runtime.py` (missing ~3 KB recovered via targeted code-search fragments; failure/recovery branch confirmed) |

## 19. Remaining Risks

1. **DNS rebinding TOCTOU** (section 14) — needs IP pinning.
2. **Two live execution stacks** (MissionRuntime vs engine/TaskRuntime path)
   — consolidation requires a local test runner and legacy-test migration.
3. **Owner sessions in memory** — restart drops active challenge sessions.
4. `agent/agent_core.py` uses `__import__("agent.trajectory", ...)` —
   hardcoded and safe, but a style-level dynamic import.
5. `evaluation/` and `scripts/` were reviewed only via targeted grep.

## 20. Unverified Claims (explicit)

- Real-provider 20+ turn mission: **UNVERIFIED**
- Crash/restart/resume with live provider: **UNVERIFIED**
- Context compaction behavior at scale: **UNVERIFIED**
- Native tool-calling continuity with a real provider: **MOCK-VERIFIED only**
- `scope_store.py` / `scope_resolver.py` full-file review: **PARTIAL**
  (signature-level only)
- Knowledge corpus coverage: **FIXTURE/SYNTHETIC** (not comprehensive)

## 21. Exact Commits

- `9945f0dc26f957169f9d1371793d63b2ee2bf07c`
- `93246fb2abd8a2b77ec42e657a0da8fd43656b13`
- (this report) `docs/OWNER_MASTER_DIRECTIVE_AUDIT_2026-09-22.md`

## 22. Exact Test Commands

```bash
python -m pip install -r requirements.txt
python -m compileall -q .
python -m pytest -q
git diff --check
```

## 23. Final Acceptance Matrix

| Capability | Status | Evidence |
| --- | --- | --- |
| Owner hierarchy | STATIC VERIFIED | binding semantics doc; no tier reordering in code |
| Owner authentication | INTEGRATION VERIFIED (unit) | `owner_session.py` + auth chain; CI green incl. new invariant tests |
| Canonical runtime | PARTIAL | MissionRuntime canonical for missions; `/api/chat` default mode uses TaskRuntime; `loop.py` still exists (documented) |
| Native tool calling | MOCK-VERIFIED | `run_model_loop` typed proposals; scripted-router tests only |
| Tool continuity | STATIC VERIFIED | `tool_results` persisted and re-assembled per turn |
| Parallel tools | STATIC VERIFIED | `execute_bounded_parallel`, per-call auth/identity, deterministic fold |
| Replanning | STATIC VERIFIED | typed strategy triggers, dead-loop guard, objective-integrity guard |
| Tool failure recovery | STATIC VERIFIED (code), MOCK-VERIFIED (behavior) | FailureClass + RecoveryPolicy; no live failure run |
| Contradiction handling | STATIC VERIFIED | HypothesisEngine counter-evidence; confirmation not model-controlled |
| Context compaction | UNVERIFIED (behavior) | mechanism present; not executed at scale |
| 20+ real turns | NOT PERFORMED | no real-provider run exists |
| Crash/restart/resume | STATIC VERIFIED (code), UNVERIFIED (live) | checkpoints + reconciliation; not exercised live |
| SSRF | INTEGRATION VERIFIED (filters) | new battery CI green; rebinding residual documented |
| DNS rebinding | PARTIAL | fail-closed resolution; no IP pinning (documented) |
| Knowledge provenance | STATIC VERIFIED | `authority: null`, trust classes; corpus is FIXTURE |
| Scope firewall | STATIC VERIFIED + INTEGRATION VERIFIED (unit) | immutable snapshots; scope-blocked transitions; registry re-check |
| Dead runtime removal | NOT IMPLEMENTED | blockers documented in section 4 |
| Final verification | STATIC VERIFIED | `GoalVerification` deterministic; model "final" not accepted without evidence |
