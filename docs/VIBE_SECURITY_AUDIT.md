# VIBE SECURITY AUDIT — Phase V2 (Authority) and later adversarial phases

Baseline: vibe/principal-engineering @ 25327049369 parent (backend = 71ce3c95 lineage).
All findings below are source-grounded (file + line, read 2026-10-02). No backend code
was modified. Status: VERIFIED / PARTIALLY VERIFIED / UNVERIFIED.

## V2.1 — Authority caller inventory (this checkpoint)

### set_current_owner_instruction (Owner Instruction mutation)

- Single production caller found: core/engine.py line ~106.
- Context (read from source): the call occurs inside the owner-authenticated engine
  path; the preceding branch completes the lifecycle with an owner-auth error and
  returns early on failed authentication, then a text-level trigger
  (casefold prefix "owner instruction:") invokes
  set_current_owner_instruction(instruction_text, source, auth_evidence=auth_evidence,
  request_id=request_id).
- No caller was found in agent/loop.py, agent/runtime.py, agent/agent_core.py,
  agent/task_runtime.py, agent/task_manager.py, agent/mission.py,
  agent/mission_worker.py, api/chat.py, api/missions.py, core/policy.py.
- Residual verification: agent/mission_runtime.py and bridge.py exceed the raw read
  channel (~32.7k chars); they remain PARTIALLY VERIFIED for absence of this caller.
  Verdict on "model output / tool result cannot legislate Owner Instruction":
  PARTIALLY VERIFIED (all readable paths clean; two large files pending an alternate
  read channel or CI-side grep test).

### authorize_tool / authorize_plan call sites (verified by grep over fetched source)

- agent/loop.py:231 — structural preflight ONLY; source comment states real Owner
  authentication remains in the executor; loop delegates to self.executor(command,
  owner_session_token, owner_session_id) and never executes tools itself
  (REGISTRY used only for tool_definitions schema exposure, line 35).
- agent/runtime.py:105 — authorize_plan before planning-driven tool use.
- agent/agent_core.py:224 — authorize_tool with Au
thorizationContext (contexts built
  at lines 201/259/432; capture_policy_snapshot at 200/406).
- agent/task_runtime.py:212 — authorize_tool with task authorization context.
- core/engine.py:129 — authorize_plan(planned tools, context, current_policy from
  policy snapshot); per-tool decisions consumed at line 186 by execute(name,
  argument, authorization_decision=decision_for_tool, scope_context, request_id):
  tool execution requires a per-tool allowed decision bound to the request_id.

### Tool execution paths (verified)

- core/engine.py:186 — execute with authorization_decision + scope_context.
- agent/task_runtime.py:240 — OwnerDirectBoundary.execute(tool, argument,
  decision=decision.decision, request_id, tool_call_id, scope_context) with
  spec.scope_required enforcement (security/execution_boundary.py:
  MissionExecutionBoundary, OwnerDirectBoundary).
- agent/mission.py:312/422/430/439 and agent/task_manager.py execute() hits are
  SQLite statements, NOT tool executions (verified by reading the lines).

### Finding F-V2-1 (open question, adversarial test required) — PARTIALLY VERIFIED

- agent/task_runtime.py:179 _authorization_context returns None when the task's
  execution_state lacks "authorization_context"; line 212 then falls back to
  authorize_tool(item) WITHOUT an owner context, and line 125 regenerates
  request_id as uuid4 when the context is absent.
- Question to resolve in V2.2: can a live task be created (via api/chat.py or the
  bridge) whose execution_state lacks the authorization_context, thereby running
  tools under structural-only authorization? Owner authentication is still enforced
  at task creation (line ~125 raises PermissionError "owner authentication required"),
  so the risk is authorization-weakening (no owner-context-bound decision), not
  authentication bypass.
- Action: reproduce with an adversarial test; if proven, fix the fallback to
  fail-closed in the correct layer; otherwise document the invariant that
  live tasks al
ways carry the context.

### Evidence tests already present (inventory)

tests/test_owner_charter_knowledge_invariant.py (EXTERNAL_DATA cannot legislate),
tests/test_owner_master_invariants.py, tests/test_governed_execution.py,
tests/runtime_authorization.py, tests/test_execution_proof_boundary.py,
tests/test_security_integrity_adversarial.py, tests/test_phase21_restart_authorization.py.

## Backend modifications by Vibe in this phase: 0


## V2.2 — F-V2-1 RESOLVED (fail-closed chain verified from source) — VERIFIED

The apparent authorization-weakening fallback in agent/task_runtime.py
(authorize_tool without context when execution_state lacks authorization_context)
was traced through the full execution chain. Result: no bypass exists; the chain
is fail-closed at three independent layers.

1. security/authorization.py authorize_tool (read in full, 6,484 chars):
   - structural_only mode (context=None, no evidence) DENIES owner_only tools
     ("sensitive tool requires AuthorizationContext") and DENIES scope_required
     tools ("scope-bound tool requires AuthorizationContext with ScopeSnapshot").
   - when context is None the returned AuthorizationResult.decision is None
     (AuthorizationDecision.issue is only invoked with a context).
2. security/execution_proof.py ExecutionAuthorizationProof.derive (read in full,
   23,159 chars): for the OWNER_DIRECT class, "if decision is None: raise
   ExecutionProofError(PROOF_INCOMPLETE, 'owner-direct proof requires the typed
   AuthorizationDecision that authorized the execution')"; decision binding is
   verified via decision.is_valid_for(tool, argument, request_id).
3. tools/registry.py execute (read in full, 16,486 chars): registry re-verifies
   independently — ExecutionAuthorizationProof REQUIRED (PROOF_REQUIRED),
   proof.verify(...) against name/argument/mission_id/request_id/tool_call_id,
   execution-class match, decision signature + policy fingerprint binding,
   spec.requires_owner / spec.scope_required demand a valid decision, and
   scope_required tools re-resolve every URL through ScopeResolver (deny by
   default).

Therefore a task created without a stored authorization_context can pass
structural preflight for non-sensitive tools but CANNOT execute any tool: the
OwnerDirectBoundary proof derivation raises before the registry is reached.
Model output, external data, or a context-less task cannot mint an
AuthorizationDecision or an ExecutionAuthorizationProof.

### set_current_owner_instruction — repository-wide corroboration

GitHub code search across the repository returns exactly two non-test,
non-doc, non-diagnostics callers: security/owner_policy.py (definition) and
core/engine.py (the owner-authenticated path, with auth_evidence and
request_id). No caller exists in bridge.py, agent/mission_runtime.py, or any
other module. (Search index covers the default branch; the checkpoint lineage
adds no new caller per the PR #17 77-file diff audited previously.)
Verdict: model output and external data cannot legislate Owner Instruction —
VERIFIED on the readable surface.

### Owner authentication notes (from source)

- security/owner_password.py: scrypt-family hash_password, _dummy_verify
  (timing-safe dummy comparison for unknown accounts), login / resolve_session /
  authenticated_owner / revoke_session / revoke_owner_sessions.
- Owner identity is server-side username+password sessions only; legacy
  OWNER_TOKEN / owner_session.py were deleted on main (commits 3cf5bccba037,
  bf388cad0e4f) with a CI regression test asserting module deletion.
- No backend change was required in V2: the audited chain is fail-closed as
  designed. F-V2-1 is closed as NOT A VULNERABILITY (fail-closed), with the
  three-layer evidence above recorded for reproduction.

## Backend modifications by Vibe in V2: 0
