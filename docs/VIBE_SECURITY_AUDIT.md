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
- agent/agent_core.py:224 — authorize_tool with AuthorizationContext (contexts built
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
  live tasks always carry the context.

### Evidence tests already present (inventory)

tests/test_owner_charter_knowledge_invariant.py (EXTERNAL_DATA cannot legislate),
tests/test_owner_master_invariants.py, tests/test_governed_execution.py,
tests/runtime_authorization.py, tests/test_execution_proof_boundary.py,
tests/test_security_integrity_adversarial.py, tests/test_phase21_restart_authorization.py.

## Backend modifications by Vibe in this phase: 0
