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


## V3 — MISSION LIFECYCLE AUDIT (source-grounded) — VERIFIED (surface + invariants)

### Mission state machine (agent/mission.py, read 27,765 chars)

MissionStatus enum (lines 23-41): CREATED, PLANNING, READY, RUNNING, OBSERVING,
VERIFYING, REPLANNING, PAUSED, GOAL_COMPLETED, OWNER_INPUT_REQUIRED,
AUTHORIZATION_BLOCKED, SCOPE_BLOCKED, RESOURCE_BLOCKED, RECOVERY_REQUIRED,
SAFETY_BLOCKED, FAILED_RETRY_EXHAUSTED, CANCELLED.
TERMINAL_MISSION_STATUSES frozenset defined at line 41.

Mission.transition() guards (read from source, lines 112-131):
- TypeError on non-MissionStatus target.
- "recovery requires reconciliation before continuation" gate.
- PAUSED only from pre-completion states; paused missions must be resumed
  (READY/CANCELLED/OWNER_INPUT_REQUIRED) before execution.
- Terminal missions cannot transition to a different status (explicit
  ValueError) except the narrow reconciled recovery / owner-intervention paths.
- GOAL_COMPLETED is a system invariant: requires the runtime's exact verified
  verification state (verified is True, no missing_criteria, matches
  verification_state) AND a valid completion proof.

Persistence invariants (agent/mission.py store):
- GOAL_COMPLETED cannot be persisted without a valid system-signed completion
  proof (line ~422 raises "refusing to persist GOAL_COMPLETED without a valid
  system-signed completion proof").
- Optimistic concurrency: stale mission writes are rejected via integrity_hash
  compare (line ~430 "stale mission write rejected") — concurrent worker
  corruption is blocked.
- Mission store issues criterion evidence (issue_criterion_evidence) and loads
  are owner-bound (load_for_owner).

### Request lifecycle (core/lifecycle.py, read in full, 125 lines)

- begin(): atomically creates a request; "an existing request is never executed
  twice" (source docstring) — idempotency at request level.
- transition(): validates against STATES and TRANSITIONS maps; invalid
  transitions raise ValueError.
- complete(): terminal succeeded/failed transition then durable final result.
- recover_incomplete(): records left in active states by a crash are marked
  failed and completed — crash-safe reconciliation.
- request_cancel() / is_cancelled(): cooperative cancellation flags.

### Worker queue (agent/mission_worker.py, read 20,356 chars)

- MissionQueue with lease columns (lease_owner, lease_expires_at);
  claim_next uses BEGIN IMMEDIATE (atomic claim) and only claims items whose
  lease is absent or expired; attempts increment on claim.
- LeaseLostError raised when a heartbeat no longer owns the lease
  (DEFAULT_WORKER_LEASE_SECONDS = 120).
- _secure_database_file hardens the SQLite file.
- main commit 7b85a339 "fix(worker): protect completion after lease expiry"
  covers the stale-worker completion race.

### Existing test batteries (inventory, not modified)

test_mission_worker_lifecycle.py, test_crash_restart_resume.py,
test_v46_lifecycle.py, test_deterministic_goal_verification.py,
test_failure_recovery_replan.py, test_long_horizon_deterministic.py,
test_phase6k7b_mission_runtime.py, test_task_mission_compatibility.py.

### Residual (carried to later phases)

- mission_runtime.py (MissionRuntime) full transition-driver logic is beyond the
  raw read channel — structure verified; deep resume/reconcile semantics to be
  verified in V11 (CI/recovery) via existing tests and, if needed, an
  alternate-channel read.
- APPROVED state and security-report/approval flow: no public route verified —
  remains a documented gap (V1/V0), nothing invented.

## Backend modifications by Vibe in V3: 0


## V4 — LEASE / FENCING HARDENING — VERIFIED (implementation + CI)

Source of truth: agent/mission_worker.py at 32e2677a24c7; tests/test_lease_fencing.py;
docs/LEASE_FENCING_MODEL.md (gaps G1-G5, designs F1-F6).

Implemented fencing model (all in MissionQueue SQL predicates, single-statement
compare-and-set under SQLite transactions):

- lease_epoch column: monotonic fencing token, advanced by claim_next, recover_expired,
  and recover_after_restart. Every ownership transition strictly increases the epoch.
- update()/release()/heartbeat() with worker_id now enforce owner match AND
  lease_expires_at > now (AND lease_epoch = expected when supplied); rowcount != 1
  raises LeaseLostError. Stale workers cannot write outcomes, release, or re-extend
  leases after expiry or takeover.
- run_once threads the claimed lease_epoch and the caller clock into every queue call;
  a stale worker's final update/release is rejected and never overwrites the reclaiming
  worker's state (LeaseLostError is caught and the queue truth is returned).
- Ambiguous in-flight execution (worker exception with checkpoint status in_flight or
  mission RECOVERY_REQUIRED) converges to RECOVERY_REQUIRED + queue WAITING_FOR_TOOL
  with an explicit reconciliation error; it never becomes SUCCESS or FAILED.
- Exactly-once is claimed ONLY for internal single-writer lease transitions
  (claim is atomic via BEGIN IMMEDIATE); external side effects remain at-least-once
  with a deterministic RECOVERY_REQUIRED path (no exactly-once external claim).

Test battery (13 deterministic frozen-clock tests, tests/test_lease_fencing.py):
epoch monotonicity; stale epoch rejection on update/release/heartbeat; expired-lease
heartbeat and outcome rejection; legacy-caller expiry fencing; valid-path success;
same-worker stale-epoch rejection; single concurrent claimant; restart recovery
fencing; no duplicate completion after stale ack; crash-after-side-effect recovery;
duplicate delivery convergence.

CI (head 32e2677a24c7): test (3.13) SUCCESS (runs 37005576764, 37005583646);
pytest-diagnostics SUCCESS (runs 37005576769, 37005583770); vibe-diagnostics SUCCESS
(run 37005576781, zero FAILED lines); export SUCCESS; Workers Builds FAILURE is
pre-existing on all branches.

Compatibility notes: tests/test_autonomous_foundation.py gained one explicit now
argument (V4.2.1) — intent preserved, fenced semantics unchanged; no production caller
passes worker_id without now except run_once's heartbeat callback, which uses the real
clock by design. api/missions.py and bridge.py call update()/enqueue() without
worker_id and are unaffected (VERIFIED by caller inventory).

## Backend modifications by Vibe in V4: agent/mission_worker.py, tests listed above.


## V6 — EVIDENCE CHAIN HARDENING — VERIFIED (finding fixed + battery)

Finding F-V6-1 (FIXED in agent/evidence.py at 7bae7623e05): EvidenceChainStore.append
accepted a caller-supplied current_hash precomputed over sequence 0 / empty
previous_hash (the shape produced by observed()); after append assigned the real
chain position, the stored hash no longer matched the record, so
observed()+append chains returned verify() == False permanently. Severity
rationale: integrity verification was silently unattainable on that path; no
completion path used it (workspace events append un-hashed), so no authority
bypass existed — a reliability/integrity defect, not an exploitable forgery.
Fix: append recomputes the record hash after chain position assignment.

tests/test_evidence_chain_hardening.py (9 tests, CI VERIFIED on 492a7d1c):
tamper/reorder/replay/removal rejection; unique sequencing for duplicate appends;
request isolation; unsigned/substituted/transplanted evidence cannot support a
completion proof; workspace event chain binding; content-bound record hashes.

## Backend modifications by Vibe in V6: agent/evidence.py (F-V6-1 fix), tests above.
