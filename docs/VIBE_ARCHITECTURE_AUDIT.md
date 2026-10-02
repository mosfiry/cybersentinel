# VIBE ARCHITECTURE AUDIT — Phase V1

Baseline: vibe/principal-engineering @ 5dc5e1cb80f9 (contains PR #17 checkpoint 71ce3c95
backend lineage + desktop additions). Audit performed 2026-10-02 by reading actual
source files from the repository. Status vocabulary: VERIFIED / PARTIALLY VERIFIED /
UNVERIFIED. No code changes were made in this phase.

## Layered model → actual source mapping

Each layer maps to code verified by direct file read (defs/classes enumerated from the
fetched source), and to existing test files in tests/.

### SYSTEM / PLATFORM — VERIFIED
- bridge.py: stdlib http.server application (no Flask); imports core.engine,
  core.lifecycle, core.db, security.owner_password, security.public_session,
  api.chat, api.missions, agent.task_manager, tools.registry, agent.mission_worker,
  agent.mission_runtime, agent.planning, security.mission_authorization.
- Public route strings found in bridge.py source: /api/public/health,
  /api/public/auth/session, /api/public/missions, /api/public/missions/...,
  /api/public/workspace/... .
- Tests: test_public_web_boundary.py, test_product_workspace_boundary.py.

### OWNER (authentication) — VERIFIED
- security/owner_password.py: hash_password (scrypt-family verifier),
  _dummy_verify (timing-safe dummy path), owner_account_exists, create_owner_account,
  login, resolve_session, authenticated_owner, revoke_session, revoke_owner_sessions,
  reset_password, logout.
- security/public_session.py: PublicSession, PublicSessionManager.
- security/owner_password_bootstrap.py exists.
- Tests: test_owner_password_auth.py, test_owner_live_path_auth.py,
  test_message0003_auth.py, test_v50_owner_session.py.
- Note (verified from main history): legacy security/owner_session.py was deleted and
  OWNER_TOKEN removed from the live path (commit 3cf5bccba037, regression test
  bf388cad0e4f); owner identity is username+password server-side sessions only.

### OWNER INSTRUCTION — VERIFIED (existence + API surface)
- security/owner_policy.py (17,657 chars, fully read via raw channel): OwnerPolicy,
  OwnerInstructionSource, OwnerInstructionStatus, OwnerAuthenticationEvidence,
  OwnerInstruction, OwnerInstructionSnapshot, OwnerPolicySnapshot, load_policy,
  set_current_owner_instruction, current_owner_policy_context,
  authenticate_owner, capture_policy_snapshot; 41 occurrences of OWNER_INSTRUCTION.
- security/owner_charter.py: CharterDomain, Stance, RuleProvenance,
  OwnerInstructionConflict, LegislationError, CharterRule, is_authoritative_source,
  try_legislate, assert_charter_compliance, assert_required_behaviors_present,
  derive, resolve_against_charter.
- Tests: test_owner_charter.py, test_owner_charter_knowledge_invariant.py
  (docs/OWNER_CHARTER.md pinned; EXTERNAL_DATA cannot legislate),
  test_owner_master_invariants.py, test_owner_authority_refactor.py.

### DETERMINISTIC ENFORCEMENT — VERIFIED (surface), enforcement-in-depth = V2 scope
- security/authority.py: AuthorityTier, assert_authority_invariant,
  validate_tier_name, authority_snapshot; OWNER_INSTRUCTION and EXTERNAL_DATA tiers
  present with invariant assertion.
- security/truthfulness.py (19,832 chars, fully read): EvidenceStatus,
  SystemEvidenceIssuer (keyed HMAC, claimed vs verified provenance), system_issuer,
  EvidenceRecord, ExecutionRecord, Claim, classify_claim, execution_outcome,
  verify_test_claim, verify_ci_claim, CompletionGate, evaluate_completion,
  mission_truth_payload.
- Tests: test_boolean_trust_battery.py, test_deterministic_goal_verification.py,
  test_security_integrity_adversarial.py.

### AUTHORIZATION — VERIFIED
- security/authorization.py: AuthorizationResult, authorize_tool, authorize_plan,
  public_plan (AuthorizationDecision referenced 5x).
- security/authorization_context.py: AuthorizationContext, AuthorizationDecision.
- security/mission_authorization.py: MissionAuthorizationSnapshot +
  MissionAuthorizationError.
- security/owner_budget.py: OwnerAuthorizedToolBudget (bounded tool use).
- Tests: tests/runtime_authorization.py, test_governed_execution.py,
  test_phase21_restart_authorization.py.

### SCOPE — VERIFIED
- security/scope.py: ScopeError, canonical_host, canonical_url, TargetIdentity,
  ProgramAuthorization, ScopeDecision, make_snapshot.
- security/scope_resolver.py: ScopeResolver.resolve (+ _expired, _out_of_scope).
- security/scope_store.py exists (not yet read in this phase).
- Tests: test_phase6c_scope_firewall.py, test_scope_firewall_battery.py.

### MISSION — VERIFIED (surface); runtime deep-dive = V3 scope
- agent/mission.py, agent/mission_runtime.py (MissionRuntime — raw fetch hit the
  32,700-char channel limit; content marked PARTIALLY VERIFIED via raw channel,
  structure VERIFIED via def enumeration), agent/mission_worker.py:
  WorkerMissionState, LeaseLostError, MissionQueue, MissionWorker, MissionSchedule,
  MissionScheduler; agent/mission_task_adapter.py; agent/task_manager.py;
  agent/task_runtime.py.
- core/lifecycle.py: LifecycleRecord, begin, transition, complete, recover_incomplete,
  request_cancel, is_cancelled — durable lifecycle records with recovery.
- Tests: test_mission_worker_lifecycle.py, test_task_mission_compatibility.py,
  test_crash_restart_resume.py, test_v46_lifecycle.py, test_long_horizon_deterministic.py.

### REASONING — VERIFIED (surface)
- reasoning/ package; agent/planning.py, agent/strategy.py, agent/hypotheses.py,
  agent/offensive_mind.py, agent/context.py, agent/knowledge_context.py.
- Tests: test_cyber_reasoning.py, test_cyber_reasoning_engine.py,
  test_offensive_mind.py, test_v47_red_team.py.

### TOOLS — VERIFIED
- tools/registry.py (16,486 chars, fully read): ToolTimeout, ToolSpec, build_registry,
  tool_definitions, get_tool, execute; handlers: _status, _latest_intel, _refresh_intel,
  _local_security, _system_info, _search, _watch, _unwatch, _run_project_tests,
  _red_team_assess, _scoped_http_probe. Tool inventory automation is V5 scope.

### EVIDENCE — VERIFIED
- agent/evidence.py: Evidence, observed, verify_chain, EvidenceChainStore.
- security/truthfulness.py EvidenceRecord/SystemEvidenceIssuer (issuer-minted,
  keyed-HMAC provenance).
- security/execution_proof.py (23,159 chars, fully read): canonical_execution_fingerprint,
  ExecutionAuthorizationProof, consume_execution_proof_once (one-time semantics),
  classify_snapshot_reason, RejectionCode, ExecutionClass.
- Tests: test_execution_proof_boundary.py, test_v45_adversarial.py
  (plan/evidence integrity).

### VALIDATION — VERIFIED (surface)
- agent/verification.py: VerificationResult, FindingClaim, VerificationPlan,
  VerificationReport, VerificationEngine.
- agent/filesystem_verification.py exists.
- security/truthfulness.py: verify_test_claim, verify_ci_claim, CompletionGate.

### REPORT / OWNER APPROVAL — UNVERIFIED as a public capability
- api/ contains exactly chat.py and missions.py. No /api/public route for security
  report retrieval or Owner approval was found in bridge.py public route strings.
- The backend may pause awaiting approval (per Manus reporting); driving such state
  from the public client is NOT a verified capability. Documented; nothing invented.

### MODEL / PROVIDER — surface VERIFIED (deep audit = V6)
- agent/model_protocol.py, model_router.py, providers.py, provider_api.py,
  conversation_provider.py, model_intelligence/.
- Tests: test_native_model_protocol.py, test_model_benchmark.py,
  test_real_provider_long_horizon.py, test_phase21_provider_compaction.py.

## Cross-layer enforcement questions deferred to V2 (authority audit)

1. Do all production tool-execution callers route through security/authorization.py
   authorize_tool with an AuthorizationContext (no direct tools.registry.execute
   bypass)?
2. Can model output, tool results, or external data mutate OwnerInstruction state
   (security/owner_policy.set_current_owner_instruction callers)?
3. Is EXTERNAL_DATA legislation blocked in every path (charter invariant)?
4. Are scope snapshots bound to Owner sessions and revalidated before dispatch
   (integration/cybersentinel-final-completion branch claims work here — unmerged,
   treated as UNVERIFIED until it lands)?

## Method and channel limits (recorded honestly)

- Files read fully via raw.githubusercontent: authority.py, owner_policy.py,
  authorization.py, scope.py, execution_boundary.py, execution_proof.py,
  truthfulness.py, public_session.py, mission_authorization.py, owner_charter.py,
  plan_integrity.py, owner_budget.py, tools/registry.py, evidence.py,
  scope_resolver.py, authorization_context.py, core/lifecycle.py, verification.py,
  owner_password.py, api/chat.py (7,824), api/missions.py (6,280).
- agent/mission_runtime.py exceeded the raw channel limit (~32,700 chars) — structure
  verified, full content PARTIALLY VERIFIED via raw channel.
- bridge.py is ≥32,793 chars; route surface extracted from the fetched portion —
  PARTIALLY VERIFIED via raw channel.
- No code was modified in this phase. Backend modifications by Vibe: 0.
