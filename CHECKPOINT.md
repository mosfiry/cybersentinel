# CyberSentinel - Engineering Checkpoint (B3-C5)

- CURRENT_PHASE: B3 - four-layer intent + canonical execution boundary
- CURRENT_UNIT: C5 FINAL HARDENING (C5-H) - registry-level execution_run_id wiring + adversarial closure
- CURRENT_STEP: verify final CI green at the dump-cleanup head (expect 1015 passed / 1 skipped); then second-pass attacker review within B3 scope only
- LAST_COMPLETED_STEP: C5-A owner-direct canonical binding (run_slice canonical ExecutionPlan gate + agent_core.run_owner_mission binds derived_initial_plan at creation); C5-B legacy containment (per-step legacy_step_execution_plan conversion, unregistered/registered-out-of-budget deterministic rejection); C5-C budget-intersection exclusion at derivation (B3-H4, expansion fails closed); C5-D run_id bound in the authorization proof across generation/validation/serialization/persistence/registry with adversarial cross-run tests; C5-E adversarial matrix (valid legacy step, out-of-budget step, unauthorized tool, modified arguments, fresh identity, cross-mission, cross-run action, cross-run proof, stale snapshot/authorization revision/plan, replan, resume, recovery, duplicate serial/parallel proposals, handler-not-called on rejection, manually constructed plan, forged fingerprint, legacy-plan widening; handler_calls == 0 asserted on rejections); C5-F recovery/resume/replan validation via bounded-replan + fail-closed stale-binding batteries; C5-G archaeology shim removed from .github/workflows/tests.yml (2d81b62f) and all diagnostics source dumps deleted
- NEXT_STEP: verify final CI green at the dump-cleanup head; then deep security review within B3 scope only (registry boundary, proof replay, stale binding, resume bypass, forged fingerprints); do NOT start B3-C6, Phase A, or R2
- C5-H FINAL HARDENING (this session): defense-in-depth gap found by the final source audit and closed - the serial and parallel model-loop call sites (mission_runtime.py) and the AgentCore slice executor (agent_core.py) called

 tools.registry.execute WITHOUT execution_run_id, so the registry-level RUN_MISMATCH cross-run proof check was silently skipped (run binding relied solely on validate_against_mission in the runtime). Wiring: serial+parallel loops now pass execution_run_id=run_id; the slice executor derives live_run_id from mission.progress (model_run_id/execution_run_id) and passes it; an absent id fails closed at the registry identity check. Adversarial battery tests/test_b3_c5_final_hardening.py (12 tests): serial/parallel/agent_core wiring, replayed-proof rejection at the registry under a rotated run with handler_calls==0, registered_owner_budget_from_snapshot pure narrowing + malformed fail-closed, legacy per-step conversion fail-closed (empty budget, out-of-budget registered tool, unregistered tool, authority-shaped arguments), repeated same-tool steps derive distinct canonical identities, stale in-flight checkpoint requires RECOVERY_REQUIRED without execution. Commits: a8f17fba (wiring + battery), a1b555d3 (indentation fix for the AgentCore insert; compileall failed on a8f17fba with IndentationError line 246 and pytest was skipped, fixed and verified), f4f51572 (temporary b64 dump shim for byte-exact fetch), 4b75831e (marker removed), 69d6b879 (shim step removed; tests.yml restored byte-identical to the pre-shim version at d3e3694b), 27b7ef53/2b767fc5/9b134897/ccff3b5b/4ff07386/068c9567/93b6acf6 (all 7 dump files deleted; ci-*.md reports kept). CI at a1b555d3: 1015 passed / 1 skipped / 0 failed (diagnostics/ci-a1b555d38208.md).
- LAST_VERIFIED_COMMIT: 2d81b62f (CI SUCCESS); dump-cleanup head 16a16cfc pending CI at write time
- TEST_STATUS: 1015 passed / 1 skipped / 0 failed at a1b555d3 (ci-a1b555d38208.md; = 1003 prior + 12 new C5-H battery tests); prior greens: da123e58 (1000), 41cfd146, 2d81b62f (1003)
- CI_STATUS: see diagnostics/ci-<sha>.md for the newest run
- OPEN_ISSUES: none blocking; diagnostics/wrap_probe*.py remain as legacy debris from an earlier phase (outside B3
-
C5 scope, harmless: CI secret scan excludes diagnostics)
- INVARIANTS_PROVEN: H1 full set (strict action identity, no tool+args fallback, no fresh identity minting, cardinality enforcement, serial+parallel gate, stale plan/lifecycle rejection, replay protection) at green CI; cross-run proof binding PROVEN (run_id in schema/hash/signature/serialization/verify/validate/registry + runtime adversarial tests); B3-H2 closed (owner-direct path via canonical typed ExecutionPlan binding; no Owner->Legacy Plan->Handler path); B3-H3 closed (legacy Plan/PlanStep compatibility-only via canonical conversion before execution; actions outside the canonical plan deterministically rejected); B3-H4 closed (budget intersection at derivation; expansion fails closed)
- INVARIANTS_NOT_PROVEN: none within B3-C5 scope (B3-C6, Phase A, R2 explicitly out of scope)
- FILES_CHANGED (C5): agent/mission_runtime.py, agent/agent_core.py, security/execution_boundary.py, security/execution_proof.py, security/owner_budget.py, planning legacy conversion path, .github/workflows/tests.yml (shim added then removed), tests/test_b3_c5_canonical_slice_binding.py, tests/test_b3_c5_owner_direct_binding.py, tests/test_b3_c5_budget_intersection.py, tests/test_b3_c5_adversarial_matrix.py and related batteries, CHECKPOINT.md, diagnostics/* (dumps added then deleted)
- NEXT_SESSION_FIRST_ACTION: read this file and the newest diagnostics/ci-*.md; confirm final green CI at the dump-cleanup head (expect 1015 passed / 1 skipped); if green, B3-C5 INCLUDING the C5-H final hardening is COMPLETE pending owner acceptance — continue only with second-pass attacker review / test-quality work within B3 scope; do NOT start B3-C6, Phase A, or R2

---

# Security Tooling Expansion — Session 1 (Stage A COMPLETE)

- BRANCH: security/b3-four-layer-intent
- START_HEAD (this session): 223ded875c0d (B3-C5 checkpoint doc commit; CI green there: 1015 passed / 1 skipped)
- B3-C5 STATUS: COMPLETE including C5-H final hardening (see sectio
n above); verified green at 223ded875c0d before this session's work
- MISSION: CyberSentinel X Security Tooling Expansion (daily until 2026-11-30); Stage A = Tool Registry + taxonomy + schemas (Layer 1 Tool Definitions)
- STAGE: A COMPLETE
- COMPLETED_SUBTASK: security/tool_inventory.py (typed, authority-free, fail-closed definition catalog; SecurityToolDefinition frozen dataclass with tool_id/canonical_name/category/capabilities/risk_class/authorization_class/schemas/network/filesystem/process/privileged/destructive/external_target/lab_only/dry_run/evidence/provenance/version/adapter_version; ToolCategory x15, ToolRiskClass x7, ToolCapability x27, ToolAvailability, ToolAuthorizationClass, ToolAccessLevel enums; fixed RISK_AUTHORIZATION_CLASS table INV-TOOL-3; offensive classes lab-only + no external targets INV-TOOL-4; evidence mandatory INV-TOOL-5; dry-run-first INV-TOOL-6; canonical uniqueness INV-TOOL-7; fail-closed validation INV-TOOL-8; seed catalog ~86 canonical definitions covering all 15 categories, all provenance OWNER_CURATED)
- TESTS_ADDED: tests/test_security_tool_inventory.py (~70 test cases incl. parametrized): risk/auth mapping totality + per-class mismatch rejection, offensive lab-only enforcement, lab-only-forbids-external-target, evidence/dry-run mandates, invalid ids/versions/provenance/capabilities/schemas rejected, authority-shaped schema keys rejected, frozen dataclass, dataclasses.replace cannot reclassify + clone re-registration rejected, duplicate tool_id and case-insensitive canonical rejection, unknown-tool fail-closed, providers_for(PORT_SCANNING)=(nmap,masscan,rustscan), Bettercap/Trivy/kube canonical single entries, all 15 categories covered, every seed definition consistent, deterministic rebuild, AST: no imports from authorization/proof/owner/plan/registry/agent layers and no execute/authorize/invoke/grant/run_ function surface, KNOWN_TOOLS untouched by catalog membership and mutation (definition != registration)
- COMMITS (this sess
ion): e168da58d93b "feat(security): Stage A typed security tool inventory (Layer 1 definitions, INV-TOOL-1..8) + adversarial test battery" (CI: 1080 passed / 6 failed — all 6 were test-helper defects: hardcoded authorization_class/lab_only in _minimal_definition); a999387a997d "test(security): fix Stage A battery helper" (CI GREEN: 1086 passed / 1 skipped, diagnostics/ci-a999387a997d.md)
- FILES_CHANGED: security/tool_inventory.py (new), tests/test_security_tool_inventory.py (new), CHECKPOINT.md (this update)
- NO production security files touched; no runtime registration added; tools/registry.py, security/authorization*, owner_*, execution_* all untouched
- TEST_STATUS: 1086 passed / 1 skipped / 0 failed at a999387a997d
- OPEN_ISSUES: none; CI diagnostics result header shows SUCCESS and tail confirms 1086/1
- NEXT_SESSION_FIRST_ACTION: begin Stage B (passive reconnaissance + informational tools) — implement the first Tool ADAPTER per the Adapter Contract (validate_input/authorize is a call INTO the existing authorization layer, never self-granted/prepare/dry_run/execute/normalize_output/collect_evidence/cleanup/error classification). Start with a local/informational adapter (whois-style or CyberChef-style local transformation) that FAILS CLOSED when the external binary is unavailable; it must reach execution ONLY through the existing ToolSpec + Owner Policy + authorization + ExecutionPlan + proof + registry chain — no new runtime path, no adapter-granted authority. Then write its 15-case mandatory battery (valid/invalid/unauthorized/out-of-scope/expired/stale-proof/cross-mission/cross-run/malformed-output/unavailable/timeout/process-failure/evidence/deterministic-normalization/dry-run; every rejection asserts the handler never ran) and push for CI.
- DISCIPLINE REMINDER: do NOT start B3-C6, Phase A, or R2; do not touch main; no reset/rebase/squash/force-push


## SESSION 2 — Security Tooling Expansion, Stage B: Tool Adapter Architecture (COMPLETE)

- BRANCH: security/b3-four-layer-intent
- START_HEAD: 1845cb77 (CI 1086 passed / 1 skipped)
- FINAL_HEAD: 0fd29599dea4 (CI GREEN: 1136 passed / 1 skipped — 1086 baseline + 50 new adapter battery tests, 0 regressions)
- RESUME_VERIFICATION: no pre-existing Stage B work found in the repo (no adapter files in security/); Stage B started from CHECKPOINT.md NEXT_SESSION_FIRST_ACTION exactly as recorded.

### Implemented
- security/tool_adapter.py (NEW, Layer 2 orchestration): ToolAdapter base contract with the 9 mandated phases — validate_input, authorize (VERIFICATION ONLY: calls ExecutionAuthorizationProof.verify / validate_against_mission and AuthorizationDecision.is_valid_for; never derives, never widens), prepare (fail-closed shutil.which binary check, no fallback), dry_run (never reaches registry/handler/subprocess), execute (ONLY via tools.registry.execute with full chain args: typed proof, live mission snapshot, execution class, live run id), normalize_output (deterministic; authority-shaped output keys rejected as untrusted data), collect_evidence (structured binding record: fingerprints/hashes only, no raw payload, provenance TOOL_ADAPTER, classification UNTRUSTED_TOOL_OUTPUT), cleanup (inert, runs exactly once on every path, never masks errors), and a deterministic error taxonomy AdapterPhase x AdapterErrorCode with underlying chain RejectionCode preserved (INV-ADP-1..8).
- AdapterResult envelope keeps raw_output / normalized_output / evidence / metadata / error_state STRICTLY separated; failures never surface as success; misbehaving evidence hooks are classified (EVIDENCE_FAILED), never fatal.
- First concrete adapter: LocalSystemInfoAdapter wrapping the EXISTING registered tool local_system_info (local/informational/read-only/non-destructive; pure local runtime, required_binary=None). Framework supports external-binary tools (required_binary + shutil.which, fail closed, tested via MissingBinaryAdapter).
- tests/test_tool_adapter.py (NEW, 50 tests): all 15 mandated adversarial cases plus real-handler integration, owner-direct path (typed context + authorize_tool + OWNER_DIRECT proof), class confusion, forged class/metadata, replay after run rotation, stale/invalid plan, forged/expired proof, timeout, normalization/evidence/cleanup failures, cleanup-does-not-mask-primary, deterministic normalization, output-metadata forgery rejection, catalog≠registration cross-layer test (nmap), consolidated 16-scenario rejection battery asserting handler_calls==0 AND execute_spy==[] for every rejection, and 5 AST module-invariant tests (import allowlist, no .derive() minting, no direct handler calls, no registry mutation/rebind/setattr, no process-execution surface).

### Commits (this session)
- f4fbbf6455e2 "feat(security): Stage B tool adapter contract" (CI green: 1086/1, module only)
- b06d7ba35c71 "fix(security): classify misbehaving evidence hooks and harden adapter envelope" (CI green: 1086/1)
- 20ac3f276cbd "test(security): Stage B adversarial tool adapter battery" (CI RED: 3 failed / 1133 passed — ALL THREE were test-side defects, no production change required)
- 6313fad83289 "fix(security): correct adapter battery fixtures (handler passthrough, AST process-surface check)" (CI: 1 failed / 1135 passed — remaining defect also test-side)
- 0fd29599dea4 "fix(security): allow full dotted module names in adapter import allowlist test" (CI GREEN: 1136 passed / 1 skipped)

### Failures and root causes (all test-side; production module never changed to force green)
1. import-allowlist test checked only the top segment of ast.Import names, so the explicitly allowed "import tools.registry" was rejected — fixed to accept full dotted names in ALLOWED_MODULES.
2. process-surface test used substring matching ("subprocess" not in source); the module docstrings legitimately mention subprocess as a PROHIBITION — rewritten as an AST check (forbidden imports: subprocess/os/sys/multiprocessing/pty/signal; forbidden calls: system/popen/Popen/spawn*/run/call/check_*/eval/exec/__import__).
3. CountingHandler fixture force-wrapped every result in dict(), so the un-normalizable-payload test failed inside the handler (EXECUTION_FAILED) instead of at NORMALIZE_OUTPUT — fixed to pass non-dict payloads through untouched.

### Adversarial security review (per checklist)
- Tool IDs: registry-validated, lowercase pattern, unknown/unregistered tools (incl. catalog-only nmap) fail closed before any execution.
- Capabilities/arguments: spec.validate + authority-shaped argument keys rejected; argument binding enforced cryptographically via proof arguments_hash.
- Provenance/authorization: adapter imports no owner/authorization-minting surface (AST-enforced); authorize() only verifies existing typed proof + decision; owner-direct requires the typed AuthorizationDecision bound to both the proof (decision_fingerprint + policy_fingerprint) and the request.
- ExecutionPlan/Proof binding: plan fingerprint, mission/request/tool/run bindings, snapshot hash+version, scope, lifecycle status+revision all re-verified; stale plan, expired/forged proof, replay after run rotation all rejected before the registry (handler_calls==0 and execute_spy==[] asserted).
- Registry: adapter never writes REGISTRY (AST); registry remains the last line of defense and re-checks proof, class, snapshot, decision.
- Subprocess/shell/env/paths: module has NO process surface (AST-enforced); binary availability via shutil.which only; no fallback execution on unavailability.
- Output handling: raw output is untrusted data; authority-shaped output keys rejected; envelope metadata/provenance cannot be forged by tool output.
- Replay/error/cleanup paths: replay rejected via run rotation; cleanup inert, once per run, failure never converts error to success and never masks the primary error.

### Architectural tension recorded for the Owner (NOT resolved unilaterally)
- Stage A enforces catalog tool_ids ∩ tools.registry.KNOWN_TOOLS = ∅ (definition != registration). Registering any catalog tool (e.g. whois) at runtime would break that invariant. This needs an Owner-level decision: either (a) keep catalog and runtime registry disjoint and add runtime tools only via the existing ToolSpec/registry path with catalog entries left as documentation, or (b) relax the disjointness invariant deliberately with a new test contract. Until decided, the adapter wraps ONLY pre-existing registered tools (local_system_info).

- NEXT_SESSION_FIRST_ACTION: Stage B is complete and CI-green at 0fd29599dea4. Next session: read this checkpoint, verify diagnostics/ci-0fd29599dea4.md is the branch HEAD CI (1136 passed / 1 skipped), then begin Stage C design per the mission sequence: a second adapter for an external-binary informational tool (e.g. whois) REQUIRING first the Owner decision on the catalog-vs-registration disjointness invariant recorded above; until that decision exists, do NOT register new runtime tools. If the Owner decision is not available, continue with hardening within current scope: adversarial review of adapter integration points in agent/runtime layers (read-only analysis) and documentation of the Adapter Contract in docs/.
- EXACT_RESUME_POINT: Stage B COMPLETE (implementation + tests + CI green + security review + checkpoint). First incomplete step: Stage C pre-work — Owner decision on catalog-vs-registration disjointness, then second adapter (external-binary, informational) + battery.
- DISCIPLINE REMINDER (unchanged): do NOT start B3-C6, Phase A, or R2; do not touch main; no reset/rebase/squash/force-push.

## SESSION 3 — Security Tooling Expansion, Stage C: Second Adapter (COMPLETE)

- Branch: security/b3-four-layer-intent
- Start HEAD (session): 0984385941098cf4edfa3d807097b5239aebee4f
- Final HEAD: 94466e2cd6311d2ee23ec8a66bc2ee8243f20ac3
- Completed stages: Stage A (typed tool inventory), Stage B (adapter contract + battery), Stage C (second adapter + battery + Path A architectural decision).
- Current stage: Security Tooling Expansion — Stage C COMPLETE; integration into mission_runtime/agent_core deferred to the next stage (boundary documented below).

### Architectural decision — Path A (catalog/registry separation retained)
- The documented tension "catalog_ids ∩ KNOWN_TOOLS = ∅" was resolved WITHOUT breaking the invariant, by adopting Path A: the catalog remains metadata/taxonomy/capability knowledge only; the runtime registry remains the ONLY source of executable authority; presence of a ToolSpec in the catalog does NOT mean a tool is executable; registration in the registry is a separate, explicit operation; the catalog alone can never grant execution authority.
- The second adapter therefore wraps a registry-registered tool that is deliberately NOT in the catalog: `local_process_info` (local/informational/read-only/non-destructive, argument-free, local-first). The Stage A disjointness test remains green and a NEW explicit test asserts local_process_info is registered in the registry and absent from the catalog.

### Second adapter — LocalProcessInfoAdapter
- Tool: `local_process_info`, tool_class INFORMATIONAL, risk READ_ONLY, required_binary="ps", timeout enforced by the adapter contract.
- All 9 contract phases from Stage B are reused unchanged: validate_input → authorize → prepare → dry_run → execute → normalize_output → collect_evidence → cleanup → error classification. No parallel execution path exists: execute() reaches the handler ONLY through tools.registry.execute.
- Fail-closed: missing `ps` binary → PREPARE rejection (BINARY_UNAVAILABLE), no fallback, handler never invoked.
- No self-granted authority: no proof minting (AST-enforced), no registry mutation (AST-enforced), owner-direct path requires the typed AuthorizationDecision bound to proof and request.

### Integration status (Stage C boundary)
- Real-handler integration is proven in-test: LocalProcessInfoAdapter drives the actual registered local_process_info handler through the full chain (Owner Policy → Authorization → ExecutionPlan → Proof → tools.registry.execute → handler) end to end.
- Structural wiring of the adapter into MissionRuntime/AgentCore slice execution is DEFERRED to the next stage: the battery proves (16-scenario consolidated rejection + execute spy) that the adapter cannot execute anything outside the existing chain, so deferral does not leave an open authority path. The stage that should perform the wiring is Stage D (adapter integration into mission_runtime slice execution through the existing proof chain), pending Owner confirmation.

### Adversarial battery — tests/test_tool_adapter_stage_c.py (NEW, ~83 test items)
- Authority: no owner authority → no execution; invalid/forged/expired proof → no execution; proof from another mission → rejected; stale plan → rejected; rotated snapshot (via real amend path) → rejected; stale authorization version → rejected. All rejections proven BEFORE handler invocation (spy counters: handler_calls==0, execute_spy==[]).
- Tool identity: unregistered tool rejected; tool absent from snapshot rejected; out-of-budget tool rejected; plan-incompatible tool rejected; forged tool ID rejected; class/risk mismatch rejected.
- Input: invalid arguments → no handler; non-canonical arguments → no handler; argument widening → rejected; out-of-plan argument injection → rejected.
- Execution: dry-run handler_calls==0; every rejection handler_calls==0; authorization failure handler_calls==0; timeout → classified failure; handler failure → classified failure; normalization failure (non-dict payload, verified to fail AT normalize_output) → classified failure; evidence failure → classified failure; cleanup failure does not mask the primary error.
- Replay: same proof after run rotation rejected; changed plan rejected; changed snapshot rejected; changed run rejected. Replay semantics confirmed as single-RUN (not single-USE) — recorded for Owner review; a single-use nonce is a candidate future hardening.
- Output poisoning: 15 authority-shaped keys (owner, authorization, permission, scope, policy, proof, plan authority, execution authority, etc.) parametrized — tool output can never inject or forge authority fields.
- The five-layer boundary test ("Adapter is not an Authorization Layer"): adapter exists ≠ authorized; ToolSpec exists ≠ registered; registered ≠ authorized for this mission; authorized ≠ proof valid; proof valid ≠ execution allowed after plan/snapshot/run changes — each boundary proven by an actual test.
- AUTHORITY_OUTPUT_TOKENS expanded for Stage C; catalog-vs-registration cross-layer test extended to local_process_info.

### Commits (this session)
- 236662116ead "feat(tools): register local_process_info informational handler" (CI green: 1136/1)
- e0a106802855 "feat(security): Stage C LocalProcessInfoAdapter (ps, fail-closed)" (CI green: 1136/1)
- 26a165c0b153 "test(security): Stage C adversarial adapter battery" (CI RED: 4 failed / 1132 passed — ALL FOUR were test-side defects, no production change required)
- 94466e2cd631 "fix(security): correct Stage C battery fixtures (two-action plan, real snapshot rotation, handler passthrough)" (CI GREEN: 1219 passed / 1 skipped, diagnostics/ci-94466e2cd631.md)

### Failures and root causes (all test-side; production never weakened)
1. proof_for_system_info: a single-action plan permitted only local_process_info, so the chain correctly refused to derive a proof for local_system_info (TOOL_NOT_ALLOWED) — fixed with a two-action plan in the fixture.
2/3. stale_snapshot_rejected / boundary_5: mutating the snapshot dict's "version" corrupted the internal authorization_hash, so the chain reported SNAPSHOT_INVALID instead of SNAPSHOT_MISMATCH — fixed by rotating the snapshot through the real path (amend with owner_approval and changes={"policy_version": ...}, helper _rotate_mission_snapshot).
4. normalization_failure_on_non_dict: CountingHandler wrapped every result in dict(), raising ValueError inside the handler before normalize_output — fixed to pass non-dict payloads through untouched so they fail at NORMALIZE_OUTPUT.

### Files changed (no deletions)
- core/local_defense.py (modified: local_process_info handler, pure-local read-only)
- tools/registry.py (modified: register local_process_info)
- security/tool_adapter.py (modified: LocalProcessInfoAdapter + expanded AUTHORITY_OUTPUT_TOKENS)
- tests/test_tool_adapter_stage_c.py (NEW: Stage C adversarial battery)
- CHECKPOINT.md (this session record)

### Security invariants upheld
- No parallel authority path; execution only through tools.registry.execute. Adapter never mints proofs, never mutates the registry, no process-execution surface (AST-enforced). Fail-closed on missing binary. Catalog cannot grant execution authority (Path A). Output can never become authority. Cleanup inert on all paths. No tests weakened; every rejection proven pre-handler.

### Unresolved risks / deferred items (for Owner)
- Replay semantics are single-RUN, not single-USE; a single-use nonce in the proof is candidate hardening (requires Owner decision since it changes proof semantics).
- Adapter wiring into MissionRuntime/AgentCore slice execution deferred to Stage D (boundary proven closed meanwhile).

- NEXT_SESSION_FIRST_ACTION: verify diagnostics/ci-<this-checkpoint-commit-sha>.md is green at branch HEAD (1219 passed / 1 skipped), then begin Stage D design: wire the adapter layer into MissionRuntime slice execution through the existing proof chain (read security/tool_adapter.py, runtime slice execution path, and the Stage B/C batteries first); keep catalog/registry disjoint (Path A); do NOT touch main, B3-C6, Phase A, or R2.
- EXACT_RESUME_POINT: Stage C COMPLETE (second adapter + ~83-item adversarial battery + CI green 1219/1 + Path A decision + checkpoint). First incomplete step: Stage D — adapter integration into MissionRuntime slice execution through the existing proof chain.

## SESSION 4 — Security Tooling Expansion, Stage C: External-Binary Hardening + Dry-Run Transparency (COMPLETE)

- Branch: security/b3-four-layer-intent
- Start HEAD (session): 0e6c9c92462d4db0d7c5e1264d447d320a49004e (verified from repository before any modification; CI SUCCESS 1231/1)
- Final HEAD (session): 6c4305b697b6fbe7b02133867fbfcb72e73c3700 (plus this checkpoint commit)
- Stage: Stage C hardening continuation. No agent-parallel work was overwritten; commits between checkpoints were CI-generated markers only.

### Milestone 1 — external-binary handler hardening (core/local_defense.py)
- Binary identity pinning: local_process_info now resolves `ps` ONCE via shutil.which at handler entry and executes the RESOLVED ABSOLUTE PATH (closing the PATH-hijack window between the adapter PREPARE availability check and the spawn); unresolvable binary fails closed BEFORE any spawn.
- Deterministic timeout classification: subprocess.TimeoutExpired is converted to a classified RuntimeError (never a partial result, never swallowed).
- Output bounding: row cap (4096 parsed rows) and command-string cap (256 chars) with explicit computed output_truncated flags; flags are computed by the handler, never taken from tool output.
- Evidence: the resolved binary identity is recorded in the structured info (auditable binary provenance; local read-only data only).
- Battery: tests/test_local_process_info_hardening.py (12 tests) — resolved path executed, fail-closed unresolvable binary (spawn count == 0), fixed argv vector with no shell, non-zero exit / empty stdout / timeout classified, malformed rows skipped, row cap, command truncation, shell metacharacters are DATA, evidence structured and authority/secret-free.

### Milestone 2 — PREPARE resolved-binary disclosure (security/tool_adapter.py)
- Byte-exact reconstruction of security/tool_adapter.py from the commit-patch chain f4fbbf64 → b06d7ba3 → e0a10680 (git blob sha 13561c10f58560b18c3d07e4fea3e9abe08f1633 verified BEFORE any modification).
- PreparedExecution gains resolved_binary (absolute path resolved once at PREPARE via shutil.which). DISCLOSURE ONLY: the handler independently resolves and pins its own path (defense in depth); the field never drives execution and can never widen authority.
- dry_run() plan now discloses resolved_binary alongside required_binary/handler_source/would_execute. Dry-run still never calls tools.registry.execute, never spawns, never reaches a handler (INV-ADP-5 unchanged).
- resolved_binary is sourced EXCLUSIVELY from shutil.which inside prepare(); the request is a frozen dataclass with no binary/path field, and tool output cannot appear in the dry-run plan (the plan is derived before any execution exists).
- Battery: tests/test_tool_adapter_resolved_binary.py (8 tests) — prepare discloses resolved absolute path; None when no binary required; dry-run disclosure with execute_spy == []; missing binary fails closed at PREPARE; resolved path follows which() not request fields; immune to forged tool output; authorization failure (PROOF_REQUIRED) never reaches prepare/handler; existing dry-run plan keys and PreparedExecution positional construction preserved.

### Commits (this session)
- 5a8cd492ef56 "feat(security): pin resolved binary path, classify timeout, bound output in local_process_info handler" (CI GREEN: 1219/1)
- f09291c8891f "test(security): adversarial battery for hardened local_process_info handler" (CI RED: 1 failed / 1230 — single test-side fixture defect: the structured info payload is the 7th positional argument of add_event, not the 5th)
- b61909ad64c0 "test(security): fix evidence-event fixture" (CI GREEN: 1231/1)
- 0e6c9c92462d "docs(runtime): Stage C hardening checkpoint" (CI GREEN: 1231/1; NEW dedicated checkpoint docs/runtime/SECURITY_TOOLING_STAGE_C_CHECKPOINT.md created per Stage C mission requirement)
- f09e6b60e5af "feat(security): resolve required binary once at PREPARE and disclose absolute path in dry-run plan" (CI GREEN: 1231/1)
- 6c4305b697b6 "test(security): adversarial battery for PREPARE resolved-binary disclosure" (CI GREEN: 1239 passed / 1 skipped / 0 failed)

### Engineering method note (byte-exactness discipline)
- The trusted retrieval paths this session: (a) github contents API base64 + JSON unescape + git blob sha verification for files under ~30KB; (b) commit full_patch chain application with hunk-offset tracking and git blob sha verification for larger files (security/tool_adapter.py 36866 bytes reconstructed and verified against 13561c10...); (c) raw.githubusercontent and truncated open_url output are NEVER pushed.
- The patch applier required cumulative hunk-offset tracking (hunk old-start lines refer to the pre-image; later hunks shift by earlier deltas) — a 3-line desync was caught by context verification before any push.

### Security invariants upheld
- No parallel authority path: execution only through tools.registry.execute; adapter never mints proofs, never mutates the registry, no process-execution surface in the adapter module (AST-enforced, unchanged).
- Dry-run is real: disclosure-only fields cannot spawn, mutate, or reach a handler; INV-ADP-1..8 unchanged.
- Catalog/registry disjointness (Path A) untouched; the authority hierarchy is untouched and was never reordered, weakened, or made configurable.
- No tests weakened; every rejection proven pre-handler (spy counters) in both new batteries.

### Unresolved risks / deferred items (for Owner)
- Replay semantics remain single-RUN, not single-USE (single-use nonce needs an Owner decision; it changes proof semantics).
- Adapter wiring into MissionRuntime/AgentCore slice execution remains deferred to Stage D (boundary proven closed by the Stage B/C batteries).
- Duplicate-execution / cancellation-boundary contracts live in the mission-orchestration track owned by the parallel engineering agent; no scheduler/DAG/worker runtime was built here (out of this track's scope).

- NEXT_SESSION_FIRST_ACTION: verify diagnostics/ci-<this-checkpoint-commit-sha>.md is green at branch HEAD (expected 1239 passed / 1 skipped), then begin Stage D design: wire the adapter layer into MissionRuntime slice execution through the existing proof chain (read security/tool_adapter.py, agent/mission_runtime.py slice path, and the Stage B/C batteries first); keep catalog/registry disjoint (Path A); do NOT touch main, B3-C6, Phase A, or R2; do not build any scheduler/DAG/worker runtime (parallel agent's track).
- EXACT_RESUME_POINT: Stage C hardening milestones 1 and 2 COMPLETE (handler binary pinning + PREPARE resolved-binary disclosure + 20 new adversarial tests + CI green 1239/1 + root checkpoint updated). First incomplete step: Stage D — adapter integration into MissionRuntime slice execution through the existing proof chain.

## SESSION 5 — Offensive Capability Activation, P0: Live Reasoning-to-Execution Bridge + Real Scoped Probe (COMPLETE)

- Branch: security/b3-four-layer-intent
- Start HEAD (session): 35eb390bd5c9a032849921a8bc875d9947661043 (CI 1254/1 green at start of milestone bookkeeping; session work began from ca90282ddc per prior checkpoint)
- Final HEAD (session): 3a59418b5652197b2b31338f6835f98eec710bdc (plus this checkpoint commit)
- Stage: Offensive Capability Activation (Owner mission, higher priority than cosmetic hardening). Source archaeology PROVED agent/offensive_mind.py (OffensiveMind/Engagement/Campaign) and cyber/offensive.py (ScopeGuard/OffensiveAction/GuardDecision) were imported ONLY by tests (dead from runtime), and tools/registry.py `scoped_http_probe` was a PLACEHOLDER handler returning a note.

### Milestone 1 — live typed bridge (agent/offensive_bridge.py)
- OffensiveActionProposal: frozen typed dataclass (proposal/mission/request/tool ids, plan_hash, target_kind local|network, target_url/target_id, argument, hypothesis, required_evidence, risk_class, source_step_id, execution_run_id, rationale). A proposal is UNTRUSTED input (INV-OFF-1).
- Bridge chain: validate_proposal (fail closed) → registry registration check (catalog definition is NOT execution; `nmap`-style catalog-only ids rejected) → adapter/tool_name match → mission identity binding (mission_id, request_id equality, plan fingerprint, live run id from progress execution_run_id|model_run_id) → SCOPE FIREWALL (network actions REQUIRE a typed ScopeSnapshot; the ScopeGuard's CANONICAL url becomes the executed argument; target_id smuggling, out-of-scope hosts, and endpoints mentioned in observed output are all rejected) → ExecutionAuthorizationProof.derive over the EXISTING owner chain → ToolAdapter nine-phase contract (execution ONLY through tools.registry.execute, INV-OFF-3/4) → OffensiveExecutionRecord + feedback_event for OffensiveMind.adapt (INV-OFF-5: feedback is reasoning, never authority).
- ScopedHttpProbeAdapter: scope_required tool contract — bind_scope (typed owner-side scope context: program_id, target_id, scope_snapshot_id, canonical url) and bind_authorization (typed Owner AuthorizationDecision); execute() routes through tools.registry.execute with scope_context and authorization_decision so the registry re-resolves scope against the persisted scope store and re-verifies the decision binding (decision signature == proof decision_fingerprint; policy fingerprints match).
- Fix during CI iterations: request identity binds by EQUALITY, not non-emptiness (mission request_id may legitimately be empty; scoped probe executions additionally require a non-empty request id because the registry demands a decision-valid request).

### Milestone 2 — scoped_http_probe is REAL (tools/registry.py)
- Byte-exact reconstruction of tools/registry.py from 19 commit patches (added at b84b8adc; every intermediate blob SHA verified; final blob 58de57fda7418bf4ba80e2a3d78a20642b40d1c7 matched BEFORE any modification).
- Placeholder replaced with a real bounded observation: ONE GET via urllib with a no-redirect opener (redirect Location recorded as OBSERVED data only — observation never widens scope), 10s hard timeout, 64KB hard body cap (truncated flag), body NEVER returned (size + sha256 only), server/content-type/content-length/location header subset, elapsed_ms, deterministic fail-closed classification (PROBE_ARGUMENT_INVALID / PROBE_FAILED / PROBE_READ_FAILED), single network seam _probe_fetch (no shell, no sockets elsewhere).
- tests/test_scoped_http_probe.py (9 tests): structured success, body hashed never returned, redirect observed never followed (exactly one fetch), hard-cap truncation, URLError/timeout fail closed, non-http(s) and non-string arguments rejected before any fetch, no authority keys in observations.
- tests/test_phase6c_scope_firewall.py updated: the suite never performs real network calls (the probe seam is faked for the allowed OWNER_DIRECT execution; all denial paths unchanged).

### Tests and CI (this session)
- tests/test_offensive_bridge.py (17 tests): 4 live reachability (full local chain with the REAL ps-backed handler; network chain through the real registry scope re-resolution with a persisted scope snapshot and a real typed Owner AuthorizationDecision; feedback loop feeding real OffensiveMind.adapt; dry-run executes nothing) + 13 negatives (no scope snapshot, out-of-scope host, target_id smuggling, cross-mission, tampered plan hash, wrong execution run, unregistered tool, adapter/tool mismatch, local proposal smuggling a network target, malformed proposals, observed-output scope smuggling) — every negative asserts execute spy AND handler spy are empty.
- CI history this session: 672508a3 12 failed (request_id over-validation + template fixture) → c3e6531 4 failed → 2b46af6 2 failed (registry requires scope_context + AuthorizationDecision) → 35eb390 CI GREEN 1254/1 → 0f79f84 1 failed (phase6c real network attempt — safely fail-closed) → a01fd4 CI GREEN 1263/1 → docs commit 3a59418b (no test changes).
- Files added: agent/offensive_bridge.py, tests/test_offensive_bridge.py, tests/test_scoped_http_probe.py, docs/runtime/OFFENSIVE_CAPABILITY_MATRIX.md, docs/runtime/OFFENSIVE_CAPABILITY_CHECKPOINT.md. Files modified: tools/registry.py (probe handler real), tests/test_phase6c_scope_firewall.py (network seam faked). No files deleted.

### Security invariants verified (evidence-backed)
- Authority hierarchy unchanged; MODEL_OUTPUT (proposal rationale) and EXTERNAL_DATA/tool output (observations) never widen scope or mint authorization (INV-OFF-1/2/5, tested).
- Single execution path: the bridge composes ScopeGuard + proof derivation + adapter; handlers reachable ONLY through tools.registry.execute (INV-OFF-3, spy-tested).
- Fail closed: every rejection happens before any execution; dry-run executes nothing (INV-OFF-6/7).
- Catalog/runtime disjointness preserved (catalog-only tool rejected by the bridge, tested).
- Secrets/credential access deliberately NOT implemented; evidence records never carry secrets in plaintext (recorded safety decision pending explicit Owner override of mission item 16).

- NEXT_SESSION_FIRST_ACTION: verify diagnostics/ci-<this-checkpoint-commit-sha>.md is green at branch HEAD (expected 1263 passed / 1 skipped), then begin P1 reconnaissance family: design and register dns_lookup as a bounded, owner-authorized, scope-bound tool (catalog definition AND runtime registration kept disjoint; adapter + adversarial battery + live bridge test; do NOT build any scheduler/DAG/worker runtime; do NOT touch main; no reset/rebase/squash/force-push).
- EXACT_RESUME_POINT: Offensive Capability Activation P0 COMPLETE (live bridge + real scoped_http_probe + 17-test bridge battery + 9-test probe battery + phase6c seam fix + capability matrix and checkpoint docs + CI green 1263/1). First incomplete step: P1 dns_lookup observation family per docs/runtime/OFFENSIVE_CAPABILITY_CHECKPOINT.md NEXT_ACTION.

## SESSION 5 (continued) — Offensive Capability Activation, P1: Real Scoped DNS Observation (COMPLETE)

- Branch: security/b3-four-layer-intent
- Session resumed from the verified checkpoint state 098b9cfe5c26 (CI 1263/1 green; the two later commits were inspected and preserved: d5aa6bdb / b5fe9cd9 are CI status markers only).
- The local workspace had been reset between sessions; byte-exactness discipline was re-applied from scratch: tools/registry.py rebuilt from its 20-commit patch chain (EVERY intermediate blob SHA verified; final blob 6a794f848f3e11b63c4fa2001a5ae75db1d8b461), agent/offensive_bridge.py from its 4-commit chain (blob 1fb3695a34f553e6f24b5b6117dbe80b5b7f1c31), and docs/runtime/OFFENSIVE_CAPABILITY_MATRIX.md (blob e6dbc0b02579e2078761b7fe5b9140edbb3977f3) — all verified BEFORE any edit.

### Milestone — scoped_dns_lookup is REAL (P1)
- tools/registry.py: `_scoped_dns_lookup` — a REAL bounded DNS observation behind the same gate sequence as scoped_http_probe. The executed argument is the ScopeGuard's CANONICAL url; the handler extracts the host from that url and resolves exactly that host. Records are deduplicated and deterministically ordered by (family, address); hard record cap SCOPED_DNS_MAX_RECORDS=32; deterministic fail-closed classification (DNS_ARGUMENT_INVALID / DNS_FAILED); a single DNS seam `_dns_resolve` (no shell, no other resolver surface); the time bound is enforced by the registry executor (adapter timeout_seconds=10). Registered as a scope_required, owner+decision-bound network-read tool. Resolved addresses are OBSERVED data only — they can never widen scope (INV-OFF-2).
- agent/offensive_bridge.py: `ScopedDnsLookupAdapter` — same contract as the probe adapter (bound typed scope context + bound typed Owner AuthorizationDecision; execution ONLY through tools.registry.execute, which re-resolves the persisted scope snapshot and re-verifies the decision binding).
- tests/test_scoped_dns_lookup.py (15 tests): handler bounds at the faked single seam; catalog/runtime disjointness via DEFAULT_SECURITY_TOOL_INVENTORY; LIVE bridge reachability with a real typed Owner AuthorizationDecision and a persisted scope snapshot (no real network in any test); dry-run; negatives (no scope snapshot, no owner decision, out-of-scope host, observed DNS address never widens scope, wrong-tool decision rejected at proof derivation) — every negative proven pre-execution (execute/handler/seam spies empty).

### Commits and CI (this milestone)
- b139c07c2c3e feat(tools): scoped_dns_lookup handler + adapter (CI GREEN 1263/1)
- 9852e2ef0545 test battery (CI RED 2 failed — both test-side defects: the wrong-tool decision is rejected even earlier, at proof derivation, raising ExecutionProofError PROOF_BINDING_MISMATCH instead of returning a REJECTED record; the observed-address test used the counting fixture's empty records instead of the real handler with the faked seam. Production fail-closed correctly in both cases.)
- 45fefef721ae test fix (CI GREEN 1278/1 — 15 new tests)
- ec13940c5966 docs: OFFENSIVE_CAPABILITY_MATRIX.md (scoped_dns_lookup LIVE; TLS/port/technology still PLANNED, not claimed) + OFFENSIVE_CAPABILITY_CHECKPOINT.md P1 milestone record

### Security invariants re-verified (evidence-backed)
- INV-OFF-1..7 unchanged and retested for the DNS family; single execution path; fail-closed before any execution; dry-run executes nothing; catalog/runtime disjointness asserted; observed DNS records are observations, never authorization (adversarial test proves a second action against a resolved address is rejected pre-execution).

- NEXT_SESSION_FIRST_ACTION: verify diagnostics/ci-<this-checkpoint-commit-sha>.md is green at branch HEAD (expected 1278 passed / 1 skipped), then continue P1: design and register the TLS inspection observation family (same bounded, owner-authorized, scope-bound pattern; single seam fakeable in tests; adapter reuse; adversarial + live bridge battery; CI green; checkpoint update), per docs/runtime/OFFENSIVE_CAPABILITY_CHECKPOINT.md NEXT_ACTION. Keep catalog/registry disjoint; do NOT touch main; no reset/rebase/squash/force-push; no scheduler/DAG/worker runtime.
- EXACT_RESUME_POINT: P0 + P1(dns_lookup) COMPLETE. First incomplete step: TLS observation family.
