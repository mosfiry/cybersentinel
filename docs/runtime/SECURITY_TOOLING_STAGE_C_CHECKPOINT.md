# SECURITY TOOLING — STAGE C CHECKPOINT

- MISSION: Security Tooling Expansion (CyberSentinel X). Complete Stage C
  (adversarial hardening of the Security Tool Execution Layer) to a hardened,
  production-oriented state: catalog → adapter → authorization verification →
  deterministic validation → safe preparation → dry-run → controlled execution
  → output normalization → evidence → cleanup → deterministic error taxonomy
  → adversarial rejection. The authority hierarchy
  OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY > DETERMINISTIC_ENFORCEMENT
  > AUTHORIZATION_SCOPE > TOOL_RUNTIME > MODEL_OUTPUT > EXTERNAL_DATA
  is immutable and is never weakened, reordered, or made configurable.
- BRANCH: security/b3-four-layer-intent
- HEAD (before this milestone): babddb3a6af2a3bf816605f14025c0f7dcd0a4ab
- HEAD (after this milestone): b61909ad64c063ae7f646d46ad498d7c58a306c7
  (plus this checkpoint commit)
- LAST VERIFIED CI (before this milestone): SUCCESS — 1219 passed / 1 skipped /
  0 failed (diagnostics/ci-babddb3a6af2.md), verified from the report at branch HEAD.
- STAGE: Stage C hardening continuation (Session 4). Stage A (typed tool
  inventory) and Stage B (adapter contract + battery) are complete and CI-green.

## COMPLETED STEPS (prior sessions)

1. Stage A: security/tool_inventory.py catalog layer (~86 definitions, Layer 1,
   definition != registration, catalog_ids ∩ KNOWN_TOOLS = ∅).
2. Stage B: security/tool_adapter.py adapter contract (INV-ADP-1..8; nine
   phases; execute only via tools.registry.execute) + Stage B adversarial
   battery (tests/test_tool_adapter.py, 50 tests).
3. Stage C (Session 3): LocalProcessInfoAdapter (local_process_info,
   required_binary="ps", fail-closed PREPARE) + Stage C adversarial battery
   (tests/test_tool_adapter_stage_c.py, ~83 items) + Path A architectural
   decision (catalog/registry disjointness preserved; registration is an
   explicit, separate, deterministic operation; the catalog alone can never
   grant execution authority).

## CURRENT MILESTONE (Session 4): external-binary handler hardening

Gaps identified by Stage C archaeology in the only subprocess-backed runtime
handler (core/local_defense.py::local_process_info):

1. The handler executed the bare PATH-relative name "ps", leaving a
   resolution-at-spawn window (PATH hijacking between the adapter's
   availability check and the spawn). Fix: resolve once via shutil.which
   inside the handler and execute the RESOLVED ABSOLUTE PATH; fail closed with
   a deterministic error if unresolvable (no spawn).
2. A subprocess timeout surfaced as an unclassified TimeoutExpired. Fix:
   classified deterministic RuntimeError ("timed out") — never a partial
   result.
3. Parsed output was unbounded. Fix: deterministic bounds — row cap (4096
   parsed rows) and command-string cap (256 chars), both surfaced as explicit
   output_truncated flags in the structured result (raw output remains
   untrusted data; the flags are computed, never taken from tool output).
4. Evidence hardening: the resolved binary identity is recorded in the
   structured info (auditable binary provenance, local read-only data only).

Adversarial battery: tests/test_local_process_info_hardening.py — resolved
path executed, fail-closed unresolvable binary (no spawn), fixed argv vector
with no shell, non-zero exit / empty stdout / timeout classified, malformed
rows skipped, row cap, command truncation, shell metacharacters in output are
DATA, evidence event structured and authority/secret-free.

## CURRENT STEP

Push the hardening commit, then the adversarial battery, then this checkpoint;
verify CI (target: previous 1219 passed / 1 skipped + new battery items, 0
failed) after each commit.

## NEXT_ACTION

After CI is verified green at this milestone's final commit: (1) reconstruct
the root CHECKPOINT.md byte-exactly (git blob sha verified) and append the
Session 4 record; (2) next hardening candidates within Stage C scope —
adapter-level dry-run binary-resolution disclosure (requires byte-exact
reconstruction of security/tool_adapter.py, ~32.8KB, via commit-patch chain)
and a binding-layer decision only if a real integration need appears (Path A
currently requires none).

## KNOWN RISKS

- The adapter dry_run report discloses the required binary NAME, not the
  resolved absolute path (prepare fail-closes on availability via
  shutil.which; the handler independently resolves and pins the absolute
  path — defense in depth holds, disclosure is a transparency gap only).
- Replay semantics for proofs are single-RUN, not single-USE (recorded for
  Owner review; a single-use nonce changes proof semantics and needs an
  Owner decision).
- Adapter wiring into MissionRuntime/AgentCore slice execution is deferred
  (Stage D); the Stage B/C batteries prove no parallel authority path exists
  meanwhile.

## ARCHITECTURAL DECISIONS

- Path A (Session 3, standing): catalog and runtime registry remain fully
  disjoint; registering a runtime tool is an explicit, deterministic,
  authority-free operation; catalog definitions can never become executable
  implicitly. Binding a catalog capability to a runtime tool would require a
  NEW explicit trusted binding layer (owner-controlled, model-output-proof);
  no such binding exists today and none is required by current adapters.
- Handler-layer binary pinning (this milestone): execution identity is
  resolved at handler entry and pinned; the adapter PREPARE check and the
  handler resolution are independent controls.

## FILES CHANGED (this milestone)

- core/local_defense.py (modified: hardened local_process_info)
- tests/test_local_process_info_hardening.py (NEW: adversarial battery)
- docs/runtime/SECURITY_TOOLING_STAGE_C_CHECKPOINT.md (NEW: this checkpoint)

## TEST COMMANDS

- pytest tests/ (full suite, as executed by CI)

## TEST RESULTS

- Baseline: 1219 passed / 1 skipped / 0 failed (babddb3a).
- 5a8cd492 (handler hardening): VERIFIED — SUCCESS, 1219 passed / 1 skipped.
- f09291c8 (adversarial battery): 1 failed / 1230 passed — the single failure
  was a test-fixture defect (the structured info payload is the 7th positional
  argument of add_event, not the 5th); no production change required.
- b61909ad (fixture fix): VERIFIED — SUCCESS, 1231 passed / 1 skipped /
  0 failed (diagnostics/ci-b61909ad64c0.md).

## LAST VERIFIED COMMIT

- b61909ad64c063ae7f646d46ad498d7c58a306c7 (CI SUCCESS, 1231 passed / 1 skipped).
