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
- HEAD (start of Session 4): babddb3a6af2a3bf816605f14025c0f7dcd0a4ab
- HEAD (latest verified): b74ac77b52001d3543da6312e362792a5b436f36
- LAST VERIFIED CI: SUCCESS — 1239 passed / 1 skipped / 0 failed
  (diagnostics/ci-b74ac77b5200.md).
- STAGE: Stage C hardening milestones 1 and 2 COMPLETE. Stage A (typed tool
  inventory) and Stage B (adapter contract + battery) are complete and
  CI-green.

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

## MILESTONE 1 (Session 4, part 1): external-binary handler hardening

Gaps identified by Stage C archaeology in the only subprocess-backed runtime
handler (core/local_defense.py::local_process_info), all closed:

1. Binary identity pinning: the handler resolves `ps` ONCE via shutil.which
   at entry and executes the RESOLVED ABSOLUTE PATH (closing the PATH-hijack
   window between the adapter's availability check and the spawn); an
   unresolvable binary fails closed BEFORE any spawn.
2. Deterministic timeout classification: subprocess.TimeoutExpired becomes a
   classified RuntimeError — never a partial result, never swallowed.
3. Output bounding: row cap (4096 parsed rows) and command-string cap (256
   chars) with explicit computed output_truncated flags; flags are computed
   by the handler, never taken from tool output.
4. Evidence: the resolved binary identity is recorded in the structured info
   (auditable binary provenance; local read-only data only).

Battery: tests/test_local_process_info_hardening.py (12 tests) — resolved
path executed, fail-closed unresolvable binary (spawn count == 0), fixed argv
vector with no shell, non-zero exit / empty stdout / timeout classified,
malformed rows skipped, row cap, command truncation, shell metacharacters
are DATA, evidence structured and authority/secret-free.

## MILESTONE 2 (Session 4, part 2): PREPARE resolved-binary disclosure

- security/tool_adapter.py was reconstructed byte-exactly from the commit
  patch chain f4fbbf64 → b06d7ba3 → e0a10680 (git blob sha 13561c10...:
  verified BEFORE modification) and then extended:
  - PreparedExecution gains resolved_binary (absolute path resolved once at
    PREPARE via shutil.which; DISCLOSURE ONLY — the handler independently
    resolves and pins its own path; the field never drives execution).
  - dry_run() discloses resolved_binary; dry-run still never spawns, never
    calls tools.registry.execute, never reaches a handler (INV-ADP-5).
  - resolved_binary is sourced exclusively from shutil.which inside
    prepare(); requests are frozen dataclasses with no binary/path field;
    tool output cannot appear in the dry-run plan.
- Battery: tests/test_tool_adapter_resolved_binary.py (8 tests).
- Engineering method note: the trusted retrieval paths are (a) github
  contents API base64 + JSON unescape + git blob sha verification (< ~30KB),
  (b) commit full_patch chain application with cumulative hunk-offset
  tracking + git blob sha verification (larger files). raw.githubusercontent
  and truncated open_url output are NEVER pushed.

## ARCHITECTURAL DECISIONS

- Path A (standing): catalog and runtime registry remain fully disjoint;
  registering a runtime tool is an explicit, deterministic, authority-free
  operation; catalog definitions can never become executable implicitly.
  No binding layer is required by the current adapters.
- Handler-layer binary pinning (Milestone 1) and PREPARE disclosure
  (Milestone 2) are independent controls (defense in depth).

## FILES CHANGED (Session 4)

- core/local_defense.py (modified: hardened local_process_info)
- tests/test_local_process_info_hardening.py (NEW: adversarial battery)
- security/tool_adapter.py (modified: resolved_binary disclosure)
- tests/test_tool_adapter_resolved_binary.py (NEW: adversarial battery)
- docs/runtime/SECURITY_TOOLING_STAGE_C_CHECKPOINT.md (this checkpoint)
- CHECKPOINT.md (Session 4 record)

## TEST COMMANDS

- pytest tests/ (full suite, as executed by CI)

## TEST RESULTS

- Baseline: 1219 passed / 1 skipped / 0 failed (babddb3a).
- 5a8cd492 (handler hardening): VERIFIED — SUCCESS, 1219/1.
- f09291c8 (handler battery): 1 failed / 1230 passed — single test-fixture
  defect (info payload is the 7th positional argument of add_event); no
  production change required.
- b61909ad (fixture fix): VERIFIED — SUCCESS, 1231/1.
- 0e6c9c92 (this checkpoint doc, part 1): VERIFIED — SUCCESS, 1231/1.
- f09e6b60 (PREPARE disclosure): VERIFIED — SUCCESS, 1231/1.
- 6c4305b6 (disclosure battery): VERIFIED — SUCCESS, 1239/1.
- b74ac77b (root CHECKPOINT.md Session 4 record): VERIFIED — SUCCESS,
  1239 passed / 1 skipped / 0 failed.

## LAST VERIFIED COMMIT

- b74ac77b52001d3543da6312e362792a5b436f36 (CI SUCCESS, 1239 passed / 1
  skipped).

## KNOWN RISKS

- Replay semantics for proofs are single-RUN, not single-USE (recorded for
  Owner review; a single-use nonce changes proof semantics and needs an
  Owner decision).
- Adapter wiring into MissionRuntime/AgentCore slice execution is deferred
  (Stage D); the Stage B/C batteries prove no parallel authority path
  exists meanwhile.
- Duplicate-execution / cancellation-boundary contracts live in the
  mission-orchestration track owned by the parallel engineering agent; no
  scheduler/DAG/worker runtime is built in this track.

## NEXT_ACTION

Stage D design: wire the adapter layer into MissionRuntime slice execution
through the existing proof chain (read security/tool_adapter.py,
agent/mission_runtime.py, and the Stage B/C batteries first). Keep
catalog/registry disjoint (Path A). Do NOT touch main, B3-C6, Phase A, or
R2. Do NOT build any scheduler/DAG/worker runtime (parallel agent's track);
if an interface contract with that track becomes necessary, design it as a
small, low-coupling contract only.
