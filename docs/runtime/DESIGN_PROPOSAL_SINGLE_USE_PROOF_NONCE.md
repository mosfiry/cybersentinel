# DESIGN PROPOSAL — Single-USE ExecutionAuthorizationProof (nonce/use-ledger)

Status: PROPOSAL FOR OWNER DECISION (Case 15). No code changes. Per the B3-C5
contract, proof semantics changes require explicit Owner approval; this
document exists so the Owner can decide from a concrete, source-grounded
design instead of an abstract risk note.

Author: autonomous engineering agent, session 8 (2026-10-01)
Scope: B3 only. Does NOT touch B3-C6, Phase A, or R2.

## 1. Current state (verified at branch head, source-cited)

- ExecutionAuthorizationProof (security/execution_proof.py) is a frozen, signed
  (HMAC-SHA256 over the binding payload), stateless authorization artifact.
  Its binding payload already includes execution_class, mission_id, request_id,
  tool, tool_call_id, run_id, arguments_hash, plan_hash, snapshot_hash,
  snapshot_version, scope_hash, policy_fingerprint, decision_fingerprint,
  mission_status, lifecycle_revision, created_at, expires_at.
- tools/registry.py execute() enforces, in order: proof presence
  (PROOF_REQUIRED), verify() (signature + expiry + tool/mission/request/
  tool_call/run/argument binding), execution-class agreement
  (EXECUTION_CLASS_MISMATCH), OWNER_DIRECT typed-decision presence
  (PROOF_INCOMPLETE, added by the C5-R second-pass review), decision binding
  (PROOF_BINDING_MISMATCH), owner_only/scope_required gates, mission-snapshot
  agreement (SNAPSHOT_MISMATCH), then the handler.
- Cross-RUN replay is closed: run_id is signed into the binding payload and
  checked at verify() (RUN_MISMATCH) and against the live mission in
  validate_against_mission().
- Cross-USE replay is NOT closed: within one run, inside the proof TTL, a
  captured proof for tool T with argument A can be executed more than once by
  any code position that reaches tools.registry.execute with the same kwargs.
  This is the pinned, characterized architecture ("single-RUN, not
  single-USE", Case 15; characterization test in
  tests/test_b3_c5_second_pass_attacker_review.py re-pins it honestly).
- RejectionCode.PROOF_REPLAY (security/execution_proof.py line 66) is defined
  but emitted nowhere today (verified by source scan at the branch head).

## 2. Threat model delta

Today the RUN_MISMATCH/plan/snapshot/lifecycle/decision gates mean a replayed
proof must be replayed within the same run, same plan revision, same snapshot,
same lifecycle revision, same arguments. The residual risk is DUPLICATE
EXECUTION inside one run: the same authorized (tool, arguments) executing
twice — double evidence, double side effects (e.g. an offensive scoped probe
fired twice), or an attacker who captured a proof+kwargs pair inside a
compromised process re-firing it while the run is live. Single-USE closes the
last duplicate-execution window at the registry boundary.

## 3. Options considered

- Option C — shorten TTL: weakens the window but keeps duplicates legal.
  Rejected (not an invariant, only a smaller hole).
- Option B — bake a nonce into the proof at derive() and track it at the
  registry: rejected because derive() must stay a pure function of existing
  authorization (no fresh identity minting, H1), and a nonce inside the signed
  payload would make proofs non-deterministic from their authorization inputs.
- Option A (RECOMMENDED) — server-side use ledger keyed by the proof
  fingerprint at the registry boundary. The proof artifact stays stateless and
  deterministic; consumption is server state, exactly like the mission
  lifecycle it already protects.

## 4. Recommended design (Option A)

1. Ledger: one SQLite table in the existing mission store,
   proof_use(proof_fingerprint TEXT PRIMARY KEY, mission_id TEXT,
   request_id TEXT, run_id TEXT, tool TEXT, first_used_at TEXT).
   proof_fingerprint = execution_binding_hash (already HMAC-signed and
   collision-resistant; identical proofs are identical by definition, which is
   exactly the duplicate-execution event we want to refuse).
2. Consumption point: in tools/registry.execute, AFTER every authorization
   check has passed and IMMEDIATELY BEFORE the handler is invoked, perform an
   atomic INSERT (INSERT ... ; duplicate primary key -> rejection). The insert
   must be inside the same transaction scope as nothing else — it is the
   commit point of "this proof has now been spent".
3. Rejection: on duplicate key, raise PermissionError with
   RejectionCode.PROOF_REPLAY ("execution proof already consumed"). The
   handler must not be invoked (handler_calls == 0 on the duplicate).
4. Failure semantics: FAIL CLOSED. If the ledger is unavailable (DB error,
   corrupt store), the registry must reject with PROOF_REPLAY (or a new
   PROOF_UNVERIFIABLE code) rather than execute un-ledgered. Never fail open.
5. Retries: legitimate retries already re-derive a fresh proof per step in
   the runtime (per-step derivation is the C5-A..G design); a consumed proof
   failing with PROOF_REPLAY is the correct signal that a step must re-derive.
6. GC: rows older than the maximum proof TTL may be pruned opportunistically;
   pruning must never delete rows younger than TTL (a pruned-in-flight proof
   would re-open duplicate execution).
7. No widening: the ledger adds a rejection reason only. It grants nothing,
   stores no secrets, and is never readable as authority by MODEL_OUTPUT or
   EXTERNAL_DATA. Ledger rows are evidence-adjacent metadata, not evidence.

## 5. Adversarial battery (mandatory before merge, ~14 tests)

1. same proof executed twice -> second rejected PROOF_REPLAY, handler_calls == 0.
2. concurrent duplicate submit (two threads) -> exactly one handler execution.
3. ledger row pre-inserted (forged ledger state) -> execution rejected
   PROOF_REPLAY, handler_calls == 0 (registry only INSERTs; rows are never
   trusted as grants).
4. ledger unavailable/closed -> execution fails closed, no handler.
5. two distinct proofs, same tool and arguments, same run -> both execute
   (derivation-level retry remains legal).
6. duplicate attempt after run rotation -> RUN_MISMATCH fires first
   (verify order preserved; assert which boundary rejects).
7. duplicate attempt with tampered serialization -> PROOF_INVALID fires first.
8. legitimate per-step re-derivation in the runtime loop -> all steps green.
9. ledger prune never removes a row within TTL.
10. resume/recovery path derives fresh proofs -> recovery unaffected.
11. OWNER_DIRECT duplicate -> PROOF_REPLAY after decision checks,
    handler_calls == 0.
12. mission-bound duplicate with rotated snapshot -> SNAPSHOT_MISMATCH first.
13. ledger row cannot be minted by model output / external data (AST boundary
    test on the new module, mirroring the Stage B/C batteries).
14. full-suite regression: no existing test relies on multi-use semantics
    except the Case-15 characterization test, which this change UPDATES (the
    pinned property changes from "multi-use within TTL" to "single-use",
    which is the Owner-approved invariant flip).

## 6. What the Owner is deciding

- Case 15 flips from "deferred" to implemented: proof semantics change from
  single-RUN to single-USE. This is a pure tightening; every existing
  authorization remains valid exactly once.
- Cost: one SQLite write per governed execution; a new small module
  (security/proof_use_ledger.py) + registry insertion point + battery.
- If approved, implementation order: ledger module -> registry consumption
  point -> adversarial battery -> characterization-test update -> CI green ->
  checkpoint. Estimated one focused session.

## 7. Explicitly out of scope

No scheduler/DAG/worker runtime, no B3-C6, no Phase A, no R2, no catalog/
registry changes, no proof payload format change, no TTL change.
