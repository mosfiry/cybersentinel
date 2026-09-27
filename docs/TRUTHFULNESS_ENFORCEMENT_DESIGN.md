# TRUTHFULNESS ENFORCEMENT DESIGN - PHASE T1

Status: DESIGN (T1). Implementation follows in T2 commits on the same branch.
Date: 2026-09-27. Branch: security/truthfulness-overhaul.
Repository state verified before design: HEAD 2c5d2ac2f10 (CI marker for
4d7fdbc3306a, "test (3.13)" succeeded 31s); T0 commits c5afdac61df6,
71ff30420389, 4d7fdbc3306a present on the branch; docs/
TRUTHFULNESS_ENFORCEMENT_AUDIT.md, docs/TRUTHFULNESS_CHECKPOINT.md,
security/truthfulness.py present. Core T0 evidence RE-VERIFIED from source
for this design: agent/mission.py transition() has NO GOAL_COMPLETED guard;
api/chat.py returns the model answer with no truth status; web/app.js
contains x.status||"completed" and the "اكتمل التحليل." fallback;
security/truthfulness.py is_authoritative() is origin-NAME membership only.

--------------------------------------------------------------------------------
## 1. BEFORE CALL GRAPH (OBSERVED)

/api/chat, /api/command (bridge.py, owner session + bridge token)
  -> api/chat.py chat()
     -> AgentCore.run_owner_mission(...)
        -> MissionRuntime loop
           -> model turn (provider/router)
           -> deterministic authorization + registry execution
           -> mission.record_action("completed"|"failed") [system-written]
           -> final model turn:
                progress["last_model_content"] = turn.content
                verification = GoalVerification.evaluate(...)  [deterministic]
                if verification.verified: transition(GOAL_COMPLETED)
                else: transition(READY, "model final lacked evidence")
  -> answer = progress["last_model_content"]
  -> HTTP {answer, status, activity, mission}    <- NO EvidenceStatus anywhere

Weaknesses on this path (= T0 bypasses): B1 no truthfulness caller, B2
name-based authority, B3 caller-supplied CI tuples, B4 unlabeled answer,
B5 evaluate_completion uncalled, B6 substring matching, B7 UI invention,
B8 no API semantics.

## 2. AFTER CALL GRAPH (DESIGNED)

/api/chat, /api/command (bridge.py)
  -> api/chat.py chat()
     -> AgentCore.run_owner_mission(...)
        -> MissionRuntime loop (unchanged execution semantics)
        -> final model turn:
             MODEL OUTPUT (turn.content)
               -> CLAIM EXTRACTION: answer text is by definition
                  source_type=MODEL_OUTPUT -> EvidenceStatus.CLAIMED
               -> EVIDENCE RESOLUTION: the only evidence eligible for
                  completion is the deterministic GoalVerification result plus
                  execution observations recorded by MissionRuntime (system).
               -> PROVENANCE VALIDATION: EvidenceRecord is authoritative ONLY
                  with a valid provenance_token (keyed HMAC minted by
                  SystemEvidenceIssuer, SYSTEM-only boundary). A caller- or
                  model-forged record (name "test_runner"/"ci_runner" without a
                  valid token) is CLAIMED PROVENANCE, never VERIFIED.
               -> TRUTHFULNESS DECISION: mission_truth_payload() derives the
                  machine-readable truth object; the answer stays CLAIMED.
               -> COMPLETION VALIDATION: Mission.transition(GOAL_COMPLETED) is
                  structurally blocked unless mission.verification_state
                  ["verified"] is True (deterministic GoalVerification).
                  MissionStore.save() rejects persisting a GOAL_COMPLETED
                  mission without that state. evaluate_completion(claims,
                  issuer=...) requires exact claim_id gate matching and
                  issuer-verified evidence.
               -> PERSISTENCE / API SEMANTICS: HTTP response gains truth =
                  {mission_status, goal_verified, completion:
                  "COMPLETE"|"NOT_COMPLETE", answer_authority: "MODEL_OUTPUT",
                  evidence_count, missing_criteria}. EVIDENCE_STATUS_SEMANTICS
                  maps every EvidenceStatus to {ok, display, completed} - no
                  serialization path may turn UNVERIFIED into success=true.

## 3. THE 12 DESIGN QUESTIONS

1. Who decides EvidenceStatus? Deterministic system code only:
   classify_claim/verify_*_claim/evaluate_completion (security layer) and
   MissionRuntime/GoalVerification (agent layer). Never the model.
2. Can the model set its own EvidenceStatus? No. Any status it emits is data
   classified by the system; protected statuses without system evidence are
   downgraded to UNVERIFIED/CLAIMED.
3. Accepted evidence: only records minted by SystemEvidenceIssuer with origin
   in TRUSTED_EVIDENCE_ORIGINS AND a valid provenance_token (keyed HMAC over
   origin|kind|payload|commit_sha|created_at).
4. Provenance proof: HMAC-SHA256 with a 32-byte system key stored at
   ~/.cybersentinel-x/evidence_provenance.key (0600, created once by system
   code). The model, HTTP callers, and untrusted sources cannot reach the key
   or the minting path; they can only produce claimed provenance.
5. Real CI verification: verify_ci_claim no longer accepts caller strings. CI
   evidence must be an issuer-minted record (origin=ci_runner,
   kind=workflow_run, payload={workflow_run_id, conclusion, commit_sha}).
   The TRUSTED CI PROVIDER BOUNDARY required to mint such records at runtime
   (e.g., a CI job signing artifacts with a repository secret) DOES NOT EXIST
   in this deployment yet; therefore all CI claims remain UNVERIFIED at
   runtime. No fake implementation is invented; an honest abstraction
   (issuer + record shape) with fail-closed default is provided.
6. Unsupported claims are rejected in classify_claim (downgrade) and in the
   API truth payload (answer_authority=MODEL_OUTPUT, completion=NOT_COMPLETE).
7. COMPLETE prevention: the structural gate in Mission.transition() plus the
   MissionStore.save() invariant. GOAL_COMPLETED without deterministic
   verification raises and cannot be persisted.
8. Evidence states VERIFIED / PARTIAL / UNVERIFIED / CONTRADICTED / MISSING:
   new EvidenceStatus members; EVIDENCE_STATUS_SEMANTICS gives each an API
   meaning; evaluate_completion marks a gate CONTRADICTED when its claim
   status is FAILED/CONTRADICTED, and blocks COMPLETE for PARTIAL/UNVERIFIED/
   MISSING like any non-verified state.
9. API: truth object + semantics mapping (above); status field remains the
   mission state machine value; no path maps a claim to success=true.
10. Frontend: web/app.js fallbacks removed - activity status defaults to
    UNKNOWN, an empty answer renders the server truth (completion/status)
    instead of an invented "completed" string. A regression test forbids the
    old patterns.
11. Completion invariant: GOAL_COMPLETED becomes a state-machine-level
    invariant (transition guard) + persistence invariant (store guard), both
    deterministic and testable from ANY caller (chat, command, tasks, worker,
    direct library use).
12. Canonical completion path: MissionRuntime final-turn ->
    GoalVerification.evaluate -> mission.verification_state["verified"]=True
    -> Mission.transition(GOAL_COMPLETED). Every completion claim in reports
    or APIs is derived FROM that state, never the reverse.

## 4. BYPASS REMEDIATION PLAN (B1-B8)

- B1: wire mission_truth_payload into api/chat.py chat() (used by /api/chat
  and /api/command alike); the completion gate moves from library function to
  state-machine invariant (B1+B5).
- B2: is_authoritative() requires provenance_token; classify/evaluate verify
  via issuer HMAC (claimed vs verified provenance separated).
- B3: verify_ci_claim signature change - caller strings can never verify;
  only issuer-minted ci_runner records can, and none exist at runtime today
  (fail-closed UNVERIFIED).
- B4: answer always labeled answer_authority=MODEL_OUTPUT + truth object.
- B5: see B1; evaluate_completion additionally requires exact gate ids (B6)
  and issuer-verified evidence.
- B7: frontend fallbacks removed + regression test on web/app.js content.
- B8: EVIDENCE_STATUS_SEMANTICS + truth object define API semantics.

## 5. PRESERVED INVARIANTS

Owner authority (server-side password sessions), authorization boundaries,
GoalVerification, VerificationEngine, evidence chain, tool registry, and
MissionRuntime execution semantics are NOT altered; the only agent-layer
change is the two structural guards on GOAL_COMPLETED (transition + store),
which make the EXISTING deterministic rule unavoidable.

## 6. TEST MATRIX (T2)

UNIT: updated test_truthfulness.py (issuer-minted evidence; CI signature).
ADVERSARIAL: forged origins, forged tokens, fake CI tuples, substring-gate
attack, direct status assignment persistence attack, no-issuer completion.
INTEGRATION: Mission.transition guard, MissionStore.save guard,
mission_truth_payload mapping, frontend file regression.
END_TO_END: within repository limits - the chat HTTP path is exercised by
existing bridge smoke tests; the completion path is exercised through the
mission state machine (the same objects the HTTP path drives). Classification
of what could NOT be run end-to-end in this environment will be stated
explicitly in the T2 report.
