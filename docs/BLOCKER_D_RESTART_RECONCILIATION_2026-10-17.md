# Blocker D: mission preflight persistence and restart verdict

## Verdict

The available evidence does **not** prove a MissionStore persistence or recovery defect for the Windows AppContainer preflight rejection. It shows two different Missions in the previous Windows run (`39002439803`), which must not be conflated:

1. The installed-desktop restart fixture was paused immediately after Mission creation, before its worker began execution.
2. The separate source-tree full-E2E fixture did reach `run_project_tests`; its Windows sandbox preflight rejection was recorded as `RESOURCE_BLOCKED` with `not_dispatched` and `process_started=false`.

No synthetic attempt/failure record is appropriate for the first Mission: no tool proposal or preflight attempt occurred there. The acceptance verdict remains **FAIL** because the installed mission produced no execution/evidence/result, and the full-E2E mission did not complete the requested project-test step. Missing or corrupt records continue to fail closed. No production behavior or reconciliation requirements were weakened.

The report directory for `39003631333` is not present on this computer, so the detailed forensic comparison below uses the available `39002439803` artifacts and the run facts supplied with the review request.

## Evidence and cause

### Installed desktop restart fixture

`/workspace/cyber-incident-evidence-39002439803/new/desktop-ui-acceptance.json` reports, before restart:

- `mission_status=READY`, `queue_state=paused`, `pause_requested=true`;
- exactly two timeline events (`MissionStarted`, `PlanCreated`);
- zero evidence records; and
- execution-chain status `NOT_PRESENT`.

After restart it reports `OWNER_REAUTH_REQUIRED` / `needs_input`, still with the same two timeline events, zero evidence, and no execution chain. This is consistent with a newly created, never-run Mission being quarantined for Owner reauthorization; it is not evidence that a preflight failure record was lost.

The sequence in `scripts/windows_desktop_acceptance.py::_installed_app_mission` creates the Mission and then posts `/pause` immediately. It does not wait for a worker claim, model turn, tool proposal, authorization decision, or preflight result before taking the restart snapshot. Consequently there is no actual attempt for that Mission to persist. The restart reconciliation correctly refuses to treat missing report/chain/evidence as proof of a completed or successfully restored operation.

### Source-tree full-E2E sandbox rejection

The separate `source_tree_e2e_supplemental` result in `new/installer-acceptance.json` records the Windows AppContainer backend as unimplemented and the project-test call as rejected before process dispatch/start. Its Mission snapshot reports `RESOURCE_BLOCKED`, `checkpoint.status=not_dispatched`, `dispatch_attempted=false`, `process_started=false`, and a bound `PROCESS_SANDBOX_UNAVAILABLE` failure diagnosis. This is the real preflight attempt; it is separate from the `READY` desktop-restart Mission above.

`MissionRuntime.run_slice` and the model-turn process-sandbox preflight path persist the structured resource failure and `not_dispatched` checkpoint before returning. Both now attach a deterministic `attempt_id` that includes an explicit `attempt_source` (`mission_slice` or `model_turn`) and the integrity-covered Mission/request identity plus the identifiers available to that path. A `mission_slice` record has empty run/turn IDs and one bound action/step history record; a `model_turn` record requires non-empty run/turn IDs and a proposal for every blocked tool-call ID. The identity and truthful negative flags are copied into the failure, checkpoint, `FailureDetected`, `FailureDiagnosed`, and `RESOURCE_BLOCKED` transition records; `MissionStore` covers the complete Mission with its integrity hash. Regression tests close and reopen the SQLite store, verify Mission/Owner/scope and attempt bindings, and prove that a terminal `RESOURCE_BLOCKED` Mission cannot be replayed into success. The tests also cover strict restart quarantine when the MissionStore row is missing or malformed.

The restart validator recomputes and verifies `attempt_id`, then requires Mission/request/source and blocked call/action/step bindings to agree across checkpoint, failure, `FailureDetected`, `FailureDiagnosed`, and the terminal transition. It matches optional singular checkpoint action/step IDs to the attempt lists; `mission_slice` requires exactly one matching failed action-history entry, while `model_turn` requires none. For model turns, every `ToolProposed` record must bind to the same Mission/request/run/turn/plan and exact call/action/step IDs, with no missing or duplicate proposals. Evidence from the status payload must match the evidence endpoint, carry Mission-bound provenance, and contain no reference to the blocked attempt/action/step/call; unrelated earlier, provenance-bound evidence may remain. Duplicate or contradictory records, including positive process-start markers, fail closed. Legacy or incomplete snapshots are never upgraded by inference. The validator separately checks the persisted Owner authorization snapshot, scope snapshot ID, target, workspace-only scope, and empty network/credential allowlists rather than manufacturing identifiers or events.

## Acceptance-harness correction under review

The installed-app harness previously posted `/pause` immediately after receiving the new Mission ID. It now waits within the existing 300-second bound for one of two explicit restart bases: (1) a valid, Mission-bound durable execution-chain record, or (2) a terminal, integrity-checked `RESOURCE_BLOCKED` AppContainer preflight record with `dispatch_attempted=false`, `process_started=false`, `process_start_confirmed=false`, a matching diagnosed failure, no completion event, a stable Owner/scope binding, and a terminal queue state. If neither basis appears, it pauses only for containment, records `NOT_RUN`/`BLOCKED`, and does not restart or resume that Mission.

The polling candidate snapshot includes the evidence array returned in Mission status so the provisional preflight probe can recognize a candidate. That candidate does not itself authorize restart: it only triggers `_mission_audit_snapshot`, which reloads the independent evidence endpoint and requires exact equality with status evidence before the full snapshot can become the restart basis. For a terminal preflight block, the existing terminal restart callback runs with inference disabled; it does not pause or resume the Mission. The post-restart check retains Owner reauthentication and exact reconciliation requirements.

The AppContainer-preflight route is only a **restart/reconciliation verdict**, reported as basis `VERIFIED` and never as Mission success. It compares Mission, request, Owner/scope, attempt ID/source, checkpoint, failure, transition, timeline, action history, evidence, and any Mission-bound execution-chain hashes after application restart and Owner reauthentication. Its validator requires all three negative process flags to agree across the durable records, binds model proposals and checkpoint IDs to the attempt, and rejects any evidence attributed to that blocked call/action/step. It rejects duplicate records and recursively scans action history (including root-level and nested normalized data) for positive process-start markers; a contradiction in any action record fails closed. A missing report is tolerated only for an HTTP 404 on a `RESOURCE_BLOCKED` Mission snapshot; the generic report/execution-chain reconciliation remains unchanged and strict. The preflight paths persist `dispatch_attempted=false`, `process_started=false`, and `process_start_confirmed=false` only when their actual pre-dispatch rejection has been observed. The final acceptance still requires `GOAL_COMPLETED`, verified project-test execution, evidence, report, approvals, and both restart cycles, so `READY` or `RESOURCE_BLOCKED` cannot pass the mission gate.

Both record producers also persist `kind` in the checkpoint and terminal transition. The restart validator uses a fixed reason-to-kind mapping (`backend_unavailable` → `PROCESS_SANDBOX_UNAVAILABLE`; `sandbox_setup_failed` → `PROCESS_SANDBOX_SETUP_FAILED`) rather than independently accepting values from two allowlists.

All set-membership checks in the preflight and restart-validation paths type-check untrusted status, kind, attempt-source, event, chain-state, and action/step identifiers before membership. Integrity-consistent malformed list values fail closed as `BLOCKED`/`False` instead of raising `TypeError`.

The acceptance-harness regressions use a real persisted Owner scope and actual `MissionRuntime.run_slice` and native model-turn preflight failures. They reopen the MissionStore and verify source/attempt bindings; they also re-sign tampered test snapshots to check contradictory checkpoint action/step IDs, missing action history, evidence linked to a blocked action/step, status/evidence-endpoint disagreement, empty model run/turn IDs, mismatched or missing/duplicate proposals, unexpected model-turn action history, expanded scope, invalid chains, duplicate/contradictory failures and diagnoses, positive process-start flags, and untouched `READY` states. Additional cases cover unhashable attempt source, failure kind, execution-chain status, action/step IDs, plan step IDs, and timeline event names. A separate native model-loop regression verifies that its persisted pre-dispatch failure and explicit negative dispatch/process flags survive store reopen and model replacement without dispatch. These are regression fixtures only; they do not claim a live Windows execution or successful project-test evidence.

## Guardrails retained

- An untouched `READY` Mission remains subject to `OWNER_REAUTH_REQUIRED` after restart and is not auto-resumed.
- A terminal `RESOURCE_BLOCKED` Mission remains blocked; it is never treated as `GOAL_COMPLETED` and its failed preflight is not represented as process start, evidence, or completion.
- Restart reconciliation still requires integrity-checked, Mission-bound sources. `NOT_PRESENT`, missing, malformed, or corrupt evidence/report sources do not become valid merely because Owner reauthentication occurred.
- The Scope/Owner bindings are asserted across MissionStore reopen in the preflight regression test; no scope is broadened and no tool is authorized by recovery.

## Required follow-up for a passing Windows acceptance run

The installed-app acceptance gate must exercise a real Mission lifecycle rather than pausing immediately after creation. A Windows run must observe an actual model/worker execution attempt, persist the resulting evidence or the truthful terminal preflight block, restart the installed app, reauthenticate the same Owner, and verify exact state restoration without automatic resume. If AppContainer remains unimplemented, the preflight-record reconciliation may verify that the failure record survived, but the overall project-test Mission must still fail. Until a live Windows run executes the bounded project tests and all required evidence/results are independently verified, preserve the failing acceptance verdict.

## Verification and branch status

- Full test suite: **2,132 passed, 28 skipped** (4 existing multiprocessing `fork` deprecation warnings; exit code 0).
- Secret scan, `compileall`, and diff hygiene: **PASS**.
- Independent read-only review: **no blocking findings**. It suggested an additional local integration test for the terminal callback; the Windows CI run on the exact SHA will exercise the installed-app path.
- CI on the exact pushed SHA: **pending** and must be reviewed before the coordinator considers merge.
- All changes remain on `fix/blocker-d-review-20261010`; `main` and `v5.1.0` remain unchanged.
