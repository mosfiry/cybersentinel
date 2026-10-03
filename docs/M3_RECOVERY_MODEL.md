# M3 Recovery Model

Recovery preserves ambiguity instead of guessing. A worker restart can restore a process, but it cannot prove that a provider-side action did or did not happen, and it cannot restore expired Owner authority. The runtime therefore separates ordinary pre-dispatch interruption, completed effects, and ambiguous in-flight effects.

## Claim and execution lifecycle

1. The authenticated Owner request is revalidated; the mission is stored with an integrity-bound authorization snapshot before it is enqueued.
2. A registered worker generation claims a queue row under a lease. The claim is bound to the mission record before execution. A fence carries the worker instance/generation, lease epoch, mission/request, task/version, execution/checkpoint, and authorization digest.
3. Before each execution slice and side effect, the current checkpoint and fence are checked again. Stale workers cannot save mission state, append evidence, reserve/dispatch effects, or invoke the fenced executor.
4. Mission state, queue claim metadata, evidence, scheduling state, and effect state use durable SQLite files. Selected cross-file mutations use attached rollback-journal transactions; see [M3 Architecture](M3_ARCHITECTURE.md) for the precise boundaries.

## Crash outcomes

| Interruption point | Durable interpretation | Recovery behavior |
|---|---|---|
| Before a claim or before a side effect is reserved | No authorized dispatch is recorded | A later claim may proceed only after normal Owner, queue, and fence checks. |
| After claim but before mission claim binding completes | Claim is incomplete | Startup recovery quarantines or safely releases it; the partially bound state cannot dispatch. |
| During an in-flight read-only slice | Execution checkpoint is uncertain | Recovery records the interrupted execution and does not let an old generation overwrite it. Fresh authority is required before protected continuation. |
| After effect reservation/dispatch, before outcome is durable | Effect outcome is ambiguous | Ledger/mission become recovery-required; no automatic replay. The queue waits for reconciliation. |
| After evidence is committed | Hash-chain evidence and mission receipt remain linked | Recovery verifies integrity and does not duplicate the already-committed evidence/effect. |
| After terminal mission save but before queue acknowledgement | Mission terminal state is authoritative | Recovery acknowledges completion without re-executing the terminal mission. |

The exact state depends on the last durable transition. In particular, an effect left `DISPATCHED`, `UNKNOWN`, `AMBIGUOUS`, or `RECOVERY_REQUIRED` is not treated as a retryable failure.

## Quarantine and Owner reauthorization

Restart registers a new `worker_instance_id` and higher durable generation under the same logical worker ID. The old generation is superseded and cannot write. In-flight effects are preserved for reconciliation; interrupted nonterminal work is not resumed with stale authorization. An Owner must establish a fresh live session and renew the mission authorization snapshot before normal execution resumes. Historical authorization snapshots are retained so an effect is matched to the snapshot active at the effect's creation time; missing or malformed history fails closed.

Owner reconciliation is allowed only when the worker lease is quiescent and the exact mission, effect, task/execution checkpoint, Owner identity, action, and evidence binding validate. `OWNER_CONFIRM_APPLIED` or `OWNER_CONFIRM_NO_EFFECT` is explicit and audited. A no-effect retry is policy-gated; an applied result is terminal evidence and is not dispatched again. Reconciliation does not infer missing legacy Owner bindings.

Source: [`agent/runtime_supervisor.py`](../agent/runtime_supervisor.py), [`agent/mission_worker.py`](../agent/mission_worker.py), [`agent/mission.py`](../agent/mission.py), [`agent/effect_reconciliation.py`](../agent/effect_reconciliation.py), and [`api/missions.py`](../api/missions.py).

## Verification

- Real child-process termination cases use test-owned children and disposable `tmp_path` databases: [`tests/test_v10_process_death.py`](../tests/test_v10_process_death.py).
- Claim races, superseded workers, and stale-generation rejection: [`tests/test_v10_multiworker_adversarial.py`](../tests/test_v10_multiworker_adversarial.py), [`tests/test_worker_generations.py`](../tests/test_worker_generations.py), and [`tests/test_execution_fence.py`](../tests/test_execution_fence.py).
- Owner restart/revalidation and no-replay behavior: [`tests/test_v8_recovery_quarantine.py`](../tests/test_v8_recovery_quarantine.py), [`tests/test_mission_service_owner_revalidation.py`](../tests/test_mission_service_owner_revalidation.py), [`tests/test_external_effect_ledger.py`](../tests/test_external_effect_ledger.py), and [`tests/test_effect_reconciliation.py`](../tests/test_effect_reconciliation.py).
- End-to-end local-bridge and exact hosted crash/restart proof: [`tests/test_v13_e2e.py`](../tests/test_v13_e2e.py) and [M3 Cutover Rehearsal](M3_CUTOVER_REHEARSAL.md).

The V16 artifact records the controlled crash after durable dispatch (exit 73), generation advance 1→2, `RECOVERY_REQUIRED` quarantine, one dispatch and effect, fresh same-Owner session, one Owner-applied event, completion, graceful shutdown, and clean resource removal. It proves the isolated local `watch` test effect only. It does not prove that an interrupted real external provider action occurred zero or one times, and it is not production deployment evidence.
