# M3 Process-Failure and Concurrency Tests

M3 tests process death at durable state boundaries, then inspects reopened state and proves stale workers cannot resume protected work. Tests that send signals are restricted to harness-owned child processes with disposable temporary databases; no service process or user/runtime database is a target.

## Termination and restart matrix

[`tests/test_v10_process_death.py`](../tests/test_v10_process_death.py) covers the following subprocess boundaries:

| Failure boundary | Recovery assertion |
|---|---|
| SIGTERM before queue claim | No side effect was dispatched; restart recovery remains safe. |
| SIGKILL after claim before mission binding | Partial claim is quarantined; no stale write or dispatch. |
| SIGKILL during a read-only tool slice with an in-flight checkpoint | Interrupted work is not silently replayed under stale execution identity. |
| SIGKILL after external-effect dispatch and before outcome | Durable intent remains ambiguous/recovery-required; no blind retry. |
| SIGKILL after evidence commit | Hash chain and mission receipt remain consistent; no duplicate effect. |
| SIGKILL after terminal mission save before queue acknowledgement | Recovery acknowledges terminal state without re-executing it. |

The same module exercises competing supervised processes, stale-generation rejection, effect ambiguity, and fresh-Owner requirements. Its child identity guard verifies the target is the exact registered test harness before a signal is sent. A transient guard failure in the latest local full-suite run stopped before signal delivery; the isolated test passed and the subsequent full rerun passed. The event and recovery are preserved in [`M3_STATE.md`](M3_STATE.md).

## Multi-worker and fence tests

[`tests/test_v10_multiworker_adversarial.py`](../tests/test_v10_multiworker_adversarial.py), [`tests/test_worker_generations.py`](../tests/test_worker_generations.py), and [`tests/test_execution_fence.py`](../tests/test_execution_fence.py) cover:

- two workers racing for one queue and claiming at most once;
- a second runtime being unable to claim an active slice;
- generation advancement when a logical worker restarts and stale-instance write rejection;
- wrong/missing lease, mission, execution, task/version, authorization, or checkpoint bindings failing before handler invocation;
- mission/evidence receipt rollback when an injected mission write fails; and
- serialized concurrent evidence appends with a valid hash-chain order.

## Graceful stop and health

[`tests/test_runtime_supervisor.py`](../tests/test_runtime_supervisor.py) and [`tests/test_v12_container_runtime.py`](../tests/test_v12_container_runtime.py) exercise startup recovery before polling, bridge request draining, bounded graceful shutdown, database reopenability, exact worker argv/process identity, and rejection of wrong, zombie, stopped, or traced worker processes. The hosted Compose smoke additionally verified bridge/worker health and worker generations advancing through restart and container recreation on a persistent isolated volume.

## End-to-end hosted rehearsal

The final exact-SHA CI rehearsal on `ecd970cbb287d154b0c0ef7635a4d0dffe0991de` ran in an isolated hosted Compose project. It passed the controlled exit-73 crash, persistent `DISPATCHED` marker, same logical worker restart (generation 1→2), `RECOVERY_REQUIRED` quarantine, fresh Owner session and typed reconciliation, no duplicate dispatch, successful completion, graceful exits, and cleanup. See [M3 Cutover Rehearsal](M3_CUTOVER_REHEARSAL.md) and its linked sanitized artifact.

## Test result and limits

The exact-SHA full GitHub suite on `ecd970cbb287d154b0c0ef7635a4d0dffe0991de` passed **1,072 tests with 1 skipped**; compileall and the hosted Compose smoke passed. The Owner Charter audit and dedicated rehearsal also passed. The separate Workers Builds check failed and is not a test-suite result. Local Docker/Compose was unavailable, so actual image/runtime execution is evidenced by hosted CI only.

All subprocess and V16 scenarios use disposable state. The V16 provider router is intentionally empty and fails closed; the rehearsal's single `watch` effect is local. These tests do not prove production monitoring/rollback, multi-host behavior, or exactly-once execution of real external provider calls.
