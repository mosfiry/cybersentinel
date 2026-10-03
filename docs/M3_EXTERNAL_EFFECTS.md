# M3 External Effects and Reconciliation

An external effect has its own durable write-ahead record because a process can fail after the provider has acted but before CyberSentinel records the result. M3 makes that ambiguity visible and non-replayable by default; it does not claim that a local database transaction can atomically commit with a remote provider.

## Ledger contract

The ledger records a deterministic effect identity bound to the mission/task/execution/request, Owner identity, provider and operation, immutable argument/target digests, and current worker/fence context. It persists intent before handler invocation, records dispatch identity and append-only transition events, and rejects identity/input changes or repeated dispatch for the same execution. Raw credentials are not ledger identity, and reconciliation/audit evidence is bounded and digest-bound rather than used as a source of authority.

The lifecycle distinguishes planned/reserved work from `DISPATCHED`, `SUCCEEDED`, `FAILED`, `UNKNOWN`/`AMBIGUOUS`, and `RECOVERY_REQUIRED` outcomes. Any uncertain post-dispatch result stays quarantined. A generic exception or lost response is not treated as proof that no effect occurred. Failure can be made retryable only when the system has explicit evidence that dispatch did not take effect and the policy allows a retry.

Source: [`agent/external_effects.py`](../agent/external_effects.py); focused checks: [`tests/test_external_effect_ledger.py`](../tests/test_external_effect_ledger.py).

## Reconciliation contract

Reconciliation is not an automatic retry loop. It requires an exact persisted effect and mission binding, current Owner identity, a matching authorization snapshot that was active when the effect was created, exact task/execution/checkpoint evidence, and no live worker lease that could race the decision. Invalid, absent, stale, or mismatched evidence fails closed.

Two sources of resolution are supported by the implementation:

- **Provider observation:** a configured adapter may return a typed observation bound to the effect, operation, argument digest, dispatch identity, and idempotency context. The adapter's verification contract must establish provenance. Missing adapters, malformed responses, invalid proofs, or `UNKNOWN` keep the effect quarantined.
- **Explicit Owner decision:** the authenticated control plane accepts the exact typed `OWNER_CONFIRM_APPLIED` or `OWNER_CONFIRM_NO_EFFECT` action, bound to the Owner session, effect, mission/checkpoint, and evidence digest. The outcome is durably audited and idempotent for the same result. A no-effect retry remains policy-gated. A fresh Owner revalidation is still required before a quarantined mission is resumed.

Source: [`agent/effect_reconciliation.py`](../agent/effect_reconciliation.py), [`api/missions.py`](../api/missions.py), and [`tests/test_effect_reconciliation.py`](../tests/test_effect_reconciliation.py).

## Atomicity and delivery limits

Ledger intent and ledger transition writes are fenced and transactionally durable within their database. They are **not** one universal transaction with the mission, scheduler, task-state, evidence, or a real provider. Strict evidence has a separate attached transaction with mission receipt and queue state; mission claim and scheduling handoff have their own documented attached transactions. No external provider call is inside those transactions.

Accordingly, the verified guarantee is **no blind replay of ambiguous recorded effects**, not exactly-once delivery to a real provider. Provider-side idempotency is optional/adapter-specific; this session has no evidenced live production provider receipt, provider-side idempotency contract, or live-provider outcome test. V13 and V16 deliberately block provider invocation and use only the local `watch` effect. The hosted one-dispatch result demonstrates the local effect ledger and recovery protocol, not generic real-provider behavior.

Legacy rows without an immutable nonempty Owner identity or required authorization history fail closed. No Owner identity is derived and no database repair/migration was performed. Any repair needs its own authorized migration decision.

## Evidence

- Durable pre-dispatch intent and no replay after simulated process death: [`tests/test_external_effect_ledger.py`](../tests/test_external_effect_ledger.py).
- Provider typed verification, invalid/unknown outcomes, lease quiescence, Owner binding, idempotency/audit, and legacy-row fail-closed tests: [`tests/test_effect_reconciliation.py`](../tests/test_effect_reconciliation.py).
- Full mission lifecycle, controlled crash, fresh Owner session, one `OWNER_CONFIRMED_APPLIED` event, and no duplicate local dispatch: [`tests/test_v13_e2e.py`](../tests/test_v13_e2e.py) and the exact hosted evidence in [M3 Cutover Rehearsal](M3_CUTOVER_REHEARSAL.md).
