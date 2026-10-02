# LEASE FENCING MODEL — Phase V4 (design, then implementation)

Baseline: vibe/principal-engineering @ 165706dba48 (agent/mission_worker.py blob
2b48dc75eb1c4ca9b98f28139c3a2ec944b4d57d, 20,346 bytes, verified byte-exact via
dual-channel fetch: raw+wrap-repair === contents-API base64).

## 1. Verified current model (source-grounded)

MissionQueue (agent/mission_worker.py):

- claim_next (line ~102): BEGIN IMMEDIATE; claims only when lease_expires_at IS NULL
  OR <= now; sets lease_owner=worker_id, lease_expires_at=now+lease_seconds.
  Ownership key = worker_id STRING. No lease epoch/generation exists.
- update (line ~114): with worker_id → WHERE lease_owner=? AND state=EXECUTING
  (terminal) or WHERE lease_owner=? (non-terminal). NO expiry predicate.
- release (line ~129): WHERE lease_owner=? AND state=EXECUTING. NO expiry predicate.
- heartbeat (line ~139): WHERE state=EXECUTING AND lease_owner=?. NO expiry
  predicate → an EXPIRED lease can be re-extended by its stale holder.
- recover_expired (line ~149): clears owner/expiry for expired EXECUTING rows.
- recover_after_restart (line ~156): clears owner/expiry for active rows.
- run_once (line ~193): heartbeat lambda passes only worker_id; update/release
  calls pass no clock argument (non-deterministic against frozen test clocks).

## 2. Confirmed gaps (each maps to the exact predicate above)

G1 — heartbeat does not reject an expired lease: a stale worker can re-extend
     an expired-but-unreclaimed lease indefinitely (heartbeat WHERE clause).
G2 — update/release do not validate expiry at commit time: a stale worker
     whose lease expired (but nobody reclaimed yet) can still write outcomes.
G3 — no lease epoch: fencing is keyed by worker_id string; two claim epochs of
     the same worker identity are indistinguishable, so a stale coroutine of
     worker A can write during A's own LATER claim epoch.
G4 — recover_expired / recover_after_restart clear ownership but do not
     advance a fencing token; combined with G3 there is no monotonic barrier.
G5 — run_once does not thread its clock into commit-time writes.

## 3. Exactly-once claims (honest classification)

A. Exactly-once INTERNAL state transition: provable per mission for queue
   state (PRIMARY KEY mission_id + owner+epoch+expiry predicates) and for
   mission persistence (integrity_hash compare-and-swap, stale write rejected
   — agent/mission.py store). VERIFIED mechanism; battery to be extended.
B. Exactly-once EXTERNAL side effect: NOT provable and NOT claimed. Once an
   external operation starts, the system cannot prove it did not complete.
C. At-least-once execution: the real guarantee for re-dispatch after lease
   expiry/restart (attempts increment on claim).
D. Ambiguous external execution: MUST surface as RECOVERY_REQUIRED
   (mission-level, transition guard verified in V3) or queue WAITING_FOR_TOOL
   with reconciliation error — never silently SUCCESS/FAILED.

## 4. Fencing design (minimal, fail-closed, backward compatible)

F1 — lease_epoch column (INTEGER NOT NULL DEFAULT 0) added to mission_queue;
     QueueItem gains lease_epoch. claim_next sets lease_epoch = lease_epoch+1
     atomically inside the BEGIN IMMEDIATE claim. The epoch is the fencing
     token: monotonically increasing per mission.
F2 — heartbeat: WHERE ... AND lease_owner=? AND lease_expires_at > now
     (rejects re-extension of an expired lease — closes G1) and, when the
     caller supplies its claim epoch, AND lease_epoch=? (closes G3 for the
     same-worker-identity case).
F3 — update/release with worker_id: add lease_expires_at > now (commit-time
     validation — closes G2) and optional lease_epoch=? match.
F4 — recover_expired and recover_after_restart advance lease_epoch by one when
     clearing (closes G4): any writer still holding the pre-recovery epoch is
     rejected even if the worker_id string later matches again.
F5 — run_once threads its clock (now) and item.lease_epoch into every
     heartbeat/update/release call (closes G5, restores determinism).
F6 — Backward compatibility: all new parameters are optional; legacy callers
     that pass only worker_id receive the strictly stronger owner+expiry
     check. No other module changes required (LeaseLostError is referenced
     only inside mission_worker.py — verified by repository-wide code search).

## 5. Failure-convergence argument (why fail-closed is safe)

- Worker completes mission but lease expired mid-run: store write already
  succeeded (or is rejected by its own CAS); queue write raises LeaseLostError;
  queue row remains EXECUTING → recover_expired requeues (epoch advanced) →
  next claim loads the persisted mission → maps to COMPLETED once. The
  GOAL_COMPLETED persistence invariant (V3) prevents duplicate completion.
- Worker crashes after external effect, before persistence: mission stays
  non-terminal; exception path releases to WAITING_FOR_TOOL with
  "ambiguous in-flight execution requires reconciliation" (existing source)
  or the lease simply expires → requeue. Nothing is auto-marked SUCCESS.
- Late heartbeat from a stale epoch after re-claim: rejected (F2).

## 6. Test matrix (deterministic, frozen clock; tests/test_lease_fencing.py)

1  A claims (epoch e1)
2  A stops; lease expires
3  expiry observed (recover_expired → epoch e1+1)
4  B claims (epoch e2 = e1+2)
5  A update/release/heartbeat with (A, e1) → LeaseLostError (all three)
6  queue outcome untouched by A
7  A late heartbeat on expired-but-unreclaimed lease → LeaseLostError (F2)
8  A update on expired-but-unreclaimed lease → LeaseLostError (F3)
9  A begins external effect (simulated), lease lost, B claims
10 A's commit attempt fails; no completion recorded
11 queue state remains owned by B; mission truth untouched by A
12 A's result unknown → system does NOT claim completion (no write path)
13 recovery path: requeue happens only via recover_expired/restart
14 RECOVERY_REQUIRED release semantics preserved (existing test keeps passing)
15 retry: attempts increment; duplicate delivery does not double-claim
16 crash after side effect before persistence → WAITING_FOR_TOOL/requeue, not FAILED-as-fact
17 crash after persistence before ack → stale ack rejected; requeue converges to COMPLETED once
18 restart: recover_after_restart advances epoch (F4)
19 concurrent claim_next at identical now → exactly one winner
20 same worker_id re-claims (epoch changes) → stale epoch write rejected (G3 closure)

## 7. Explicitly NOT claimed

- Exactly-once external side effects (impossible to prove; classified D).
- Any change to MissionStore semantics (its CAS invariant is already verified).
- Any desktop/backend contract change (queue internals are not public surface).
