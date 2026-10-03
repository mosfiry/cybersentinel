# V11 Owner Cutover and Recovery Contract

**Status: BLOCKED / OWNER DECISION REQUIRED.** This note records the current source boundary and the decisions required before anyone can safely implement Owner-controlled recovery. It is not an authorization to reconcile an external effect, retry a tool call, release a quarantined mission, or change the Owner identity model.

## Current implemented boundary

The bridge resolves a server-side Owner session and requires the username/password authentication method for mission actions. The session record includes the Owner ID, username, session ID, method, and expiry, and the service requires fresh typed Owner evidence before starting or resuming an eligible mission (`bridge.py:76-80,89-97,268-285`; `security/owner_password.py:165-211`; `api/missions.py:84-111`). The HTTP mission routes expose start, resume, pause, cancel, and schedule, but no reconciliation action (`bridge.py:268-297`).

A critical mismatch remains below that route boundary. `MissionRuntime.reconcile_in_flight()` accepts a bare `executed` boolean and optional unverified observation. When `executed=True`, it can synthesize a successful `external_reconciliation` observation; when `executed=False`, it marks the checkpoint `reconciled_not_executed` and returns the mission to `READY` (`agent/mission_runtime.py:193-239`). This method does not verify a provider receipt, a negative-effect proof, or an Owner-signed recovery decision. The mission service currently refuses to queue a `RECOVERY_REQUIRED` mission before and after Owner revalidation (`api/missions.py:84-111`), and V8/V9 keep unknown work quarantined and non-claimable (`agent/mission_worker.py:136-174,345-408`; `tests/test_v8_recovery_quarantine.py:11-42`; `tests/test_v9_crash_injection.py:45-85,210-274`). Preserve those guards.

Owner authentication evidence binds method, timestamps, proof fingerprint, request ID, session ID, and nonce, but its HMAC verifier uses a random process-local key and evidence has a five-minute lifetime (`security/owner_policy.py:20-22,67-99,245-253`). That mechanism is suitable for fresh request-bound checks in the current process; it is not a durable, restart-verifiable recovery attestation. The mission stores a request ID, Owner reference, policy/authorization snapshots, provenance, and an untyped `recovery_events` list, not a versioned recovery-decision record (`agent/mission.py:66-82`). A hashed, time-limited authorization snapshot binds mission/Owner/target/scope, but it is not evidence that an external effect did or did not occur (`security/mission_authorization.py:27-118`).

## Decisions required before implementation

The following points remain unresolved. They must be decided before adding a recovery route, transitioning an ambiguous mission to `READY`, or permitting replay:

- **Who may decide:** whether recovery requires the same Owner identity bound to the mission or another explicitly authorized principal, and what fresh authentication is required after a restart or session revocation.
- **What proves an outcome:** what external receipt proves `EXECUTED`, what independent evidence can prove `NOT_EXECUTED`, and whether an Owner attestation alone may ever suffice. If neither outcome is proven, the mission must remain `UNKNOWN` and quarantined; do not retry.
- **What the decision binds:** at minimum, the mission and request IDs, action/tool-call IDs, immutable intent digest, Owner identity, authorization snapshot hash/version, attempt and provider idempotency/receipt identifiers, and current mission/queue fence. The accepted fields and verifier are not defined here.
- **How evidence survives and resists replay:** define durable verification-key custody/rotation, decision expiry, nonce or monotonic decision version, and a persistent anti-replay/audit record. Do not persist the current ephemeral HMAC key or weaken verification as an expedient.
- **How state changes commit:** define a crash-safe ordering or idempotent transaction for decision evidence, mission checkpoint/status, queue release/re-enqueue, and the external-effect barrier. Mission, queue, and evidence stores are separate; the V4 Mission/Queue atomicity decision remains blocked.
- **What cutover means:** define which Owner authority and policy version remain valid for work authorized before a cutover, including how revocation, expiry, and already-in-flight work are handled.

## Safe behavior until the gate is resolved

Keep ambiguous missions in `RECOVERY_REQUIRED` and their queue rows in non-claimable `WAITING_FOR_TOOL`; do not make a direct runtime reconciliation call, expose a recovery endpoint, synthesize an observation, or replay a provider/tool call. Do not change the per-process evidence key, Owner identity reference, queue/mission transition, or external-effect contract to guess the missing authority. This preserves the existing V8/V9 quarantine while allowing independent V12 provider/model-boundary work to continue.

V11's safe deliverable is this decision-gate document and its architecture/state record only. Runtime behavior is unchanged; the phase remains **BLOCKED / OWNER DECISION REQUIRED** until the missing trust and cutover choices are supplied through the controlling mission authority.
