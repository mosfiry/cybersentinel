# M3 Runtime Contract

This contract describes the implemented mission path, not a general promise about every legacy or external integration. The production mission dispatch path is fail-closed: the bridge authenticates control requests, `MissionService` revalidates live Owner authority before queueing or resuming, and the strict worker/runtime/tool executor require a current `ExecutionFence` before mutation or dispatch.

## Identity and authority

- **Bridge credential:** `BRIDGE_TOKEN` authenticates bridge requests. It is not an Owner identity or approval.
- **Owner identity:** Username/password login creates a server-side session. Mission controls resolve the session and require the expected authentication method and Owner-to-mission binding.
- **Authorization snapshot:** An Owner-authorized mission carries an immutable snapshot of owner, mission, allowed actions/tools, scope, workspace, network/data/credential boundaries, policy version, approval fingerprint, and expiry. Model output, provider data, and repository content do not grant authority.
- **Queue/resume:** `MissionService` requires a configured Owner revalidator and fresh proof before enqueue/resume. Missing or stale proof cannot clear a pause or make the mission claimable. A `RECOVERY_REQUIRED` mission cannot be reauthorized or enqueued before its ambiguous effect is reconciled.
- **Restart:** An interrupted mission is quarantined; it does not regain authorization from the prior process merely because the worker restarts. Sensitive work requires fresh Owner proof.

Source: [`bridge.py`](../bridge.py), [`api/missions.py`](../api/missions.py), [`security/owner_password.py`](../security/owner_password.py), [`agent/agent_core.py`](../agent/agent_core.py), and [`agent/mission.py`](../agent/mission.py).

## Durable worker identity and fence

Each logical `worker_id` receives a durable generation and a unique `worker_instance_id` when registered. Registration atomically advances the generation and supersedes the prior active instance. A fence binds the current worker and instance to the mission, request, claim/lease epoch, task and version, execution/checkpoint, and authorization digest. A reclaimed or superseded worker cannot commit through an older generation, lease, snapshot, or task context.

The strict production path is wired as follows:

1. `bridge.py` constructs `MissionQueue(require_execution_fence=True, mission_store=...)` and `MissionRuntime(require_authorization_snapshot=True, require_execution_fence=True)`.
2. `MissionWorker` registers its generation, performs restart recovery before polling, claims a queue row, and binds that claim to the authoritative mission record.
3. `MissionRuntime` receives the resulting fence; save, checkpoint, evidence, effect reservation, and tool-dispatch paths revalidate it at their mutation boundary.
4. `AgentCore._executor` rejects `None`, asserts an active execution, validates the tool and authorization, and passes the fence to `tools.registry.execute`.
5. The synchronous `AgentCore` facade uses `_run_via_fenced_worker`; the source explicitly keeps it inside the durable worker/runtime path rather than a second `AgentTaskRuntime` core-engine dispatch path.

Source: [`agent/execution_fence.py`](../agent/execution_fence.py), [`agent/mission_worker.py`](../agent/mission_worker.py), [`agent/mission_runtime.py`](../agent/mission_runtime.py), and [`agent/agent_core.py`](../agent/agent_core.py). Adversarial coverage is in [`tests/test_execution_fence.py`](../tests/test_execution_fence.py), [`tests/test_v10_multiworker_adversarial.py`](../tests/test_v10_multiworker_adversarial.py), and [`tests/test_v13_e2e.py`](../tests/test_v13_e2e.py).

## Persistence and evidence

A strict `MissionStore.save` compares the durable mission version and validates the fence within an attached rollback-journal transaction that also holds the queue claim stable. A strict evidence append rechecks the active claim/checkpoint and commits the hash-chain record and mission receipt together. These guarantees apply to the named transactions; they do not create one transaction across all application databases or an external service.

## Startup, health, and shutdown

`RuntimeSupervisor` recovers before entering its running/polling state, observes worker failure, and drains/stops on shutdown. Worker shutdown retires its generation under a fence. The Compose worker health probe requires the exact configured argv for the expected direct child in an accepted active process state. Bridge health is a liveness check, not proof of production readiness.

The container target is non-root and read-only except for the persistent state volume and bounded temporary mount. The bridge listens on its private container interface only with explicit container opt-in, while the host port mapping remains loopback-only by default. See [`compose.yaml`](../compose.yaml), [`Dockerfile`](../Dockerfile), [`scripts/container_entrypoint.sh`](../scripts/container_entrypoint.sh), and [`scripts/worker_healthcheck.py`](../scripts/worker_healthcheck.py).

## Scheduling boundary

Scheduling persists an authorization snapshot binding and validates it at due time; it does not persist a reusable session token or manufacture fresh Owner authority. A missing, expired, mismatched, or revoked Owner proof causes fail-closed quarantine/`NEEDS_INPUT` rather than unattended reauthorization. Recurring/cron execution with a separately delegated live Owner authority is not established by M3.

Tests: [`tests/test_mission_service_owner_revalidation.py`](../tests/test_mission_service_owner_revalidation.py), [`tests/test_v9_scheduled_authorization.py`](../tests/test_v9_scheduled_authorization.py), and [`tests/test_runtime_supervisor.py`](../tests/test_runtime_supervisor.py).

## Explicit limits

M3 proves local and hosted non-production contracts on a single host. It does not prove production authority, multi-host leases, network-filesystem safety, a provider-side exactly-once guarantee, or unattended Owner delegation. The hosted runtime is verified through GitHub Actions; Docker/Compose was unavailable on the local computer during this phase.
