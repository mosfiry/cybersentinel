# Crash Recovery

Mission payloads are stored as JSON in SQLite by `MissionStore`. Before execution, `MissionRuntime` persists an in-flight checkpoint containing step, action ID, status, and plan version. After the tool boundary it persists the completed checkpoint, observation, action history, and evidence.

Action IDs are deterministic for a Mission, plan version, step ID, and step index. Replaying an already completed action advances the Mission without executing it again. If a process crashes while an external action is `in_flight`, the next runtime **does not automatically execute it again**: it transitions to `RECOVERY_REQUIRED` because the side-effect outcome is ambiguous. `MissionRuntime.reconcile_in_flight()` is a runtime method that accepts an outcome recorded by a trusted caller; this repository has no production Owner-authenticated reconciliation route or caller. Absence of a persisted response is not evidence that the effect did not occur. Marking an already-executed effect as `executed=False` can permit a duplicate attempt, so reconciliation must rely on an independently verified receipt. This is a fail-closed automatic-replay boundary, not an at-most-once or exactly-once guarantee. Exactly-once behavior would require an idempotent external tool or a durable external receipt/transaction protocol.

A new `AgentCore` instance can load the Mission and resume it through `resume_mission()` after Owner reauthentication. `/api/chat` accepts `mode=mission` with `mission_id` to use this path.

The legacy `core.lifecycle` and `AgentTaskRuntime` persistence paths remain separate compatibility systems. They are not silently conflated with MissionStore; production migration and cross-store reconciliation remain a future integration task.
