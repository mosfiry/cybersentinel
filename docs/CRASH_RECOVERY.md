# Crash Recovery

Mission payloads are stored as JSON in SQLite by `MissionStore`. Before execution, `MissionRuntime` persists an in-flight checkpoint containing step, action ID, status, and plan version. After the tool boundary it persists the completed checkpoint, observation, action history, and evidence.

Action IDs are deterministic for a Mission, plan version, step ID, and step index. Replaying an already completed action advances the Mission without executing it again. If a process crashes while an external action is `in_flight`, the next runtime **does not execute it again**: it transitions to `RECOVERY_REQUIRED` because the side-effect outcome is ambiguous. The operator or an external receipt reconciler must call `MissionRuntime.reconcile_in_flight()` and record whether the action executed before the Mission may continue. This is the safe at-most-once boundary; exactly-once behavior requires an idempotent external tool or a durable external receipt/transaction protocol.

A new `AgentCore` instance can load the Mission and resume it through `resume_mission()` after Owner reauthentication. `/api/chat` accepts `mode=mission` with `mission_id` to use this path.

The legacy `core.lifecycle` and `AgentTaskRuntime` persistence paths remain separate compatibility systems. They are not silently conflated with MissionStore; production migration and cross-store reconciliation remain a future integration task.
