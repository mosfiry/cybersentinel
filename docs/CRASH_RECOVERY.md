# Crash Recovery

Mission payloads are stored as JSON in SQLite by `MissionStore`. Before execution, `MissionRuntime` persists an in-flight checkpoint containing step, action ID, status, and plan version. After the tool boundary it persists the completed checkpoint, observation, action history, and evidence.

Action IDs are deterministic for a Mission, plan version, step ID, and step index. Replaying an already completed action advances the Mission without executing it again. A new `AgentCore` instance can load the Mission and resume it through `resume_mission()` after Owner reauthentication. `/api/chat` accepts `mode=mission` with `mission_id` to use this path.

The legacy `core.lifecycle` and `AgentTaskRuntime` persistence paths remain separate compatibility systems. They are not silently conflated with MissionStore; production migration and cross-store reconciliation remain a future integration task.
