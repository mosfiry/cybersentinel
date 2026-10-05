# Mission and Task Scheduling

The canonical execution path remains `MissionStore`, `MissionQueue`, the worker, and `MissionRuntime`. It persists leases/checkpoints, revalidates Owner authorization, fences effects, and quarantines ambiguous in-flight work rather than replaying it automatically.

`AgentCore` now opts into a `MissionTaskGraphAdapter` for new and resumed missions. It maps existing plan steps into a deterministic dependency graph and gates each MissionRuntime dispatch on a current, authorized ready node. Graph state is embedded in the integrity-covered Mission payload; claim/completion updates are persisted with Mission checkpoints and action history. The adapter runs one coordinator task at a time by default. It does not create independent agents, parallel workers, or a second MissionQueue. See [Mission-Atomic Task-Graph Dispatch](MISSION_TASK_GRAPH_DISPATCH.md).

The standalone `TaskGraphStore` persists owner-bound graph revisions for domain use, but it is not used as a separate graph transaction in canonical MissionRuntime dispatch. Recurring/unattended schedules, multi-host high availability, coordinated backup across mission databases, scheduler list/get/update/delete UI/API, and Windows acceptance are not established. Preserve conservative recovery: graph readiness alone is never grounds to replay a task with an ambiguous effect.
