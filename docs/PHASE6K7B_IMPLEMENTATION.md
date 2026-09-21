# Phase 6K.7B — Mission Runtime Audit and Implementation

## Repository before

The work started from commit `e684cee` on `main`, with a clean working tree and 248 passing tests. The existing repository had a durable SQLite-backed `Task` and `AgentTaskRuntime`, typed planning primitives in `agent/planning.py`, and a deterministic authorization/tool firewall. The audit found that these pieces were not a Mission abstraction and were not integrated as one autonomous long-horizon loop.

## Audit findings before this phase

| Requirement | Before | Finding |
|---|---:|---|
| Durable state after HTTP request | Partial | Tasks were persisted, but no Mission entity existed. |
| Process restart resume | Partial | Task storage and resume state existed, but no Mission checkpoint protocol existed. |
| Autonomous execution loop | Partial | `AgentTaskRuntime.run_slice()` existed, but it was a task/tool loop rather than a Mission lifecycle. |
| Observation to next decision | Partial | Tool results entered task context, but no Mission observation drove recovery/replanning. |
| Replanning integration | No | `Plan.replan()` was a standalone primitive and was not called by runtime. |
| Goal verification gate | No | `GoalVerification` existed as a standalone value and did not prevent runtime completion. |
| Recovery integration | No | `RecoveryPolicy` existed as a standalone value and was not connected to execution. |
| Owner intervention | Partial | Task authorization existed, but there was no persisted Mission waiting state and resume decision. |

## Repository after

This phase adds a persistent Mission layer without replacing the existing Task or changing the authorization hierarchy:

- `agent/mission.py` — durable Mission model, lifecycle statuses, action history, observations, evidence, plan history, checkpoint, and SQLite store.
- `agent/mission_runtime.py` — bounded Mission loop with authorization gate, action execution, structured observation persistence, failure classification, recovery, replanning, verification, idempotency, owner intervention, and restart-safe slices.
- `tests/test_phase6k7b_mission_runtime.py` — five integration tests covering end-to-end failure/replan/verification, a new runtime instance after simulated crash, verification blocking, owner deny/allow, and duplicate action prevention.

## Mission lifecycle

```text
CREATED
  -> PLANNING
  -> READY
  -> RUNNING
  -> OBSERVING
  -> READY
  -> VERIFYING
  -> GOAL_COMPLETED
```

Failure and intervention terminals are explicit:

```text
OWNER_INPUT_REQUIRED
AUTHORIZATION_BLOCKED
SCOPE_BLOCKED
RESOURCE_BLOCKED
SAFETY_BLOCKED
FAILED_RETRY_EXHAUSTED
CANCELLED
```

A Mission is stored as JSON in SQLite. The HTTP request is not its lifetime. A new `MissionRuntime` instance can load the Mission and continue from its checkpoint.

## Actual execution path

```text
MissionRuntime.create()
  -> MissionStore.save()
  -> run_slice()
  -> load persisted Mission
  -> enforce iteration budget
  -> choose current PlanStep
  -> derive stable action_id
  -> authorization gate
  -> persist in-flight checkpoint
  -> execute callback/tool boundary
  -> create structured observation
  -> persist observation and action history
  -> classify success/failure
  -> retry, replan, block, or continue
  -> verify required criteria
  -> persist terminal state
```

The stable action identifier is derived from mission ID, plan version, step ID, and step position. Completed action IDs are not executed a second time.

## Actual authorization path

A step with an authorization requirement first checks the Mission's persisted authorization context. The default Mission authorizer then reconstructs `AuthorizationContext.from_dict()` and therefore validates typed Owner evidence, policy snapshot integrity, request binding, freshness, and HMAC. An arbitrary dictionary is not accepted as sensitive authorization.

The Mission layer does not issue an `AuthorizationDecision` and does not replace `security.authorization.py`. The existing deterministic authorization core and tool firewall remain the execution authority. Mission state is a consumer of authorization, not a source of it.

Owner intervention is persisted as `OWNER_INPUT_REQUIRED`. A deny transitions to `AUTHORIZATION_BLOCKED` without executing the action. An allow must provide a serialized, typed `AuthorizationContext`; the Mission then resumes without being recreated.

## Actual scope path

A scope-required step is blocked when no scope snapshot is present. The Mission layer does not modify scope. Scope validation remains the responsibility of the existing typed scope and tool-firewall path. A future adapter should pass a validated `ScopeSnapshot` and invoke the existing resolver before execution.

## Actual model path

This Mission Runtime is provider-neutral. It accepts an executor callback and does not treat model output, Plan objects, memory, knowledge, external content, or reasoning profiles as authority. The existing `ModelRouter` and `ReasoningProfile` remain separate from Mission authorization.

The current phase does **not** yet connect natural-language `/api/chat` messages to Mission creation. That is an explicit remaining gap, not an implementation claim.

## Actual tool and observation paths

The executor returns a structured result. The runtime normalizes it as a `tool_observation` containing mission ID, step ID, stable action ID, success state, and provenance supplied by the executor. The result is stored in `Mission.observations`, while successful results also become evidence candidates. Tool output cannot modify Owner Instruction, Owner Policy, AuthorizationContext, or ScopeSnapshot.

## Actual recovery and replanning paths

A failed observation is classified using `FailureClass`:

- `COMPILATION`, `TEST_FAILURE`, and `LOGIC` can select `REPLAN` within budget.
- `NETWORK`, `PROVIDER`, and `TRANSIENT` can select bounded `RETRY`.
- `AUTHORIZATION` selects `OWNER_INPUT_REQUIRED`.
- `SCOPE` selects `SCOPE_BLOCKED`.
- `RESOURCE` selects `RESOURCE_BLOCKED`.
- exhausted recovery selects `FAILED_RETRY_EXHAUSTED`.

For a replan, the runtime calls the replanner, persists a new Plan version and fingerprint, records the prior plan in `plan_history`, resets the step cursor, and resumes from the new plan. The integration test proves `Plan v2 -> failure observation -> Plan v3 -> repair step`.

## Actual persistence and resume path

Before execution, the runtime persists:

```json
{
  "step_id": "...",
  "action_id": "mission:plan:step:index",
  "status": "in_flight",
  "plan_version": 3
}
```

If the process fails after this checkpoint, a new runtime loads the Mission. Because no completed action record exists, it safely retries the unfinished action. A completed prior action is protected by `action_history` and is not executed again.

## Integration evidence

The five new tests demonstrate:

1. A failed compilation observation is persisted, classified, causes a new Plan version, executes a repair step, and reaches `GOAL_COMPLETED` only after required verification evidence.
2. A simulated crash leaves an in-flight checkpoint; a new `MissionRuntime` instance loads the SQLite state and resumes successfully.
3. Missing required verification evidence keeps the Mission in `RUNNING` after `VERIFYING` rather than completing it.
4. Unauthorized action transitions to `OWNER_INPUT_REQUIRED` without execution; Owner deny blocks permanently; Owner allow with a real typed `AuthorizationContext` resumes and executes.
5. A completed action is not repeated after the persisted cursor is reset.

## Verification

- Focused integration tests: `5 passed`.
- Full suite: `253 passed`.
- `python3 -m compileall -q .`: passed.
- `git diff --check`: passed.

## Remaining gaps

This phase is **not** claimed as full acceptance of every item in the supplied specification. The following remain:

1. `/api/chat` and `core.engine` do not yet create and operate Missions from one natural-language Owner goal.
2. The current `agent/conversation.py` still has a deterministic keyword baseline; multi-turn natural-language Mission extraction is not yet connected to Mission creation.
3. The Mission executor is an explicit callback boundary; a production adapter still needs to connect it to the existing registry and `AuthorizationDecision` for every concrete tool.
4. Scope persistence needs a production adapter that reloads and validates a real `ScopeSnapshot` before scope-bound actions.
5. Internet research, source trust classification, and cross-source evidence collection are not yet wired as Mission steps.
6. Mission-level pause/resume and Owner corrections beyond authorization allow/deny need a conversation adapter.

Therefore the accurate claim is: **the persistent Mission Runtime core and its end-to-end integration tests are implemented; the natural-conversation/API integration and full production tool adapter remain open work.**
