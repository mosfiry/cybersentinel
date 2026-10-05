# Mission Events and Hooks

`agent/intelligence_layer/events.py` adds a schema-versioned SQLite event journal and an in-process `EventBus`. Events are scoped to an Owner and mission, ordered by per-mission sequence, appended in a transaction, and linked by SHA-256 hashes. Reads verify event integrity and chain continuity; rows cannot be updated or deleted through the database. Common credential fields and token patterns are redacted before the bounded JSON payload is persisted. The digest detects modification but is not an Owner signature.

The bus commits before it invokes observers. A subscriber failure is returned to the publisher and does not rewrite or roll back the durable event. Observers may be called again when an idempotent event publish is retried, so consumer handlers must use the event ID as their own deduplication key. Durable consumer offsets and automatic retry workers are not part of this slice.

## Hooks

`HookRegistry` supports the requested before/after mission, tool and provider phases, plus evidence-created, finding-created and skill-candidate-created phases. Handlers are trusted in-process code, not model-authored scripts. Registration and every invocation call a host-supplied current-authorization check bound to the same Owner, mission and phase.

A before-hook returns a typed allow/deny decision; it may veto but cannot approve a missing grant, change arguments, expand scope or replace MissionRuntime authorization. Exceptions, revoked authorization, malformed decisions, and a failed audit write block a pre-effect action. After-hooks are observers only: their failure is surfaced but cannot retroactively block a completed effect. The host must still run the canonical authorization, scope, execution-fence and evidence checks.

`AgentCore` and `MissionRuntime` accept opt-in `EventBus` and `HookRegistry` instances and pass them to canonical `ToolRegistry.execute` for both plan-step and native-model tool dispatch. After the existing owner decision, mission snapshot, scope and execution-fence checks, a before-tool hook is invoked with only bounded identifiers and an argument digest; owner/scope/snapshot and fence checks run again before effect reservation. A veto or pre-dispatch journal failure prevents the handler from running. `TaskStarted` and `ToolCalled` are recorded as pre-dispatch intent; `TaskCompleted` is best-effort after a known handler result so a post-effect journal outage cannot cause an ambiguous retry. Hosts must explicitly inject these services. Mission lifecycle/provider/evidence transitions, after-tool hooks, durable subscriber offsets, restart reconciliation and product APIs are not universally integrated.

## Verification

`tests/agent_intelligence/test_events.py` covers chain ordering and integrity, idempotency conflicts, Owner isolation, credential redaction, subscriber failures, immutable hook context, authorization revocation, before-hook denial, audit failure and after-hook behavior. `tests/test_tool_registry_hooks.py` covers the canonical dispatcher integration, pre-effect veto, owner-scoped events, redacted/minimal payloads and fail-closed pre-dispatch persistence.
