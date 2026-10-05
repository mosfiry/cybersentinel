# Mission Events and Hooks

`agent/intelligence_layer/events.py` adds a schema-versioned SQLite event journal and an in-process `EventBus`. Events are scoped to an Owner and mission, ordered by per-mission sequence, appended in a transaction, and linked by SHA-256 hashes. Reads verify event integrity and chain continuity; rows cannot be updated or deleted through the database. Common credential fields and token patterns are redacted before the bounded JSON payload is persisted. The digest detects modification but is not an Owner signature.

The bus commits before it invokes observers. A subscriber failure is returned to the publisher and does not rewrite or roll back the durable event. Observers may be called again when an idempotent event publish is retried, so consumer handlers must use the event ID as their own deduplication key. Durable consumer offsets and automatic retry workers are not part of this slice.

## Hooks

`HookRegistry` supports the requested before/after mission, tool and provider phases, plus evidence-created, finding-created and skill-candidate-created phases. Handlers are trusted in-process code, not model-authored scripts. Registration and every invocation call a host-supplied current-authorization check bound to the same Owner, mission and phase.

A before-hook returns a typed allow/deny decision; it may veto but cannot approve a missing grant, change arguments, expand scope or replace MissionRuntime authorization. Exceptions, revoked authorization, malformed decisions, and a failed audit write block a pre-effect action. After-hooks are observers only: their failure is surfaced but cannot retroactively block a completed effect. The host must still run the canonical authorization, scope, execution-fence and evidence checks.

The event journal and hook registry are additive primitives; they are not yet wired into every AgentCore, MissionRuntime, provider or ToolRegistry transition. A production integration must install the registry at each required boundary and prove restart, revocation, timeout and replay behavior before claiming complete observability or universal hook coverage.

## Verification

`tests/agent_intelligence/test_events.py` covers chain ordering and integrity, idempotency conflicts, Owner isolation, credential redaction, subscriber failures, immutable hook context, authorization revocation, before-hook denial, audit failure and after-hook behavior.