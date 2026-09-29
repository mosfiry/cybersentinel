# CyberSentinel X — Current Runtime Truth

**Snapshot date:** 2026-09-29. This document distinguishes repository-controlled behavior from externally observed state; it is not a production, provider, or deployment attestation.

## Canonical runtime and security boundaries

Browser chat (`POST /api/public/chat`), internal chat (`POST /api/chat`), and the legacy-named `/api/command` path converge on `api.chat.chat → AgentCore → MissionRuntime`. The `/api/tasks` interface retains a compatibility `Task` envelope but persists and controls canonical missions through `MissionTaskAdapter`. `AgentTaskRuntime`, `AgentRuntime`, `AgentLoop`, and `core.engine` remain compatibility/test surfaces rather than the current browser/API mission path.

Owner authority is established by server-side username/password authentication. The public CSRF session is not Owner authority; the browser's Owner session is an HttpOnly cookie, and internal clients use the separate bridge transport credential. Missions, conversations, and mission-backed Tasks are Owner-scoped. Tool proposals are untrusted: deterministic policy, typed authorization, a signed mission snapshot, scope checks, and a one-use execution proof are validated before registry dispatch.

Tool output, model text, generic success booleans, and Owner reconciliation choices do not establish goal completion. Completion requires system-issued evidence for supported criteria, deterministic verification, and a valid mission completion proof. The Findings UI displays only system-evidenced records; the application has no separate persisted `Finding` entity.

The authenticated Product Workspace is mission-bound and read-only. File listings, file reads, and fixed Git views deny sensitive paths case-insensitively, including nested environment files and common credential stores; Git diff uses explicit path exclusions, remote credentials are redacted, and commit/push/arbitrary shell actions are not exposed.

## Durable work, recovery, and dependency semantics

The supervised SQLite queue atomically limits active entries to 10 by default and rejects overflow as `mission_queue_full` (HTTP 429). The worker processes one mission slice at a time, renews its lease while a blocking model/tool call runs, recovers expired leases, and preserves ambiguous in-flight effects for Owner reconciliation rather than replaying them blindly. A parallel checkpoint with unresolved tool results is guarded from unsafe automatic replay.

`PlanStep` prerequisites are validated for duplicate IDs, missing steps, and cycles; execution waits for ready predecessors. Non-empty top-level `Plan.dependencies` are rejected because their semantics are undefined. Cross-mission dependency scheduling and a distinct user-visible `WAITING_FOR_DEPENDENCY` mission state are not implemented. The durable scheduler supports one-time dispatch only; recurring intervals and nonzero scheduled retries are rejected rather than reported as working.

## Tool and provider capability truth

`run_project_tests` is available only after startup verifies the OS sandbox. It runs against a filtered, read-only project snapshot in `bubblewrap`, with network and inherited credentials removed and `prlimit` resource bounds; if preflight fails, the tool is marked unavailable and rejected before execution. Exact exclusions and limits are in [Tool Execution](TOOL_EXECUTION.md).

`scoped_http_probe` and general-web search are **unavailable/not implemented**. Scope validation alone is not an HTTP request, and there is no generic web transport. GitHub repository search, where configured, is a separate capability and is not general-web search. Available provider code is an OpenAI-compatible synchronous adapter for text generation and explicitly enabled native tool calling; streaming, structured output, vision, or provider-side reasoning are not verified merely because flags exist. No live provider was configured for this acceptance run; the live-provider test remains skipped/unverified. Provider-backed specialist agents are not implemented; expert modes are deterministic analytical templates.

The model and conversation benchmark outputs mark metrics without signed, repeatable execution harnesses `NOT_VERIFIED` or `NOT_IMPLEMENTED`; heuristic scores are not represented as measured production quality.

## Browser persistence acceptance

The frontend stores only a non-secret Owner/conversation pointer for continuity; transcript content and Task records are fetched from the Owner-scoped server endpoint. On 2026-09-29, a disposable localhost Owner session was exercised through the UI: a local chat marker survived a full page reload, and the UI restored the Owner session, transcript, and mission state. A controlled localhost service restart produced an offline indicator; after the frontend's 15-second poll detected the restarted service, it cleared the offline state and restored the Owner session, transcript, and mission state without a page reload or manual refresh. No live model/provider or production service was contacted.

## Verification and external boundaries

Final post-documentation verification on this isolated branch ran `python3 -m compileall -q .`, `node --check web/app.js`, `git diff --check`, and the full pytest suite (`python3 -m pytest -q -rs -p no:cacheprovider`): **786 passed, 1 skipped, 0 failed**. The skip is `tests/test_real_provider_long_horizon.py:35`: `UNVERIFIED - REAL PROVIDER UNAVAILABLE`; no live provider credentials are configured, so live-provider behavior is not verified. The focused cross-cutting suite passed **122 tests**. GitHub CI results are checked against the exact pushed SHA, not inferred from an earlier PR or integration run.

The repository contains no Wrangler configuration, Worker entrypoint, or production deployment manifest. A read-only Cloudflare snapshot taken 2026-09-29 11:35–11:37 UTC found four stopped/failed Workers Builds for the external `cybersentinel` service, zero previews, and no preview URL for the latest build. That build (`d898f9d5-9a84-4f8c-98e1-e9ab445133d9`, source commit `71ce3c9550ad258a9cb01f03a7dc5e337f08ce93`) ran `npx wrangler preview`; its log states that the Wrangler configuration is missing a `previews` block. The log text was treated as diagnostic data; no suggested configuration was applied.

The same read-only snapshot returned three existing deployments, with 100% traffic routed to version 3 (`39fb0620-a8a5-4566-b7e1-8b085529fa1b`). The source relationship to this repository and live runtime health were not established. No Cloudflare settings, triggers, Worker configuration, or deployment were changed. The external deployment state is separate from the loopback-only Python bridge documented here.

At the start of finalization, the local isolated branch was `integration/cybersentinel-final-completion` at `09ec8879eb6ba42cbd2f7437830afc49f10e2487`; the remote final-completion ref did not yet exist. The verified `main`, PR #17, Vibe, and `integration/agent-workspace-pr17` refs were left unchanged. The authorized push is limited to the isolated final-completion branch; no merge or deployment is part of this work.
