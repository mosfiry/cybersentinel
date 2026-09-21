# Agent Core Testing

The native Agent Core tests use real `MissionRuntime`, `MissionStore`, `AuthorizationContext`, provider adapters, registry tools, persistence, and `/api/chat` mission routing. They are not isolated mocks of the loop.

Current focused coverage includes:

- Owner goal to Mission and Plan;
- multi-step observations and evidence;
- malformed proposal recovery and dynamic replan;
- objective preservation during replan;
- goal verification blocking premature completion;
- Mission persistence and restart load;
- crash during an in-flight action stops at `RECOVERY_REQUIRED` without silent replay, followed by explicit receipt reconciliation;
- `/api/chat` to `AgentCore` integration;
- typed MissionState and trajectory persistence;
- dead-loop detection;
- authorization-required step stopping before executor;
- model proposal unable to create authorization;
- Owner policy provenance and external-data authority boundaries.

The existing full regression suite remains mandatory. Every phase runs `compileall`, focused pytest, full pytest, and `git diff --check` before release. Acceptance claims must identify the exact test and execution path; a helper that is not called by production is classified as unwired.
