# CyberSentinel X — Mission IDE UI (feature branch)

Product/UI layer ONLY. All data in this UI is clearly-marked MOCK fixture
data; no backend is connected. Backend security semantics (Authorization
Core, OwnerSession, MissionRuntime, AgentCore, Policy Engine, Scope
Firewall, Evidence Chain) are NOT modified by this branch.

- web/src/App.jsx — full IDE shell (missions rail, workspace/editor,
  terminal, timeline, evidence, findings, git review, authorization
  snapshot, scheduler, agent activity rail, confirmations)
- docs/WEB_API_REQUIREMENTS.md — requested backend contract (no invented
  security semantics)
- docs/UI_TESTS.md — test plan mapping to acceptance gates

Do NOT merge to main without backend integration review.
