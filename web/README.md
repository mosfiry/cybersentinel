# CyberSentinel X — Mission IDE UI (feature branch)

Product/UI layer ONLY. All data is clearly-marked MOCK; the backend is
NOT connected. Backend security semantics (Authorization Core,
OwnerSession, MissionRuntime, AgentCore, Policy Engine, Scope Firewall,
Evidence Chain) are NOT modified by this branch.

Layout: VS Code-class IDE shell with CyberSentinel identity —
Activity Bar / Sidebar (Explorer, Missions, Search, Source Control,
Evidence, Findings, Reports, Scheduler, Tools, Settings) / Tabs /
Editor (line numbers, current-line highlight, minimap, deterministic
syntax coloring, breadcrumbs) / Bottom Panel (Terminal, Problems,
Output, Evidence, Logs — collapsible) / Agent Panel (mission state,
recent activity, evidence + verification counts; no chat, no
chain-of-thought) / Status Bar (mission status, phase, elapsed,
checkpoint).

- web/src/App.jsx — full IDE shell (single file, componentized inline:
  Icon, Editor, Tabs, ExplorerTree, AgentPanel, TerminalView, and one
  view component per rich view)
- docs/WEB_API_REQUIREMENTS.md — 16 requested endpoints (requests,
  not inventions)
- docs/UI_VERIFICATION.md — manual verification record (honest scope)

Single-file note: App.jsx intentionally stays one file at this stage so
the same source runs in both the repo and the interactive canvas render
without a bundler. Splitting into web/src/components/* is safe (pure
functions, no shared mutable state) and listed as follow-up.

Do NOT merge to main without backend integration review.
