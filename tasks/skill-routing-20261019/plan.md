# Skill routing integration

Base: `bb1148f9caf91dc6511718e7869ae57861dc211a`; isolated branch `feature/skill-routing-20261019`. Do not change main, v5.1.0, or create tags/releases. Exclude the independent Windows token-handle experiment.

## Decisions and assumptions

Improve the canonical SkillRegistry and AgentCore/MissionRuntime path, not a parallel executor. Routing is explicit opt-in per Mission; the existing explicit selection remains compatible. Only active approved owner revisions are eligible. Ambiguous/no-match routing abstains, then the normal authorized model planner continues without Skill guidance. Selection is not authentication, authorization or execution. Reuse the existing local ModelRouter, composite plans, checkpoints, integrity-covered binding/provenance and evidence chain. Never import or run external skill instructions/scripts or paid APIs. No schema migration/dependency addition is planned.

## Ordered implementation

1. Capture actual repository refs, working trees, reference code/license audit, integration map, pre-change full Python suite and base exact-SHA CI outcomes.
2. Add deterministic bounded lexical routing over name/capabilities, available tools, scope and required actions. Fixed reason codes; tie abstention; unavailable-tool fallback. Tests use real temporary SQLite registries and prove lifecycle/owner isolation, hostile-string safety and no execution.
3. Add `auto_skill: bool=False` to authenticated AgentCore: authenticate first, select, reuse bind_mission/live validation, persist only bounded decision metadata. Tests prove no provider/dispatch on auth failure and live validation after reopening stores/revocation. No replacement planner or checkpoint system.
4. Add strict boolean bridge input and opt-in UI; reject explicit+automatic conflict; allowlist summaries and render textContent alongside existing current-step/evidence/error view. Keep Owner/CSRF gates and installer unchanged.
5. Independent review; focused authorization/scope/recovery suite; full Python regression, compile/diff/secret/JS/Electron gates. Make small tested commits and non-force push feature branch only. Recompare protected refs; document exact counts, remote checkpoint and remaining gaps.

Dependencies: 3 consumes 2; 4 consumes the established core parameter and provenance contract; 5 follows all implementation. Parallel ownership: router module/tests, bridge/UI/tests, parent core integration/tests/docs. No shared-file parallel editing.

## Acceptance and limits

Each slice must pass focused tests before its checkpoint. Final full suite must not remove tests or add skips. Routing must not broaden tool/scope ceilings, trust free-form descriptions, execute procedures, or resurrect approvals after restart. Invalid/tied selection is explicit abstention. Review reference prompt injection, path traversal, tool discovery side effects and journal poisoning. Windows installed acceptance is not inferred from Linux or source contracts. Base Windows installer/AppContainer CI failures and diagnostic-only LowBox success remain separate from feature results; Blocker D cannot be called resolved by this mission.

Existing tasks/plan.md and tasks/todo.md are completed historical multi-phase logs; this feature uses this nested plan/checklist to avoid overwriting those records.
