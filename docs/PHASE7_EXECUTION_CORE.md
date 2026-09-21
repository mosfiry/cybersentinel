# Phase 7 — Execution Core and Model Boundary

## Scope

This phase adds a typed execution-core foundation for long-horizon work without introducing Qwen weights, a Qwen runtime, or a model-specific authorization path. The model remains a planner and interpreter; deterministic policy, authorization, scope, and the tool firewall remain the only execution boundary.

## Implemented contracts

`agent/planning.py` defines immutable `Plan`, `PlanStep`, and `PlanRevision` values. A plan has a version, objective, assumptions, dependencies, completion criteria, risk, and provenance. Replanning creates a new version and preserves the prior object instead of overwriting history.

`GoalVerification` evaluates explicit `VerificationCriterion` values against typed `VerificationEvidence`. A model statement such as “done” is not completion evidence. Required criteria must be present and passed before `require_verified()` succeeds. Evidence includes a deterministic result hash and provenance metadata.

`FailureClass` and `RecoveryPolicy` provide bounded recovery. Authorization failures require owner input, scope failures remain blocked, transient/network/provider failures may retry within budget, and compilation/test/logic failures may request a replan. No recovery branch bypasses authorization or scope.

`ReasoningMode` and `ReasoningProfile` separate performance configuration from authority. The runtime selects `FAST`, `BALANCED`, or `DEEP` from task shape and records the profile in task state. The profile only changes generation temperature; it cannot create an `AuthorizationContext`, alter a `ScopeSnapshot`, or authorize a tool.

## Engineering conclusions from official Qwen sources

The following official sources were reviewed as engineering references only:

1. [Qwen3 repository](https://github.com/QwenLM/Qwen3)
2. [Qwen3 README](https://github.com/QwenLM/Qwen3/blob/main/README.md)
3. [Qwen3 technical report](https://arxiv.org/abs/2505.09388)
4. [Qwen3 official blog](https://qwenlm.github.io/blog/qwen3/)
5. [Qwen3 non-thinking chat template](https://github.com/QwenLM/Qwen3/blob/main/docs/source/assets/qwen3_nonthinking.jinja)
6. [Official Qwen documentation](https://qwen.readthedocs.io/)

The reusable principles are: keep reasoning and non-thinking as a bounded performance choice; use structured tool proposals and strict schema validation; preserve multi-step context where useful; treat tool results as observations rather than authority; and isolate provider adapters from the deterministic execution gateway.

These sources do **not** establish CyberSentinel X authorization, identity, scope, sandboxing, or execution guarantees. Their templates and reasoning fields are formatting/inference mechanisms, not security controls. Qwen weights and runtime are intentionally excluded from this repository.

## Verification

The phase adds five regression tests covering reasoning-mode bounds, immutable plan versioning, evidence-gated goal completion, optional versus required criteria, and the rule that recovery cannot bypass authorization or scope. The full suite passes with 248 tests.
