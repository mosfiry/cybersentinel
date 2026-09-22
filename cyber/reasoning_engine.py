"""Advanced offensive reasoning engine.

Reasoning-strength techniques inspired by open reasoning models
(DeepSeek-R1-style self-verification, Qwen3-style hypothesis fanout),
specialized for offensive cyber planning — and still authorization-bound:
this engine produces ranked, critiqued, verified reasoning artifacts and
never executes anything. Execution authority remains security.authorization.

Techniques implemented:

1. HYPOTHESIS FANOUT — breadth scaled by reasoning effort; every hypothesis
   carries discriminating power (what evidence would separate it from its
   siblings) so exploration stays falsifiable instead of decorative.
2. ADVERSARIAL SELF-CRITIQUE — the engine attacks its own plan the way a
   defender (or a rival model) would: unfalsifiable steps, unverified
   premises, blind spots, scope violations. Weak points must be explicit.
3. MULTI-PATH EXPLORATION + VOTING — several candidate attack paths are
   generated, scored on evidence support and discriminating power, and
   ranked. Alternatives are retained, never discarded to a single answer.
4. PROGRESSIVE DEEPENING WITH REFLECTION — reasoning proceeds in passes;
   between passes the engine reflects on what changed and whether more
   effort would change the conclusion (diminishing-returns stop).
5. VERIFICATION REQUIREMENTS — every step declares what observable evidence
   would confirm or refute it before it may be ranked first.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Sequence


class ReasoningEffort(str, Enum):
    FAST = "fast"          # 1 path, 2 hypotheses, no second pass
    STANDARD = "standard"  # 2 paths, 4 hypotheses, 2 passes
    DEEP = "deep"          # 3 paths, 8 hypotheses, 3 passes + reflection
    EXHAUSTIVE = "exhaustive"  # 5 paths, 16 hypotheses, 4 passes + reflection


_EFFORT_CONFIG = {
    ReasoningEffort.FAST: {"paths": 1, "hypotheses": 2, "passes": 1, "reflect": False},
    ReasoningEffort.STANDARD: {"paths": 2, "hypotheses": 4, "passes": 2, "reflect": True},
    ReasoningEffort.DEEP: {"paths": 3, "hypotheses": 8, "passes": 3, "reflect": True},
    ReasoningEffort.EXHAUSTIVE: {"paths": 5, "hypotheses": 16, "passes": 4, "reflect": True},
}


@dataclass
class OffensiveHypothesis:
    hypothesis_id: str
    statement: str
    discriminating_question: str = ""
    verification_requirement: str = ""
    prior: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.prior <= 1.0:
            raise ValueError("prior must be within [0, 1]")


@dataclass
class ReasoningStep:
    step_id: str
    description: str
    technique: str = ""
    evidence_required: str = ""
    falsifiable: bool = True

    def __post_init__(self) -> None:
        if not self.description:
            raise ValueError("a reasoning step requires a description")
        if self.falsifiable and not self.evidence_required:
            raise ValueError(
                "a falsifiable step must declare the evidence that would refute it"
            )


@dataclass
class AttackPath:
    path_id: str
    objective: str
    steps: tuple[ReasoningStep, ...]
    hypothesis: str = ""
    evidence_support: float = 0.0
    discriminating_power: float = 0.0
    risk_note: str = ""
    votes: int = 0

    def score(self) -> float:
        # ranked by evidence first: a path without support can never outrank
        # a supported one, no matter how many steps it has.
        return self.evidence_support * 2.0 + self.discriminating_power


@dataclass
class Critique:
    weakness: str
    kind: str = "blind_spot"
    suggestion: str = ""


@dataclass
class ReasoningRun:
    objective: str
    effort: ReasoningEffort
    hypotheses: list[OffensiveHypothesis] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)
    critiques: list[Critique] = field(default_factory=list)
    passes: int = 0
    reflections: list[str] = field(default_factory=list)
    stopped_for: str = "completed"


class OffensiveReasoningEngine:
    """Deep offensive reasoning; deterministic, inspectable, effort-scaled."""

    def __init__(self, knowledge_lookup: Callable[[str], dict[str, Any]] | None = None):
        # knowledge_lookup returns {"classification": ..., "sources": ...}
        # for an entity id — wired to the cyber knowledge graph when present.
        self.knowledge_lookup = knowledge_lookup

    # -- 1. hypothesis fanout ----------------------------------------------

    def generate_hypotheses(
        self, objective: str, seeds: Sequence[str], effort: ReasoningEffort
    ) -> list[OffensiveHypothesis]:
        """Fanout from seed attack-surface features, capped by effort.

        Every hypothesis is required to name its discriminating question:
        a hypothesis that nothing could distinguish from its siblings is
        decorative and is marked with a critique instead of being ranked.
        """
        limit = _EFFORT_CONFIG[effort]["hypotheses"]
        hypotheses: list[OffensiveHypothesis] = []
        for index, seed in enumerate(seeds[:limit]):
            hypotheses.append(
                OffensiveHypothesis(
                    hypothesis_id="h-{:02d}".format(index + 1),
                    statement="the objective is reachable through: {}".format(seed),
                    discriminating_question=(
                        "what observable on {} would confirm this entry point "
                        "and not the alternatives?".format(seed)
                    ),
                    verification_requirement=(
                        "probe evidence from {} consistent with this hypothesis "
                        "and inconsistent with its siblings".format(seed)
                    ),
                    prior=1.0 / max(1, len(seeds[:limit])),
                )
            )
        return hypotheses

    # -- 2. adversarial self-critique --------------------------------------

    def critique_path(self, path: AttackPath) -> list[Critique]:
        """Attack our own plan the way a defender or rival would."""
        critiques: list[Critique] = []
        if not path.steps:
            critiques.append(Critique("path has no steps", "empty_plan"))
        for step in path.steps:
            if not step.falsifiable:
                critiques.append(
                    Critique(
                        "step '{}' is unfalsifiable — no evidence could refute it".format(
                            step.description
                        ),
                        "unfalsifiable_step",
                        "declare the observable that would refute this step",
                    )
                )
            if not step.evidence_required:
                critiques.append(
                    Critique(
                        "step '{}' does not declare its evidence requirement".format(
                            step.description
                        ),
                        "missing_evidence",
                    )
                )
        if path.evidence_support <= 0.0:
            critiques.append(
                Critique(
                    "path '{}' has no evidence support; it is speculation".format(path.path_id),
                    "unsupported_path",
                    "gather supporting evidence before ranking this path first",
                )
            )
        if self.knowledge_lookup is not None:
            for step in path.steps:
                if step.technique:
                    verdict = self.knowledge_lookup(step.technique)
                    if verdict and verdict.get("classification") == "UNKNOWN":
                        critiques.append(
                            Critique(
                                "technique '{}' is UNKNOWN to the knowledge base; "
                                "it must not be treated as established".format(step.technique),
                                "unverified_technique",
                            )
                        )
        return critiques

    # -- 3. multi-path exploration + voting --------------------------------

    def explore_paths(
        self, objective: str, path_builders: Sequence[Callable[[], AttackPath]],
        effort: ReasoningEffort,
    ) -> list[AttackPath]:
        limit = _EFFORT_CONFIG[effort]["paths"]
        paths = [build() for build in path_builders[:limit]]
        for path in paths:
            path.votes = 0
        # self-consistency vote: paths sharing the same primary hypothesis
        # reinforce each other, but evidence support gates everything.
        for i, path in enumerate(paths):
            for j, other in enumerate(paths):
                if i != j and path.hypothesis and path.hypothesis == other.hypothesis:
                    if path.score() > 0:
                        path.votes += 1
        return sorted(paths, key=lambda p: (p.score(), p.votes), reverse=True)

    # -- 4. progressive deepening with reflection ---------------------------

    def run(
        self, objective: str, seeds: Sequence[str],
        path_builders: Sequence[Callable[[], AttackPath]],
        effort: ReasoningEffort = ReasoningEffort.DEEP,
    ) -> ReasoningRun:
        config = _EFFORT_CONFIG[effort]
        run = ReasoningRun(objective=objective, effort=effort)
        run.hypotheses = self.generate_hypotheses(objective, seeds, effort)
        best_score = -1.0
        for pass_index in range(config["passes"]):
            run.paths = self.explore_paths(objective, path_builders, effort)
            for path in run.paths:
                run.critiques.extend(self.critique_path(path))
            current_best = run.paths[0].score() if run.paths else -1.0
            run.passes = pass_index + 1
            if config["reflect"]:
                reflection = (
                    "pass {}: best path '{}' score {:.3f} (support {:.2f}, "
                    "discriminating {:.2f}); {} critiques raised".format(
                        pass_index + 1,
                        run.paths[0].path_id if run.paths else "-",
                        current_best,
                        run.paths[0].evidence_support if run.paths else 0.0,
                        run.paths[0].discriminating_power if run.paths else 0.0,
                        len(run.critiques),
                    )
                )
                run.reflections.append(reflection)
                # diminishing-returns stop: if a new pass did not improve the
                # best score, more effort would not change the conclusion.
                if pass_index > 0 and current_best <= best_score:
                    run.stopped_for = "diminishing_returns"
                    break
            best_score = max(best_score, current_best)
        # an unsupported path may not be crowned even if it is the only one
        if run.paths and run.paths[0].evidence_support <= 0.0:
            run.stopped_for = "no_supported_path"
        return run

    # -- 5. verification requirements ---------------------------------------

    def verification_plan(self, run: ReasoningRun) -> list[dict[str, Any]]:
        if not run.paths:
            return []
        best = run.paths[0]
        return [
            {
                "path_id": best.path_id,
                "step_id": step.step_id,
                "evidence_required": step.evidence_required,
                "falsifiable": step.falsifiable,
            }
            for step in best.steps
        ]
