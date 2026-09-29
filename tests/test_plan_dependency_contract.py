from __future__ import annotations

import pytest

from agent.planning import Plan, PlanStep


def test_step_prerequisites_are_the_supported_dependency_graph():
    plan = Plan(
        version=1,
        objective="analyze in order",
        steps=(
            PlanStep("discover", "discover inputs"),
            PlanStep("analyze", "analyze inputs", prerequisites=("discover",)),
        ),
    )
    plan.validate_dependency_graph()


def test_unsupported_top_level_plan_dependencies_fail_closed():
    plan = Plan(
        version=1,
        objective="run after another mission",
        steps=(PlanStep("analyze", "analyze inputs"),),
        dependencies=("mission-parent",),
    )
    with pytest.raises(ValueError, match="top-level Plan.dependencies is unsupported"):
        plan.validate_dependency_graph()
