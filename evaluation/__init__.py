from importlib import import_module

from .benchmark import BenchmarkCase, SAFE_STARTER_CASES, evaluate_assessment
from .critic import CriticReport, critique
from .gate import compare
from .agent_evaluation import (
    EvaluationConflict,
    EvaluationDecision,
    EvaluationError,
    EvaluationIntegrityError,
    EvaluationMeasurement,
    EvaluationMetric,
    EvaluationPolicy,
    EvaluationRun,
    EvaluationStore,
    EvaluationVerdict,
    StoredEvaluation,
    evaluate_run,
)

_CONVERSATION_BENCHMARK_EXPORTS = frozenset({
    "CONVERSATION_CASES",
    "ConversationBenchmarkCase",
    "compare_conversation_benchmarks",
    "run_conversation_benchmark",
    "run_conversation_contract_benchmark",
})


def __getattr__(name: str):
    if name not in _CONVERSATION_BENCHMARK_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(".conversation_benchmark", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | _CONVERSATION_BENCHMARK_EXPORTS)


__all__ = [
    "BenchmarkCase",
    "SAFE_STARTER_CASES",
    "evaluate_assessment",
    "CriticReport",
    "critique",
    "compare",
    "CONVERSATION_CASES",
    "ConversationBenchmarkCase",
    "compare_conversation_benchmarks",
    "run_conversation_benchmark",
    "run_conversation_contract_benchmark",
    "EvaluationConflict",
    "EvaluationDecision",
    "EvaluationError",
    "EvaluationIntegrityError",
    "EvaluationMeasurement",
    "EvaluationMetric",
    "EvaluationPolicy",
    "EvaluationRun",
    "EvaluationStore",
    "EvaluationVerdict",
    "StoredEvaluation",
    "evaluate_run",
]
