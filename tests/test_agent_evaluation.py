from __future__ import annotations

import sqlite3

import pytest

from evaluation.agent_evaluation import (
    EvaluationConflict,
    EvaluationError,
    EvaluationMeasurement,
    EvaluationMetric as M,
    EvaluationPolicy,
    EvaluationRun,
    EvaluationStore,
    EvaluationVerdict as V,
    evaluate_run,
)


def complete_run(*, owner: str = "owner:1", success: float = 0.95, evidence_refs: tuple[str, ...] = ("evidence:1",), safety: int = 0) -> EvaluationRun:
    return EvaluationRun(
        owner_identity_ref=owner,
        mission_id="mission:1",
        task_id="task:1",
        case_id="case:memory-recall",
        benchmark_version="2.0",
        provider_id="provider:test",
        model_id="model:test",
        created_at="2026-10-05T10:00:00+00:00",
        measurements=(
            EvaluationMeasurement(M.TASK_SUCCESS, success),
            EvaluationMeasurement(M.EVIDENCE_QUALITY, 0.92, evidence_refs),
            EvaluationMeasurement(M.HALLUCINATION, 0.01),
            EvaluationMeasurement(M.TOOL_CORRECTNESS, 0.98),
            EvaluationMeasurement(M.SKILL_USEFULNESS, 0.7),
            EvaluationMeasurement(M.MEMORY_USEFULNESS, 0.8),
            EvaluationMeasurement(M.LATENCY, 850),
            EvaluationMeasurement(M.COST, 1.25),
            EvaluationMeasurement(M.RECOVERY, 1.0),
            EvaluationMeasurement(M.SAFETY_VIOLATIONS, safety),
            EvaluationMeasurement(M.TOKEN_USAGE, 2_500),
            EvaluationMeasurement(M.AGENT_COORDINATION, 0.75),
        ),
        provenance={"harness": "tests", "prompt_sha256": "a" * 64},
    )


def test_evaluation_is_multidimensional_and_requires_independent_evidence_validation():
    run = complete_run()
    unchecked = evaluate_run(run)
    assert unchecked.verdict is V.INDETERMINATE
    assert "evidence_unverified:evidence_quality" in unchecked.reasons

    accepted = evaluate_run(run, evidence_validator=lambda owner, mission, ref: (owner, mission, ref) == ("owner:1", "mission:1", "evidence:1"))
    assert accepted.verdict is V.ACCEPTED
    assert len(accepted.measurements) == 12
    assert not hasattr(accepted, "score")


def test_policy_rejects_low_success_safety_violations_and_missing_evidence():
    validator = lambda *_: True
    assert evaluate_run(complete_run(success=0.5), evidence_validator=validator).verdict is V.REJECTED
    assert evaluate_run(complete_run(safety=1), evidence_validator=validator).verdict is V.REJECTED
    no_evidence = evaluate_run(complete_run(evidence_refs=()), evidence_validator=validator)
    assert no_evidence.verdict is V.REJECTED
    assert "missing_evidence:evidence_quality" in no_evidence.reasons


def test_invalid_or_unavailable_evidence_validator_never_accepts_a_run():
    run = complete_run()
    invalid = evaluate_run(run, evidence_validator=lambda *_: False)
    assert invalid.verdict is V.REJECTED
    assert "invalid_evidence:evidence_quality" in invalid.reasons
    def broken_validator(*_):
        raise RuntimeError("evidence store unavailable")
    unavailable = evaluate_run(run, evidence_validator=broken_validator)
    assert unavailable.verdict is V.INDETERMINATE
    assert "evidence_validator_error:evidence_quality" in unavailable.reasons


def test_missing_required_dimension_is_indeterminate_not_implicitly_successful():
    run = complete_run()
    partial = EvaluationRun(
        owner_identity_ref=run.owner_identity_ref,
        mission_id=run.mission_id,
        task_id=run.task_id,
        case_id=run.case_id,
        benchmark_version=run.benchmark_version,
        provider_id=run.provider_id,
        model_id=run.model_id,
        created_at=run.created_at,
        measurements=(EvaluationMeasurement(M.TASK_SUCCESS, 1.0),),
    )
    result = evaluate_run(partial, evidence_validator=lambda *_: True)
    assert result.verdict is V.INDETERMINATE
    assert "missing_metric:evidence_quality" in result.reasons


def test_metric_values_units_and_policies_are_strict():
    with pytest.raises(EvaluationError, match="between 0 and 1"):
        EvaluationMeasurement(M.HALLUCINATION, 1.1)
    with pytest.raises(EvaluationError, match="cannot be negative"):
        EvaluationMeasurement(M.LATENCY, -1)
    with pytest.raises(EvaluationError, match="integer count"):
        EvaluationMeasurement(M.SAFETY_VIOLATIONS, 0.5)
    with pytest.raises(EvaluationError, match="finite number"):
        EvaluationMeasurement(M.COST, float("nan"))
    with pytest.raises(EvaluationError, match="bounded integer token count"):
        EvaluationMeasurement(M.TOKEN_USAGE, 1.5)
    with pytest.raises(EvaluationError, match="bounded integer token count"):
        EvaluationMeasurement(M.TOKEN_USAGE, 10_000_000_001)


def test_evaluation_store_is_owner_scoped_append_only_and_idempotent(tmp_path):
    store = EvaluationStore(tmp_path / "evaluation.sqlite")
    run = complete_run()
    first = store.append(run, idempotency_key="run:one")
    repeated = store.append(run, idempotency_key="run:one")
    assert repeated.evaluation_id == first.evaluation_id
    assert repeated.record_sha256 == first.record_sha256
    assert store.get(owner_identity_ref="owner:2", evaluation_id=first.evaluation_id) is None
    assert store.list(owner_identity_ref="owner:2") == []
    assert store.get(owner_identity_ref="owner:1", evaluation_id=first.evaluation_id).run == run
    assert store.list(owner_identity_ref="owner:1", mission_id="mission:1")[0].evaluation_id == first.evaluation_id

    with sqlite3.connect(store.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE evaluation_runs SET model_id = 'forged' WHERE evaluation_id = ?", (first.evaluation_id,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM evaluation_runs WHERE evaluation_id = ?", (first.evaluation_id,))


def test_evaluation_idempotency_and_persisted_integrity_conflicts_are_detected(tmp_path):
    store = EvaluationStore(tmp_path / "evaluation.sqlite")
    first = store.append(complete_run(), idempotency_key="run:one")
    with pytest.raises(EvaluationConflict, match="different evaluation contents"):
        store.append(complete_run(success=0.8), idempotency_key="run:one")

    with sqlite3.connect(store.db_path) as connection:
        connection.execute("DROP TRIGGER evaluation_no_update")
        connection.execute("UPDATE evaluation_runs SET measurements_json = '[]' WHERE evaluation_id = ?", (first.evaluation_id,))
    from evaluation.agent_evaluation import EvaluationIntegrityError
    with pytest.raises(EvaluationIntegrityError, match="integrity check"):
        store.get(owner_identity_ref="owner:1", evaluation_id=first.evaluation_id)


def test_evaluation_store_caps_query_and_preserves_private_file_mode(tmp_path):
    store = EvaluationStore(tmp_path / "private" / "evaluation.sqlite")
    assert store.db_path.stat().st_mode & 0o077 == 0
    with pytest.raises(EvaluationError, match="limit"):
        store.list(owner_identity_ref="owner:1", limit=101)


def test_evaluation_policy_and_nested_provenance_are_deeply_immutable():
    original = complete_run()
    caller_provenance = {"nested": [{"source": "verified"}]}
    run = EvaluationRun(
        owner_identity_ref=original.owner_identity_ref,
        mission_id=original.mission_id,
        task_id=original.task_id,
        case_id=original.case_id,
        benchmark_version=original.benchmark_version,
        provider_id=original.provider_id,
        model_id=original.model_id,
        measurements=original.measurements,
        provenance=caller_provenance,
        created_at=original.created_at,
    )
    caller_provenance["nested"][0]["source"] = "changed-after-construction"
    assert run.provenance["nested"][0]["source"] == "verified"
    with pytest.raises(TypeError):
        run.provenance["nested"][0]["source"] = "mutated"
    policy = EvaluationPolicy()
    with pytest.raises(TypeError):
        policy.minimums[M.TASK_SUCCESS] = 0.0
