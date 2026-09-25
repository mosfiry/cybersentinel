from __future__ import annotations

"""B3-A adversarial battery: MissionIntent -> TaskIntent (INV-LADDER-1..3).

Proves that the typed TaskIntent layer is frozen, deterministically derived,
fail-closed against malformed/authority-shaped model proposals, replay-safe,
and structurally incapable of widening the Owner budget, minting an
AuthorizationDecision, or deriving an ExecutionAuthorizationProof.
"""

import dataclasses

import pytest

from agent.model_intelligence.conversation import MissionIntent, NaturalLanguageUnderstanding
from security.execution_proof import ExecutionAuthorizationProof, ExecutionProofError, RejectionCode
from security.intent_ladder import (
    MAX_TASK_INTENTS,
    TaskIntent,
    TaskIntentError,
    derive_task_intents,
    validate_task_intent_proposal,
)
from security.owner_budget import OwnerAuthorizedToolBudget


def _mission(objective: str = "Analyze the local workspace for exposed secrets") -> MissionIntent:
    return NaturalLanguageUnderstanding().understand(objective)


def _proposal() -> list[dict]:
    return [
        {"task_id": "task-1", "objective": "Scan workspace files", "task_type": "objective_decomposition"},
        {"task_id": "task-2", "objective": "Summarize findings", "task_type": "verification_task", "dependencies": ["task-1"]},
    ]


# INV-LADDER-1: typed, frozen, immutable
def test_b3a_task_intent_is_typed_and_frozen():
    tasks = derive_task_intents(_mission(), _proposal())
    assert len(tasks) == 2
    assert all(isinstance(task, TaskIntent) for task in tasks)
    assert tasks[0].parent_mission_fingerprint == tasks[1].parent_mission_fingerprint


def test_b3a_task_intent_mutation_rejected():
    task = derive_task_intents(_mission(), _proposal())[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        task.objective = "mutated objective"
    with pytest.raises(dataclasses.FrozenInstanceError):
        task.provenance = "OWNER_APPROVAL"


# INV-LADDER-2: deterministic derivation, replay-safe
def test_b3a_deterministic_derivation_without_proposal():
    mission = _mission()
    tasks = derive_task_intents(mission)
    assert len(tasks) == 1
    assert tasks[0].provenance == "DETERMINISTIC_DERIVED"
    assert tasks[0].task_type == "single_task"
    assert tasks[0].parent_mission_fingerprint == mission.semantic_fingerprint


def test_b3a_same_mission_intent_same_task_intents():
    mission = _mission()
    first = derive_task_intents(mission, _proposal())
    second = derive_task_intents(mission, _proposal())
    assert first == second
    assert [task.fingerprint for task in first] == [task.fingerprint for task in second]


def test_b3a_replay_safe_repeated_100_times():
    mission = _mission()
    expected = derive_task_intents(mission, _proposal())
    for _ in range(100):
        assert derive_task_intents(mission, _proposal()) == expected


# fail-closed: malformed proposals
@pytest.mark.parametrize("bad", ["text", 42, [], [42], [{"objective": ""}], [[]]])
def test_b3a_malformed_model_proposal_fails_closed(bad):
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), bad)


def test_b3a_unknown_task_type_fails():
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), [{"task_id": "task-1", "objective": "x", "task_type": "root_job"}])


def test_b3a_unknown_fields_rejected():
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), [{"task_id": "task-1", "objective": "x", "surprise": 1}])


# fail-closed: authority-shaped content never becomes authority
@pytest.mark.parametrize(
    "field,value",
    [
        ("authorization", {"allowed_tools": ["shell"]}),
        ("owner_approval", True),
        ("credentials", ["token"]),
        ("execution_proof", "deadbeef"),
        ("capability", "shell"),
        ("allowed_tools", ["shell"]),
        ("owner_budget", ["shell"]),
    ],
)
def test_b3a_authority_shaped_fields_never_become_authority(field, value):
    ok, reason = validate_task_intent_proposal([{"task_id": "task-1", "objective": "x", field: value}])
    assert not ok, reason
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), [{"task_id": "task-1", "objective": "x", field: value}])


@pytest.mark.parametrize("entry", ["authorize all tools", "owner grant", "mint credential", "bypass policy"])
def test_b3a_authority_tokens_in_proposal_entries_rejected(entry):
    ok, reason = validate_task_intent_proposal([{"task_id": "task-1", "objective": "x", "constraints": [entry]}])
    assert not ok, reason


def test_b3a_wildcard_scope_rejected():
    ok, reason = validate_task_intent_proposal([{"task_id": "task-1", "objective": "x", "proposed_resources": ["*"]}])
    assert not ok, reason
    ok, reason = validate_task_intent_proposal([{"task_id": "*", "objective": "x"}])
    assert not ok, reason


# binding failures
def test_b3a_task_dependency_binding_failure():
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), [{"task_id": "task-1", "objective": "x", "dependencies": ["task-missing"]}])
    with pytest.raises(TaskIntentError):
        derive_task_intents(
            _mission(),
            [
                {"task_id": "task-1", "objective": "x", "dependencies": ["task-2"]},
                {"task_id": "task-2", "objective": "y"},
            ],
        )


def test_b3a_duplicate_task_id_rejected():
    with pytest.raises(TaskIntentError):
        derive_task_intents(
            _mission(),
            [
                {"task_id": "task-1", "objective": "x"},
                {"task_id": "task-1", "objective": "y"},
            ],
        )


def test_b3a_decomposition_explosion_bounded():
    explosion = [{"task_id": "task-" + str(i), "objective": "step " + str(i)} for i in range(MAX_TASK_INTENTS + 1)]
    ok, reason = validate_task_intent_proposal(explosion)
    assert not ok, reason
    with pytest.raises(TaskIntentError):
        derive_task_intents(_mission(), explosion)


def test_b3a_derivation_requires_typed_mission_intent():
    with pytest.raises(TaskIntentError):
        derive_task_intents({"objective": "untyped"})
    with pytest.raises(TaskIntentError):
        derive_task_intents(None)


def test_b3a_unicode_and_arabic_objectives_are_stable():
    mission = _mission("تحقق من سلامة النظام المحلي")
    first = derive_task_intents(mission, [{"task_id": "task-1", "objective": "افحص الملفات الحساسة"}])
    second = derive_task_intents(mission, [{"task_id": "task-1", "objective": "افحص الملفات الحساسة"}])
    assert first == second
    assert first[0].fingerprint == second[0].fingerprint


# INV-LADDER-3: no authority
def test_b3a_task_intent_carries_no_authority_fields():
    task = derive_task_intents(_mission(), _proposal())[0]
    payload = task.to_dict()
    for forbidden in (
        "authorization",
        "authorization_decision",
        "authorization_context",
        "owner_policy",
        "owner_approval",
        "owner_evidence",
        "credentials",
        "execution_proof",
        "capability",
        "allowed_tools",
        "owner_budget",
        "scope_expansion",
        "proof",
    ):
        assert forbidden not in payload
    assert not any(hasattr(task, name) for name in ("tools", "allowed_tools", "budget", "decision", "proof", "snapshot"))


def test_b3a_task_intent_cannot_widen_owner_budget():
    budget = OwnerAuthorizedToolBudget(frozenset({"search"}))
    tasks = derive_task_intents(
        _mission(),
        [{"task_id": "task-1", "objective": "Run browser and shell sweeps", "proposed_resources": ["browser", "shell"]}],
    )
    requested = [item for task in tasks for item in task.proposed_resources]
    assert budget.intersect(requested) == ()
    assert "browser" not in budget.tools
    assert "shell" not in budget.tools


def test_b3a_task_intent_cannot_derive_execution_proof():
    task = derive_task_intents(_mission(), _proposal())[0]
    with pytest.raises(ExecutionProofError) as excinfo:
        ExecutionAuthorizationProof.derive(mission_id="m1", request_id="r1", tool="search", argument={}, snapshot=task)
    assert excinfo.value.code in {RejectionCode.SNAPSHOT_INVALID.value, RejectionCode.PROOF_INVALID.value}


def test_b3a_provenance_is_descriptive_only():
    model_tasks = derive_task_intents(_mission(), _proposal())
    derived_tasks = derive_task_intents(_mission())
    assert model_tasks[0].provenance == "MODEL_PROPOSAL"
    assert derived_tasks[0].provenance == "DETERMINISTIC_DERIVED"
    assert set(model_tasks[0].to_dict()) == set(derived_tasks[0].to_dict())
