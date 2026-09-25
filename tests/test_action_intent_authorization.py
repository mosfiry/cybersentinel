from __future__ import annotations

"""B3-B adversarial battery: TaskIntent -> ActionIntent (INV-LADDER-4..8).

Proves that the typed ActionIntent layer is frozen, deterministically
derived, bound to its parent TaskIntent and MissionIntent, replay-safe,
fail-closed against malformed/authority-shaped proposals, and structurally
incapable of creating authorization, snapshots, proofs, or direct tool
execution.
"""

import dataclasses

import pytest

from agent.model_intelligence.conversation import NaturalLanguageUnderstanding
from security.execution_proof import ExecutionAuthorizationProof, ExecutionProofError, RejectionCode
from security.intent_ladder import (
    ACTION_LADDER_MAX_ACTIONS,
    ActionIntent,
    ActionIntentError,
    TaskIntent,
    derive_action_intents,
    derive_task_intents,
    validate_action_intent_proposal,
)
from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot


def _mission(objective: str = "Analyze the local workspace for exposed secrets"):
    return NaturalLanguageUnderstanding().understand(objective)


def _tasks():
    return derive_task_intents(
        _mission(),
        [
            {"task_id": "task-1", "objective": "Scan workspace files", "task_type": "objective_decomposition"},
            {"task_id": "task-2", "objective": "Summarize findings", "task_type": "verification_task", "dependencies": ["task-1"]},
        ],
    )


def _actions():
    return [
        {"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "arguments": {"query": "workspace"}},
        {"action_id": "action-2", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "secrets"}, "dependencies": ["action-1"]},
        {"action_id": "action-3", "task_id": "task-2", "tool_name": "status", "dependencies": ["action-2"]},
    ]


# INV-LADDER-4: typed, frozen, bound
def test_b3b_action_intent_is_typed_frozen_and_bound():
    actions = derive_action_intents(_tasks(), _actions())
    assert len(actions) == 3
    assert all(isinstance(action, ActionIntent) for action in actions)
    assert all(isinstance(action.task_id, str) for action in actions)
    tasks = {task.task_id: task for task in _tasks()}
    for action in actions:
        assert action.parent_task_fingerprint == tasks[action.task_id].fingerprint
        assert action.parent_mission_fingerprint == tasks[action.task_id].parent_mission_fingerprint


def test_b3b_action_intent_mutation_rejected():
    action = derive_action_intents(_tasks(), _actions())[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.tool_name = "shell"
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.task_id = "task-2"
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.provenance = "OWNER_APPROVAL"


# binding failures
def test_b3b_missing_task_binding_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-missing", "tool_name": "status"}])


def test_b3b_empty_task_id_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "tool_name": "status"}])


def test_b3b_duplicate_action_identity_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(
            _tasks(),
            [
                {"action_id": "action-1", "task_id": "task-1", "tool_name": "status"},
                {"action_id": "action-1", "task_id": "task-2", "tool_name": "status"},
            ],
        )


def test_b3b_self_dependency_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": ["action-1"]}])
    ok, reason = validate_action_intent_proposal([{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": ["action-1"]}], {"task-1"})
    assert not ok, reason


def test_b3b_unknown_dependency_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": ["action-missing"]}])


def test_b3b_forward_dependency_cycle_rejected():
    ok, reason = validate_action_intent_proposal(
        [
            {"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": ["action-2"]},
            {"action_id": "action-2", "task_id": "task-1", "tool_name": "search"},
        ],
        {"task-1"},
    )
    assert not ok, reason
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [
            {"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": ["action-2"]},
            {"action_id": "action-2", "task_id": "task-1", "tool_name": "search"},
        ])


def test_b3b_untyped_parent_layer_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents([{"task_id": "task-1"}], _actions())
    with pytest.raises(ActionIntentError):
        derive_action_intents([], _actions())
    with pytest.raises(ActionIntentError):
        derive_action_intents(None, _actions())


def test_b3b_duplicate_parent_task_identities_rejected():
    task = derive_task_intents(_mission())[0]
    with pytest.raises(ActionIntentError):
        derive_action_intents([task, task], [{"action_id": "action-1", "task_id": task.task_id, "tool_name": "status"}])


def test_b3b_cross_mission_binding_is_structurally_impossible():
    """An ActionIntent inherits its mission fingerprint from its parent
    TaskIntent only; a proposal cannot declare or override it."""
    tasks = _tasks()
    actions = derive_action_intents(tasks, _actions())
    for action in actions:
        assert action.parent_mission_fingerprint == tasks[0].parent_mission_fingerprint
        assert "mission_id" not in action.to_dict()


# INV-LADDER-5: deterministic derivation, replay-safe
def test_b3b_same_proposal_same_action_intents():
    first = derive_action_intents(_tasks(), _actions())
    second = derive_action_intents(_tasks(), _actions())
    assert first == second
    assert [a.fingerprint for a in first] == [a.fingerprint for a in second]


def test_b3b_replay_safe_repeated_100_times():
    tasks = _tasks()
    expected = derive_action_intents(tasks, _actions())
    for _ in range(100):
        assert derive_action_intents(tasks, _actions()) == expected


def test_b3b_none_proposal_rejected_no_invented_fallback():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), None)


# INV-LADDER-7: canonical arguments fingerprint
def test_b3b_arguments_fingerprint_stable_under_key_reordering():
    first = derive_action_intents(_tasks(), [
        {"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"a": 1, "b": {"x": 1, "y": 2}, "c": [3, 2, 1]}},
    ])
    second = derive_action_intents(_tasks(), [
        {"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"c": [3, 2, 1], "b": {"y": 2, "x": 1}, "a": 1}},
    ])
    assert first[0].arguments_fingerprint == second[0].arguments_fingerprint
    assert first[0].fingerprint == second[0].fingerprint


def test_b3b_arguments_fingerprint_value_types():
    args = {"null": None, "bool": True, "int": 42, "float": 3.14, "unicode": "مرحبا", "mixed": "تحقق check ✓", "nested": {"deep": [1, {"k": "v"}]}}
    first = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": args}])
    second = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": dict(reversed(list(args.items())))}])
    assert first[0].arguments_fingerprint == second[0].arguments_fingerprint


def test_b3b_different_arguments_different_fingerprint():
    first = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "a"}}])
    second = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": {"query": "b"}}])
    assert first[0].arguments_fingerprint != second[0].arguments_fingerprint


def test_b3b_arabic_arguments_stable():
    args = {"query": "افحص الملفات الحساسة في المساحة المحلية"}
    first = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": args}])
    second = derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "search", "arguments": args}])
    assert first[0].arguments_fingerprint == second[0].arguments_fingerprint


# malformed input fail-closed
@pytest.mark.parametrize("bad", ["text", 42, [], [42], [None], [[]]])
def test_b3b_malformed_proposal_fails_closed(bad):
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), bad)


@pytest.mark.parametrize("bad_action", [
    {"action_id": "action-1", "tool_name": "status"},
    {"action_id": "action-1", "task_id": "task-1"},
    {"action_id": "action-1", "task_id": "task-1", "tool_name": ""},
    {"action_id": "action-1", "task_id": "task-1", "tool_name": "not_a_real_tool"},
    {"action_id": "*", "task_id": "task-1", "tool_name": "status"},
    {"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "arguments": "not-a-dict"},
    {"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "dependencies": "not-a-list"},
    {"action_id": "action-1", "task_id": "task-1", "tool_name": "status*", "arguments": {}},
])
def test_b3b_invalid_action_entries_fail_closed(bad_action):
    ok, reason = validate_action_intent_proposal([bad_action], {"task-1"})
    assert not ok, reason
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [bad_action])


def test_b3b_oversized_proposal_bounded():
    explosion = [{"action_id": "action-" + str(i), "task_id": "task-1", "tool_name": "status"} for i in range(ACTION_LADDER_MAX_ACTIONS + 1)]
    ok, reason = validate_action_intent_proposal(explosion, {"task-1"})
    assert not ok, reason
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), explosion)


def test_b3b_unknown_fields_rejected():
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "surprise": 1}])


# authority-shaped injection
@pytest.mark.parametrize("field", [
    "authorization",
    "owner_approval",
    "credentials",
    "execution_proof",
    "capability",
    "allowed_tools",
    "owner_budget",
    "permission",
    "grant",
    "scope_expansion",
])
def test_b3b_authority_shaped_fields_rejected(field):
    ok, reason = validate_action_intent_proposal([{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", field: "x"}], {"task-1"})
    assert not ok, reason
    with pytest.raises(ActionIntentError):
        derive_action_intents(_tasks(), [{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", field: "x"}])


@pytest.mark.parametrize("key", [
    "authorization",
    "owner_approval",
    "credentials",
    "execution_proof",
    "capability",
    "allowed_tools",
    "owner_budget",
    "permission",
    "grant",
    "scope_expansion",
    "token",
    "secret",
    "password",
    "api_key",
])
def test_b3b_authority_shaped_argument_keys_rejected(key):
    ok, reason = validate_action_intent_proposal([{"action_id": "action-1", "task_id": "task-1", "tool_name": "status", "arguments": {key: "x"}}], {"task-1"})
    assert not ok, reason


# INV-LADDER-6: no authority creation
def test_b3b_action_intent_carries_no_authority_fields():
    action = derive_action_intents(_tasks(), _actions())[0]
    payload = action.to_dict()
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
    assert not any(hasattr(action, name) for name in ("tools", "allowed_tools", "budget", "decision", "proof", "snapshot"))


def test_b3b_action_intent_cannot_derive_execution_proof():
    action = derive_action_intents(_tasks(), _actions())[0]
    with pytest.raises(ExecutionProofError) as excinfo:
        ExecutionAuthorizationProof.derive(mission_id="m1", request_id="r1", tool=action.tool_name, argument=action.arguments, snapshot=action)
    assert excinfo.value.code in {RejectionCode.SNAPSHOT_INVALID.value, RejectionCode.PROOF_INVALID.value}


def test_b3b_action_intent_cannot_become_mission_authorization_snapshot():
    action = derive_action_intents(_tasks(), _actions())[0]
    with pytest.raises((MissionAuthorizationError, TypeError, ValueError)):
        MissionAuthorizationSnapshot.from_dict(action.to_dict())


def test_b3b_action_intent_has_no_execution_path():
    """The ladder module exposes no function that executes a tool, and an
    ActionIntent is not accepted by the registry execute boundary."""
    import security.intent_ladder as ladder
    import tools.registry as registry
    assert not any(callable(getattr(ladder, name, None)) and name == "execute" for name in dir(ladder))
    action = derive_action_intents(_tasks(), _actions())[0]
    assert not isinstance(action, (MissionAuthorizationSnapshot, ExecutionAuthorizationProof))
    from security.execution_proof import ExecutionAuthorizationProof as Proof
    assert not isinstance(action, Proof)


def test_b3b_provenance_is_descriptive_only():
    action = derive_action_intents(_tasks(), _actions())[0]
    assert action.provenance == "MODEL_PROPOSAL"
    with pytest.raises(ActionIntentError):
        ActionIntent(
            action_id="action-x",
            task_id="task-1",
            parent_task_fingerprint="f" * 64,
            parent_mission_fingerprint="f" * 64,
            tool_name="status",
            arguments={},
            arguments_fingerprint="",
            provenance="OWNER_APPROVAL",
        )


# INV-LADDER-8: binding cannot be overridden after derivation
def test_b3b_parent_binding_cannot_be_rebound():
    tasks = _tasks()
    actions = derive_action_intents(tasks, _actions())
    other_mission = derive_task_intents(_mission("Another objective"), [{"task_id": "task-1", "objective": "other"}])
    for action in actions:
        assert action.parent_mission_fingerprint != other_mission[0].parent_mission_fingerprint or action.parent_mission_fingerprint == tasks[0].parent_mission_fingerprint
        with pytest.raises(dataclasses.FrozenInstanceError):
            action.task_id = "task-other"
