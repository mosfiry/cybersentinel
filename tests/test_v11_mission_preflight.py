from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import security.authorization as authorization_module
import tools.registry as registry_module
from agent.context import RuntimeLimits
from agent.external_effects import ExternalEffectLedger
from agent.model_protocol import ModelTurn, ToolCallProposal, derive_action_id
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.provider_api import InvalidModelResponse
from runtime_authorization import make_test_snapshot, mission_model_tools


def _runtime_and_mission(
    tmp_path: Path,
    *,
    action: str,
    runtime_limits: RuntimeLimits | None = None,
) -> tuple[MissionRuntime, Any, MissionStore]:
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(
        store,
        executor=lambda *_args: {},
        authorization_snapshot_factory=make_test_snapshot,
        runtime_limits=runtime_limits,
    )
    objective = "exercise bounded model-turn preflight"
    plan = Plan.initial(objective).replan(
        steps=(PlanStep("v11-step", "exercise a bounded tool proposal", action=action),),
        reason="V11 adversarial test",
    )
    mission = runtime.create(
        objective,
        "v11-request",
        plan,
        completion_criteria=[{"criterion_id": "v11-goal"}],
    )
    return runtime, mission, store


def _proposal(
    mission: Any,
    run_id: str,
    turn_id: str,
    name: str,
    arguments: dict[str, Any],
    suffix: str,
    identity_overrides: dict[str, Any] | None = None,
) -> ToolCallProposal:
    identity = {
        "mission_id": mission.mission_id,
        "run_id": run_id,
        "turn_id": turn_id,
        "request_id": mission.request_id,
        "plan_version": mission.plan.version,
        "tool_call_id": f"v11-call-{suffix}",
    }
    identity.update(identity_overrides or {})
    return ToolCallProposal.create(name, arguments, **identity)


def _allow_structural(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(allowed=True, reason="test authorization", decision=None)


def _event_names(mission: Any) -> list[str]:
    return [event["event"] for event in mission.trajectory]


def test_malformed_sibling_rejects_valid_state_write_before_any_dispatch_or_ledger_row(tmp_path, monkeypatch):
    dispatches: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    authorizations: list[Any] = []

    def execute_spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        dispatches.append((args, kwargs))
        return {"ok": True, "source": "must-not-run"}

    def authorize_spy(*args: Any, **kwargs: Any) -> SimpleNamespace:
        authorizations.append((args, kwargs))
        return _allow_structural()

    monkeypatch.setattr(registry_module, "execute", execute_spy)
    monkeypatch.setattr(authorization_module, "authorize_tool", authorize_spy)
    runtime, mission, store = _runtime_and_mission(tmp_path, action="watch")

    class MixedBatchModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            assert mission_id == mission.mission_id
            assert plan_version == mission.plan.version
            return ModelTurn(
                turn_id,
                tool_calls=(
                    _proposal(mission, run_id, turn_id, "watch", {"query": "valid sibling"}, "valid"),
                    _proposal(mission, run_id, turn_id, "watch", {"query": "malformed sibling", "extra": "reject"}, "invalid"),
                ),
            )

    result = runtime.run_model_loop(
        mission.mission_id,
        MixedBatchModel(),
        tools=mission_model_tools("watch"),
        max_turns=1,
    )

    assert dispatches == []
    assert authorizations == []
    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["tool_results"] == []
    assert result.progress["model_loop"]["seen_call_ids"] == []
    assert result.evidence == []
    assert result.checkpoint.get("status") not in {"in_flight", "in_flight_parallel"}
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert not any(name in _event_names(result) for name in ("ModelTurn", "ToolProposed", "AuthorizationChecked"))
    ledger = ExternalEffectLedger(store.db_path)
    assert ledger.list_effects(mission_id=mission.mission_id) == []
    with sqlite3.connect(store.db_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "external_effect_events" in tables:
            assert connection.execute("SELECT COUNT(*) FROM external_effect_events").fetchone()[0] == 0


def test_stale_direct_native_model_turn_is_rejected_before_persistence(tmp_path):
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status")

    class StaleTurnModel:
        def complete(self, _messages, _tools, **_kwargs):
            return ModelTurn("old-run:turn:9", content="not current")

    result = runtime.run_model_loop(mission.mission_id, StaleTurnModel(), tools=[], max_turns=1)

    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["tool_results"] == []
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert "ModelTurn" not in _event_names(result)


@pytest.mark.parametrize(
    ("limits", "budget"),
    [
        (RuntimeLimits(max_context_chars=1), "max_context_chars"),
        (RuntimeLimits(max_context_messages=1), "max_context_messages"),
    ],
)
def test_owner_context_budgets_block_before_provider_call(tmp_path, limits, budget):
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status", runtime_limits=limits)

    class MustNotCallModel:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("context over budget must block before provider dispatch")

    model = MustNotCallModel()
    result = runtime.run_model_loop(mission.mission_id, model, tools=mission_model_tools("status"), max_turns=1)

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == budget
    assert model.calls == 0
    assert result.progress["model_loop"]["turns"] == []
    assert "ModelTurn" not in _event_names(result)


def test_owner_total_tool_budget_is_cumulative_across_model_turns(tmp_path, monkeypatch):
    executions: list[tuple[str, Any]] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow_structural)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda name, arguments, **_kwargs: executions.append((name, arguments)) or {"ok": True, "source": "budget-test"},
    )
    limits = RuntimeLimits(max_tool_calls=1, max_same_tool_calls=10)
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status", runtime_limits=limits)

    class TwoToolModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            if self.calls == 1:
                proposal = _proposal(mission, run_id, turn_id, "status", {}, "first")
            else:
                proposal = _proposal(mission, run_id, turn_id, "search", {"query": "distinct query"}, "second")
            return ModelTurn(turn_id, tool_calls=(proposal,))

    model = TwoToolModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status", "search"),
        max_turns=3,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_tool_calls"
    assert model.calls == 2
    assert executions == [("status", {})]
    assert len(result.progress["model_loop"]["turns"]) == 1
    assert len(result.progress["model_loop"]["tool_results"]) == 1
    assert _event_names(result).count("ModelTurn") == 1
    assert _event_names(result).count("ToolProposed") == 1


def test_owner_exact_repeat_budget_is_cumulative_across_model_turns(tmp_path, monkeypatch):
    executions: list[tuple[str, Any]] = []
    monkeypatch.setattr(authorization_module, "authorize_tool", _allow_structural)
    monkeypatch.setattr(
        registry_module,
        "execute",
        lambda name, arguments, **_kwargs: executions.append((name, arguments)) or {"ok": True, "source": "repeat-test"},
    )
    limits = RuntimeLimits(max_tool_calls=10, max_same_tool_calls=1)
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status", runtime_limits=limits)

    class RepeatingModel:
        calls = 0

        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            self.calls += 1
            proposal = _proposal(mission, run_id, turn_id, "status", {}, f"repeat-{self.calls}")
            return ModelTurn(turn_id, tool_calls=(proposal,))

    model = RepeatingModel()
    result = runtime.run_model_loop(
        mission.mission_id,
        model,
        tools=mission_model_tools("status"),
        max_turns=3,
    )

    assert result.status is MissionStatus.RESOURCE_BLOCKED
    assert result.failures[-1]["budget"] == "max_same_tool_calls"
    assert model.calls == 2
    assert executions == [("status", {})]
    assert len(result.progress["model_loop"]["turns"]) == 1
    assert len(result.progress["model_loop"]["tool_results"]) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mission_id", ""),
        ("mission_id", "other-mission"),
        ("run_id", ""),
        ("run_id", "stale-run"),
        ("turn_id", "stale-turn"),
        ("action_id", "model-selected-action"),
        ("plan_version", 0),
        ("plan_version", 999),
    ],
)
def test_missing_or_stale_model_input_identity_is_rejected_before_durable_turn(
    tmp_path, monkeypatch, field, value
):
    dispatches: list[Any] = []
    monkeypatch.setattr(registry_module, "execute", lambda *args, **kwargs: dispatches.append(args) or {"ok": True})
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status")

    class BadIdentityModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = _proposal(
                mission,
                run_id,
                turn_id,
                "status",
                {},
                "bad-identity",
                identity_overrides={field: value},
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    result = runtime.run_model_loop(
        mission.mission_id,
        BadIdentityModel(),
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert dispatches == []
    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["tool_results"] == []
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert result.checkpoint.get("status") not in {"in_flight", "in_flight_parallel"}
    assert not any(name in _event_names(result) for name in ("ModelTurn", "ToolProposed", "AuthorizationChecked"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "stale-request"),
        ("step_id", "stale-step"),
        ("authorization_context_id", "stale-auth-context"),
        ("scope_snapshot_id", "stale-scope-snapshot"),
    ],
)
def test_stale_runtime_owned_identity_is_rejected_before_durable_turn(
    tmp_path, monkeypatch, field, value
):
    dispatches: list[Any] = []
    monkeypatch.setattr(registry_module, "execute", lambda *args, **kwargs: dispatches.append(args) or {"ok": True})
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status")

    class StaleRuntimeIdentityModel:
        def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version):
            proposal = _proposal(
                mission,
                run_id,
                turn_id,
                "status",
                {},
                "stale-runtime-identity",
                identity_overrides={field: value},
            )
            return ModelTurn(turn_id, tool_calls=(proposal,))

    result = runtime.run_model_loop(
        mission.mission_id,
        StaleRuntimeIdentityModel(),
        tools=mission_model_tools("status"),
        max_turns=1,
    )

    assert dispatches == []
    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_loop"]["tool_results"] == []
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert not any(name in _event_names(result) for name in ("ModelTurn", "ToolProposed", "AuthorizationChecked"))


def test_one_message_context_is_allowed_by_exact_owner_message_limit(tmp_path, monkeypatch):
    import agent.mission_runtime as mission_runtime_module

    runtime, mission, _store = _runtime_and_mission(
        tmp_path,
        action="status",
        runtime_limits=RuntimeLimits(max_context_messages=1),
    )
    monkeypatch.setattr(
        mission_runtime_module.ContextAssembler,
        "build",
        lambda *_args, **_kwargs: SimpleNamespace(
            context_chars=1,
            messages=({"role": "user", "content": "x"},),
            context_hash="bounded-one-message",
            compacted=False,
            compacted_items=0,
        ),
    )

    class OneMessageFinalModel:
        message_counts: list[int] = []

        def complete(self, messages, _tools, *, turn_id, **_kwargs):
            self.message_counts.append(len(messages))
            return ModelTurn(turn_id, content="not yet verified")

    model = OneMessageFinalModel()
    result = runtime.run_model_loop(mission.mission_id, model, tools=[], max_turns=1)

    assert model.message_counts == [1]
    assert len(result.progress["model_loop"]["turns"]) == 1
    assert result.status is not MissionStatus.RESOURCE_BLOCKED
    assert not any(failure.get("budget") == "max_context_messages" for failure in result.failures)
    accepted_turn = result.progress["model_loop"]["turns"][0]
    assert accepted_turn["provider"] == "native"
    assert accepted_turn["model"].endswith("OneMessageFinalModel")
    assert accepted_turn["capability"] == "native"


def test_direct_native_model_cannot_claim_router_provenance(tmp_path):
    runtime, mission, _store = _runtime_and_mission(tmp_path, action="status")

    class ForgedProvenanceModel:
        trusted_provider = "attacker-selected-provider"
        trusted_model = "attacker-selected-model"
        trusted_capability = "tool_calling"

        def complete(self, _messages, _tools, *, turn_id, **_kwargs):
            return ModelTurn(
                turn_id,
                content="untrusted model provenance",
                provider=self.trusted_provider,
                model=self.trusted_model,
                capability=self.trusted_capability,
            )

    result = runtime.run_model_loop(
        mission.mission_id,
        ForgedProvenanceModel(),
        tools=[],
        max_turns=1,
    )

    assert result.progress["model_loop"]["turns"] == []
    assert result.progress["model_failures"][-1]["kind"] == "INVALID_MODEL_RESPONSE"
    assert not any(name == "ModelTurn" for name in _event_names(result))


@pytest.mark.parametrize("mutation", ["altered_schema", "extra_metadata", "duplicate", "unknown"])
def test_noncanonical_tool_definitions_fail_before_provider_or_effect(tmp_path, mutation):
    runtime, mission, store = _runtime_and_mission(tmp_path, action="watch")
    definitions = registry_module.model_tool_definitions(["watch"])
    if mutation == "altered_schema":
        definitions[0]["function"]["parameters"]["properties"]["query"]["maxLength"] = 4096
    elif mutation == "extra_metadata":
        definitions[0]["risk_class"] = "owner-approved"
    elif mutation == "duplicate":
        definitions.append(registry_module.model_tool_definitions(["watch"])[0])
    elif mutation == "unknown":
        definitions[0]["function"]["name"] = "unregistered_tool"

    class MustNotCallProvider:
        calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("noncanonical definitions must fail before provider dispatch")

    model = MustNotCallProvider()
    with pytest.raises(InvalidModelResponse):
        runtime.run_model_loop(mission.mission_id, model, tools=definitions, max_turns=1)

    saved = store.load(mission.mission_id)
    assert model.calls == 0
    assert saved.progress.get("model_loop") is None
    assert saved.progress.get("model_run_id") is None
    assert ExternalEffectLedger(store.db_path).list_effects(mission_id=mission.mission_id) == []


def test_action_id_encoding_is_unambiguous_for_embedded_separators():
    left = derive_action_id("a\0b", "c", "d")
    right = derive_action_id("a", "\0b", "c")
    assert left != right
