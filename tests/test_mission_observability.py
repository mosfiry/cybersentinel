from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from agent.intelligence_layer.events import EventStore, IntelligenceEventType
from agent.intelligence_layer.graph import TaskGraph
from agent.intelligence_layer.runtime_adapter import MissionTaskGraphAdapter
from agent.mission import Mission, MissionStore
from agent.planning import Plan, PlanStep
from api.observability import (
    MissionObservabilityError,
    MissionObservabilityService,
    MissionObservabilityTooLarge,
)
from api.missions import MissionService
from runtime_authorization import make_test_snapshot


class _AuthorizedMissionService:
    def __init__(self, mission):
        self.mission = mission

    def load_authorized_mission(self, mission_id, owner_session_token):
        if owner_session_token != "owner-session-token":
            raise PermissionError("denied")
        if mission_id != self.mission.mission_id:
            raise KeyError("unknown")
        if self.mission.owner_identity_ref != "owner:7":
            raise PermissionError("denied")
        return self.mission, "owner:7"


def _stored_mission(tmp_path, *, owner="owner:7", step_count=1):
    tmp_path.mkdir(parents=True, exist_ok=True)
    steps = tuple(
        PlanStep(
            step_id=f"step-{index + 1}",
            objective=f"TASK_PROMPT_SECRET_{index}",
            action="search",
        )
        for index in range(step_count)
    )
    plan = Plan(version=1, objective="MISSION_PROMPT_SECRET", steps=steps)
    mission = Mission.create(
        "MISSION_PROMPT_SECRET",
        "MISSION_PROMPT_SECRET",
        plan,
        mission_id="mission-observe-1",
        request_id="request-safe-1",
        owner_identity_ref=owner,
    )
    mission.provenance["authorization_snapshot_version"] = 1
    snapshot = make_test_snapshot(mission)
    mission.authorization_snapshot = snapshot.to_dict()
    if step_count == 1:
        adapter = MissionTaskGraphAdapter()
        graph, mapping = adapter._build(mission, snapshot, 1)
        for task_id in mapping.values():
            graph.claim_task(task_id, snapshot, authorization_version=1)
        task = next(iter(graph.tasks.values()))
        task.result = {"raw_tool_arguments": "TOOL_ARGUMENT_SECRET", "credential": "CREDENTIAL_SECRET"}
        task.error = "password=ERROR_SECRET"
        adapter._store(mission, graph, mapping, mission.plan.fingerprint, 0)
        mission.progress["execution_evidence_refs"] = [{
            "mission_id": mission.mission_id,
            "request_id": mission.request_id,
            "task_id": "step-1",
            "evidence_id": "evidence-safe-1",
            "sequence": 1,
            "fence_id": "f" * 64,
            "current_hash": "a" * 64,
            "execution_id": "EXECUTION_SECRET",
            "authorization_hash": "AUTHORIZATION_HASH_SECRET",
        }]
    mission.error = "Bearer PRIVATE_TOKEN_SECRET"
    store = MissionStore(tmp_path / "missions.sqlite3")
    store.save(mission)
    return store.load(mission.mission_id), store


def _service_for(mission, *, event_store=None):
    return MissionObservabilityService(
        _AuthorizedMissionService(mission),
        event_store=event_store,
    )


def test_projection_is_owner_bound_and_excludes_untrusted_prompts_results_errors_and_tool_data(tmp_path):
    mission, _store = _stored_mission(tmp_path)
    response = _service_for(mission).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
    )
    encoded = json.dumps(response, ensure_ascii=False)
    assert response["stage"]["status"] == "PLANNING"
    assert response["stage"]["error_category"] is None
    assert response["graph"]["available"] is True
    assert response["graph"]["tasks"][0]["status"] == "RUNNING"
    assert response["graph"]["tasks"][0]["error_category"] is None
    assert response["graph"]["tasks"][0]["evidence_refs"] == ["evidence-safe-1"]
    assert response["evidence_refs"] == [{
        "evidence_id": "evidence-safe-1",
        "sequence": 1,
        "task_id": response["graph"]["tasks"][0]["task_id"],
        "reference_type": "execution_fenced_receipt",
    }]
    assert response["stage"]["current_step"]["task_status"] == "RUNNING"
    for forbidden in (
        "MISSION_PROMPT_SECRET",
        "TASK_PROMPT_SECRET",
        "TOOL_ARGUMENT_SECRET",
        "CREDENTIAL_SECRET",
        "ERROR_SECRET",
        "PRIVATE_TOKEN_SECRET",
        "EXECUTION_SECRET",
        "AUTHORIZATION_HASH_SECRET",
        "a" * 64,
        "f" * 64,
        "raw_tool_arguments",
    ):
        assert forbidden not in encoded
    with pytest.raises(KeyError, match="unknown_mission"):
        _service_for(mission).get(mission.mission_id, owner_session_token="foreign-session")


def test_projection_includes_running_specialist_agents_but_never_proposal_bodies(tmp_path):
    mission, store = _stored_mission(tmp_path, step_count=2)
    snapshot = make_test_snapshot(mission)
    adapter = MissionTaskGraphAdapter()
    adapter.ensure(mission, snapshot)
    ready = adapter.ready_specialist_steps(mission, snapshot)
    step_ids = tuple(step_id for step_id, _task_id in ready)
    task_by_step = dict(ready)
    batch_id = "observability-specialist-batch"
    execution_ids = tuple(f"{batch_id}:{task_by_step[step_id]}" for step_id in step_ids)
    adapter.claim_specialist_batch(
        mission,
        snapshot,
        step_ids,
        batch_id=batch_id,
        provider_name="local",
        model_name="qwen-test",
        execution_ids=execution_ids,
    )
    task_ids = tuple(task_by_step[step_id] for step_id in step_ids)
    bindings = [
        {"task_id": task_id, "execution_id": execution_id}
        for task_id, execution_id in zip(task_ids, execution_ids)
    ]
    mission.checkpoint = {
        "status": "in_flight_specialists",
        "batch_id": batch_id,
        "task_ids": list(task_ids),
        "execution_ids": list(execution_ids),
        "task_execution_bindings": bindings,
    }
    specialist = mission.agent_task_graph_state["specialist_graph"]
    specialist_graph = TaskGraph.from_dict(specialist["graph"])
    specialist_graph.tasks[task_ids[0]].result = {
        "record_type": "UNTRUSTED_SPECIALIST_PROPOSAL",
        "authority": "none",
        "proposal": {"summary": "PROPOSAL_BODY_SECRET"},
    }
    specialist_graph.tasks[task_ids[0]].result_validation_state = "UNTRUSTED_PROPOSAL"
    specialist["graph"] = specialist_graph.to_dict()
    store.save(mission)
    mission = store.load(mission.mission_id)

    response = _service_for(mission).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
    )

    specialist_tasks = [task for task in response["graph"]["tasks"] if task["task_kind"] == "mission_specialist_analysis"]
    specialist_agents = [agent for agent in response["graph"]["agents"] if agent["role"] == "mission_specialist_analyst"]
    assert response["graph"]["specialist_available"] is True
    assert response["graph"]["specialist_revision"] is not None
    assert len(specialist_tasks) == 2
    assert len(specialist_agents) == 2
    assert all(task["status"] == "RUNNING" for task in specialist_tasks)
    assert all(agent["status"] == "RUNNING" for agent in specialist_agents)
    assert response["stage"]["current_step"]["specialist_task_status"] == "RUNNING"
    encoded = json.dumps(response, ensure_ascii=False)
    assert "PROPOSAL_BODY_SECRET" not in encoded
    assert '"proposal"' not in encoded


def test_foreign_mission_and_missing_mission_are_the_same_service_result(tmp_path):
    mission, _store = _stored_mission(tmp_path)
    service = _service_for(mission)
    with pytest.raises(KeyError, match="unknown_mission"):
        service.get("mission-other-owner", owner_session_token="owner-session-token")


def test_invalid_mission_integrity_and_trajectory_chain_fail_closed(tmp_path):
    mission, store = _stored_mission(tmp_path)
    mission.objective = "changed without updating the Mission digest"
    with pytest.raises(MissionObservabilityError, match="mission_integrity_invalid"):
        _service_for(mission).get(mission.mission_id, owner_session_token="owner-session-token")

    clean, store = _stored_mission(tmp_path / "second")
    clean.trajectory[0]["data"]["objective"] = "trajectory tampering"
    payload = clean.to_dict()
    clean.integrity_hash = payload["integrity_hash"]
    assert clean.verify_integrity() is True
    with pytest.raises(MissionObservabilityError, match="mission_timeline_integrity_invalid"):
        _service_for(clean).get(clean.mission_id, owner_session_token="owner-session-token")


def test_store_load_filters_by_canonical_owner_before_deserializing_and_redacts_integrity_errors(tmp_path, monkeypatch):
    mission, store = _stored_mission(tmp_path)
    service = MissionService(SimpleNamespace(store=store), object())
    import security.owner_password as owner_password

    monkeypatch.setattr(
        owner_password,
        "authenticated_owner",
        lambda token: {"owner_id": 7 if token == "owner-session-token" else 8},
    )
    loaded, owner_ref = service.load_authorized_mission(mission.mission_id, "owner-session-token")
    assert loaded.mission_id == mission.mission_id
    assert owner_ref == "owner:7"
    with pytest.raises(KeyError, match="unknown_mission"):
        service.load_authorized_mission(mission.mission_id, "foreign-owner-token")
    import api.missions as mission_api

    with monkeypatch.context() as context:
        context.setattr(mission_api, "MAX_OBSERVABILITY_MISSION_BYTES", 1)
        with pytest.raises(ValueError, match="mission_observability_too_large"):
            service.load_authorized_mission(mission.mission_id, "owner-session-token")

    payload = mission.to_dict()
    payload["objective"] = "tampered private mission data"
    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "UPDATE missions SET payload=? WHERE mission_id=?",
            (json.dumps(payload, ensure_ascii=False), mission.mission_id),
        )
    with pytest.raises(ValueError, match="mission_integrity_invalid"):
        service.load_authorized_mission(mission.mission_id, "owner-session-token")


def test_event_journal_is_owner_mission_scoped_sanitized_and_paginated(tmp_path):
    mission, _store = _stored_mission(tmp_path)
    events = EventStore(tmp_path / "mission_events.sqlite3")
    for index in range(3):
        events.append(
            owner_identity_ref="owner:7",
            mission_id=mission.mission_id,
            event_type=IntelligenceEventType.TOOL_CALLED,
            idempotency_key=f"tool-call-{index}",
            request_id=mission.request_id,
            task_id=f"step-{index + 1}",
            payload={
                "tool_id": "search",
                "argument_sha256": "ARGUMENT_DIGEST_SECRET",
                "password": "PASSWORD_SECRET",
            },
        )
    events.append(
        owner_identity_ref="owner:7",
        mission_id="mission-other",
        event_type=IntelligenceEventType.TOOL_CALLED,
        idempotency_key="foreign-mission-event",
        payload={"tool_id": "PRIVATE_MISSION_TOOL"},
    )
    events.append(
        owner_identity_ref="owner:8",
        mission_id=mission.mission_id,
        event_type=IntelligenceEventType.TOOL_CALLED,
        idempotency_key="foreign-owner-event",
        payload={"tool_id": "PRIVATE_OWNER_TOOL"},
    )
    result = _service_for(mission, event_store=events).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
        event_limit=2,
    )
    assert len(result["event_log"]["events"]) == 2
    assert result["event_log"]["has_more"] is True
    assert result["event_log"]["next_after_sequence"] == 2
    encoded = json.dumps(result, ensure_ascii=False)
    assert "ARGUMENT_DIGEST_SECRET" not in encoded
    assert "PASSWORD_SECRET" not in encoded
    assert "PRIVATE_MISSION_TOOL" not in encoded
    assert "PRIVATE_OWNER_TOOL" not in encoded
    assert "argument_sha256" not in encoded

    next_page = _service_for(mission, event_store=events).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
        event_after_sequence=2,
        event_limit=2,
    )
    assert [event["sequence"] for event in next_page["event_log"]["events"]] == [3]
    assert next_page["event_log"]["has_more"] is False


def test_mission_trajectory_timeline_uses_bounded_stable_offset_pages(tmp_path):
    mission, _store = _stored_mission(tmp_path)
    service = _service_for(mission)
    first = service.get(
        mission.mission_id,
        owner_session_token="owner-session-token",
        timeline_limit=1,
    )
    assert len(first["timeline"]["events"]) == 1
    assert first["timeline"]["events"][0]["sequence"] == 1
    assert first["timeline"]["has_more"] is True
    assert first["timeline"]["next_offset"] == 1

    second = service.get(
        mission.mission_id,
        owner_session_token="owner-session-token",
        timeline_offset=first["timeline"]["next_offset"],
        timeline_limit=1,
    )
    assert len(second["timeline"]["events"]) == 1
    assert second["timeline"]["events"][0]["sequence"] == 2
    assert second["timeline"]["has_more"] is False


def test_observability_enforces_page_task_and_trajectory_size_bounds(tmp_path):
    mission, _store = _stored_mission(tmp_path)
    service = _service_for(mission)
    with pytest.raises(ValueError, match="timeline_limit"):
        service.get(mission.mission_id, owner_session_token="owner-session-token", timeline_limit=51)
    with pytest.raises(ValueError, match="event_after_sequence"):
        service.get(mission.mission_id, owner_session_token="owner-session-token", event_after_sequence=2_147_483_648)

    oversized, _store = _stored_mission(tmp_path / "oversized", step_count=129)
    with pytest.raises(MissionObservabilityTooLarge, match="mission_plan_exceeds_observability_limit"):
        _service_for(oversized).get(oversized.mission_id, owner_session_token="owner-session-token")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda state: state["graph"].__setitem__("revision", True),
        lambda state: state["graph"]["tasks"][0].__setitem__("attempt_count", True),
    ],
)
def test_graph_projection_rejects_coercive_boolean_schema_values(tmp_path, mutation):
    mission, _store = _stored_mission(tmp_path)
    mutation(mission.agent_task_graph_state)
    mission.integrity_hash = mission.to_dict()["integrity_hash"]
    with pytest.raises(MissionObservabilityError, match="mission_graph_integrity_invalid"):
        _service_for(mission).get(mission.mission_id, owner_session_token="owner-session-token")
