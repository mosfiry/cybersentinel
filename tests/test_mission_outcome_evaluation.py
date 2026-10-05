from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.evidence import Evidence, EvidenceChainStore
from agent.execution_fence import authorization_digest
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState
from agent.planning import Plan, PlanStep
from agent.trajectory import EventType
from api.evaluation_observability import MissionEvaluationSummaryService
from evaluation.agent_evaluation import EvaluationError, EvaluationMetric, EvaluationStore
from evaluation.mission_outcomes import MissionOutcomeRecorder
from runtime_authorization import make_test_snapshot
from security.mission_authorization import MissionAuthorizationSnapshot


class _AuthorizedMissionService:
    def __init__(self, store: MissionStore, owner: str):
        self.store = store
        self.owner = owner

    def load_authorized_mission(self, mission_id: str, owner_session_token: str):
        if owner_session_token != "owner-session" or mission_id == "foreign-id":
            raise KeyError("unknown_mission")
        mission = self.store.load(mission_id)
        if mission is None or mission.owner_identity_ref != self.owner:
            raise KeyError("unknown_mission")
        return mission, self.owner


def _terminal_mission(tmp_path: Path, *, with_evidence: bool = True, status: MissionStatus = MissionStatus.GOAL_COMPLETED):
    tmp_path.mkdir(parents=True, exist_ok=True)
    owner = "owner:evaluation"
    mission = Mission.create(
        "PRIVATE_OWNER_PROMPT_MARKER",
        "PRIVATE_OBJECTIVE_MARKER",
        Plan(version=1, objective="Private plan", steps=(
            PlanStep(step_id="step-1", objective="Private task prompt", action="status"),
        )),
        mission_id="mission-evaluation-1",
        request_id="request-evaluation-1",
        owner_identity_ref=owner,
    )
    snapshot = make_test_snapshot(mission)
    mission.authorization_snapshot = snapshot.to_dict()
    mission.provenance["authorization_snapshot_version"] = snapshot.version
    mission.verification_state = {"verified": status is MissionStatus.GOAL_COMPLETED}
    mission.transition(status, "controlled evaluation fixture")
    mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state})

    evidence_path = tmp_path / "evidence_chain.db"
    if with_evidence:
        record = Evidence(
            claim="bounded evaluated observation",
            source="status",
            evidence={"private_payload": "NEVER_COPY_TO_EVALUATION"},
            verification="verified",
            confidence=10,
            evidence_id="evidence-evaluation-1",
            request_id=mission.request_id,
            sequence=1,
            previous_hash="",
            mission_id=mission.mission_id,
            task_id="step-1",
            execution_id="execution-evaluation-1",
            worker_id="worker-evaluation-1",
            worker_instance_id="worker-instance-evaluation-1",
            runtime_generation=1,
            lease_epoch=1,
            task_version=1,
            authorization_hash=authorization_digest(snapshot),
            fence_id="f" * 64,
        )
        mission.progress["execution_evidence_refs"] = [EvidenceChainStore._receipt(record.to_dict())]
        with sqlite3.connect(evidence_path) as connection:
            connection.execute(
                "CREATE TABLE evidence_chain (sequence INTEGER PRIMARY KEY, current_hash TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
                (1, record.current_hash, json.dumps(record.to_dict(), sort_keys=True)),
            )

    mission_store = MissionStore(tmp_path / "missions.sqlite3")
    mission_store.save(mission)
    return mission_store.load(mission.mission_id), mission_store, evidence_path


def _recorder(tmp_path: Path, mission_store: MissionStore, evidence_path: Path) -> tuple[MissionOutcomeRecorder, EvaluationStore]:
    store = EvaluationStore(tmp_path / "agent_evaluations.sqlite3")
    return MissionOutcomeRecorder(mission_store, store, evidence_db_path=evidence_path), store


def test_completed_mission_records_only_measurable_metrics_and_summary_is_safe(tmp_path):
    mission, mission_store, evidence_path = _terminal_mission(tmp_path, with_evidence=True)
    mission.progress["model_loop"] = {"turns": [
        {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}},
        {"usage": {"total_tokens": 7}},
    ]}
    mission.agent_task_graph_state = {"specialist_graph": {"graph": {
        "agents": [
            {"agent_id": agent_id, "mission_id": mission.mission_id, "owner_identity_ref": mission.owner_identity_ref,
             "permission_scope": {"mission_id": mission.mission_id, "owner_identity_ref": mission.owner_identity_ref},
             "lifecycle": lifecycle}
            for agent_id, lifecycle in (("agent-1", "COMPLETED"), ("agent-2", "FAILED"))
        ],
        "tasks": [
            {"task_id": "child-1", "mission_id": mission.mission_id, "assigned_agent_id": "agent-1", "lifecycle": "COMPLETED", "result": "PRIVATE_UNTRUSTED_PROPOSAL"},
            {"task_id": "child-2", "mission_id": mission.mission_id, "assigned_agent_id": "agent-2", "lifecycle": "FAILED", "result": "PRIVATE_UNTRUSTED_PROPOSAL"},
        ],
    }}}
    mission_store.save(mission)
    recorder, evaluation_store = _recorder(tmp_path, mission_store, evidence_path)

    stored = recorder.record(mission.mission_id)
    assert stored is not None
    metrics = stored.run.measurement_map()
    assert set(metrics) == {
        EvaluationMetric.TASK_SUCCESS,
        EvaluationMetric.EVIDENCE_QUALITY,
        EvaluationMetric.LATENCY,
        EvaluationMetric.TOKEN_USAGE,
        EvaluationMetric.AGENT_COORDINATION,
    }
    assert metrics[EvaluationMetric.TASK_SUCCESS].value == 1.0
    assert metrics[EvaluationMetric.EVIDENCE_QUALITY].value == 1.0
    assert metrics[EvaluationMetric.EVIDENCE_QUALITY].evidence_refs == ("evidence-evaluation-1",)
    assert 0 <= metrics[EvaluationMetric.LATENCY].value <= 31 * 24 * 60 * 60 * 1000
    assert metrics[EvaluationMetric.TOKEN_USAGE].value == 22
    assert metrics[EvaluationMetric.AGENT_COORDINATION].value == 0.5
    assert stored.run.provenance["metric_definition_evidence_quality"].endswith("not_semantic_support")
    assert stored.run.provenance["metric_definition_token_usage"].endswith("not_attested_ground_truth")
    assert stored.run.provenance["metric_definition_agent_coordination"].endswith("not_semantic_quality")
    assert tuple(stored.run.provenance["not_measured"]) == (
        "hallucination", "tool_correctness", "skill_usefulness", "memory_usefulness",
        "cost", "recovery", "safety_violations",
    )
    assert "PRIVATE_OWNER_PROMPT_MARKER" not in json.dumps(stored.run.to_dict())
    assert "PRIVATE_OBJECTIVE_MARKER" not in json.dumps(stored.run.to_dict())
    assert "NEVER_COPY_TO_EVALUATION" not in json.dumps(stored.run.to_dict())
    assert "PRIVATE_UNTRUSTED_PROPOSAL" not in json.dumps(stored.run.to_dict())

    repeated = recorder.record(mission.mission_id)
    assert repeated is not None and repeated.evaluation_id == stored.evaluation_id
    assert len(evaluation_store.list(owner_identity_ref=mission.owner_identity_ref, mission_id=mission.mission_id)) == 1

    service = MissionEvaluationSummaryService(
        _AuthorizedMissionService(mission_store, mission.owner_identity_ref),
        evaluation_store,
        evidence_db_path=evidence_path,
    )
    summary = service.get(mission.mission_id, owner_session_token="owner-session")
    metrics_by_name = {item["metric"]: item for item in summary["metrics"]}
    assert summary["status"] == "run_recorded"
    assert summary["verdict"] == "not_persisted"
    assert metrics_by_name["evidence_quality"]["value"] == 1.0
    assert metrics_by_name["evidence_quality"]["verified_evidence_ref_count"] == 1
    assert metrics_by_name["evidence_quality"]["verified_evidence_refs"][0].startswith("evref_")
    assert "evidence-evaluation-1" not in json.dumps(summary)


def test_missing_evidence_and_reconcilable_statuses_are_not_invented_as_quality(tmp_path):
    mission, mission_store, evidence_path = _terminal_mission(tmp_path, with_evidence=False)
    recorder, evaluation_store = _recorder(tmp_path, mission_store, evidence_path)
    stored = recorder.record(mission.mission_id)
    assert stored is not None
    assert EvaluationMetric.TASK_SUCCESS in stored.run.measurement_map()
    assert EvaluationMetric.LATENCY in stored.run.measurement_map()
    assert EvaluationMetric.EVIDENCE_QUALITY not in stored.run.measurement_map()
    assert {"token_usage", "agent_coordination"}.issubset(set(stored.run.provenance["not_measured"]))

    resumable, store2, evidence2 = _terminal_mission(
        tmp_path / "resumable", with_evidence=False, status=MissionStatus.OWNER_REAUTH_REQUIRED
    )
    recorder2, eval2 = _recorder(tmp_path / "resumable", store2, evidence2)
    assert recorder2.record(resumable.mission_id) is None
    assert eval2.list(owner_identity_ref=resumable.owner_identity_ref, mission_id=resumable.mission_id) == []


def test_malformed_provider_usage_and_foreign_specialist_graph_are_not_measured(tmp_path):
    mission, mission_store, evidence_path = _terminal_mission(tmp_path, with_evidence=False)
    mission.progress["model_loop"] = {"turns": [
        {"usage": {"prompt_tokens": True, "completion_tokens": 3}},
    ]}
    mission.agent_task_graph_state = {"specialist_graph": {"graph": {
        "agents": [
            {"agent_id": "agent-1", "mission_id": mission.mission_id, "owner_identity_ref": mission.owner_identity_ref,
             "permission_scope": {"mission_id": mission.mission_id, "owner_identity_ref": mission.owner_identity_ref},
             "lifecycle": "COMPLETED"},
        ],
        "tasks": [
            {"task_id": "foreign-task", "mission_id": "foreign-mission", "assigned_agent_id": "agent-1", "lifecycle": "COMPLETED"},
        ],
    }}}
    mission_store.save(mission)

    recorder, _store = _recorder(tmp_path, mission_store, evidence_path)
    stored = recorder.record(mission.mission_id)
    assert stored is not None
    assert EvaluationMetric.TOKEN_USAGE not in stored.run.measurement_map()
    assert EvaluationMetric.AGENT_COORDINATION not in stored.run.measurement_map()
    assert {"token_usage", "agent_coordination"}.issubset(set(stored.run.provenance["not_measured"]))


def test_tampered_evidence_chain_makes_evidence_quality_unavailable_not_accepted(tmp_path):
    mission, mission_store, evidence_path = _terminal_mission(tmp_path, with_evidence=True)
    with sqlite3.connect(evidence_path) as connection:
        row = connection.execute("SELECT payload FROM evidence_chain WHERE sequence=1").fetchone()
        payload = json.loads(row[0])
        payload["claim"] = "tampered claim"
        connection.execute("UPDATE evidence_chain SET payload=? WHERE sequence=1", (json.dumps(payload),))
    recorder, _evaluation_store = _recorder(tmp_path, mission_store, evidence_path)
    stored = recorder.record(mission.mission_id)
    assert stored is not None
    assert EvaluationMetric.TASK_SUCCESS in stored.run.measurement_map()
    assert EvaluationMetric.EVIDENCE_QUALITY not in stored.run.measurement_map()


def test_foreign_owner_authorization_and_tampered_mission_fail_closed(tmp_path):
    mission, mission_store, evidence_path = _terminal_mission(tmp_path, with_evidence=False)
    foreign = MissionAuthorizationSnapshot.create(
        owner_identity="owner:foreign",
        mission_id=mission.mission_id,
        target_identity="test-target",
        scope=("workspace",),
        allowed_actions=("status",),
        forbidden_actions=(),
        allowed_tools=("status",),
        time_window={"timezone": "UTC"},
        max_duration=300,
        rate_limits={"status": 1},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": "/workspace/test"},
        policy_version="test-policy-v1",
        owner_approval="foreign-owner-approval",
    )
    mission.authorization_snapshot = foreign.to_dict()
    mission_store.save(mission)
    recorder, _ = _recorder(tmp_path, mission_store, evidence_path)
    with pytest.raises(EvaluationError, match="authorization binding"):
        recorder.record(mission.mission_id)

    # Rebuild a valid mission, then tamper with its payload without updating its digest.
    mission, mission_store, evidence_path = _terminal_mission(tmp_path / "tampered", with_evidence=False)
    with sqlite3.connect(mission_store.db_path) as connection:
        row = connection.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
        payload = json.loads(row[0])
        payload["objective"] = "tampered"
        connection.execute("UPDATE missions SET payload=? WHERE mission_id=?", (json.dumps(payload), mission.mission_id))
    recorder, _ = _recorder(tmp_path / "tampered", mission_store, evidence_path)
    with pytest.raises(EvaluationError, match="unavailable"):
        recorder.record(mission.mission_id)


def test_worker_evaluation_failure_does_not_turn_completed_mission_into_retry(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-worker-outcome")

    class Completed:
        status = MissionStatus.GOAL_COMPLETED
        is_terminal = True
        evidence = []
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            assert mission_id == "mission-worker-outcome"
            return Completed()

    def recorder(_mission_id):
        raise RuntimeError("never reflect this exception")

    worker = MissionWorker(queue, lambda: Runtime(), outcome_recorder=recorder)
    result = worker.run_once()
    assert result.state is WorkerMissionState.COMPLETED
    assert result.last_error == ""
    assert worker.outcome_recording_failures == 1


def test_worker_records_outcome_only_for_terminal_mission_results(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("mission-worker-success")
    calls = []

    class Completed:
        status = MissionStatus.GOAL_COMPLETED
        is_terminal = True
        evidence = []
        error = ""

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            return Completed()

    worker = MissionWorker(queue, lambda: Runtime(), outcome_recorder=calls.append)
    result = worker.run_once()
    assert result.state is WorkerMissionState.COMPLETED
    assert calls == ["mission-worker-success"]
