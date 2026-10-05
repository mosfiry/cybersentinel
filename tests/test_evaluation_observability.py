from __future__ import annotations

import json
import sqlite3

import pytest

from agent.evidence import Evidence, EvidenceChainStore
from agent.mission import Mission, MissionStore
from agent.planning import Plan, PlanStep
from agent.execution_fence import authorization_digest
from api.evaluation_observability import (
    MissionEvaluationSummaryError,
    MissionEvaluationSummaryService,
    MissionEvaluationSummaryTooLarge,
)
from evaluation.agent_evaluation import (
    EvaluationError,
    EvaluationMeasurement,
    EvaluationMetric,
    EvaluationRun,
    EvaluationStore,
)
from runtime_authorization import make_test_snapshot


class _AuthorizedMissionService:
    def __init__(self, mission):
        self.mission = mission

    def load_authorized_mission(self, mission_id, owner_session_token):
        if owner_session_token != "owner-session-token" or mission_id != self.mission.mission_id:
            raise KeyError("unknown_mission")
        return self.mission, self.mission.owner_identity_ref


def _stored_mission(tmp_path, *, owner="owner:7", mission_id="mission-eval-1", with_evidence=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    plan = Plan(version=1, objective="Private mission objective", steps=(
        PlanStep(step_id="step-1", objective="Private task prompt", action="search"),
    ))
    mission = Mission.create(
        "Private mission objective",
        "Private mission objective",
        plan,
        mission_id=mission_id,
        request_id="request-eval-1",
        owner_identity_ref=owner,
    )
    mission.provenance["authorization_snapshot_version"] = 1
    snapshot = make_test_snapshot(mission)
    mission.authorization_snapshot = snapshot.to_dict()
    evidence_path = tmp_path / "evidence_chain.db"
    evidence_id = "evidence-eval-safe-1"
    if with_evidence:
        record = Evidence(
            claim="private evidence claim",
            source="tool",
            evidence={"payload": "PRIVATE_EVIDENCE_PAYLOAD"},
            verification="verified",
            confidence=10,
            evidence_id=evidence_id,
            request_id=mission.request_id,
            sequence=1,
            previous_hash="",
            mission_id=mission.mission_id,
            task_id="step-1",
            execution_id="execution-eval-1",
            worker_id="worker-eval-1",
            worker_instance_id="worker-instance-eval-1",
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
    store = MissionStore(tmp_path / "missions.sqlite3")
    store.save(mission)
    return store.load(mission.mission_id), store, evidence_path, evidence_id


def _run(owner, mission_id, *, evidence_id=None, marker="PRIVATE"):
    measurements = []
    for metric in EvaluationMetric:
        refs = (evidence_id,) if metric is EvaluationMetric.EVIDENCE_QUALITY and evidence_id else ()
        measurements.append(EvaluationMeasurement(metric, 0 if metric is EvaluationMetric.SAFETY_VIOLATIONS else 0.75, refs))
    return EvaluationRun(
        owner_identity_ref=owner,
        mission_id=mission_id,
        task_id=f"{marker}_TASK_TEXT",
        case_id=f"{marker}_CASE_TEXT",
        benchmark_version="2.0",
        provider_id=f"{marker}_PROVIDER_TEXT",
        model_id=f"{marker}_MODEL_TEXT",
        measurements=tuple(measurements),
        provenance={
            "prompt": f"{marker}_RAW_PROMPT",
            "provider_response": f"{marker}_RAW_PROVIDER_RESPONSE",
            "proposal": f"{marker}_RAW_PROPOSAL",
            "secret": "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890",
        },
        created_at="2026-10-05T12:00:00+00:00",
    )


def _service(mission, store, evidence_path):
    return MissionEvaluationSummaryService(
        _AuthorizedMissionService(mission),
        store,
        evidence_db_path=evidence_path,
    )


def test_no_run_returns_ten_explicitly_unavailable_metrics_without_creating_data(tmp_path):
    mission, _mission_store, evidence_path, _evidence_id = _stored_mission(tmp_path)
    missing_path = tmp_path / "missing-evaluation.sqlite3"
    with pytest.raises(EvaluationError, match="unavailable"):
        EvaluationStore(missing_path, read_only=True)
    assert not missing_path.exists()
    result = _service(mission, None, evidence_path).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
    )
    assert result["status"] == "no_run"
    assert result["run_count"] == 0
    assert result["verdict"] == "not_persisted"
    assert len(result["metrics"]) == len(EvaluationMetric) == 10
    assert all(item["status"] == "unavailable" and item["value"] is None for item in result["metrics"])

    empty_store_path = tmp_path / "empty-evaluations.sqlite3"
    EvaluationStore(empty_store_path)
    empty_store_result = _service(
        mission,
        EvaluationStore(empty_store_path, read_only=True),
        evidence_path,
    ).get(mission.mission_id, owner_session_token="owner-session-token")
    assert empty_store_result["status"] == "no_run"
    assert empty_store_result["run_count"] == 0
    assert len(empty_store_result["metrics"]) == 10


def test_bridge_does_not_create_an_evaluation_database_for_a_read_request(tmp_path, monkeypatch):
    import bridge
    from types import SimpleNamespace

    database_anchor = tmp_path / "missions.sqlite3"
    evidence_path = tmp_path / "evidence_chain.db"
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    mission_service = SimpleNamespace(runtime=SimpleNamespace(store=SimpleNamespace(db_path=database_anchor)))
    monkeypatch.setattr(bridge, "DB_PATH", database_anchor)
    handler = SimpleNamespace(_mission_service=lambda: mission_service)

    service = bridge.Handler._mission_evaluation_service(handler)

    assert service.evaluation_store is None
    assert service.evidence_db_path == evidence_path
    assert not evaluation_path.exists()


def test_summary_is_exact_owner_mission_scoped_and_only_exposes_opaque_verified_evidence(tmp_path):
    mission, _mission_store, evidence_path, evidence_id = _stored_mission(tmp_path, with_evidence=True)
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    writer = EvaluationStore(evaluation_path)
    writer.append(_run("owner:7", mission.mission_id, evidence_id=evidence_id), idempotency_key="current")
    writer.append(_run("owner:8", mission.mission_id, marker="FOREIGN_OWNER"), idempotency_key="foreign-owner")
    writer.append(_run("owner:7", "mission-other", marker="FOREIGN_MISSION"), idempotency_key="foreign-mission")

    before = evaluation_path.read_bytes()
    readonly = EvaluationStore(evaluation_path, read_only=True)
    result = _service(mission, readonly, evidence_path).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
    )
    assert result["status"] == "run_recorded"
    assert result["run_count"] == 1
    assert result["run_count_capped"] is False
    assert result["verdict"] == "not_persisted"
    assert len(result["metrics"]) == 10
    assert [item["metric"] for item in result["metrics"]] == [metric.value for metric in EvaluationMetric]
    assert all(item["status"] == "recorded" and isinstance(item["value"], (int, float)) for item in result["metrics"])
    evidence_metric = next(item for item in result["metrics"] if item["metric"] == "evidence_quality")
    assert evidence_metric["verified_evidence_refs"] == [
        MissionEvaluationSummaryService._opaque_ref("owner:7", mission.mission_id, evidence_id)
    ]
    assert evidence_metric["verified_evidence_refs"][0].startswith("evref_")
    assert evaluation_path.read_bytes() == before, "the public read path must not mutate EvaluationStore"
    assert evidence_id not in json.dumps(result)
    encoded = json.dumps(result)
    for forbidden in (
        "PRIVATE_RAW_PROMPT",
        "PRIVATE_RAW_PROVIDER_RESPONSE",
        "PRIVATE_RAW_PROPOSAL",
        "PRIVATE_PROVIDER_TEXT",
        "PRIVATE_MODEL_TEXT",
        "PRIVATE_TASK_TEXT",
        "PRIVATE_CASE_TEXT",
        "PRIVATE_EVIDENCE_PAYLOAD",
        "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890",
        "FOREIGN_OWNER",
        "FOREIGN_MISSION",
    ):
        assert forbidden not in encoded
    with pytest.raises(EvaluationError, match="read-only"):
        readonly.append(_run("owner:7", mission.mission_id), idempotency_key="forbidden-write")


def test_foreign_or_missing_mission_is_indistinguishable(tmp_path):
    mission, _mission_store, evidence_path, _evidence_id = _stored_mission(tmp_path)
    service = _service(mission, None, evidence_path)
    for mission_id, token in (("mission-other", "owner-session-token"), (mission.mission_id, "foreign-session")):
        with pytest.raises(KeyError, match="unknown_mission"):
            service.get(mission_id, owner_session_token=token)


def test_tampered_evaluation_record_fails_closed(tmp_path):
    mission, _mission_store, evidence_path, _evidence_id = _stored_mission(tmp_path)
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    writer = EvaluationStore(evaluation_path)
    stored = writer.append(_run("owner:7", mission.mission_id), idempotency_key="tamper")
    with sqlite3.connect(evaluation_path) as connection:
        connection.execute("DROP TRIGGER evaluation_no_update")
        connection.execute(
            "UPDATE evaluation_runs SET measurements_json='[]' WHERE evaluation_id=?",
            (stored.evaluation_id,),
        )
    readonly = EvaluationStore(evaluation_path, read_only=True)
    with pytest.raises(MissionEvaluationSummaryError, match="evaluation_integrity_invalid"):
        _service(mission, readonly, evidence_path).get(
            mission.mission_id,
            owner_session_token="owner-session-token",
        )


def test_evidence_chain_tampering_never_returns_an_unverified_reference(tmp_path):
    mission, _mission_store, evidence_path, evidence_id = _stored_mission(tmp_path, with_evidence=True)
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    writer = EvaluationStore(evaluation_path)
    writer.append(_run("owner:7", mission.mission_id, evidence_id=evidence_id), idempotency_key="tampered-chain")
    with sqlite3.connect(evidence_path) as connection:
        connection.execute("UPDATE evidence_chain SET payload=? WHERE sequence=1", (json.dumps({"evidence_id": evidence_id}),))
    result = _service(mission, EvaluationStore(evaluation_path, read_only=True), evidence_path).get(
        mission.mission_id,
        owner_session_token="owner-session-token",
    )
    metric = next(item for item in result["metrics"] if item["metric"] == "evidence_quality")
    assert result["evidence_status"] == "integrity_unverified"
    assert metric["verified_evidence_refs"] == []


def test_evidence_chain_resource_cap_fails_closed(tmp_path, monkeypatch):
    from api import evaluation_observability

    mission, _mission_store, evidence_path, evidence_id = _stored_mission(tmp_path, with_evidence=True)
    # Add a second structurally valid row so the configured one-record bound is exceeded.
    with sqlite3.connect(evidence_path) as connection:
        connection.execute(
            "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
            (2, "b" * 64, json.dumps({"evidence_id": "other"})),
        )
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    writer = EvaluationStore(evaluation_path)
    writer.append(_run("owner:7", mission.mission_id, evidence_id=evidence_id), idempotency_key="oversized-chain")
    monkeypatch.setattr(evaluation_observability, "MAX_EVIDENCE_CHAIN_RECORDS", 1)
    service = _service(mission, EvaluationStore(evaluation_path, read_only=True), evidence_path)
    with pytest.raises(MissionEvaluationSummaryTooLarge, match="verification bound"):
        service.get(mission.mission_id, owner_session_token="owner-session-token")


def test_serialized_summary_size_cap_is_enforced(tmp_path, monkeypatch):
    from api import evaluation_observability

    mission, _mission_store, evidence_path, _evidence_id = _stored_mission(tmp_path)
    evaluation_path = tmp_path / "agent_evaluations.sqlite3"
    writer = EvaluationStore(evaluation_path)
    writer.append(_run("owner:7", mission.mission_id), idempotency_key="response-cap")
    monkeypatch.setattr(evaluation_observability, "MAX_SUMMARY_BYTES", 1)
    service = _service(mission, EvaluationStore(evaluation_path, read_only=True), evidence_path)
    with pytest.raises(MissionEvaluationSummaryTooLarge, match="response bound"):
        service.get(mission.mission_id, owner_session_token="owner-session-token")
