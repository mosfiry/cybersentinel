from __future__ import annotations

from pathlib import Path

import pytest

from api.missions import MissionService
from api.skills import OwnerSkillService
from agent.agent_core import AgentCore
from agent.intelligence_layer.skills import SkillAuthorizationError, SkillCondition, SkillDefinition, SkillError, SkillStep, SkillTestCase
from agent.mission import Mission, MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
from agent.trajectory import EventType
from owner_session_testutils import allow_owner_sessions, persist_canonical_scope, workspace_scope_context


class StatusProvider:
    name = "mission-test"
    model = "mission-test-1"

    def __init__(self):
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)
        self.responses = [ProviderResponse(tool_calls=[ToolCall("run_project_tests", {"query": "."}, "workspace-source-call")])]

    def tool_calling(self, _messages, _tools, **_kwargs):
        return self.responses.pop(0)

    def generate(self, _messages, **_kwargs):
        return {"content": "unused"}


def _candidate_definition(description: str) -> SkillDefinition:
    return SkillDefinition(
        skill_id="owner-test-guide",
        name="Owner test guide",
        description=description,
        version=1,
        author_source="verified-owner-mission",
        capabilities=("workspace-test-review",),
        required_tools=("run_project_tests",),
        allowed_scope=("workspace",),
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 240}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        procedure=(SkillStep(
            "test-step", "run_project_tests", "run_project_tests",
            argument_bindings={"query": "input.query"}, expects_evidence=True,
        ),),
        preconditions=("Owner authorization is current",),
        postconditions=("The governed local test suite passes",),
        examples=(),
        tests=(SkillTestCase("test-fixture", {"query": "."}, ("run_project_tests",), {"test-step": {"ok": True}}),),
        provenance="derived from an Owner-verified mission",
        output_bindings={"ok": "step.test-step.ok"},
        precondition_checks=(SkillCondition("query-nonempty", "query", "non_empty"),),
        postcondition_checks=(SkillCondition("ok-true", "ok", "equals", True),),
    )


def _completed_mission(tmp_path: Path, monkeypatch):
    allow_owner_sessions(monkeypatch, "valid-owner")
    project = tmp_path / "owner-project"
    project.mkdir()
    (project / "test_owner_skill_source.py").write_text(
        "def test_verified_source():\n    assert 2 + 2 == 4\n",
        encoding="utf-8",
    )
    scope_snapshot = persist_canonical_scope(
        monkeypatch, tmp_path, owner_session_token="valid-owner",
        target_id="local-project:owner-skill-test",
    )
    store = MissionStore(tmp_path / "missions.sqlite3")
    core = AgentCore(ModelRouter([StatusProvider()]), store=store)
    mission = core.run_owner_mission(
        "Run project tests and verify they pass",
        owner_session_token="valid-owner",
        scope_context=workspace_scope_context(scope_snapshot, project),
    )
    assert mission.status.value == "GOAL_COMPLETED"
    assert mission.verify_integrity()
    assert mission.verification_state.get("verified") is True
    assert any(item.get("event") == "GoalVerified" for item in mission.trajectory)

    # Management operations use this canonical MissionService for authenticated
    # owner resolution and integrity-checked Mission loading. No runtime action
    # is dispatched by OwnerSkillService.
    runtime = MissionRuntime(store, executor=core._executor, require_execution_fence=True)
    mission_service = MissionService(runtime, MissionQueue(tmp_path / "management-queue.sqlite3"))
    service = OwnerSkillService(tmp_path / "skills.sqlite3", mission_service)
    return service, mission, store


def test_owner_skill_outcome_analysis_exposes_only_verified_safe_summary(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    analysis = service.analyze_mission("valid-owner", mission.mission_id)

    assert analysis["analysis_version"] == 1
    assert analysis["status"] == "GOAL_COMPLETED"
    assert analysis["outcome_class"] == "verified_success"
    assert analysis["verified"] is True
    assert analysis["completed_tool_sequence"] == ["run_project_tests"]
    assert analysis["evidence_count"] >= 1
    assert analysis["candidate_seed_eligible"] is True
    assert analysis["reason_code"] == "ready_for_owner_authored_candidate"
    assert len(analysis["analysis_digest"]) == 64
    assert set(analysis) == {
        "analysis_version", "status", "outcome_class", "verified", "completed_tool_sequence",
        "failure_classes", "evidence_count", "candidate_seed_eligible", "reason_code", "analysis_digest",
    }
    assert mission.owner_request not in str(analysis)
    assert "owner-project" not in str(analysis)
    assert service.registry.list_owner_revisions("owner:1") == []


def test_owner_skill_outcome_analysis_requires_verified_completion_trajectory(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    mission.trajectory = []
    mission.emit(EventType.MISSION_STARTED)
    mission.emit(EventType.PLAN_CREATED)
    mission.integrity_hash = mission.to_dict()["integrity_hash"]

    def authorized(mission_id, owner_session_token):
        assert mission_id == mission.mission_id
        assert owner_session_token == "valid-owner"
        return mission, "owner:1"

    monkeypatch.setattr(service.mission_service, "load_authorized_mission", authorized)
    analysis = service.analyze_mission("valid-owner", mission.mission_id)
    assert analysis["outcome_class"] == "verified_success"
    assert analysis["verified"] is True
    assert analysis["candidate_seed_eligible"] is False
    assert analysis["reason_code"] == "completion_trajectory_not_qualified"
    assert analysis["evidence_count"] == 0


def test_owner_skill_outcome_analysis_rejects_out_of_order_completion_trajectory(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    mission.trajectory = []
    mission.emit(EventType.GOAL_VERIFIED)
    mission.emit(EventType.MISSION_STARTED)
    mission.emit(EventType.MISSION_COMPLETED)
    mission.integrity_hash = mission.to_dict()["integrity_hash"]

    def authorized(mission_id, owner_session_token):
        assert mission_id == mission.mission_id
        assert owner_session_token == "valid-owner"
        return mission, "owner:1"

    monkeypatch.setattr(service.mission_service, "load_authorized_mission", authorized)
    analysis = service.analyze_mission("valid-owner", mission.mission_id)
    assert analysis["verified"] is True
    assert analysis["candidate_seed_eligible"] is False
    assert analysis["reason_code"] == "completion_trajectory_not_qualified"
    assert analysis["evidence_count"] == 0


def test_owner_skill_outcome_analysis_classifies_failure_without_candidate_eligibility(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    failed = Mission.create(
        mission.owner_request,
        mission.objective,
        mission.plan,
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        owner_identity_ref=mission.owner_identity_ref,
        authorization_snapshot=mission.authorization_snapshot,
        scope_snapshot=mission.scope_snapshot,
        provenance=mission.provenance,
    )
    failed.transition(MissionStatus.RUNNING, "test worker started")
    failed.failures = [{"class": "TIMEOUT"}, {"class": "<script>"}]
    failed.emit(EventType.FAILURE_DETECTED, data={"failure_class": "TIMEOUT"})
    failed.transition(MissionStatus.FAILED_RETRY_EXHAUSTED, "retry limit reached")
    failed.integrity_hash = failed.to_dict()["integrity_hash"]

    def authorized(mission_id, owner_session_token):
        assert mission_id == failed.mission_id
        assert owner_session_token == "valid-owner"
        return failed, "owner:1"

    monkeypatch.setattr(service.mission_service, "load_authorized_mission", authorized)
    analysis = service.analyze_mission("valid-owner", failed.mission_id)
    assert analysis["status"] == "FAILED_RETRY_EXHAUSTED"
    assert analysis["outcome_class"] == "failed"
    assert analysis["verified"] is False
    assert analysis["candidate_seed_eligible"] is False
    assert analysis["reason_code"] == "mission_failed"
    assert analysis["failure_classes"] == ["TIMEOUT"]
    assert analysis["completed_tool_sequence"] == []
    assert "<script>" not in str(analysis)
    assert service.registry.list_owner_revisions("owner:1") == []


def test_owner_skill_outcome_analysis_rejects_mission_integrity_tampering(tmp_path, monkeypatch):
    import json
    import sqlite3

    service, mission, store = _completed_mission(tmp_path, monkeypatch)
    with sqlite3.connect(store.db_path) as conn:
        row = conn.execute("SELECT payload FROM missions WHERE mission_id=?", (mission.mission_id,)).fetchone()
        payload = json.loads(row[0])
        payload["objective"] = "tampered objective"
        conn.execute(
            "UPDATE missions SET payload=? WHERE mission_id=?",
            (json.dumps(payload, ensure_ascii=False), mission.mission_id),
        )
    with pytest.raises(ValueError, match="mission_integrity_invalid"):
        service.analyze_mission("valid-owner", mission.mission_id)


def test_owner_skill_outcome_analysis_obeys_bounded_mission_payload_load(tmp_path, monkeypatch):
    import json
    import sqlite3
    import api.missions as missions_api

    service, mission, store = _completed_mission(tmp_path, monkeypatch)
    monkeypatch.setattr(missions_api, "MAX_OBSERVABILITY_MISSION_BYTES", 512)
    oversized = {
        "mission_id": mission.mission_id,
        "owner_identity_ref": "owner:1",
        "padding": "x" * 1024,
    }
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "UPDATE missions SET payload=? WHERE mission_id=?",
            (json.dumps(oversized), mission.mission_id),
        )
    with pytest.raises(ValueError, match="mission_observability_too_large"):
        service.analyze_mission("valid-owner", mission.mission_id)


def test_owner_skill_outcome_analysis_rejects_tampered_evidence_for_seed_eligibility(tmp_path, monkeypatch):
    import json
    import sqlite3

    service, mission, store = _completed_mission(tmp_path, monkeypatch)
    assert service.analyze_mission("valid-owner", mission.mission_id)["candidate_seed_eligible"] is True
    evidence_db = Path(store.db_path).with_name("evidence_chain.db")
    with sqlite3.connect(evidence_db) as db:
        row = db.execute("SELECT payload FROM evidence_chain ORDER BY sequence LIMIT 1").fetchone()
        assert row is not None
        record = json.loads(row[0])
        record["claim"] = "attacker-controlled replacement claim"
        db.execute(
            "UPDATE evidence_chain SET payload=? WHERE sequence=?",
            (json.dumps(record, sort_keys=True), record["sequence"]),
        )

    analysis = service.analyze_mission("valid-owner", mission.mission_id)
    assert analysis["outcome_class"] == "verified_success"
    assert analysis["candidate_seed_eligible"] is False
    assert analysis["reason_code"] == "completed_tool_sequence_not_fully_evidenced"
    assert analysis["evidence_count"] == 0
    assert "attacker-controlled" not in str(analysis)


def test_owner_skill_service_qualifies_only_real_fenced_mission_evidence(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    malicious_description = '<img src=x onerror="alert(1)">'
    candidate = service.submit_candidate(
        "valid-owner",
        mission.mission_id,
        _candidate_definition(malicious_description).to_dict(),
    )

    assert candidate["status"] == "candidate"
    assert candidate["active"] is False
    assert candidate["execution_mode"] == "untrusted_guidance_only"
    assert candidate["source_mission_id"] == mission.mission_id
    assert candidate["content_hash"]

    listed = service.list_revisions("valid-owner")
    assert len(listed) == 1
    assert candidate["skill_id"] == "owner-test-guide"
    assert listed[0]["status"] == "candidate"
    assert listed[0]["active"] is False
    assert listed[0]["description"] == malicious_description

    detail = service.detail("valid-owner", candidate["skill_id"], candidate["version"])
    assert detail["content_hash"] == candidate["content_hash"]
    # Candidate evidence is server-derived; client-supplied verifier IDs are not
    # accepted as qualification and are not reflected in the public DTO.
    assert "candidate_evidence" not in detail
    with pytest.raises(SkillAuthorizationError, match="content digest"):
        service.approve("valid-owner", candidate["skill_id"], 1, "0" * 64)

    approved = service.approve("valid-owner", candidate["skill_id"], 1, candidate["content_hash"])
    assert approved["status"] == "approved"
    assert approved["active"] is True
    assert service.registry.get_active("owner:1", candidate["skill_id"]) is not None

    revoked = service.revoke("valid-owner", candidate["skill_id"], 1, candidate["content_hash"])
    assert revoked["status"] == "revoked"
    assert revoked["active"] is False
    assert service.registry.get_active("owner:1", candidate["skill_id"]) is None


def test_owner_skill_service_rejects_foreign_owner_mission_and_revision_access(tmp_path, monkeypatch):
    service, mission, _store = _completed_mission(tmp_path, monkeypatch)
    definition = _candidate_definition("bounded status guidance")
    candidate = service.submit_candidate("valid-owner", mission.mission_id, definition.to_dict())
    import security.owner_password as owner_password

    original_resolve = owner_password.resolve_session

    def resolve_second_owner(token):
        if token == "foreign-owner-token":
            return {
                "session_id": "foreign-owner-session",
                "owner_id": 2,
                "username": "other-owner",
                "auth_method": "username_password",
                "expires_at": "2999-01-01T00:00:00+00:00",
            }
        return original_resolve(token)

    monkeypatch.setattr(owner_password, "resolve_session", resolve_second_owner)

    with pytest.raises(PermissionError, match="mission access denied"):
        service.submit_candidate("foreign-owner-token", mission.mission_id, definition.to_dict())
    with pytest.raises(PermissionError, match="mission access denied"):
        service.analyze_mission("foreign-owner-token", mission.mission_id)
    assert service.list_revisions("foreign-owner-token") == []
    with pytest.raises(KeyError, match="unknown_skill_revision"):
        service.detail("foreign-owner-token", candidate["skill_id"], 1)


def test_owner_skill_service_rejects_tampered_source_evidence_before_approval(tmp_path, monkeypatch):
    import json
    import sqlite3

    service, mission, store = _completed_mission(tmp_path, monkeypatch)
    candidate = service.submit_candidate(
        "valid-owner",
        mission.mission_id,
        _candidate_definition("candidate with tampered provenance").to_dict(),
    )
    evidence_db = Path(store.db_path).with_name("evidence_chain.db")
    with sqlite3.connect(evidence_db) as db:
        row = db.execute("SELECT payload FROM evidence_chain ORDER BY sequence LIMIT 1").fetchone()
        assert row is not None
        record = json.loads(row[0])
        record["claim"] = "attacker-controlled replacement claim"
        db.execute(
            "UPDATE evidence_chain SET payload=? WHERE sequence=?",
            (json.dumps(record, sort_keys=True), record["sequence"]),
        )

    with pytest.raises(SkillError, match="evidence chain integrity"):
        service.approve("valid-owner", candidate["skill_id"], 1, candidate["content_hash"])
