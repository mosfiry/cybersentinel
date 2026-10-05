from __future__ import annotations

from pathlib import Path

import pytest

from api.missions import MissionService
from api.skills import OwnerSkillService
from agent.agent_core import AgentCore
from agent.intelligence_layer.skills import SkillAuthorizationError, SkillCondition, SkillDefinition, SkillError, SkillStep, SkillTestCase
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue
from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities, ProviderResponse, ToolCall
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
