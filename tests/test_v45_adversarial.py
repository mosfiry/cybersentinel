import json

import pytest

from agent.evidence import observed, verify_chain
from agent.model_router import ModelRouter
from agent.runtime import AgentRuntime
from security.plan_integrity import plan_hash, validate_plan_object
from tools.registry import ToolSpec, build_registry, execute


class ForgedProvider:
    name = "trusted-name"
    model = "trusted-model"

    def status(self):
        return {"name": self.name, "model": self.model}

    def chat(self, messages, temperature=0):
        return {"content": json.dumps({"tools": ["status"]}), "provider": "forged", "model": "forged-model"}


def test_registry_rejects_duplicates_and_invalid_handlers():
    spec = ToolSpec("x", "read", "read", True, None, lambda _: None)
    with pytest.raises(ValueError):
        build_registry([spec, spec])
    with pytest.raises(ValueError):
        build_registry([ToolSpec("bad", "bad", "read", True, None, None)])
    with pytest.raises(ValueError):
        build_registry([ToolSpec("bad-risk", "bad", "dangerous", True, None, lambda _: None)])


def test_plan_schema_rejects_unknown_fields_and_hash_is_canonical():
    with pytest.raises(ValueError):
        validate_plan_object({"tools": ["status"], "unknown": "inject"})
    assert plan_hash([{"b": 1, "a": 2}]) == plan_hash([{"a": 2, "b": 1}])


def test_router_discards_forged_provider_metadata():
    result = ModelRouter([ForgedProvider()]).chat([])
    assert result["provider"] == "trusted-name"
    assert result["model"] == "trusted-model"
    assert AgentRuntime(ModelRouter([ForgedProvider()])).plan("Owner status")["provider"] == "trusted-name"


def test_tampered_evidence_is_detected():
    first = observed("one", "test", {"value": 1}, request_id="r", sequence=1)
    second = observed("two", "test", {"value": 2}, request_id="r", sequence=2, previous_hash=first["current_hash"])
    assert verify_chain([first, second])
    tampered = dict(second)
    tampered["evidence"] = {"value": "changed"}
    assert not verify_chain([first, tampered])


def test_unknown_tool_cannot_reach_handler():
    with pytest.raises(ValueError):
        execute("delete_everything")


def test_run_project_tests_is_bounded_and_not_shell(tmp_path):
    # The registry no longer mints a compatibility authorization snapshot: a
    # governed workspace, a real Owner mission authorization snapshot and an
    # execution proof derived from that snapshot are required. Argument
    # escape ("../") is rejected even with its own correctly-derived proof,
    # because the proof binds the exact arguments and cannot widen them.
    from datetime import datetime, timedelta, timezone

    from security.execution_proof import ExecutionAuthorizationProof
    from security.mission_authorization import MissionAuthorizationSnapshot
    from workspace import Workspace

    now = datetime.now(timezone.utc)
    snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner-proof",
        mission_id="m1",
        target_identity="target-1",
        scope=["workspace"],
        allowed_actions=["run_project_tests"],
        forbidden_actions=[],
        allowed_tools=["run_project_tests"],
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={"run_project_tests": 1},
        network_boundary={"allowed": []},
        data_boundary={"allowed": ["target-1"]},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": str(tmp_path)},
        policy_version="policy-v1",
        owner_approval="approval",
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=10)).isoformat(),
    )
    workspace = Workspace(tmp_path, authorization_snapshot=snapshot)
    proof = ExecutionAuthorizationProof.derive(mission_id="m1", request_id="req-1", tool="run_project_tests", argument=".", snapshot=snapshot, mission_status="READY", lifecycle_revision=0)
    result = execute("run_project_tests", ".", request_id="req-1", mission_authorization=snapshot, workspace=workspace, mission_id="m1", execution_proof=proof)
    assert set(result) == {"ok", "timed_out", "returncode", "output"}
    escape_proof = ExecutionAuthorizationProof.derive(mission_id="m1", request_id="req-1", tool="run_project_tests", argument="../", snapshot=snapshot, mission_status="READY", lifecycle_revision=0)
    with pytest.raises(ValueError):
        execute("run_project_tests", "../", request_id="req-1", mission_authorization=snapshot, workspace=workspace, mission_id="m1", execution_proof=escape_proof)
