from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from agent.evidence import EvidenceChainStore
from agent.mission_worker import MissionQueue, WorkerMissionState
from agent.self_repair import BoundedSelfRepair
from security.authorization import authorize_tool
from security.authorization_context import AuthorizationContext
from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import execute
from workspace import Workspace, WorkspaceBoundaryError, WorkspacePolicyError


def auth(root: str, *, mission_id: str = "m1", owner: str = "owner-proof", actions=None, tools=None, forbidden=None, expiry=None):
    created = (expiry - timedelta(minutes=1)) if expiry is not None and expiry <= datetime.now(timezone.utc) else datetime.now(timezone.utc)
    return MissionAuthorizationSnapshot.create(
        owner_identity=owner,
        mission_id=mission_id,
        target_identity="target-1",
        scope=["workspace"],
        allowed_actions=list(actions if actions is not None else ["run_project_tests", "read", "write", "process", "development"]),
        forbidden_actions=list(forbidden if forbidden is not None else []),
        allowed_tools=list(tools if tools is not None else ["run_project_tests"]),
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={"run_project_tests": 1},
        network_boundary={"allowed": []},
        data_boundary={"allowed": ["target-1"]},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": root},
        policy_version="policy-v1",
        owner_approval="approval",
        created_at=(created - timedelta(seconds=1)).isoformat(),
        expires_at=(expiry or created + timedelta(minutes=10)).isoformat(),
    )


def test_run_project_tests_uses_workspace_and_persists_evidence(tmp_path, monkeypatch):
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert 2 + 2 == 4\n")
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    snapshot = auth(str(tmp_path))
    workspace = Workspace(tmp_path)
    import security.owner_policy as owner_policy
    monkeypatch.setattr(owner_policy, "STATE_PATH", tmp_path / "owner-policy.json")
    evidence = owner_policy._issue_evidence("owner_token", "req-1", "proof")
    context = AuthorizationContext(request_id="req-1", owner_evidence=evidence, policy_snapshot=owner_policy.capture_policy_snapshot("req-1", evidence))
    decision = authorize_tool(["run_project_tests", "."], context=context)
    assert decision.allowed and decision.decision is not None
    result = execute("run_project_tests", ".", authorization_decision=decision.decision, request_id="req-1", mission_authorization=snapshot, workspace=workspace, evidence_store=store, mission_id="m1")
    assert result["ok"] is True
    assert result["returncode"] == 0
    records = store.list(request_id="req-1")
    assert records and store.verify()
    provenance = records[0]["evidence"]["provenance"]
    assert provenance["mission_id"] == "m1"
    assert provenance["request_id"] == "req-1"
    assert provenance["tool_id"] == "run_project_tests"
    assert provenance["authorization_snapshot_hash"] == snapshot.authorization_hash


def test_workspace_requires_snapshot_and_blocks_boundary_and_symlink(tmp_path):
    workspace = Workspace(tmp_path)
    with pytest.raises(WorkspacePolicyError, match="snapshot"):
        workspace.read("x")
    snapshot = auth(str(tmp_path), actions=["read", "write"] , tools=[])
    workspace = Workspace(tmp_path, authorization_snapshot=snapshot)
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret")
    with pytest.raises(WorkspaceBoundaryError):
        workspace.read("../outside.txt")
    link = tmp_path / "escape"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(WorkspaceBoundaryError):
        workspace.read("escape")


def test_snapshot_tamper_expiry_wrong_mission_target_and_forbidden_tool_are_blocked(tmp_path):
    snapshot = auth(str(tmp_path), mission_id="m1")
    assert snapshot.validate_for_mission(mission_id="m1", owner_identity="owner-proof", target_identity="target-1")[0]
    assert not snapshot.validate_for_mission(mission_id="m2", owner_identity="owner-proof", target_identity="target-1")[0]
    assert not snapshot.validate_for_mission(mission_id="m1", owner_identity="other", target_identity="target-1")[0]
    assert not snapshot.check(action="other-tool", tool_id="other-tool", target_identity="target-1")[0]
    expired = auth(str(tmp_path), expiry=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not expired.is_active()
    tampered = snapshot.to_dict()
    tampered["allowed_tools"] = ["other-tool"]
    with pytest.raises(Exception):
        MissionAuthorizationSnapshot.from_dict(tampered)


def test_worker_lease_prevents_duplicate_and_recovers_expired(tmp_path):
    queue = MissionQueue(tmp_path / "queue.sqlite3")
    queue.enqueue("m1", available_at="2026-01-01T00:00:00+00:00")
    first = queue.claim_next(now="2026-01-01T00:00:00+00:00", worker_id="a", lease_seconds=10)
    assert first and first.lease_owner == "a"
    assert queue.claim_next(now="2026-01-01T00:00:01+00:00", worker_id="b", lease_seconds=10) is None
    with pytest.raises(PermissionError):
        queue.heartbeat("m1", worker_id="b", now="2026-01-01T00:00:01+00:00")
    recovered = queue.recover_expired(now="2026-01-01T00:00:11+00:00")
    assert recovered[0].state is WorkerMissionState.QUEUED
    second = queue.claim_next(now="2026-01-01T00:00:11+00:00", worker_id="b", lease_seconds=10)
    assert second and second.lease_owner == "b"


def test_successful_command_without_goal_evidence_is_unknown_and_repair_requires_auth(tmp_path):
    from agent.verification import FindingClaim, VerificationEngine, VerificationPlan, VerificationResult
    claim = FindingClaim("file created", "target-1")
    report = VerificationEngine().verify(claim, VerificationPlan("filesystem-validator", required_evidence=("filesystem",)), [{"source": "command", "type": "process", "exit_code": 0}])
    assert report.result is VerificationResult.UNKNOWN
    repaired = BoundedSelfRepair(max_retries=1).run(lambda: (_ for _ in ()).throw(RuntimeError("fail")), lambda exc: str(exc), lambda _d, _a: pytest.fail("unauthorized repair executed"), lambda _v: True, authorize_repair=lambda _d: False)
    assert not repaired.success
    assert repaired.reason == "repair authorization denied"
    assert any(item.phase == "authorization" for item in repaired.records)
