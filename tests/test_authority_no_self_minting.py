from __future__ import annotations

"""Adversarial battery: the tool runtime can never mint authority for itself.

Constitution: docs/AUTHORITY_CONSTITUTION.md, Article 8 (No Self-Minting
Authority). The tool registry is an execution boundary that must consume
Owner-derived authorization; every case below asserts the fail-closed
boundary at tools.registry.execute.
"""

from datetime import datetime, timedelta, timezone

import pytest

from security.mission_authorization import MissionAuthorizationSnapshot
from tools.registry import execute
from workspace import Workspace


def make_snapshot(root: str, *, owner: str = "owner-proof", mission_id: str = "m1", target: str = "local-workspace", created_minutes_ago: int = 0, expires_minutes_from_now: int = 10) -> MissionAuthorizationSnapshot:
    now = datetime.now(timezone.utc)
    created = now - timedelta(minutes=created_minutes_ago)
    return MissionAuthorizationSnapshot.create(
        owner_identity=owner,
        mission_id=mission_id,
        target_identity=target,
        scope=("workspace",),
        allowed_actions=["run_project_tests"],
        forbidden_actions=[],
        allowed_tools=["run_project_tests"],
        time_window={"timezone": "UTC"},
        max_duration=600,
        rate_limits={"run_project_tests": 1},
        network_boundary={"allowed": []},
        data_boundary={"allowed": [target]},
        credential_boundary={"allowed": []},
        workspace_boundary={"root": root},
        policy_version="policy-v1",
        owner_approval="owner-approval",
        created_at=created.isoformat(),
        expires_at=(now + timedelta(minutes=expires_minutes_from_now)).isoformat(),
    )


def test_tool_cannot_mint_authorization_for_itself(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    with pytest.raises(PermissionError, match="mint"):
        execute("run_project_tests", ".")


def test_governed_workspace_without_owner_derived_authorization_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    workspace = Workspace(tmp_path)
    with pytest.raises(PermissionError, match="mint"):
        execute("run_project_tests", ".", workspace=workspace, mission_id="m1", request_id="r1")


def test_authorization_without_governed_workspace_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    snapshot = make_snapshot(str(tmp_path))
    with pytest.raises(PermissionError, match="governed Workspace"):
        execute("run_project_tests", ".", mission_authorization=snapshot, mission_id="m1", request_id="r1")


def test_owner_derived_authorization_executes_and_binds_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    from agent.evidence import EvidenceChainStore
    store = EvidenceChainStore(tmp_path / "evidence.sqlite3")
    snapshot = make_snapshot(str(tmp_path))
    workspace = Workspace(tmp_path)
    result = execute("run_project_tests", ".", mission_authorization=snapshot, workspace=workspace, evidence_store=store, mission_id="m1", request_id="r1")
    assert result["ok"] is True
    assert result["returncode"] == 0
    assert store.verify()


def test_tampered_authorization_payload_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    snapshot = make_snapshot(str(tmp_path))
    payload = snapshot.to_dict()
    payload["allowed_tools"] = ["run_project_tests", "status"]
    with pytest.raises(PermissionError):
        execute("run_project_tests", ".", mission_authorization=payload, mission_id="m1", request_id="r1")


def test_expired_authorization_is_not_executed(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    snapshot = make_snapshot(str(tmp_path), created_minutes_ago=20, expires_minutes_from_now=-10)
    workspace = Workspace(tmp_path)
    with pytest.raises(PermissionError, match="authorization snapshot"):
        execute("run_project_tests", ".", mission_authorization=snapshot, workspace=workspace, mission_id="m1", request_id="r1")


def test_cross_target_authorization_is_not_executed(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    snapshot = make_snapshot(str(tmp_path), target="other-target")
    workspace = Workspace(tmp_path)
    with pytest.raises(PermissionError, match="target"):
        execute("run_project_tests", ".", mission_authorization=snapshot, workspace=workspace, mission_id="m1", request_id="r1", target_identity="local-workspace")
