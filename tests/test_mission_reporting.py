from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan
from agent.reporting import build_mission_report
from security.mission_authorization import MissionAuthorizationSnapshot


def _mission(
    tmp_path: Path,
    *,
    status: MissionStatus = MissionStatus.READY,
    verification: dict | None = None,
    evidence: list[dict] | None = None,
    interpretations: list[dict] | None = None,
):
    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda *_args, **_kwargs: {})
    mission = runtime.create(
        "report fixture",
        "report fixture objective",
        Plan.initial("report fixture objective"),
        request_id="report-request",
        owner_identity_ref="owner-private-identity",
        completion_criteria=[{"criterion_id": "goal", "description": "goal criterion"}],
    )
    mission.status = status
    mission.verification_state = verification or {}
    mission.evidence = list(evidence or [])
    mission.interpretations = list(interpretations or [])
    mission.authorization_snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner-private-identity",
        mission_id=mission.mission_id,
        target_identity="local-test-target",
        scope=("local-test",),
        allowed_actions=("status",),
        forbidden_actions=(),
        allowed_tools=("status",),
        time_window={"timezone": "UTC"},
        max_duration=3600,
        rate_limits={"status": 10},
        network_boundary={"allowed": ()},
        data_boundary={"allowed": ("local-test-target",)},
        credential_boundary={"allowed": ()},
        workspace_boundary={"root": str(tmp_path)},
        policy_version="report-test-v1",
        owner_approval="owner-approval-fingerprint",
    ).to_dict()
    return mission


def test_verified_report_contains_hashes_and_per_item_confidence_without_owner_identity(tmp_path):
    mission = _mission(
        tmp_path,
        status=MissionStatus.GOAL_COMPLETED,
        verification={"verified": True, "missing_criteria": [], "evidence_count": 1},
        evidence=[
            {
                "criterion_id": "goal",
                "passed": True,
                "source": "deterministic-test-runner",
                "confidence": 8,
                "result_hash": "a" * 64,
                "provenance": {"verification_authority": "deterministic_tool_result"},
            }
        ],
    )
    record = {
        "evidence_id": "evidence-1",
        "source": "run_project_tests",
        "sequence": 1,
        "previous_hash": "",
        "current_hash": "b" * 64,
        "mission_id": mission.mission_id,
        "request_id": mission.request_id,
        "task_id": "task-1",
        "execution_id": "execution-1",
        "worker_id": "worker-1",
        "worker_instance_id": "worker-instance-1",
        "runtime_generation": 2,
        "lease_epoch": 4,
        "authorization_hash": "c" * 64,
    }

    report = build_mission_report(
        mission,
        execution_evidence=[record],
        evidence_chain_integrity="VALID",
    )

    assert report["schema_version"] == "cybersentinel.mission-report.v1"
    assert report["mission_summary"]["outcome"] == "VERIFIED"
    assert report["evidence"]["execution_chain_integrity"] == "VALID"
    assert len(report["evidence"]["digest_sha256"]) == 64
    assert report["confidence"]["items"] == [
        {
            "source": "deterministic-test-runner",
            "confidence": 8,
            "evidence_id": "",
            "verification": "TRUSTED_SOURCE",
        }
    ]
    assert report["confidence"]["aggregate"] is None
    assert report["supporting_evidence"][0]["criterion_id"] == "goal"
    assert report["provenance"]["execution_chain"][0]["current_hash"] == "b" * 64
    assert report["owner_approval_status"]["status"] == "RECORDED"
    assert "action-level approval is not assessed" in report["owner_approval_status"]["scope"]
    assert "owner-private-identity" not in json.dumps(report)


@pytest.mark.parametrize(
    ("status", "verification", "evidence", "expected"),
    [
        (MissionStatus.READY, {}, [], "UNKNOWN"),
        (
            MissionStatus.GOAL_COMPLETED,
            {"verified": False, "missing_criteria": ["goal"], "evidence_count": 1},
            [{"criterion_id": "goal", "passed": False, "source": "fixture", "provenance": {"verification_authority": "deterministic_tool_result"}}],
            "PARTIALLY_VERIFIED",
        ),
        (MissionStatus.OWNER_INPUT_REQUIRED, {}, [], "OWNER_INPUT_REQUIRED"),
        (MissionStatus.OWNER_REAUTH_REQUIRED, {}, [], "OWNER_REAUTH_REQUIRED"),
        (MissionStatus.RECOVERY_REQUIRED, {}, [], "RECOVERY_REQUIRED"),
    ],
)
def test_report_never_claims_verified_for_unknown_partial_or_blocked_states(
    tmp_path, status, verification, evidence, expected
):
    mission = _mission(
        tmp_path,
        status=status,
        verification=verification,
        evidence=evidence,
    )
    report = build_mission_report(mission)
    assert report["mission_summary"]["outcome"] == expected
    assert "success" not in report
    if expected != "VERIFIED":
        assert report["mission_summary"]["outcome"] != "VERIFIED"


def test_invalid_evidence_chain_withholds_verified_outcome(tmp_path):
    mission = _mission(
        tmp_path,
        status=MissionStatus.GOAL_COMPLETED,
        verification={"verified": True, "missing_criteria": [], "evidence_count": 1},
        evidence=[{"criterion_id": "goal", "passed": True, "source": "fixture"}],
    )
    report = build_mission_report(mission, evidence_chain_integrity="INVALID")
    assert report["mission_summary"]["outcome"] == "UNKNOWN"
    assert any(item.get("state") == "EVIDENCE_CHAIN_INVALID" for item in report["unknown_states"])


def test_untrusted_legacy_pass_record_does_not_support_verified_report(tmp_path):
    mission = _mission(
        tmp_path,
        status=MissionStatus.GOAL_COMPLETED,
        verification={"verified": True, "missing_criteria": [], "evidence_count": 1},
        evidence=[{"criterion_id": "goal", "passed": True, "source": "legacy-record"}],
    )
    report = build_mission_report(mission)

    assert report["mission_summary"]["outcome"] == "UNKNOWN"
    assert report["mission_summary"]["verification"]["runtime_reported_verified"] is True
    assert report["mission_summary"]["verification"]["verified"] is False
    assert report["supporting_evidence"] == []
    assert report["evidence"]["goal"][0]["report_verification"] == "UNVERIFIED_PROVENANCE"
    assert report["evidence"]["goal"][0]["claimed_passed"] is True
    assert any(item.get("state") == "UNVERIFIED_EVIDENCE_PROVENANCE" for item in report["unknown_states"])


def test_model_proposals_are_reported_as_unverified_not_supporting_evidence(tmp_path):
    mission = _mission(
        tmp_path,
        status=MissionStatus.READY,
        interpretations=[
            {
                "observation_id": "obs-model",
                "summary": "model claim",
                "provenance": {"proposal_origin": "model"},
                "new_evidence": [{"criterion_id": "goal", "passed": True, "source": "model"}],
            }
        ],
    )
    report = build_mission_report(mission)
    assert report["mission_summary"]["outcome"] == "UNKNOWN"
    assert report["findings"][0]["status"] == "UNVERIFIED_MODEL_PROPOSAL"
    assert report["supporting_evidence"] == []
    assert report["evidence"]["unverified_model_proposals"][0]["verification"] == "UNVERIFIED_MODEL_PROPOSAL"
    assert any("Model-proposed evidence" in item for item in report["limitations"])
