from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import security.owner_password as owner_password
from agent.evidence import EvidenceChainStore
from agent.mission import MissionStatus, MissionStore
from agent.mission_runtime import MissionRuntime
from agent.mission_worker import MissionQueue
from agent.planning import Plan
from api.missions import MissionReportApprovalConflict, MissionService
from security.mission_authorization import MissionAuthorizationSnapshot


OWNER_TOKEN = "report-approval-owner-session"
OTHER_TOKEN = "report-approval-other-session"


def _fixture(tmp_path: Path, monkeypatch):
    def resolve(token):
        identity = {
            OWNER_TOKEN: (1, "canonical-owner"),
            OTHER_TOKEN: (2, "different-identity"),
        }.get(token)
        if identity is None:
            return None
        owner_id, username = identity
        return {
            "session_id": f"session-ref-{owner_id}",
            "owner_id": owner_id,
            "username": username,
            "auth_method": "username_password",
            "expires_at": "2999-01-01T00:00:00+00:00",
        }

    monkeypatch.setattr(owner_password, "resolve_session", resolve)
    monkeypatch.setattr(owner_password, "_resolve_session_reference", resolve)

    store = MissionStore(tmp_path / "missions.sqlite3")
    runtime = MissionRuntime(store, executor=lambda *_args, **_kwargs: {})
    mission = runtime.create(
        "Owner report approval fixture",
        "Review a locally recorded result",
        Plan.initial("Review a locally recorded result"),
        request_id="report-approval-request",
        owner_identity_ref="owner:1",
    )
    mission.transition(MissionStatus.RUNNING, "acceptance fixture execution")
    mission.transition(MissionStatus.GOAL_COMPLETED, "acceptance fixture completed")
    mission.authorization_snapshot = MissionAuthorizationSnapshot.create(
        owner_identity="owner:1",
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
        policy_version="report-approval-test-v1",
        owner_approval="fixture-owner-approval-fingerprint",
    ).to_dict()
    store.save(mission)

    evidence_chain = EvidenceChainStore(tmp_path / "evidence_chain.db")
    evidence_chain.append(
        {
            "claim": "A local synthetic result was recorded",
            "source": "report-approval-test-fixture",
            "evidence": {"kind": "unit-test-only"},
            "verification": "observed",
            "confidence": 10,
            "request_id": mission.request_id,
            "mission_id": mission.mission_id,
            "chain": (f"mission:{mission.mission_id}",),
        }
    )
    service = MissionService(runtime, MissionQueue(tmp_path / "queue.sqlite3"))
    return service, store, mission


def _canonical_digest(report: dict) -> str:
    body = {
        key: value
        for key, value in report.items()
        if key not in {"report_sha256", "report_digest_scope", "final_report_approval"}
    }
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_report_approval_is_owner_only_digest_bound_and_persisted(tmp_path, monkeypatch):
    service, store, mission = _fixture(tmp_path, monkeypatch)
    report = service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)

    assert report["schema_version"] == "cybersentinel.mission-report.v1"
    assert report["mission_summary"]["mission_status"] == "GOAL_COMPLETED"
    assert report["mission_summary"]["outcome"] == "PARTIALLY_VERIFIED"
    assert report["evidence"]["execution_chain_integrity"] == "VALID"
    assert report["final_report_approval"]["status"] == "PENDING"
    assert report["report_sha256"] == _canonical_digest(report)

    wrong_digest = ("0" if report["report_sha256"][0] != "0" else "1") + report["report_sha256"][1:]
    with pytest.raises(MissionReportApprovalConflict, match="report_sha256_mismatch"):
        service.approve_report(
            mission.mission_id,
            owner_session_token=OWNER_TOKEN,
            report_sha256=wrong_digest,
        )

    with pytest.raises(PermissionError, match="mission access denied"):
        service.approve_report(
            mission.mission_id,
            owner_session_token=OTHER_TOKEN,
            report_sha256=report["report_sha256"],
        )

    approved = service.approve_report(
        mission.mission_id,
        owner_session_token=OWNER_TOKEN,
        report_sha256=report["report_sha256"],
    )
    assert approved["approval"]["status"] == "APPROVED"
    assert approved["approval"]["approval_scope"] == "report_only"
    assert approved["report_sha256"] == report["report_sha256"]

    persisted = store.load(mission.mission_id)
    assert persisted is not None
    assert persisted.status is MissionStatus.GOAL_COMPLETED
    assert persisted.progress["final_report_approval"]["report_sha256"] == report["report_sha256"]
    assert persisted.progress["final_report_approval"]["approval_scope"] == "report_only"
    assert persisted.trajectory[-1]["event"] == "FinalReportApproved"
    assert persisted.verify_integrity()

    replay = service.approve_report(
        mission.mission_id,
        owner_session_token=OWNER_TOKEN,
        report_sha256=report["report_sha256"],
    )
    assert replay["approval"]["approved_at"] == approved["approval"]["approved_at"]
    assert len(store.load(mission.mission_id).trajectory) == len(persisted.trajectory)
    assert service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)["final_report_approval"]["status"] == "APPROVED"

    changed = store.load(mission.mission_id)
    changed.objective = "A materially changed report objective"
    store.save(changed)
    refreshed = service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)
    assert refreshed["report_sha256"] != report["report_sha256"]
    assert refreshed["final_report_approval"]["status"] == "STALE"


def test_incomplete_mission_cannot_receive_final_report_approval(tmp_path, monkeypatch):
    service, store, mission = _fixture(tmp_path, monkeypatch)
    pending = store.load(mission.mission_id)
    pending.status = MissionStatus.READY
    store.save(pending)
    report = service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)

    with pytest.raises(MissionReportApprovalConflict, match="report_not_eligible_for_approval"):
        service.approve_report(
            mission.mission_id,
            owner_session_token=OWNER_TOKEN,
            report_sha256=report["report_sha256"],
        )


def test_empty_or_unrelated_evidence_chain_cannot_qualify_owner_approval(tmp_path, monkeypatch):
    service, store, mission = _fixture(tmp_path, monkeypatch)
    completed = store.load(mission.mission_id)
    assert completed is not None
    completed.evidence.append({
        "criterion_id": "local-result",
        "passed": True,
        "source": "deterministic-local-observation",
        "result": {"ok": True},
        "provenance": {
            "mission_id": mission.mission_id,
            "verification_authority": "deterministic_observation",
        },
    })
    store.save(completed)

    evidence_path = tmp_path / "evidence_chain.db"
    evidence_path.unlink()
    unrelated_chain = EvidenceChainStore(evidence_path)

    empty_report = service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)
    assert empty_report["mission_summary"]["outcome"] == "PARTIALLY_VERIFIED"
    assert empty_report["evidence"]["execution_chain_integrity"] == "NOT_PRESENT"
    with pytest.raises(MissionReportApprovalConflict, match="report_not_eligible_for_approval"):
        service.approve_report(
            mission.mission_id,
            owner_session_token=OWNER_TOKEN,
            report_sha256=empty_report["report_sha256"],
        )

    unrelated_chain.append({
        "claim": "A different Mission recorded a local result",
        "source": "report-approval-unrelated-fixture",
        "evidence": {"kind": "other-mission-only"},
        "verification": "observed",
        "confidence": 10,
        "request_id": "unrelated-report-request",
        "mission_id": "unrelated-report-mission",
        "chain": ("mission:unrelated-report-mission",),
    })
    unrelated_report = service.report(mission.mission_id, owner_session_token=OWNER_TOKEN)
    assert unrelated_report["mission_summary"]["outcome"] == "PARTIALLY_VERIFIED"
    assert unrelated_report["evidence"]["execution_chain_integrity"] == "NOT_PRESENT"
    with pytest.raises(MissionReportApprovalConflict, match="report_not_eligible_for_approval"):
        service.approve_report(
            mission.mission_id,
            owner_session_token=OWNER_TOKEN,
            report_sha256=unrelated_report["report_sha256"],
        )


def test_bridge_http_report_approval_route_is_owner_only_digest_bound_and_idempotent(tmp_path, monkeypatch):
    from http.client import HTTPConnection
    from http.server import ThreadingHTTPServer
    from threading import Thread

    import bridge

    service, store, mission = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "BRIDGE_TOKEN", "bridge-test-token")
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda _self: service)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method: str, path: str, *, owner_token: str, payload: dict | None = None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {
            "X-CyberSentinel-Token": "bridge-test-token",
            "X-CyberSentinel-Owner-Session": owner_token,
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw.decode("utf-8"))
        finally:
            connection.close()

    try:
        report_path = f"/api/missions/{mission.mission_id}/report"
        approval_path = f"/api/missions/{mission.mission_id}/approve-report"
        status, report_body = request("GET", report_path, owner_token=OWNER_TOKEN)
        assert status == 200 and report_body["ok"] is True
        report = report_body["report"]
        assert report["evidence"]["execution_chain_integrity"] == "VALID"
        digest = report["report_sha256"]

        wrong_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
        wrong_status, wrong_body = request(
            "POST", approval_path, owner_token=OWNER_TOKEN,
            payload={"report_sha256": wrong_digest},
        )
        assert wrong_status == 409
        assert wrong_body["error"] == "report_sha256_mismatch"

        other_status, other_body = request(
            "POST", approval_path, owner_token=OTHER_TOKEN,
            payload={"report_sha256": digest},
        )
        assert other_status == 403
        assert other_body["error"] == "mission access denied"

        approved_status, approved_body = request(
            "POST", approval_path, owner_token=OWNER_TOKEN,
            payload={"report_sha256": digest},
        )
        assert approved_status == 200 and approved_body["ok"] is True
        assert approved_body["approval"]["status"] == "APPROVED"
        approved_at = approved_body["approval"]["approved_at"]

        replay_status, replay_body = request(
            "POST", approval_path, owner_token=OWNER_TOKEN,
            payload={"report_sha256": digest},
        )
        assert replay_status == 200 and replay_body["approval"]["approved_at"] == approved_at

        final_status, final_body = request("GET", report_path, owner_token=OWNER_TOKEN)
        assert final_status == 200
        assert final_body["report"]["report_sha256"] == digest
        assert final_body["report"]["final_report_approval"]["status"] == "APPROVED"

        persisted = store.load(mission.mission_id)
        assert persisted is not None and persisted.verify_integrity()
        assert sum(event["event"] == "FinalReportApproved" for event in persisted.trajectory) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
