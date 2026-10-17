from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from agent.evidence import Evidence, EvidenceChainStore, verify_chain
from agent.mission import Mission, MissionStatus, MissionStore
from agent.reporting import build_mission_report
from agent.local_runtime.catalog import get_model
from agent.planning import Plan, PlanStep
from agent.trajectory import EventType, verify_trajectory
from scripts.run_full_e2e_gate_acceptance import (
    _qwen_planning_diagnostics,
    _safe_action_names,
    find_llama_server_binary,
)
from scripts.acceptance_evidence import (
    safe_acceptance_error,
    safe_exception_type,
    safe_mission_failure_snapshot,
    safe_opaque_identifier,
    safe_static_code,
)
import scripts.windows_desktop_acceptance as windows_acceptance
from scripts.windows_desktop_acceptance import (
    EXPECTED_QWEN3_4B_INSTALL_IDENTITY,
    INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS,
    MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES,
    MODEL_STATE_API_MAX_TOTAL_FAILURES,
    OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS,
    OWNER_MISSION_RUNTIME_LIMIT_SECONDS,
    _build_expected_qwen_install_consent,
    _canonical_sha256,
    _canonical_report_body_sha256,
    _contains_blocked_or_unverified_status,
    _effect_ledger_projection,
    _handle_qwen_install_dialog,
    _local_health_status,
    _is_expected_qwen_install_post_request,
    _may_continue_qwen_install_post,
    _may_resume_after_application_restart,
    _mission_audit_projection,
    _mission_project_test_execution_proof,
    _model_runtime_after_restart,
    _owner_auth_after_restart,
    _process_start_fields_match,
    _process_tree_termination_status,
    _process_tree_termination_from_alive_probe,
    _qwen_installed_digest_report,
    _require_qwen_installed_digest,
    _require_qwen_install_consent,
    _refresh_qwen_model_snapshot,
    _safe_checkpoint_diagnostics,
    _safe_early_restart_audit_projection,
    _safe_failure_diagnostics,
    _safe_mission_event_trace,
    _safe_tool_result_summary,
    _tool_execution_projection,
    _tools_within_authorized_allowlist,
    _validate_qwen_install_post_response,
)

ROOT = Path(__file__).resolve().parents[1]


def test_simulated_github_full_acceptance_binds_installed_executable_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "CyberSentinel.exe"
    executable.write_bytes(b"simulated-installed-executable")
    report_path = tmp_path / "acceptance.json"
    source_commit = "2ef29b7de9eb43a7880223d0d256699eac2d4945"

    class FakePlaywright:
        chromium = SimpleNamespace(
            connect_over_cdp=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("simulated CI: no installed application/CDP endpoint")
            )
        )

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    playwright_package = ModuleType("playwright")
    playwright_package.__path__ = []
    playwright_sync_api = ModuleType("playwright.sync_api")
    playwright_sync_api.TimeoutError = TimeoutError
    playwright_sync_api.sync_playwright = FakePlaywright
    monkeypatch.setitem(sys.modules, "playwright", playwright_package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", playwright_sync_api)

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "mosfiry/cybersentinel")
    monkeypatch.setenv("GITHUB_RUN_ID", "987654321")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/fix/blocker-d-review-20261010")
    monkeypatch.setenv("GITHUB_SHA", source_commit)
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("ImageOS", "windows-2022")
    monkeypatch.setenv("ImageVersion", "simulated-image")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "windows_desktop_acceptance.py",
            "--cdp-port",
            "9222",
            "--expected-version",
            "5.1.0",
            "--profile-root",
            str(tmp_path / "profile"),
            "--installed-executable",
            str(executable),
            "--launch-in-owned-job",
            "--mode",
            "full",
            "--output",
            str(report_path),
        ],
    )

    assert windows_acceptance.main() == 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "FAIL"  # Deliberate: no real installed app/CDP in this simulation.
    assert report["run_identity"] == {
        "provider": "github-actions",
        "repository": "mosfiry/cybersentinel",
        "run_id": "987654321",
        "run_attempt": "2",
        "ref": "refs/heads/fix/blocker-d-review-20261010",
        "source_commit": source_commit,
        "runner_os": "Windows",
        "image_os": "windows-2022",
        "image_version": "simulated-image",
    }
    assert report["application_fingerprint"]["installed_executable_sha256"] == hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    assert report["application_fingerprint"]["source_commit"] == source_commit


def _linked_project_test_snapshot(*, include_unrelated_prior: bool = False) -> tuple[str, dict]:
    mission_id = "mission-acceptance-1"
    request_id = "request-acceptance-1"
    tool_call_id = "call-once"
    action_id = "action-once"
    task_id = "test-step"
    process_payload = {
        "record_type": "UNTRUSTED_SANDBOX_PROCESS_RESULT",
        "trust": "untrusted_data",
        "authority": "none",
        "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
        "network": "disabled",
        "workspace_mode": "read_only",
        "outcome": "SUCCEEDED",
        "reason_code": "process_exit_zero",
        "resource_limit_reason": None,
        "exit_code": 0,
        "timed_out": False,
        "cancelled": False,
        "process_started": True,
        "process_id": 4242,
        "process_started_at_utc": "2026-10-16T14:00:00+00:00",
        "output_sha256": "c" * 64,
        "artifact_refs": [],
        "artifact_capture_truncated": False,
    }
    prior_record = None
    if include_unrelated_prior:
        prior_record = Evidence(
            claim="unrelated prior mission evidence",
            source="other-tool:prior",
            evidence={"record_type": "OTHER_MISSION"},
            verification="observed",
            confidence=10,
            evidence_id="prior-evidence-1",
            request_id="request-prior-1",
            chain=("mission:mission-prior-1",),
            sequence=1,
            previous_hash="",
            mission_id="mission-prior-1",
            task_id="prior-step",
            execution_id="prior-execution",
            worker_id="worker-prior",
            worker_instance_id="worker-instance-prior",
            runtime_generation=1,
            lease_epoch=1,
            task_version=1,
            authorization_hash="f" * 64,
            fence_id="a" * 64,
        ).to_dict()
    process_sequence = 2 if prior_record is not None else 1
    process_previous_hash = prior_record["current_hash"] if prior_record is not None else ""
    process_record = Evidence(
        claim="run_project_tests sandbox process result",
        source="sandboxed-process:run_project_tests",
        evidence=process_payload,
        verification="observed",
        confidence=10,
        evidence_id="process-evidence-1",
        request_id=request_id,
        chain=(f"mission:{mission_id}", "tool:run_project_tests", f"call:{tool_call_id}"),
        sequence=process_sequence,
        previous_hash=process_previous_hash,
        mission_id=mission_id,
        task_id=task_id,
        execution_id=action_id,
    ).to_dict()
    process_evidence_ref = {
        "evidence_id": process_record["evidence_id"],
        "sequence": process_record["sequence"],
        "current_hash": process_record["current_hash"],
    }
    raw_result = {
        "ok": True,
        "timed_out": False,
        "cancelled": False,
        "outcome": "SUCCEEDED",
        "reason_code": "process_exit_zero",
        "resource_limit_reason": None,
        "returncode": 0,
        "output": "1 passed in 0.02s",
        "trust": "untrusted_data",
        "authority": "none",
        "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
        "network": "disabled",
        "workspace_mode": "read_only",
        "process_started": True,
        "process_id": 4242,
        "process_started_at_utc": "2026-10-16T14:00:00+00:00",
        "artifact_refs": [],
        "artifact_capture_truncated": False,
        "evidence_ref": process_evidence_ref,
    }
    result_bytes = json.dumps(
        raw_result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False, default=str,
    ).encode("utf-8")
    result = {
        **raw_result,
        "type": "tool_observation",
        "action_id": action_id,
        "step_id": task_id,
        "mission_id": mission_id,
        "tool_call_id": tool_call_id,
    }
    tool_result = {
        "tool_call_id": tool_call_id,
        "name": "run_project_tests",
        "arguments": {"command": "pytest -q"},
        "ok": True,
        "result": result,
        "error": "",
        "mission_id": mission_id,
        "request_id": request_id,
        "action_id": action_id,
        "step_id": task_id,
        "authorization_context_id": "authorization-context-once",
        "scope_snapshot_id": "scope-once",
        "run_id": "run-once",
        "turn_id": "turn-once",
        "plan_version": 1,
    }
    native_record = Evidence(
        claim="run_project_tests native tool result",
        source="native-tool:run_project_tests",
        evidence={
            "record_type": "NATIVE_TOOL_RESULT",
            "tool_name": "run_project_tests",
            "tool_call_id": tool_call_id,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "result_bytes": len(result_bytes),
            "result_type": "dict",
            "trust_classification": "untrusted_data",
            "authority": "none",
            "authorized_tool": True,
            "authorization_snapshot_sha256": "d" * 64,
            "scope_snapshot_id": "scope-once",
            "scope_sha256": "e" * 64,
            "target_id": "local-project:acceptance",
        },
        verification="observed",
        confidence=10,
        evidence_id="native-evidence-1",
        request_id=request_id,
        chain=(f"mission:{mission_id}", "tool:run_project_tests", f"call:{tool_call_id}"),
        sequence=process_sequence + 1,
        previous_hash=process_record["current_hash"],
        mission_id=mission_id,
        task_id=task_id,
        execution_id=action_id,
    ).to_dict()
    chain = [process_record, native_record]
    full_execution_chain = ([prior_record] if prior_record is not None else []) + chain
    assert verify_chain(full_execution_chain) is True
    provenance_chain = [
        {
            key: record.get(key)
            for key in (
                "evidence_id", "source", "sequence", "previous_hash", "current_hash",
                "mission_id", "request_id", "task_id", "execution_id", "worker_id",
                "worker_instance_id", "runtime_generation", "lease_epoch", "task_version",
                "authorization_hash", "fence_id",
            )
        }
        for record in chain
    ]
    mission_evidence = {
        "criterion_id": "project-tests",
        "passed": True,
        "source": "run_project_tests",
        "mission_id": mission_id,
        "result": {"source": "run_project_tests", "result": result},
        "provenance": {
            "mission_id": mission_id,
            "tool_call_id": tool_call_id,
            "verification_authority": "project_test_process_exit",
        },
    }
    action_history = [{
        "action_id": action_id,
        "step_id": task_id,
        "status": "completed",
        "observation": {
            "action_id": action_id,
            "step_id": task_id,
            "mission_id": mission_id,
            "tool_call_id": tool_call_id,
            "ok": True,
        },
    }]
    mission_status = {
        "mission_id": mission_id,
        "request_id": request_id,
        "status": "GOAL_COMPLETED",
        "objective": "Run the authorized project tests",
        "current_step": 1,
        "iteration_count": 1,
        "completion_criteria": [{"criterion_id": "project-tests", "required": True}],
        "verification_state": {"verified": True, "evidence_count": 1, "missing_criteria": []},
        "evidence": [mission_evidence],
        "action_history": action_history,
        "failures": [],
        "interpretations": [],
        "owner_identity_ref": "",
        "progress": {
            "pause_requested": False,
            "model_loop": {"tool_results": [tool_result]},
        },
        "queue": {"state": "completed"},
    }
    report = build_mission_report(
        SimpleNamespace(**mission_status),
        execution_evidence=chain,
        evidence_chain_integrity="VALID",
    )
    report["limitations"] = list(report["limitations"]) + [
        "Final report approval is a separate Owner decision bound to this report digest; it does not authorize actions or replace action-level approvals."
    ]
    report["report_sha256"] = _canonical_report_body_sha256(report)
    report["report_digest_scope"] = (
        "SHA-256 over canonical sorted compact UTF-8 JSON report content before the digest and approval envelope."
    )
    report["final_report_approval"] = {
        "status": "PENDING", "report_sha256": report["report_sha256"]
    }
    snapshot = {
        "status": mission_status,
        "timeline": [
            {
                "event": "ToolProposed",
                "mission_id": mission_id,
                "request_id": request_id,
                "data": {
                    "mission_id": mission_id,
                    "request_id": request_id,
                    "name": "run_project_tests",
                    "tool_call_id": tool_call_id,
                    "action_id": action_id,
                    "step_id": task_id,
                    "authorization_context_id": "authorization-context-once",
                    "scope_snapshot_id": "scope-once",
                },
            },
            {
                "event": "AuthorizationChecked",
                "mission_id": mission_id,
                "request_id": request_id,
                "data": {
                    "mission_id": mission_id,
                    "request_id": request_id,
                    "name": "run_project_tests",
                    "tool_call_id": tool_call_id,
                    "action_id": action_id,
                    "step_id": task_id,
                    "authorization_context_id": "authorization-context-once",
                    "scope_snapshot_id": "scope-once",
                    "allowed": True,
                },
            },
            {
                "event": "ToolExecuted",
                "mission_id": mission_id,
                "request_id": request_id,
                "step_id": task_id,
                "data": {"action_id": action_id, "status": "completed"},
            },
            {"event": "EvidenceAdded", "mission_id": mission_id, "request_id": request_id},
        ],
        "evidence": [mission_evidence],
        "effects": [],
        "report": report,
        "full_execution_chain": full_execution_chain,
        "full_execution_chain_status": "VALID",
    }
    return mission_id, snapshot


def _refresh_report_digest(snapshot: dict) -> None:
    snapshot["report"]["report_sha256"] = _canonical_report_body_sha256(snapshot["report"])


def _runtime_trajectory_mission(mission_id: str, request_id: str) -> Mission:
    plan = Plan(version=1, objective="Run the authorized project tests", steps=())
    mission = Mission.create(
        "Run project tests", "Run the authorized project tests", plan,
        mission_id=mission_id, request_id=request_id,
    )
    # MissionRuntime emits this real event type with a reason before terminal dispatch.
    mission.emit(EventType.FAILURE_DETECTED, data={"reason": "test timeline anchor"})
    return mission


def _d4_runtime_snapshot() -> tuple[str, dict, Mission]:
    mission_id, request_id = "mission-d4-runtime", "request-d4-runtime"
    mission = _runtime_trajectory_mission(mission_id, request_id)
    snapshot = {
        "status": mission.to_dict(),
        "timeline": json.loads(json.dumps(mission.trajectory)),
        "evidence": json.loads(json.dumps(mission.evidence)),
        "report": {},
        "effects": [],
        "full_execution_chain": None,
        "full_execution_chain_status": "NOT_PRESENT",
    }
    return mission_id, snapshot, mission


def _d4_evidence_report_fixture_snapshot() -> tuple[str, dict, Mission]:
    """Fixture for negative report/evidence tampering checks, never a success-path proof."""
    mission_id, snapshot = _linked_project_test_snapshot()
    request_id = snapshot["status"]["request_id"]
    mission = _runtime_trajectory_mission(mission_id, request_id)
    snapshot["timeline"] = json.loads(json.dumps(mission.trajectory))
    snapshot["status"]["plan"] = mission.plan.to_dict()
    snapshot["status"]["plan_history"] = json.loads(json.dumps(mission.plan_history))
    return mission_id, snapshot, mission


def _attach_completed_mission_trajectory(
    snapshot: dict,
    *,
    completion_events: tuple[str, ...] = ("GoalVerified", "MissionCompleted"),
) -> None:
    """Replace a projection-only fixture timeline with a real, hash-linked Mission record."""
    source = snapshot["status"]
    objective = str(source["objective"])
    mission = Mission.create(
        "Run the authorized project tests",
        objective,
        Plan(version=1, objective=objective, steps=()),
        mission_id=source["mission_id"],
        request_id=source["request_id"],
        completion_criteria=source["completion_criteria"],
    )
    mission.current_step = source["current_step"]
    mission.iteration_count = source["iteration_count"]
    mission.verification_state = source["verification_state"]
    mission.evidence = source["evidence"]
    mission.action_history = source["action_history"]
    mission.progress = source["progress"]
    mission.owner_identity_ref = source["owner_identity_ref"]
    for event in snapshot["timeline"]:
        mission.emit(
            EventType(event["event"]),
            step_id=str(event.get("step_id", "")),
            data=event.get("data") if isinstance(event.get("data"), dict) else {},
        )
    mission.transition(MissionStatus.GOAL_COMPLETED, "verified acceptance fixture")
    for event_name in completion_events:
        if event_name == "GoalVerified":
            mission.emit(EventType.GOAL_VERIFIED, data=mission.verification_state)
        elif event_name == "MissionCompleted":
            mission.emit(EventType.MISSION_COMPLETED, data={"verification": mission.verification_state})
        else:
            mission.emit(EventType(event_name), data={"reason": "fixture event after completion"})
    snapshot["timeline"] = json.loads(json.dumps(mission.trajectory))
    snapshot["status"] = mission.to_dict()
    snapshot["status"]["queue"] = {"state": "completed"}


@pytest.mark.parametrize(
    "producer_state",
    [
        "MISSING_REQUIRED_EVIDENCE",
        "RUNTIME_VERIFICATION_NOT_SUPPORTED_BY_REPORT_EVIDENCE",
        "VERIFICATION_NOT_RECORDED",
    ],
)
def test_completed_report_rejects_nonempty_producer_unknown_states(producer_state: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["report"]["unknown_states"] = [{"state": producer_state}]
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False
    assert projection["completed_mission_inspectable"] is False


def test_redigested_report_with_nonempty_missing_criteria_is_not_verified() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["report"]["mission_summary"]["verification"]["missing_criteria"] = [
        "project-tests"
    ]
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("outcome", "SUCCESSFUL"), ("mission_status", "COMPLETE")],
)
def test_unrecognized_completed_report_status_values_fail_closed(field: str, value: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["report"]["mission_summary"][field] = value
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("verified", "true"), ("runtime_reported_verified", "yes")],
)
def test_unrecognized_report_verification_values_fail_closed(field: str, value: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["report"]["mission_summary"]["verification"][field] = value
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False


@pytest.mark.parametrize(
    "record",
    [
        {"status": "ASSERTED_COMPLETE"},
        {"mission_status": "GOAL_FINISHED"},
        {"outcome": "CERTAIN_SUCCESS"},
        {"state": "ASSERTED_COMPLETE"},
        {"verification": "CONFIRMED"},
        {"execution_chain_integrity": "CHAIN_IS_VALID"},
        {"nested": {"status": "ASSERTED_COMPLETE"}},
        {
            "verification_state": {
                "verified": True, "evidence_count": 1, "missing_criteria": [],
                "unknown_states": [], "nested": {"status": "ASSERTED_COMPLETE"},
            }
        },
    ],
)
def test_status_scanner_rejects_unrecognized_scalar_values(record: dict) -> None:
    assert _contains_blocked_or_unverified_status(record) is True


@pytest.mark.parametrize(
    "record",
    [
        {"status": "completed"},
        {"mission_status": "GOAL_COMPLETED"},
        {"verification": "observed"},
        {"execution_chain_integrity": "VALID"},
        {"report_verification": "TRUSTED_DETERMINISTIC_SOURCE"},
    ],
)
def test_status_scanner_allows_known_producer_values(record: dict) -> None:
    assert _contains_blocked_or_unverified_status(record) is False


def test_status_scanner_allows_only_known_success_reason_code() -> None:
    assert _contains_blocked_or_unverified_status({"reason_code": "process_exit_zero"}) is False
    assert _contains_blocked_or_unverified_status({"reason_code": "unrecognized_success_code"}) is True


@pytest.mark.parametrize("field", ["reason_code", "error_code", "code", "failure_class"])
def test_status_scanner_rejects_nonempty_failure_diagnostic_codes(field: str) -> None:
    assert _contains_blocked_or_unverified_status({field: "UNRECOGNIZED_FAILURE_CODE"}) is True


def test_status_scanner_rejects_unknown_status_token_in_scalar_result_but_allows_plain_text() -> None:
    assert _contains_blocked_or_unverified_status({"result": "ASSERTED_COMPLETE"}) is True
    assert _contains_blocked_or_unverified_status({"result": "ERROR OCCURRED"}) is True
    assert _contains_blocked_or_unverified_status({"result": "ERROR: OCCURRED"}) is True
    assert _contains_blocked_or_unverified_status({"result": "Installer output: ERROR: OCCURRED"}) is True
    assert _contains_blocked_or_unverified_status({"result": "Installer output: ERROR OCCURRED"}) is True
    assert _contains_blocked_or_unverified_status({"result": "Installer output: FAILED"}) is True
    assert _contains_blocked_or_unverified_status({"result": "execution failed during restart"}) is True
    assert _contains_blocked_or_unverified_status({"result": "execution failed: restart"}) is True
    assert _contains_blocked_or_unverified_status({"result": "all checks completed"}) is False
    assert _contains_blocked_or_unverified_status({"result": "the report mentions no errors"}) is False
    assert _contains_blocked_or_unverified_status({"result": "no error occurred; all checks completed"}) is False
    assert _contains_blocked_or_unverified_status({"result": "error handling is complete"}) is False


def test_durable_tool_result_with_embedded_error_label_is_not_successful() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    record = snapshot["status"]["progress"]["model_loop"]["tool_results"][0]
    record["result"]["result"] = "Installer output: ERROR OCCURRED"

    linkage = windows_acceptance._durable_tool_result_linkage(
        record, mission_id, snapshot["status"]["request_id"]
    )

    assert linkage is not None
    assert linkage["successful"] is False


@pytest.mark.parametrize("field", ["missing_criteria", "unknown_states"])
def test_completed_report_requires_producer_emitted_empty_status_lists(field: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    if field == "missing_criteria":
        del snapshot["report"]["mission_summary"]["verification"][field]
    else:
        del snapshot["report"][field]
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False


@pytest.mark.parametrize("field", ["finding", "nested_goal", "confidence", "owner_approval", "final_approval"])
def test_arbitrary_producer_status_values_fail_closed(field: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    report = snapshot["report"]
    if field == "finding":
        report["findings"][0]["status"] = "ASSERTED_COMPLETE"
    elif field == "nested_goal":
        report["evidence"]["goal"][0]["report_verification"] = "ASSERTED_COMPLETE"
    elif field == "confidence":
        report["confidence"]["items"][0]["verification"] = "ASSERTED_COMPLETE"
    elif field == "owner_approval":
        report["owner_approval_status"]["status"] = "ASSERTED_COMPLETE"
    else:
        report["final_report_approval"]["status"] = "ASSERTED_COMPLETE"
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False


@pytest.mark.parametrize("field", ["finding", "owner_approval"])
def test_completed_report_requires_nested_producer_status_fields(field: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    report = snapshot["report"]
    if field == "finding":
        del report["findings"][0]["status"]
    else:
        del report["owner_approval_status"]["status"]
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_verification_summary_consistent"] is False
    assert projection["report_projection_valid"] is False


def test_valid_global_chain_accepts_exact_mission_filtered_report_slice() -> None:
    mission_id, snapshot = _linked_project_test_snapshot(include_unrelated_prior=True)
    _attach_completed_mission_trajectory(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)
    proof = projection["project_test_execution_proof"]

    assert proof["global_execution_chain_hash_valid"] is True
    assert proof["report_execution_chain_matches_global"] is True
    assert proof["execution_chain_hash_valid"] is True
    assert projection["report_projection_valid"] is True
    assert projection["mission_record_integrity_verified"] is True
    assert projection["timeline_integrity_verified"] is True
    assert projection["goal_completion_events_verified"] is True
    assert projection["completed_mission_inspectable"] is True


@pytest.mark.parametrize(
    "completion_events",
    [
        (),
        ("MissionCompleted",),
        ("GoalVerified",),
        ("MissionCompleted", "GoalVerified"),
        ("GoalVerified", "MissionCompleted", "FailureDetected"),
        ("GoalVerified", "MissionCompleted"),
    ],
)
def test_completed_mission_requires_one_ordered_final_terminal_event_pair(
    completion_events: tuple[str, ...],
) -> None:
    mission_id, snapshot = _linked_project_test_snapshot(include_unrelated_prior=True)
    _attach_completed_mission_trajectory(snapshot, completion_events=completion_events)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["mission_record_integrity_verified"] is True
    assert projection["timeline_matches_integrity_checked_mission"] is True
    assert projection["timeline_integrity_verified"] is True
    expected = completion_events == ("GoalVerified", "MissionCompleted")
    assert projection["goal_completion_events_verified"] is expected
    assert projection["completed_mission_inspectable"] is expected


def test_completed_mission_requires_integrity_bound_persisted_trajectory() -> None:
    mission_id, snapshot = _linked_project_test_snapshot(include_unrelated_prior=True)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["timeline_records_bound_to_mission"] is True
    assert projection["mission_record_integrity_verified"] is False
    assert projection["timeline_integrity_verified"] is False
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize("tamper", ["global_record", "report_subset"])
def test_global_chain_tampering_or_report_subset_mismatch_fails_closed(tamper: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot(include_unrelated_prior=True)
    if tamper == "global_record":
        snapshot["full_execution_chain"][0]["claim"] = "tampered prior payload"
    else:
        snapshot["report"]["evidence"]["execution_chain"][0]["claim"] = (
            "forged report-only payload"
        )
        _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)
    proof = projection["project_test_execution_proof"]

    assert proof["verified"] is False
    assert proof["execution_chain_hash_valid"] is False
    assert proof["report_execution_chain_matches_global"] is False
    assert projection["report_projection_valid"] is False
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize(
    "field",
    [
        "evidence_id",
        "source",
        "sequence",
        "previous_hash",
        "current_hash",
        "mission_id",
        "request_id",
        "task_id",
        "execution_id",
        "worker_id",
        "worker_instance_id",
        "runtime_generation",
        "lease_epoch",
        "task_version",
        "authorization_hash",
        "fence_id",
    ],
)
def test_every_report_provenance_mirror_field_matches_payload(field: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    projected = snapshot["report"]["provenance"]["execution_chain"][0]
    original = projected[field]
    projected[field] = original + "-changed" if isinstance(original, str) else original + 1
    _refresh_report_digest(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["execution_chain_provenance_matches_payload"] is False
    assert projection["report_projection_valid"] is False
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize("receipt_mode", ["exact", "missing", "extra", "duplicate"])
def test_profile_evidence_chain_reader_checks_global_receipts_read_only(
    tmp_path: Path, receipt_mode: str
) -> None:
    sqlite3 = __import__("sqlite3")
    _mission_id, snapshot = _linked_project_test_snapshot(include_unrelated_prior=True)
    profile_root = tmp_path / "profile"
    state_directory = profile_root / "userData" / "state"
    (state_directory / "workspaces").mkdir(parents=True)
    (state_directory / "intel.sqlite3").touch()
    evidence_path = state_directory / "evidence_chain.db"
    records = snapshot["full_execution_chain"]
    expected_records = json.loads(json.dumps(records))
    prior_record = next(record for record in records if record.get("fence_id"))
    prior_records = [
        record for record in records
        if record.get("fence_id") and record.get("mission_id") == prior_record["mission_id"]
    ]
    expected_prior_receipts = [EvidenceChainStore._receipt(record) for record in prior_records]
    if receipt_mode == "exact":
        stored_receipts = expected_prior_receipts
    elif receipt_mode == "missing":
        stored_receipts = []
    elif receipt_mode == "extra":
        stored_receipts = [
            *expected_prior_receipts,
            {**expected_prior_receipts[0], "evidence_id": "orphan-evidence"},
        ]
    else:
        stored_receipts = [*expected_prior_receipts, expected_prior_receipts[0]]
    prior_mission = Mission.create(
        "prior request", "prior objective", Plan.initial("prior objective"),
        mission_id=prior_record["mission_id"], request_id=prior_record["request_id"],
        owner_identity_ref="owner:prior",
    )
    prior_mission.progress["execution_evidence_refs"] = stored_receipts
    MissionStore(state_directory / "missions.sqlite3").save(prior_mission)
    with sqlite3.connect(evidence_path) as db:
        db.execute(
            "CREATE TABLE evidence_chain "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, current_hash TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)"
        )
        db.executemany(
            "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
            [
                (record["sequence"], record["current_hash"], json.dumps(record))
                for record in records
            ],
        )
    before_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

    diagnostic_records, diagnostic_status = windows_acceptance._read_profile_evidence_chain_diagnostic(
        profile_root
    )
    loaded = windows_acceptance._read_profile_evidence_chain(profile_root)

    expected_status = "VALID" if receipt_mode == "exact" else "INVALID"
    assert diagnostic_status == expected_status
    assert diagnostic_records == (expected_records if receipt_mode == "exact" else None)
    assert loaded == (expected_records if receipt_mode == "exact" else None)
    assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == before_sha256


def test_profile_chain_storage_and_integrity_failures_remain_distinct(tmp_path: Path) -> None:
    import sqlite3

    profile_root = tmp_path / "profile"
    state_directory = profile_root / "userData" / "state"
    (state_directory / "workspaces").mkdir(parents=True)
    (state_directory / "intel.sqlite3").touch()

    assert windows_acceptance._read_profile_evidence_chain_diagnostic(profile_root) == (
        [], "NOT_PRESENT"
    )

    evidence_path = state_directory / "evidence_chain.db"
    evidence_path.write_bytes(b"not a sqlite database")
    assert windows_acceptance._read_profile_evidence_chain_diagnostic(profile_root) == (
        None, "UNREADABLE"
    )

    evidence_path.unlink()
    _mission_id, snapshot = _linked_project_test_snapshot()
    record = dict(snapshot["full_execution_chain"][0])
    record["claim"] = "tampered without recomputing the record hash"
    with sqlite3.connect(evidence_path) as db:
        db.execute(
            "CREATE TABLE evidence_chain "
            "(sequence INTEGER PRIMARY KEY AUTOINCREMENT, current_hash TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)"
        )
        db.execute(
            "INSERT INTO evidence_chain(sequence,current_hash,payload) VALUES(?,?,?)",
            (record["sequence"], record["current_hash"], json.dumps(record)),
        )

    assert windows_acceptance._read_profile_evidence_chain_diagnostic(profile_root) == (
        None, "INVALID"
    )


def test_mission_audit_endpoint_failure_is_classified_as_restoration_failure(tmp_path: Path) -> None:
    class UnavailableAuditPage:
        @staticmethod
        def evaluate(_script: str, _arguments: dict) -> dict:
            return {"http_status": 503, "body": {}}

    with pytest.raises(windows_acceptance._MissionAuditSnapshotError) as error:
        windows_acceptance._mission_audit_snapshot(
            UnavailableAuditPage(), "mission-acceptance-1", tmp_path
        )

    assert error.value.failure_class == "restoration"
    assert error.value.reason_code == "mission_audit_endpoints_unavailable"


def test_installed_mission_http_wait_matches_bounded_policy_budget() -> None:
    policy = json.loads((ROOT / "security" / "owner_policy.json").read_text(encoding="utf-8"))
    runtime_limit = int(policy["runtime_limits"]["max_execution_time_seconds"])

    assert runtime_limit == OWNER_MISSION_RUNTIME_LIMIT_SECONDS == 300
    assert OWNER_MISSION_RESPONSE_FINALIZATION_MARGIN_SECONDS == 30
    assert INSTALLED_APP_MISSION_RESPONSE_TIMEOUT_MS == (runtime_limit + 30) * 1000


def test_full_e2e_runtime_preflight_accepts_native_windows_server_name(tmp_path: Path) -> None:
    executable = tmp_path / "llama-server.exe"
    executable.write_bytes(b"test fixture")

    assert find_llama_server_binary(tmp_path, is_windows=True) == executable


def test_full_e2e_runtime_preflight_accepts_posix_server_name(tmp_path: Path) -> None:
    executable = tmp_path / "llama-server"
    executable.write_bytes(b"test fixture")

    assert find_llama_server_binary(tmp_path, is_windows=False) == executable


def test_failure_diagnostics_keep_only_safe_codes_and_bounded_limits() -> None:
    result = _safe_failure_diagnostics({
        "plan": {"steps": [
            {"step_id": "step-1-browser", "action": "browser", "objective": "private objective"},
            {"step_id": "step-2-status", "action": "status", "objective": "another private objective"},
        ]},
        "failures": [{
            "class": "resource",
            "budget": "model_loop_state",
            "reason_code": "repeated_read_only_tool_call",
            "limit": 0,
            "reason": "untrusted arbitrary mission text",
            "step_id": "step-1-browser",
            "details": {"prompt": "must not be serialized"},
        }, {
            "class": "RESOURCE",
            "reason": "repeated read-only tool call",
            "step_id": "step-2-status",
        }],
    })

    assert result == [
        {
            "class": "resource",
            "budget": "model_loop_state",
            "reason_code": "repeated_read_only_tool_call",
            "limit": 0,
            "plan_step_index": 1,
            "step_action": "browser",
        },
        {
            "class": "RESOURCE",
            "reason_code": "repeated_read_only_tool_call",
            "plan_step_index": 2,
            "step_action": "status",
        },
    ]
    assert "private objective" not in repr(result)
    assert "untrusted arbitrary mission text" not in repr(result)


def test_exception_diagnostics_never_emit_exception_text_or_credentials() -> None:
    password = "test-only-owner-secret"
    diagnostics = windows_acceptance._safe_exception_diagnostics(
        RuntimeError(f"request failed while submitting password={password}")
    )

    assert diagnostics == {
        "error_type": "RuntimeError",
        "error": "failure details omitted for secret safety",
    }
    assert password not in repr(diagnostics)


def test_acceptance_browser_and_hardware_diagnostics_exclude_raw_text() -> None:
    canary = "acceptance-canary-secret-token"
    renderer = f"http://user:{canary}@127.0.0.1:9443/app?token={canary}#private"
    diagnostics = {
        "renderer_origin_class": windows_acceptance._safe_renderer_origin_class(renderer),
        "hardware": windows_acceptance._safe_hardware_diagnostics(f"Device details {canary}"),
        "invalid_login_error_code": safe_static_code("error_code", canary),
    }

    serialized = json.dumps(diagnostics)
    source = Path(windows_acceptance.__file__).read_text(encoding="utf-8")
    assert diagnostics["renderer_origin_class"] == "invalid"
    assert diagnostics["hardware"]["detected"] is True
    assert diagnostics["hardware"]["text_sha256"] == hashlib.sha256(
        f"Device details {canary}".encode("utf-8")
    ).hexdigest()
    assert diagnostics["invalid_login_error_code"] is None
    assert canary not in serialized
    assert "display_text" not in serialized
    assert '"renderer_url": page.url' not in source
    assert '"display_text": hardware_text' not in source
    assert '"invalid_login_error": invalid_body.get("error")' not in source
    assert '"renderer_origin_class": _safe_renderer_origin_class(page.url)' in source
    assert 'report["hardware"] = _safe_hardware_diagnostics(hardware_text)' in source
    assert '"invalid_login_error_code": _safe_static_code("error_code", invalid_body.get("error"))' in source
    assert windows_acceptance._safe_renderer_origin_class("http://127.0.0.1:9443/app") == "loopback"
    assert windows_acceptance._safe_renderer_origin_class("https://example.invalid/app") == "non_loopback"


def test_acceptance_report_writer_atomically_replaces_complete_json(tmp_path: Path, monkeypatch) -> None:
    report_path = tmp_path / "acceptance.json"
    report_path.write_text('{"old": true}\n', encoding="utf-8")

    windows_acceptance._write_json_atomically(report_path, {"status": "PASS", "complete": True})

    assert json.loads(report_path.read_text(encoding="utf-8")) == {"status": "PASS", "complete": True}
    assert list(tmp_path.glob(".acceptance.json.*.tmp")) == []

    original = report_path.read_text(encoding="utf-8")
    monkeypatch.setattr(windows_acceptance.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("blocked")))
    with pytest.raises(OSError):
        windows_acceptance._write_json_atomically(report_path, {"status": "FAIL"})
    assert report_path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob(".acceptance.json.*.tmp")) == []


def test_model_manager_operation_error_is_allowlisted_before_progress_serialization(monkeypatch) -> None:
    # Build the synthetic credential at runtime so strict source scanning stays enabled.
    canary = "ghp_" + ("x" * 20)
    progress: list[dict] = []
    monkeypatch.setattr(
        windows_acceptance,
        "_model_state",
        lambda _page: {"manager": {"operation": {"status": "failed", "kind": "download", "error": canary}}},
    )
    monkeypatch.setattr(windows_acceptance, "_find_qwen", lambda _state: None)

    with pytest.raises(RuntimeError, match="^model_manager_operation_failed$"):
        windows_acceptance._wait_for_model(
            object(), lambda *_args: False, timeout=10, phase="model_download", progress=progress
        )

    assert len(progress) == 1
    assert progress[0]["error_code"] == "unclassified_model_manager_error"
    assert canary not in json.dumps(progress)
    assert windows_acceptance._safe_model_manager_error_code("backend_unavailable") == "backend_unavailable"


def test_tool_result_summary_reads_nested_model_loop_and_redacts_payloads() -> None:
    summary, source = _safe_tool_result_summary({
        "progress": {"model_loop": {"tool_results": [{
            "name": "browser",
            "arguments": {"url": "secret.example"},
            "tool_call_id": "call_123",
            "ok": False,
            "error": "repeated_read_only_tool_call",
            "result": {
                "failure_class": "RESOURCE",
                "exception": "RuntimeError",
                "error": "untrusted observation text",
            },
        }]}}
    })

    assert source == "model_loop"
    assert summary == [{
        "name": "browser",
        "ok": False,
        "tool_call_id": "call_123",
        "error_code": "repeated_read_only_tool_call",
        "failure_class": "RESOURCE",
        "exception_type": "RuntimeError",
    }]
    assert "secret.example" not in repr(summary)
    assert "untrusted observation text" not in repr(summary)


def test_tool_result_summary_falls_back_to_top_level_results() -> None:
    summary, source = _safe_tool_result_summary({
        "progress": {
            "model_loop": {"tool_results": []},
            "tool_results": [{"name": "run_project_tests", "ok": True}],
        }
    })

    assert source == "top_level"
    assert summary == [{"name": "run_project_tests", "ok": True}]


def test_tool_result_summary_keeps_sandbox_start_and_outcome_metadata() -> None:
    summary, source = _safe_tool_result_summary({
        "progress": {"model_loop": {"tool_results": [{
            "name": "run_project_tests",
            "tool_call_id": "call_42",
            "ok": False,
            "result": {
                "outcome": "CANCELLED",
                "reason_code": "process_cancelled",
                "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
                "resource_limit_reason": None,
                "process_started": True,
                "process_id": 4242,
                "process_started_at_utc": "2026-10-16T14:00:00+00:00",
                "output": "untrusted output is not included",
            },
        }]}}
    })

    assert source == "model_loop"
    assert summary == [{
        "name": "run_project_tests",
        "ok": False,
        "tool_call_id": "call_42",
        "outcome": "CANCELLED",
        "reason_code": "process_cancelled",
        "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
        "process_started": True,
        "process_id": 4242,
        "process_started_at_utc": "2026-10-16T14:00:00+00:00",
    }]
    assert "untrusted output" not in repr(summary)


def test_acceptance_rejects_tool_executed_without_backend_process_start_identity() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    status = snapshot["status"]
    result = status["progress"]["model_loop"]["tool_results"][0]["result"]
    process_payload = snapshot["report"]["evidence"]["execution_chain"][0]["evidence"]
    assert _process_start_fields_match(process_payload, result) is windows_acceptance.sys.platform.startswith("linux")

    missing_pid = dict(result)
    missing_pid.pop("process_id")
    mismatched_time = {**result, "process_started_at_utc": "2026-10-16T14:01:00+00:00"}
    untrusted_backend = {**result, "sandbox_backend": "bubblewrap+prlimit"}
    not_started = {**result, "process_started": False}
    for candidate in (missing_pid, mismatched_time, untrusted_backend, not_started):
        assert _process_start_fields_match(process_payload, candidate) is False

    result["process_started"] = False
    proof = _mission_project_test_execution_proof(
        status, snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1",
        snapshot["report"]["evidence"]["execution_chain_integrity"],
        full_execution_chain=snapshot["full_execution_chain"],
    )
    assert proof["tool_executed_event_count"] == 1
    assert proof["actual_process_start_verified"] is False
    assert proof["verified"] is False


def test_acceptance_rejects_unimplemented_windows_sandbox_backend(monkeypatch) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    status = snapshot["status"]
    result = status["progress"]["model_loop"]["tool_results"][0]["result"]
    process_payload = snapshot["report"]["evidence"]["execution_chain"][0]["evidence"]
    monkeypatch.setattr(windows_acceptance, "sys", SimpleNamespace(platform="win32"))

    for backend in ("windows-appcontainer-job", "bubblewrap+prlimit+cgroup-v2"):
        result["sandbox_backend"] = backend
        process_payload["sandbox_backend"] = backend
        assert _process_start_fields_match(process_payload, result) is False

    proof = _mission_project_test_execution_proof(
        status, snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1",
        snapshot["report"]["evidence"]["execution_chain_integrity"],
        full_execution_chain=snapshot["full_execution_chain"],
    )
    assert proof["actual_process_start_verified"] is False
    assert proof["verified"] is False


def test_mission_event_trace_preserves_order_codes_and_hash_but_redacts_free_text() -> None:
    trace, truncated = _safe_mission_event_trace([{
        "sequence": 8,
        "timestamp": "2026-10-16T13:00:00+01:00",
        "event": "FailureDetected",
        "mission_id": "mission-1",
        "request_id": "request-1",
        "data": {
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": "backend_unavailable",
            "detail_code": "windows_appcontainer_backend_unimplemented",
            "dispatch_attempted": False,
            "process_started": False,
            "reason": "private diagnostic text",
            "token": "raw-secret-token",
        },
    }])

    assert truncated is False
    assert trace == [{
        "timeline_index": 0,
        "sequence": 8,
        "event": "FailureDetected",
        "mission_id": "mission-1",
        "request_id": "request-1",
        "timestamp_utc": "2026-10-16T12:00:00+00:00",
        "data": {
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": "backend_unavailable",
            "detail_code": "windows_appcontainer_backend_unimplemented",
            "dispatch_attempted": False,
            "process_started": False,
        },
        "raw_data_available": True,
        "raw_data_sha256": _canonical_sha256({
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": "backend_unavailable",
            "detail_code": "windows_appcontainer_backend_unimplemented",
            "dispatch_attempted": False,
            "process_started": False,
            "reason": "private diagnostic text",
            "token": "raw-secret-token",
        }),
    }]
    assert "private diagnostic text" not in repr(trace)
    assert "raw-secret-token" not in repr(trace)


def test_mission_event_trace_keeps_safe_process_start_metadata_and_raw_payload_digest() -> None:
    raw_data = {
        "phase": "process-started",
        "process_started": True,
        "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
        "process_id": 4242,
        "started_at_utc": "2026-10-16T14:00:00+00:00",
        "reason_code": "process_exit_zero",
        "resource_limit_reason": "memory_max",
        "token": "raw-secret-token",
    }
    trace, _truncated = _safe_mission_event_trace([{
        "sequence": 9, "event": "ToolCalled", "data": raw_data,
    }])

    assert trace[0]["data"] == {
        "process_started": True,
        "sandbox_backend": "bubblewrap+prlimit+cgroup-v2",
        "process_id": 4242,
        "started_at_utc": "2026-10-16T14:00:00+00:00",
        "reason_code": "process_exit_zero",
        "resource_limit_reason": "memory_max",
    }
    assert trace[0]["raw_data_available"] is True
    assert trace[0]["raw_data_sha256"] == _canonical_sha256(raw_data)
    assert "raw-secret-token" not in repr(trace)


def test_safe_mission_failure_snapshot_preserves_block_reason_and_redacts_free_text() -> None:
    plan = Plan.initial("safe failure fixture").replan(
        steps=(PlanStep("step-1", "run_project_tests", action="run_project_tests"),),
        reason="fixture",
    )
    mission = Mission.create(
        "PRIVATE_OWNER_REQUEST", "PRIVATE_OBJECTIVE", plan,
        mission_id="42mission", request_id="42request", owner_identity_ref="owner:fixture",
    )
    failure = {
        "kind": "PROCESS_SANDBOX_UNAVAILABLE",
        "reason_code": "backend_unavailable",
        "detail_code": "windows_appcontainer_backend_unimplemented",
        "dispatch_attempted": False,
        "blocked_tool_call_ids": ["call-42"],
        "reason": "PRIVATE_DIAGNOSTIC_TEXT",
        "token": "PRIVATE_TOKEN_VALUE",
    }
    mission.transition(
        MissionStatus.RESOURCE_BLOCKED,
        "PRIVATE_TRANSITION_TEXT",
        reason_code="backend_unavailable",
        dispatch_attempted=False,
    )
    mission.failures.append(failure)
    mission.checkpoint = {
        "status": "not_dispatched",
        "reason_code": "backend_unavailable",
        "blocked_tool_call_ids": ["call-42"],
        "token": "PRIVATE_CHECKPOINT_TOKEN",
    }
    mission.progress["tool_results"] = [{
        "name": "run_project_tests",
        "tool_call_id": "call-42",
        "ok": False,
        "error": "process_sandbox_unavailable",
        "output": "PRIVATE_RAW_TOOL_OUTPUT",
    }]
    mission.emit(EventType.FAILURE_DETECTED, data=failure)

    snapshot = safe_mission_failure_snapshot(mission)

    assert snapshot["status_final"] == "RESOURCE_BLOCKED"
    assert snapshot["trajectory_integrity_verified"] is True
    assert snapshot["failure_diagnostics"][-1]["detail_code"] == "windows_appcontainer_backend_unimplemented"
    assert snapshot["failure_diagnostics"][-1]["dispatch_attempted"] is False
    assert snapshot["checkpoint_diagnostics"]["status"] == "not_dispatched"
    assert snapshot["tool_result_diagnostics"][0]["error_code"] == "process_sandbox_unavailable"
    failure_event = next(item for item in snapshot["trajectory_event_trace"] if item["event"] == "FailureDetected")
    assert failure_event["mission_id"] == "42mission"
    assert failure_event["request_id"] == "42request"
    assert failure_event["data"]["blocked_tool_call_ids"] == ["call-42"]
    assert "PRIVATE_" not in repr(snapshot)


def test_safe_mission_failure_snapshot_preserves_allowlisted_runtime_budget_only() -> None:
    plan = Plan.initial("safe budget fixture").replan(
        steps=(PlanStep("step-1", "bounded work", action="mcp.invoke"),),
        reason="fixture",
    )
    mission = Mission.create(
        "PRIVATE_OWNER_REQUEST", "PRIVATE_OBJECTIVE", plan,
        mission_id="budget-mission", request_id="budget-request", owner_identity_ref="owner:fixture",
    )
    failure = {
        "class": "RESOURCE",
        "reason": "PRIVATE_RUNTIME_BUDGET_DETAIL",
        "budget": "max_execution_time_seconds",
        "limit": 300,
        "token": "PRIVATE_TOKEN_VALUE",
    }
    mission.failures.append(failure)
    mission.emit(EventType.FAILURE_DIAGNOSED, data={
        "class": "RESOURCE",
        "budget": "max_execution_time_seconds",
        "limit": 300,
        "recovery": "RESOURCE_BLOCKED",
        "reason": "PRIVATE_RUNTIME_BUDGET_DETAIL",
    })

    snapshot = safe_mission_failure_snapshot(mission)

    assert snapshot["failure_diagnostics"][-1] == {
        "class": "RESOURCE",
        "budget": "max_execution_time_seconds",
        "limit": 300,
    }
    diagnosed = next(item for item in snapshot["trajectory_event_trace"] if item["event"] == "FailureDiagnosed")
    assert diagnosed["data"]["budget"] == "max_execution_time_seconds"
    assert diagnosed["data"]["limit"] == 300
    assert "PRIVATE_RUNTIME_BUDGET_DETAIL" not in repr(snapshot)
    assert "PRIVATE_TOKEN_VALUE" not in repr(snapshot)
    assert safe_static_code("budget", "unapproved_private_budget") is None


def test_safe_acceptance_error_keeps_machine_codes_and_redacts_arbitrary_text() -> None:
    assert safe_acceptance_error(
        RuntimeError("integrated_mission_did_not_reach_goal_completed:RESOURCE_BLOCKED")
    ) == "integrated_mission_did_not_reach_goal_completed:RESOURCE_BLOCKED"
    assert safe_acceptance_error(RuntimeError("private token=do-not-export")) == "failure_details_omitted_for_secret_safety"
    assert safe_acceptance_error(RuntimeError("sk_test_51CompactSecretValue")) == "failure_details_omitted_for_secret_safety"


def test_acceptance_evidence_allowlists_drop_compact_token_shaped_codes_and_ids() -> None:
    token = "sk_test_" + "51CompactSecretValue"
    github_token = "github_pat_" + "CompactSecretValue123"
    assert safe_opaque_identifier(token) is None
    assert safe_static_code("reason_code", "process_exit_zero") == "process_exit_zero"
    assert safe_static_code("reason_code", "cgroup_memory_limit") == "cgroup_memory_limit"
    assert safe_static_code("resource_limit_reason", "cgroup_process_count_limit") == "cgroup_process_count_limit"
    assert safe_static_code("detail_code", "cgroup_resource_event_attribution_unavailable") == "cgroup_resource_event_attribution_unavailable"
    assert safe_static_code("reason_code", token) is None
    assert safe_exception_type(token) == "UnknownError"
    trace, _truncated = _safe_mission_event_trace([{
        "sequence": 1,
        "event": "ToolCalled",
        "mission_id": token,
        "request_id": "request-safe-1",
        "data": {
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": token,
            "detail_code": github_token,
            "tool_call_id": "ghp_" + "CompactSecretValue123456789",
        },
    }])

    assert trace[0]["event"] == "ToolCalled"
    assert "mission_id" not in trace[0]
    assert trace[0]["request_id"] == "request-safe-1"
    assert trace[0]["data"] == {"kind": "PROCESS_SANDBOX_UNAVAILABLE"}
    assert token not in repr(trace)
    assert github_token not in repr(trace)
    summary, _source = _safe_tool_result_summary({
        "tool_results": [{"name": token, "error": token, "result": {"reason_code": token}}]
    })
    assert summary == []


def test_early_restart_failure_projection_keeps_safe_timeline_and_chain_digests() -> None:
    timeline = [{
        "sequence": 1,
        "timestamp": "2026-10-16T14:00:00Z",
        "event": "FailureDetected",
        "mission_id": "42mission",
        "request_id": "42request",
        "data": {
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": "backend_unavailable",
            "detail_code": "windows_appcontainer_backend_unimplemented",
            "dispatch_attempted": False,
            "blocked_tool_call_ids": ["call-42"],
            "reason": "PRIVATE_TIMELINE_REASON",
        },
    }]
    failure = {
        "kind": "PROCESS_SANDBOX_UNAVAILABLE",
        "reason_code": "backend_unavailable",
        "detail_code": "windows_appcontainer_backend_unimplemented",
        "dispatch_attempted": False,
        "reason": "PRIVATE_FAILURE_REASON",
    }
    snapshot = {
        "status": {
            "mission_id": "42mission",
            "request_id": "42request",
            "status": "RESOURCE_BLOCKED",
            "queue": {"state": "paused"},
            "trajectory": timeline,
            "failures": [failure],
            "checkpoint": {"status": "not_dispatched", "reason_code": "backend_unavailable"},
            "plan": {"steps": []},
            "progress": {"tool_results": []},
        },
        "timeline": timeline,
        "evidence": [{"evidence_id": "evidence-1", "private": "PRIVATE_EVIDENCE_TEXT"}],
        "report": {"mission_summary": {"outcome": "NOT_VERIFIED"}, "evidence": {
            "execution_chain": [], "execution_chain_integrity": "NOT_PRESENT",
        }},
        "effects": [],
        "full_execution_chain": [],
        "full_execution_chain_status": "NOT_PRESENT",
    }

    projection = _safe_early_restart_audit_projection(snapshot)

    assert projection["request_id"] == "42request"
    assert projection["timeline_event_count"] == 1
    assert projection["timeline_event_types"] == ["FailureDetected"]
    assert projection["timeline_event_trace"][0]["data"]["detail_code"] == "windows_appcontainer_backend_unimplemented"
    assert projection["timeline_event_trace"][0]["data"]["dispatch_attempted"] is False
    assert projection["evidence_item_count"] == 1
    assert len(projection["evidence_sha256"]) == 64
    assert projection["execution_chain_integrity"] == "NOT_PRESENT"
    assert "PRIVATE_" not in repr(projection)


def test_split_tool_results_preserve_cross_source_duplicates_and_fail_closed() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    progress = snapshot["status"]["progress"]
    project_test = progress["model_loop"]["tool_results"].pop()
    status_result = {"name": "status", "tool_call_id": "status-call", "ok": True}
    progress["model_loop"]["tool_results"].append(status_result)
    progress["tool_results"] = [project_test, dict(status_result)]

    summary, source = _safe_tool_result_summary(snapshot["status"])
    projection = _mission_audit_projection(snapshot, mission_id)
    tool_projection = _tool_execution_projection(snapshot["status"])

    assert source == "model_loop+top_level"
    assert [item["name"] for item in summary] == ["status", "run_project_tests", "status"]
    assert projection["project_test_execution_proof"]["verified"] is False
    assert projection["project_test_execution_proof"]["unaccounted_durable_tool_result_record_count"] > 0
    assert tool_projection["records_count"] == 3
    assert tool_projection["duplicate_tool_call_ids"] is True


def test_identical_nested_and_top_level_project_result_duplicate_fails_closed() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    project_test = snapshot["status"]["progress"]["model_loop"]["tool_results"][0]
    snapshot["status"]["progress"]["tool_results"] = [dict(project_test)]

    summary, source = _safe_tool_result_summary(snapshot["status"])
    projection = _mission_audit_projection(snapshot, mission_id)

    assert source == "model_loop+top_level"
    assert [item["name"] for item in summary] == ["run_project_tests", "run_project_tests"]
    assert projection["project_test_execution_proof"]["verified"] is False
    assert _tool_execution_projection(snapshot["status"])["duplicate_tool_call_ids"] is True


def test_malformed_durable_tool_result_is_not_ignored_by_authorization_projection() -> None:
    summary, _source = _safe_tool_result_summary({
        "progress": {"model_loop": {"tool_results": [
            {"name": "status", "tool_call_id": "status-call", "ok": True},
            "malformed-result-record",
        ]}}
    })

    assert summary[-1] == {"name": "<invalid_action_name>", "ok": None}
    assert _tools_within_authorized_allowlist(summary, ["status"]) is False

    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["status"]["progress"]["tool_results"] = {"malformed": "not-a-list"}
    projection = _mission_audit_projection(snapshot, mission_id)
    assert projection["project_test_execution_proof"]["durable_result_records_valid"] is False
    assert projection["project_test_execution_proof"]["verified"] is False


def test_empty_tool_results_do_not_vacuously_pass_authorization_gate() -> None:
    assert not _tools_within_authorized_allowlist([], ["browser"])
    assert _tools_within_authorized_allowlist([{"name": "browser"}], ["browser"])
    assert not _tools_within_authorized_allowlist([{"name": "mcp.invoke"}], ["browser"])


def test_restart_resume_requires_persisted_pause_authorization_and_unchanged_execution_history() -> None:
    accepted = {
        "mission_status": "RUNNING",
        "queue_state": "paused",
        "pause_requested": True,
        "owner_authorized": True,
        "runtime_ready": True,
        "execution_history_unchanged": True,
    }
    assert _may_resume_after_application_restart(**accepted)
    for key, value in (
        ("queue_state", "running"),
        ("pause_requested", False),
        ("owner_authorized", False),
        ("runtime_ready", False),
        ("execution_history_unchanged", False),
        ("mission_status", "RESOURCE_BLOCKED"),
    ):
        candidate = {**accepted, key: value}
        assert not _may_resume_after_application_restart(**candidate), key

    reauth_checkpoint = {
        **accepted,
        "mission_status": "OWNER_REAUTH_REQUIRED",
        "queue_state": "needs_input",
    }
    assert _may_resume_after_application_restart(**reauth_checkpoint)
    assert not _may_resume_after_application_restart(**{**reauth_checkpoint, "owner_authorized": False})
    assert not _may_resume_after_application_restart(**{**reauth_checkpoint, "queue_state": "paused"})
    assert not _may_resume_after_application_restart(**{**accepted, "queue_state": "needs_input"})


def test_owner_reauthentication_after_restart_rejects_invalid_password_and_restores_same_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id = "mission-acceptance-1"
    identity = "owner:0123456789abcdef"
    responses = [
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 200, "body": {"status": {"mission_id": mission_id, "owner_identity_ref": identity}}},
    ]
    login_attempts = []

    def fake_login(_page, _username, password):
        login_attempts.append(password)
        if password == "correct-test-only-password":
            return {
                "http_status": 200,
                "authenticated": True,
                "username": "mosfiry",
                "credentials_submitted": True,
                "submitted_username_matches": True,
                "submitted_password_matches": True,
            }
        return {
            "http_status": 403,
            "authenticated": False,
            "credentials_submitted": True,
            "submitted_username_matches": True,
            "submitted_password_matches": True,
            "error_code": "invalid_credentials",
        }

    def forbidden_csrf_rotation(_page):
        raise AssertionError("restart authentication must use the renderer-managed CSRF session")

    def fake_api(_page, _method, _path, *, csrf="", payload=None):
        return responses.pop(0)

    monkeypatch.setattr(windows_acceptance, "_public_api", fake_api)
    monkeypatch.setattr(windows_acceptance, "_new_csrf_token", forbidden_csrf_rotation)
    monkeypatch.setattr(windows_acceptance, "_login_owner_after_restart", fake_login)
    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True, "login_form_hidden": True, "logout_button_visible": True},
    )

    result = _owner_auth_after_restart(
        object(), f"/api/public/missions/{mission_id}", "mosfiry",
        "correct-test-only-password", identity,
    )

    assert result["status"] == "PASS"
    assert result["invalid_credentials_rejected"] is True
    assert result["invalid_login_preserved_existing_owner"] is False
    assert result["invalid_login_did_not_create_owner_session"] is True
    assert result["invalid_login_authorization_state_unchanged"] is True
    assert result["invalid_login_error_code"] == "invalid_credentials"
    assert result["valid_login_after_restart"] is True
    assert result["valid_login_credentials_submitted"] is True
    assert result["post_restart_authentication_mode"] == "fresh_valid_login"
    assert result["valid_login_error_code"] is None
    assert result["owner_identity_matches"] is True
    assert result["mission_read_authorized"] is True
    assert login_attempts == ["invalid-after-application-restart", "correct-test-only-password"]
    assert "correct-test-only-password" not in repr(result)


def test_owner_session_survives_restart_but_invalid_login_does_not_replace_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id = "mission-acceptance-1"
    identity = "owner:0123456789abcdef"
    status_body = {"status": {"mission_id": mission_id, "owner_identity_ref": identity}}
    responses = [
        {"http_status": 200, "body": status_body},
        {"http_status": 200, "body": status_body},
        {"http_status": 200, "body": status_body},
    ]

    monkeypatch.setattr(windows_acceptance, "_public_api", lambda *_args, **_kwargs: responses.pop(0))
    monkeypatch.setattr(
        windows_acceptance, "_new_csrf_token",
        lambda _page: (_ for _ in ()).throw(AssertionError("unexpected CSRF session rotation")),
    )
    monkeypatch.setattr(
        windows_acceptance, "_login_owner_after_restart",
        lambda *_args: {
            "http_status": 403,
            "authenticated": False,
            "credentials_submitted": True,
            "submitted_username_matches": True,
            "submitted_password_matches": True,
            "error_code": "invalid_credentials",
        },
    )
    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True, "login_form_hidden": True, "logout_button_visible": True},
    )

    class FakePage:
        class FakeLocator:
            @staticmethod
            def evaluate(_script):
                return None

        @staticmethod
        def locator(_selector):
            return FakePage.FakeLocator()

    result = _owner_auth_after_restart(
        FakePage(), f"/api/public/missions/{mission_id}", "mosfiry", "test-only-password", identity
    )

    assert result["status"] == "PASS"
    assert result["owner_session_restored"] is True
    assert result["valid_login_after_restart"] is False
    assert result["valid_login_credentials_submitted"] is False
    assert result["post_restart_authentication_mode"] == "restored_session"
    assert result["invalid_login_preserved_existing_owner"] is True
    assert result["invalid_login_did_not_create_owner_session"] is False
    assert result["invalid_login_authorization_state_unchanged"] is True
    assert "test-only-password" not in repr(result)


def test_restart_login_helper_matches_actual_post_body_without_recording_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResponseInfo:
        def __init__(self, response):
            self.value = response

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Locator:
        @staticmethod
        def evaluate(_script):
            return None

        @staticmethod
        def fill(_value):
            return None

        @staticmethod
        def click(**_kwargs):
            return None

    class FakePage:
        def __init__(self, username: str, password: str, *, method: str = "POST", request_url: str | None = None):
            self.url = "http://127.0.0.1:5000/app/index.html"
            request = type("Request", (), {})()
            request.method = method
            request.url = request_url or "http://127.0.0.1:5000/api/public/auth/login"
            request.post_data = json.dumps({"username": username, "password": password})
            self.response = type("Response", (), {})()
            self.response.request = request
            self.response.url = request.url
            self.response.status = 200
            self.response.json = lambda: {"authenticated": True, "username": username}

        @staticmethod
        def locator(_selector):
            return Locator()

        def expect_response(self, predicate, timeout):
            assert timeout == 30_000
            assert predicate(self.response)
            return ResponseInfo(self.response)

    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True},
    )
    password = "test-only-password"
    page = FakePage("mosfiry", password)

    valid = windows_acceptance._login_owner_after_restart(page, "mosfiry", password)
    assert valid["credentials_submitted"] is True
    assert valid["submitted_username_matches"] is True
    assert valid["submitted_password_matches"] is True
    assert password not in repr(valid)

    page.response.request.post_data = json.dumps({"username": "mosfiry", "password": "wrong-password"})
    page.response.status = 403
    page.response.json = lambda: {"error": "invalid_credentials"}
    mismatched = windows_acceptance._login_owner_after_restart(page, "mosfiry", password)
    assert mismatched["credentials_submitted"] is False
    assert mismatched["submitted_username_matches"] is True
    assert mismatched["submitted_password_matches"] is False
    assert password not in repr(mismatched)

    invalid_targets = [
        (
            "POST",
            "http://127.0.0.1:5000/api/public/auth/login/extra",
        ),
        (
            "POST",
            "http://localhost:5000/api/public/auth/login",
        ),
        (
            "GET",
            "http://127.0.0.1:5000/api/public/auth/login",
        ),
    ]
    for method, request_url in invalid_targets:
        unsafe_page = FakePage("mosfiry", password, method=method, request_url=request_url)
        unsafe_result = windows_acceptance._login_owner_after_restart(
            unsafe_page, "mosfiry", password
        )
        assert unsafe_result["credentials_submitted"] is False
        assert unsafe_result["authenticated"] is False
        assert password not in repr(unsafe_result)


def test_post_restart_model_gate_reports_unrestored_selection_and_runtime_truthfully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    digest = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]
    state = {
        "models": [{
            **_qwen_model_payload(), "installed": True, "installed_sha256": digest,
            "selected": False, "active": False,
        }],
        "manager": {"runtime": {"status": "stopped", "model_id": None}, "operation": {"status": "complete"}},
    }
    monkeypatch.setattr(windows_acceptance, "_model_state", lambda _page: state)
    monkeypatch.setattr(windows_acceptance, "_wait_for_model", lambda _page, _predicate, **_kwargs: state)
    monkeypatch.setattr(
        windows_acceptance, "_installed_runtime_binary_evidence",
        lambda _executable: {"exists": True, "sha256": "c" * 64, "version": "test-version"},
    )

    result = _model_runtime_after_restart(object(), tmp_path / "CyberSentinel.exe", [], verify_inference=False)

    assert result["status"] == "FAIL"
    assert result["selected_after_restart"] is False
    assert result["active_after_restart"] is False
    assert result["runtime_ready_after_restart"] is False
    assert result["runtime_binary"]["version"] == "test-version"


def test_mission_project_test_source_labels_without_dispatched_process_proof_are_rejected() -> None:
    mission_id = "mission-acceptance-1"
    proof = _mission_project_test_execution_proof(
        {"mission_id": mission_id, "progress": {"model_loop": {"tool_results": []}}},
        [],
        [{"mission_id": mission_id, "source": "run_project_tests"}],
        [{"mission_id": mission_id, "source": "run_project_tests",
          "report_verification": "TRUSTED_DETERMINISTIC_SOURCE"}],
        [{"mission_id": mission_id, "source": "sandboxed-process:run_project_tests"}],
        mission_id,
        "request-acceptance-1",
        "VALID",
    )

    assert proof["verified"] is False
    assert proof["exactly_one_actual_execution_verified"] is False
    assert proof["verified_linked_execution_count"] == 0
    assert proof["mission_request_binding_verified"] is False


def test_blocked_or_used_unverified_state_overrides_conflicting_success_data() -> None:
    conflicting_success = {
        "mission": {
            "status": "GOAL_COMPLETED",
            "progress": {"tool_results": [{"name": "run_project_tests", "ok": True,
                                             "result": {"status": "BLOCKED"}}]},
        },
        "report": {
            "mission_summary": {
                "outcome": "VERIFIED",
                "verification": {"verified": True, "status": "USED_UNVERIFIED"},
            }
        },
    }
    assert _contains_blocked_or_unverified_status(conflicting_success) is True
    assert _contains_blocked_or_unverified_status(
        {"mission": {"status": "GOAL_COMPLETED"},
         "report": {"mission_summary": {"outcome": "VERIFIED", "verification": {
             "verified": True, "evidence_count": 1, "missing_criteria": []
         }}}}
    ) is False


@pytest.mark.parametrize(
    "record",
    [
        {"status": "UNVERIFIED"},
        {"verification": "UNVERIFIED"},
        {"report_verification": "UNVERIFIED_PROVENANCE"},
        {"validation_state": "UNVERIFIED"},
        {"validation_state": "PENDING_VALIDATION"},
        {"result_validation_state": "UNVERIFIED"},
        {"result_validation_state": "PENDING_VALIDATION"},
        {"execution_chain_integrity": "NOT_PRESENT"},
        {"status": "RECOVERY_REQUIRED"},
    ],
)
def test_exact_unverified_and_incomplete_status_forms_are_rejected(record: dict) -> None:
    assert _contains_blocked_or_unverified_status(record) is True


@pytest.mark.parametrize(
    "record",
    [
        {"status": []},
        {"status": {"value": "GOAL_COMPLETED"}},
        {"verification_status": ["VERIFIED"]},
        {"verification_state": {"value": "VERIFIED"}},
        {"report_verification": {"value": "TRUSTED_DETERMINISTIC_SOURCE"}},
        {"verification": ["VERIFIED"]},
        {"verification": {"verified": True}},
        {"result": {"status": ["GOAL_COMPLETED"]}},
    ],
)
def test_non_scalar_or_malformed_status_encodings_fail_closed(record: dict) -> None:
    assert _contains_blocked_or_unverified_status(record) is True


@pytest.mark.parametrize(
    "extra_result",
    [
        {
            "name": "run_project_tests",
            "ok": True,
            "result": {"ok": True, "returncode": 0},
        },
        {
            "name": "run_project_tests",
            "tool_call_id": "foreign-call",
            "ok": True,
            "result": {"ok": True, "returncode": 0},
            "mission_id": "another-mission",
            "request_id": "request-acceptance-1",
        },
    ],
)
def test_extra_successful_project_test_result_is_counted_and_fails_closed(extra_result: dict) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    tool_results = snapshot["status"]["progress"]["model_loop"]["tool_results"]
    tool_results.append(extra_result)

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["result_record_count"] == 2
    assert proof["successful_result_record_count"] == 2
    assert proof["unaccounted_successful_result_record_count"] == 1
    assert proof["verified"] is False
    assert proof["exactly_one_actual_execution_verified"] is False


def test_unaccounted_failed_authorization_result_for_another_tool_blocks_project_test_proof() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["status"]["progress"]["model_loop"]["tool_results"].append({
        "tool_call_id": "call-auth-denied",
        "name": "browser",
        "arguments": {"url": "https://example.invalid/"},
        "ok": False,
        "result": {},
        "error": "authorization_denied",
        "mission_id": mission_id,
        "request_id": "request-acceptance-1",
        "run_id": "run-once",
        "turn_id": "turn-once",
        "action_id": "action-auth-denied",
        "step_id": "step-auth-denied",
        "plan_version": 1,
    })

    proof = _mission_audit_projection(snapshot, mission_id)["project_test_execution_proof"]

    assert proof["verified"] is False
    assert proof["all_durable_tool_results_accounted"] is False
    assert proof["all_durable_tool_results_successful"] is False
    assert proof["durable_tool_result_record_count"] == 2
    assert proof["unaccounted_durable_tool_result_record_count"] == 1
    assert proof["failed_durable_tool_result_record_count"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "scope", "context", "step", "call_id", "missing_authorization_call_id",
        "missing_authorization", "duplicate_authorization", "producer_minimal",
        "denied_but_executed", "late",
    ],
)
def test_project_test_proof_requires_ordered_scope_bound_authorization(mutation: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    authorization_index = next(
        index for index, event in enumerate(snapshot["timeline"])
        if event.get("event") == "AuthorizationChecked"
    )
    authorization_event = snapshot["timeline"][authorization_index]
    data = authorization_event["data"]
    if mutation == "scope":
        data["scope_snapshot_id"] = "different-scope"
    elif mutation == "context":
        data["authorization_context_id"] = "different-context"
    elif mutation == "step":
        data["step_id"] = "different-step"
    elif mutation == "call_id":
        data["tool_call_id"] = "different-call"
    elif mutation == "missing_authorization_call_id":
        del data["tool_call_id"]
    elif mutation == "missing_authorization":
        snapshot["timeline"].pop(authorization_index)
    elif mutation == "duplicate_authorization":
        snapshot["timeline"].append(dict(authorization_event))
    elif mutation == "producer_minimal":
        authorization_event["data"] = {
            "tool_call_id": data["tool_call_id"],
            "allowed": True,
            "reason": "allowed",
        }
    elif mutation == "denied_but_executed":
        data["allowed"] = False
    else:
        snapshot["timeline"].pop(authorization_index)
        executed_index = next(
            index for index, event in enumerate(snapshot["timeline"])
            if event.get("event") == "ToolExecuted"
        )
        snapshot["timeline"].insert(executed_index + 1, authorization_event)

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"], snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1", "VALID",
        full_execution_chain=snapshot["full_execution_chain"],
    )

    assert proof["authorization_timeline_reconciled"] is False
    assert proof["all_calls_fully_authorized_successful"] is False
    assert proof["verified"] is False
    if mutation == "producer_minimal":
        assert proof["authorization_schema_status"] == "BLOCKED"


def test_current_runtime_authorization_schema_is_blocked_without_scope_fields() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    authorization_event = next(
        event for event in snapshot["timeline"] if event.get("event") == "AuthorizationChecked"
    )
    authorization_event["data"] = {
        "tool_call_id": authorization_event["data"]["tool_call_id"],
        "allowed": True,
        "reason": "allowed",
    }

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"], snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1", "VALID",
        full_execution_chain=snapshot["full_execution_chain"],
    )

    assert proof["authorization_schema_status"] == "BLOCKED"
    assert proof["authorization_timeline_reconciled"] is False
    assert proof["verified"] is False


def test_orphan_authorization_event_blocks_project_test_proof() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["timeline"].append({
        "event": "AuthorizationChecked",
        "mission_id": mission_id,
        "request_id": "request-acceptance-1",
        "data": {"tool_call_id": "call-orphan", "allowed": True},
    })

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"], snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1", "VALID",
        full_execution_chain=snapshot["full_execution_chain"],
    )

    assert proof["authorization_timeline_reconciled"] is False
    assert proof["verified"] is False


@pytest.mark.parametrize("authorization_name", ["browser", None])
def test_authorization_event_must_bind_the_name_of_the_executed_tool(
    authorization_name: str | None,
) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    authorization = next(
        event for event in snapshot["timeline"]
        if event.get("event") == "AuthorizationChecked"
    )
    if authorization_name is None:
        authorization["data"].pop("name")
    else:
        authorization["data"]["name"] = authorization_name

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1", "VALID",
        full_execution_chain=snapshot["full_execution_chain"],
    )

    assert proof["authorization_timeline_reconciled"] is False
    assert proof["verified"] is False


def test_project_test_proof_rejects_native_tool_result_without_a_name() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["status"]["progress"]["model_loop"]["tool_results"][0].pop("name")

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"],
        mission_id, "request-acceptance-1", "VALID",
        full_execution_chain=snapshot["full_execution_chain"],
    )

    assert proof["authorization_timeline_reconciled"] is False
    assert proof["verified"] is False


def test_pre_dispatch_authorization_denial_is_classified_but_never_a_success() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    denied = dict(snapshot["status"]["progress"]["model_loop"]["tool_results"][0])
    denied.update({"name": "browser", "ok": False, "result": {}, "error": "authorization_denied"})
    denied["action_id"] = "action-denied"
    denied["step_id"] = "step-denied"
    denied["tool_call_id"] = "call-denied"
    proposal = dict(snapshot["timeline"][0])
    proposal["data"] = {
        **proposal["data"], "name": "browser", "tool_call_id": "call-denied",
        "action_id": "action-denied", "step_id": "step-denied",
    }
    authorization = dict(snapshot["timeline"][1])
    authorization["data"] = {
        **authorization["data"], "name": "browser", "tool_call_id": "call-denied",
        "action_id": "action-denied", "step_id": "step-denied", "allowed": False,
    }
    mission_state = {**snapshot["status"], "action_history": []}

    result = windows_acceptance._reconcile_tool_authorization_timeline(
        mission_state, [proposal, authorization], [denied], mission_id, "request-acceptance-1"
    )

    assert result["verified"] is True
    assert result["call_classifications"] == ["PRE_DISPATCH_DENIED"]
    assert result["fully_authorized_successful_execution"] is False


def test_post_dispatch_tool_failure_is_not_misclassified_as_pre_dispatch_denial() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    failed = dict(snapshot["status"]["progress"]["model_loop"]["tool_results"][0])
    failed.update({"ok": False, "error": "tool execution failed"})
    failed["result"] = {**failed["result"], "ok": False, "returncode": 1}
    executed_event = next(
        event for event in snapshot["timeline"] if event.get("event") == "ToolExecuted"
    )
    executed_event["data"]["status"] = "failed"
    action_record = snapshot["status"]["action_history"][0]
    action_record["status"] = "failed"
    action_record["observation"]["ok"] = False

    result = windows_acceptance._reconcile_tool_authorization_timeline(
        snapshot["status"], snapshot["timeline"], [failed], mission_id, "request-acceptance-1"
    )

    assert result["verified"] is True
    assert result["call_classifications"] == ["POST_DISPATCH_FAILURE"]
    assert result["fully_authorized_successful_execution"] is False


@pytest.mark.parametrize(
    "field",
    ["timeline_sha256", "action_history_sha256", "report_sha256", "full_execution_chain_sha256"],
)
def test_restart_reconciliation_rejects_changed_persisted_record_hashes(field: str) -> None:
    mission_id, snapshot, _mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(snapshot, mission_id)
    assert before["timeline_integrity_verified"] is True
    after = dict(before)
    changed_digest = "0" * 64
    if before[field] == changed_digest:
        changed_digest = "1" * 64
    after[field] = changed_digest

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert result["reconciled"] is False
    assert field in result["mismatched_fields"]


@pytest.mark.parametrize(
    "field",
    sorted(set(windows_acceptance._RESTART_STABLE_PROJECTION_FIELDS)),
)
def test_restart_reconciliation_rejects_each_required_field_missing_from_both_projections(
    field: str,
) -> None:
    mission_id, snapshot, _mission = _d4_runtime_snapshot()
    projection = _mission_audit_projection(snapshot, mission_id)
    assert projection["timeline_integrity_verified"] is True
    before, after = dict(projection), dict(projection)
    before.pop(field, None)
    after.pop(field, None)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert result["reconciled"] is False
    assert field in result["mismatched_fields"]


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("mission_id", None),
        ("mission_status", ""),
        ("timeline_integrity_verified", None),
        ("timeline_sha256", ""),
        ("timeline_event_count", None),
        ("project_test_execution_proof", {}),
        ("evidence_sha256", "not-a-sha256"),
    ],
)
def test_restart_reconciliation_rejects_empty_null_or_malformed_projection_values(
    field: str, invalid_value: object,
) -> None:
    mission_id, snapshot, _mission = _d4_runtime_snapshot()
    projection = _mission_audit_projection(snapshot, mission_id)
    before, after = dict(projection), dict(projection)
    before[field] = invalid_value
    after[field] = invalid_value

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert result["reconciled"] is False
    assert field in result["mismatched_fields"]


def test_restart_reconciliation_rejects_changed_mission_plan_and_history() -> None:
    mission_id, before_snapshot, _mission = _d4_runtime_snapshot()
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["status"]["plan"]["objective"] = "Different objective"
    after_snapshot["status"]["plan_history"].append(
        {"version": 2, "fingerprint": "a" * 64, "reason": "replanned"}
    )

    before = _mission_audit_projection(before_snapshot, mission_id)
    after = _mission_audit_projection(after_snapshot, mission_id)
    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert result["reconciled"] is False
    assert "mission_plan_sha256" in result["mismatched_fields"]
    assert "mission_plan_history_sha256" in result["mismatched_fields"]


def test_runtime_timeline_passes_but_incomplete_audit_projection_fails_closed() -> None:
    mission_id, snapshot, mission = _d4_runtime_snapshot()
    assert verify_trajectory(mission.trajectory) is True
    projection = _mission_audit_projection(snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(projection, dict(projection))

    assert projection["mission_record_integrity_verified"] is True
    assert projection["timeline_matches_integrity_checked_mission"] is True
    assert projection["timeline_integrity_verified"] is True
    assert projection["report_sha256"] is None
    assert result["reconciled"] is False
    assert "report_sha256" in result["mismatched_fields"]
    assert "full_execution_chain_sha256" in result["mismatched_fields"]


@pytest.mark.parametrize("field", sorted(windows_acceptance._TRAJECTORY_EVENT_FIELDS))
def test_timeline_rejects_each_missing_runtime_event_field(field: str) -> None:
    mission_id, snapshot, mission = _d4_runtime_snapshot()
    del mission.trajectory[1][field]
    snapshot["timeline"] = mission.trajectory

    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["timeline_integrity_verified"] is False


def test_restart_reconciliation_rejects_a_deleted_timeline_event() -> None:
    mission_id, before_snapshot, _mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["timeline"].pop(1)
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is False
    assert result["reconciled"] is False
    assert "timeline_integrity_verified" in result["mismatched_fields"]


def test_restart_reconciliation_rejects_a_valid_runtime_event_inserted_after_snapshot() -> None:
    mission_id, before_snapshot, mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    mission.emit(EventType.FAILURE_DETECTED, data={"reason": "test-only extra event"})
    after_snapshot["timeline"] = json.loads(json.dumps(mission.trajectory))
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is True
    assert after["timeline_matches_integrity_checked_mission"] is False
    assert result["reconciled"] is False
    assert "timeline_sha256" in result["mismatched_fields"]
    assert "timeline_event_count" in result["mismatched_fields"]


def test_restart_reconciliation_rejects_a_resealed_chain_not_bound_to_mission_integrity() -> None:
    mission_id, before_snapshot, mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    mission.emit(EventType.FAILURE_DETECTED, data={"reason": "inserted before projection"})
    after_timeline = json.loads(json.dumps(mission.trajectory))
    after_snapshot["timeline"] = after_timeline
    after_snapshot["status"]["trajectory"] = after_timeline
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is True
    assert after["mission_record_integrity_verified"] is False
    assert after["timeline_matches_integrity_checked_mission"] is False
    assert result["reconciled"] is False


def test_restart_reconciliation_rejects_a_duplicated_timeline_event() -> None:
    mission_id, before_snapshot, _mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["timeline"].append(dict(after_snapshot["timeline"][-1]))
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is False
    assert result["reconciled"] is False


def test_restart_reconciliation_rejects_reordered_timeline_events() -> None:
    mission_id, before_snapshot, _mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["timeline"][1], after_snapshot["timeline"][2] = (
        after_snapshot["timeline"][2], after_snapshot["timeline"][1]
    )
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is False
    assert result["reconciled"] is False


def test_restart_reconciliation_rejects_a_changed_timeline_event_hash_identifier() -> None:
    mission_id, before_snapshot, _mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["timeline"][2]["event_hash"] = "0" * 64
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["timeline_integrity_verified"] is False
    assert result["reconciled"] is False


def test_restart_reconciliation_rejects_a_report_that_differs_from_its_evidence_source() -> None:
    mission_id, before_snapshot, _mission = _d4_evidence_report_fixture_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["report"]["evidence"]["digest_sha256"] = "0" * 64
    _refresh_report_digest(after_snapshot)
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["report_digest_matches_canonical_body"] is True
    assert after["report_evidence_digest_matches_source"] is False
    assert result["reconciled"] is False
    assert "report_evidence_digest_matches_source" in result["mismatched_fields"]


def test_restart_reconciliation_rejects_a_tampered_evidence_chain_hash() -> None:
    mission_id, before_snapshot, _mission = _d4_evidence_report_fixture_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["report"]["evidence"]["execution_chain"][0]["current_hash"] = "0" * 64
    _refresh_report_digest(after_snapshot)
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert after["report_digest_matches_canonical_body"] is True
    assert after["execution_chain_hash_valid"] is False
    assert result["reconciled"] is False
    assert "execution_chain_hash_valid" in result["mismatched_fields"]


def test_restart_revalidates_runtime_timeline_after_store_restore_and_blocks_missing_sources(
    tmp_path: Path,
) -> None:
    mission_id, before_snapshot, mission = _d4_runtime_snapshot()
    before = _mission_audit_projection(before_snapshot, mission_id)
    store = MissionStore(tmp_path / "d4-mission-store.sqlite3")
    store.save(mission)
    restored = store.load(mission_id)
    assert restored is not None

    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["timeline"] = restored.trajectory
    after_snapshot["status"]["plan"] = restored.plan.to_dict()
    after_snapshot["status"]["plan_history"] = restored.plan_history
    after = _mission_audit_projection(after_snapshot, mission_id)
    result = windows_acceptance._mission_restart_reconciliation(before, after)

    assert verify_trajectory(restored.trajectory) is True
    assert after["mission_record_integrity_verified"] is True
    assert after["timeline_matches_integrity_checked_mission"] is True
    assert after["timeline_integrity_verified"] is True
    assert before["timeline_sha256"] == after["timeline_sha256"]
    assert result["reconciled"] is False
    assert "report_sha256" in result["mismatched_fields"]
    assert "full_execution_chain_sha256" in result["mismatched_fields"]


def test_owner_reauth_option_does_not_bypass_missing_real_report_or_chain() -> None:
    mission_id, snapshot, _mission = _d4_runtime_snapshot()
    projection = _mission_audit_projection(snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(
        projection, dict(projection), allow_owner_reauth_transition=True
    )

    assert result["reconciled"] is False
    assert result["owner_reauth_transition_justified"] is False
    assert "report_sha256" in result["mismatched_fields"]
    assert "full_execution_chain_sha256" in result["mismatched_fields"]


@pytest.mark.parametrize("changed_field", ["objective", "completion_criteria"])
def test_owner_reauth_transition_rejects_changed_report_source_inputs(changed_field: str) -> None:
    mission_id, before_snapshot, mission = _d4_runtime_snapshot()
    before_source = mission.to_dict()
    after_mission = Mission.from_dict(before_source)
    if changed_field == "objective":
        after_mission.objective = "Changed objective"
    else:
        after_mission.completion_criteria = [{"criterion_id": "changed", "required": True}]
    after_source = after_mission.to_dict()
    assert windows_acceptance._report_producer_source_sha256(before_source) != (
        windows_acceptance._report_producer_source_sha256(after_source)
    )
    after_snapshot = json.loads(json.dumps(before_snapshot))
    after_snapshot["status"][changed_field] = after_source[changed_field]
    before = _mission_audit_projection(before_snapshot, mission_id)
    after = _mission_audit_projection(after_snapshot, mission_id)

    result = windows_acceptance._mission_restart_reconciliation(
        before, after, allow_owner_reauth_transition=True
    )

    assert result["reconciled"] is False
    assert result["owner_reauth_transition_justified"] is False
    assert "report_sha256" in result["mismatched_fields"]


def test_pid_only_process_tree_termination_never_reports_pass() -> None:
    assert _process_tree_termination_status(
        taskkill_started=True, taskkill_exit_code=0, initial_tree_verified=True,
        remaining_process_count=0, process_id_stopped=True, cdp_endpoint_unavailable=True,
    ) == "NOT_RUN"
    assert _process_tree_termination_status(
        taskkill_started=True, taskkill_exit_code=1, initial_tree_verified=True,
        remaining_process_count=0, process_id_stopped=True, cdp_endpoint_unavailable=True,
    ) == "NOT_RUN"
    assert _process_tree_termination_status(
        taskkill_started=True, taskkill_exit_code=0, initial_tree_verified=False,
        remaining_process_count=0, process_id_stopped=True, cdp_endpoint_unavailable=True,
    ) == "NOT_RUN"
    assert _process_tree_termination_status(
        taskkill_started=False, taskkill_exit_code=None, initial_tree_verified=False,
        remaining_process_count=None, process_id_stopped=None, cdp_endpoint_unavailable=None,
    ) == "NOT_RUN"


def test_process_tree_alive_probe_does_not_promote_pid_only_kill_to_pass() -> None:
    status, process_stopped = _process_tree_termination_from_alive_probe(
        taskkill_started=True,
        taskkill_exit_code=0,
        initial_tree_verified=True,
        remaining_process_count=0,
        process_alive=False,
        cdp_endpoint_unavailable=True,
    )

    assert process_stopped is True
    assert status == "NOT_RUN"

    alive_status, alive_stopped = _process_tree_termination_from_alive_probe(
        taskkill_started=True,
        taskkill_exit_code=0,
        initial_tree_verified=True,
        remaining_process_count=0,
        process_alive=True,
        cdp_endpoint_unavailable=True,
    )
    assert alive_stopped is False
    assert alive_status == "NOT_RUN"


class _FakeProcessHandleAPI:
    def __init__(self, unavailable_process_ids: tuple[int, ...] = ()) -> None:
        self.unavailable_process_ids = set(unavailable_process_ids)
        self.opened: list[int] = []
        self.closed: list[int] = []

    def OpenProcess(self, _access: int, _inherit: bool, process_id: int):
        self.opened.append(process_id)
        return None if process_id in self.unavailable_process_ids else process_id

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(handle)
        return True


@pytest.mark.parametrize("invalid_member", ["missing_image", "parent_pid_reused"])
def test_process_tree_snapshot_rejects_missing_member_identity_or_reused_parent_pid(
    invalid_member: str, tmp_path: Path
) -> None:
    root_executable = tmp_path / "CyberSentinel.exe"
    child_executable = tmp_path / "renderer.exe"
    root_executable.write_bytes(b"root executable fixture")
    child_executable.write_bytes(b"child executable fixture")
    root_time = "134050176000000000"
    child_time = "134050176010000000"
    child_image: str | None = str(child_executable)
    if invalid_member == "missing_image":
        child_image = None
    else:
        root_time, child_time = child_time, root_time
    snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": root_time,
            "image_path": str(root_executable),
        },
        124: {
            "parent_process_id": 123,
            "creation_time": child_time,
            "image_path": child_image,
        },
    }

    assert windows_acceptance._windows_process_tree_identity_records(snapshot, 123) is None


@pytest.mark.parametrize("failure_mode", ["snapshot_unavailable", "image_mismatch"])
def test_process_termination_refuses_taskkill_without_verified_installed_identity(
    failure_mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    other_executable = tmp_path / "Other.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    other_executable.write_bytes(b"different executable fixture")
    snapshot = None if failure_mode == "snapshot_unavailable" else {
        123: {
            "parent_process_id": 1,
            "creation_time": "134050176000000000",
            "image_path": str(other_executable),
        },
    }
    taskkill_calls = []

    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        windows_acceptance.subprocess,
        "run",
        lambda *args, **kwargs: taskkill_calls.append((args, kwargs)),
    )

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert taskkill_calls == []
    assert result["taskkill_attempted"] is False
    assert result["process_tree_termination_verified"] is False
    assert result["process_tree_termination_status"] == "NOT_RUN"
    assert result["installed_process_identity_verified"] is False


@pytest.mark.parametrize(
    "identity_change",
    [
        "pid_reused_by_same_image",
        "missing_creation_time",
        "malformed_creation_time",
        "missing_image_path",
        "wrong_process_id",
        "not_running",
    ],
)
def test_pre_kill_process_identity_must_match_captured_pid_instance(
    identity_change: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    creation_time = "134050176000000000"
    snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": creation_time,
            "image_path": str(installed_executable),
        },
    }
    pre_kill_identity = {
        "process_id": 123,
        "image_path": str(installed_executable),
        "creation_time": creation_time,
        "running": True,
    }
    if identity_change == "pid_reused_by_same_image":
        pre_kill_identity["creation_time"] = "134050176010000000"
    elif identity_change == "missing_creation_time":
        pre_kill_identity.pop("creation_time")
    elif identity_change == "malformed_creation_time":
        pre_kill_identity["creation_time"] = "not-a-filetime"
    elif identity_change == "missing_image_path":
        pre_kill_identity.pop("image_path")
    elif identity_change == "wrong_process_id":
        pre_kill_identity["process_id"] = 456
    else:
        pre_kill_identity["running"] = False
    process_api = _FakeProcessHandleAPI()
    taskkill_calls = []

    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        windows_acceptance, "_windows_process_api", lambda: process_api
    )
    monkeypatch.setattr(
        windows_acceptance,
        "_windows_process_handle_identity",
        lambda _api, _handle: pre_kill_identity,
    )
    monkeypatch.setattr(
        windows_acceptance.subprocess,
        "run",
        lambda *args, **kwargs: taskkill_calls.append((args, kwargs)),
    )

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert taskkill_calls == []
    assert result["taskkill_attempted"] is False
    assert result["process_tree_termination_verified"] is False
    assert result["process_tree_termination_status"] == "NOT_RUN"
    assert result["installed_process_identity_verified"] is False
    assert result["termination_refusal_reason"] == "process_tree_member_handle_or_identity_unavailable"
    assert process_api.opened == [123]
    assert process_api.closed == [123]


@pytest.mark.parametrize("identity_change", ["changed_creation_time", "missing_identity"])
def test_child_identity_change_immediately_before_taskkill_refuses_and_releases_all_handles(
    identity_change: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    child_executable = tmp_path / "renderer.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    child_executable.write_bytes(b"child executable fixture")
    root_time = "134050176000000000"
    child_time = "134050176010000000"
    snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": root_time,
            "image_path": str(installed_executable),
        },
        124: {
            "parent_process_id": 123,
            "creation_time": child_time,
            "image_path": str(child_executable),
        },
    }
    root_identity = {
        "process_id": 123,
        "image_path": str(installed_executable),
        "creation_time": root_time,
        "running": True,
    }
    child_identity = {
        "process_id": 124,
        "image_path": str(child_executable),
        "creation_time": child_time,
        "running": True,
    }
    changed_child = dict(child_identity)
    if identity_change == "changed_creation_time":
        changed_child["creation_time"] = "134050176020000000"
    else:
        changed_child = None
    # Pin-time reads and the post-open recheck match; the final pre-taskkill recheck changes.
    identity_sequences = {
        123: [root_identity, root_identity, root_identity],
        124: [child_identity, child_identity, changed_child],
    }

    def read_handle_identity(_api, handle):
        values = identity_sequences[handle]
        return values.pop(0) if len(values) > 1 else values[0]

    process_api = _FakeProcessHandleAPI()
    taskkill_calls = []
    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: snapshot)
    monkeypatch.setattr(windows_acceptance, "_windows_process_api", lambda: process_api)
    monkeypatch.setattr(windows_acceptance, "_windows_process_handle_identity", read_handle_identity)
    monkeypatch.setattr(
        windows_acceptance.subprocess,
        "run",
        lambda *args, **kwargs: taskkill_calls.append((args, kwargs)),
    )

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert taskkill_calls == []
    assert result["taskkill_attempted"] is False
    assert result["process_tree_termination_verified"] is False
    assert result["termination_refusal_reason"] == "pre_kill_pinned_process_tree_identity_mismatch"
    assert process_api.opened == [123, 124]
    assert process_api.closed == [124, 123]


def test_missing_child_handle_refuses_taskkill_and_closes_handles_already_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    child_executable = tmp_path / "renderer.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    child_executable.write_bytes(b"child executable fixture")
    snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": "134050176000000000",
            "image_path": str(installed_executable),
        },
        124: {
            "parent_process_id": 123,
            "creation_time": "134050176010000000",
            "image_path": str(child_executable),
        },
    }
    process_api = _FakeProcessHandleAPI(unavailable_process_ids=(124,))
    identity_by_pid = {
        123: {
            "process_id": 123,
            "image_path": str(installed_executable),
            "creation_time": "134050176000000000",
            "running": True,
        },
    }
    taskkill_calls = []
    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: snapshot)
    monkeypatch.setattr(windows_acceptance, "_windows_process_api", lambda: process_api)
    monkeypatch.setattr(
        windows_acceptance,
        "_windows_process_handle_identity",
        lambda _api, handle: identity_by_pid.get(handle),
    )
    monkeypatch.setattr(
        windows_acceptance.subprocess,
        "run",
        lambda *args, **kwargs: taskkill_calls.append((args, kwargs)),
    )

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert taskkill_calls == []
    assert result["installed_process_identity_verified"] is False
    assert process_api.opened == [123, 124]
    assert process_api.closed == [123]


def test_changed_process_tree_snapshot_refuses_taskkill_and_releases_all_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    child_executable = tmp_path / "renderer.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    child_executable.write_bytes(b"child executable fixture")
    initial_snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": "134050176000000000",
            "image_path": str(installed_executable),
        },
        124: {
            "parent_process_id": 123,
            "creation_time": "134050176010000000",
            "image_path": str(child_executable),
        },
    }
    process_api = _FakeProcessHandleAPI()
    identity_by_pid = {
        123: {
            "process_id": 123,
            "image_path": str(installed_executable),
            "creation_time": "134050176000000000",
            "running": True,
        },
        124: {
            "process_id": 124,
            "image_path": str(child_executable),
            "creation_time": "134050176010000000",
            "running": True,
        },
    }
    snapshots = iter([initial_snapshot, {123: initial_snapshot[123]}])
    taskkill_calls = []
    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(windows_acceptance, "_windows_process_api", lambda: process_api)
    monkeypatch.setattr(
        windows_acceptance,
        "_windows_process_handle_identity",
        lambda _api, handle: identity_by_pid.get(handle),
    )
    monkeypatch.setattr(
        windows_acceptance.subprocess,
        "run",
        lambda *args, **kwargs: taskkill_calls.append((args, kwargs)),
    )

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert taskkill_calls == []
    assert result["termination_refusal_reason"] == "process_tree_changed_after_handle_pin"
    assert process_api.closed == [124, 123]


def test_process_tree_handles_are_released_when_unbound_pid_taskkill_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed_executable = tmp_path / "CyberSentinel.exe"
    child_executable = tmp_path / "renderer.exe"
    grandchild_executable = tmp_path / "gpu-process.exe"
    installed_executable.write_bytes(b"installed executable fixture")
    child_executable.write_bytes(b"child executable fixture")
    grandchild_executable.write_bytes(b"grandchild executable fixture")
    snapshot = {
        123: {
            "parent_process_id": 1,
            "creation_time": "134050176000000000",
            "image_path": str(installed_executable),
        },
        124: {
            "parent_process_id": 123,
            "creation_time": "134050176010000000",
            "image_path": str(child_executable),
        },
        125: {
            "parent_process_id": 124,
            "creation_time": "134050176020000000",
            "image_path": str(grandchild_executable),
        },
    }
    process_api = _FakeProcessHandleAPI()
    identity_by_pid = {
        123: {
            "process_id": 123,
            "image_path": str(installed_executable),
            "creation_time": "134050176000000000",
            "running": True,
        },
        124: {
            "process_id": 124,
            "image_path": str(child_executable),
            "creation_time": "134050176010000000",
            "running": True,
        },
        125: {
            "process_id": 125,
            "image_path": str(grandchild_executable),
            "creation_time": "134050176020000000",
            "running": True,
        },
    }
    snapshots = iter([snapshot, snapshot])
    calls = []
    monkeypatch.setattr(windows_acceptance.os, "name", "nt")
    monkeypatch.setattr(windows_acceptance, "_windows_process_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(windows_acceptance, "_windows_process_api", lambda: process_api)
    monkeypatch.setattr(
        windows_acceptance,
        "_windows_process_handle_identity",
        lambda _api, handle: identity_by_pid.get(handle),
    )
    monkeypatch.setattr(windows_acceptance, "APPLICATION_PROCESS_EXIT_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(windows_acceptance, "_windows_process_alive", lambda _pid: False)
    monkeypatch.setattr(windows_acceptance, "_cdp_version", lambda _port: None)

    def fake_taskkill(command, **kwargs):
        calls.append((command, kwargs))
        raise AssertionError("PID-only taskkill must remain disabled")

    monkeypatch.setattr(windows_acceptance.subprocess, "run", fake_taskkill)

    result = windows_acceptance._terminate_installed_process_tree(
        123, 4312, installed_executable
    )

    assert calls == []
    assert result["taskkill_attempted"] is False
    assert result["process_tree_termination_status"] == "NOT_RUN"
    assert result["process_tree_termination_verified"] is False
    assert result["process_tree_initial_member_count"] == 3
    assert result["termination_refusal_reason"] == "launch_bound_process_identity_unavailable"
    assert process_api.opened == [123, 124, 125]
    assert process_api.closed == [125, 124, 123]


def test_owner_auth_does_not_claim_valid_login_without_observed_credential_submission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id = "mission-acceptance-1"
    identity = "owner:0123456789abcdef"
    responses = [
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 403, "body": {"error": "owner_authentication_required"}},
        {"http_status": 200, "body": {"status": {"mission_id": mission_id, "owner_identity_ref": identity}}},
    ]

    def fake_login(_page, _username, password):
        if password == "correct-test-only-password":
            return {
                "http_status": 200, "authenticated": True, "username": "mosfiry",
                "credentials_submitted": False,
            }
        return {"http_status": 403, "authenticated": False, "error_code": "invalid_credentials"}

    monkeypatch.setattr(windows_acceptance, "_public_api", lambda *_args, **_kwargs: responses.pop(0))
    monkeypatch.setattr(windows_acceptance, "_login_owner_after_restart", fake_login)
    monkeypatch.setattr(
        windows_acceptance, "_renderer_owner_auth_state",
        lambda _page: {"authenticated": True, "login_form_hidden": True, "logout_button_visible": True},
    )

    result = _owner_auth_after_restart(
        object(), f"/api/public/missions/{mission_id}", "mosfiry",
        "correct-test-only-password", identity,
    )

    assert result["status"] == "FAIL"
    assert result["valid_login_after_restart"] is False
    assert result["valid_login_credentials_submitted"] is False


def test_tool_execution_projection_detects_replayed_call_ids_without_payloads() -> None:
    mission = {
        "progress": {"model_loop": {"tool_results": [
            {"name": "run_project_tests", "tool_call_id": "call_once", "ok": True,
             "arguments": {"workspace": "private-path", "secret": "must-not-appear"}},
            {"name": "run_project_tests", "tool_call_id": "call_once", "ok": True,
             "arguments": {"workspace": "private-path", "secret": "must-not-appear"}},
        ]}}
    }

    projection = _tool_execution_projection(mission)

    assert projection["count"] == 2
    assert projection["run_project_tests_result_record_count"] == 2
    assert not any("invocation" in key for key in projection)
    assert projection["duplicate_tool_call_ids"] is True
    assert "private-path" not in repr(projection)
    assert "must-not-appear" not in repr(projection)


def test_blocked_project_test_result_is_not_reported_as_a_process_invocation() -> None:
    projection = _tool_execution_projection({
        "progress": {"model_loop": {"tool_results": [{
            "name": "run_project_tests",
            "tool_call_id": "proposal-rejected-before-process-start",
            "ok": False,
            "error": "operation_not_authorized",
        }]}}
    })

    assert projection["run_project_tests_result_record_count"] == 1
    assert "run_project_tests_invocation_count" not in projection


def test_tool_execution_projection_detects_payload_only_changes_without_exposing_them() -> None:
    mission = {"progress": {"model_loop": {"tool_results": [{
        "name": "status",
        "tool_call_id": "status-call",
        "ok": True,
        "result": {"private_payload": "first-private-result"},
    }]}}}

    before = _tool_execution_projection(mission)
    mission["progress"]["model_loop"]["tool_results"][0]["result"]["private_payload"] = "second-private-result"
    after = _tool_execution_projection(mission)

    assert before["summary_sha256"] == after["summary_sha256"]
    assert before["records_sha256"] != after["records_sha256"]
    assert before["records_count"] == after["records_count"] == 1
    assert "first-private-result" not in repr(before)
    assert "second-private-result" not in repr(after)


def test_effect_ledger_projection_detects_duplicate_or_misbound_effects_without_payloads() -> None:
    mission_id = "mission-acceptance-1"
    records = [
        {
            "effect_id": "effect-1", "mission_id": mission_id, "task_id": "step-1",
            "execution_id": "execution-1", "provider": "local", "operation": "inspect",
            "state": "completed", "requires_reconciliation": False, "owner_binding_status": "bound",
            "updated_at": "2026-10-10T00:00:00Z", "private_payload": "must-not-appear",
        },
        {
            "effect_id": "effect-1", "mission_id": mission_id, "task_id": "step-1",
            "execution_id": "execution-1", "provider": "local", "operation": "inspect",
            "state": "completed", "requires_reconciliation": False, "owner_binding_status": "bound",
            "updated_at": "2026-10-11T00:00:00Z", "private_payload": "must-not-appear",
        },
    ]

    projection = _effect_ledger_projection(records, mission_id)
    misbound = _effect_ledger_projection([{**records[0], "mission_id": "another-mission"}], mission_id)
    nested_misbound = _effect_ledger_projection(
        [{**records[0], "metadata": {"provenance": {"mission_id": "another-mission"}}}],
        mission_id,
    )
    timestamp_only_change = _effect_ledger_projection(
        [{**records[0], "updated_at": "2026-10-12T00:00:00Z"},
         {**records[1], "updated_at": "2026-10-13T00:00:00Z"}], mission_id
    )

    assert projection["available"] is True
    assert projection["count"] == 2
    assert projection["duplicate_effect_ids"] is True
    assert projection["mission_binding_verified"] is True
    assert projection["sha256"] == timestamp_only_change["sha256"]
    assert projection["full_records_sha256"] != timestamp_only_change["full_records_sha256"]
    assert misbound["mission_binding_verified"] is False
    assert nested_misbound["mission_binding_verified"] is False
    assert "must-not-appear" not in repr(projection)


def test_mission_audit_projection_requires_mission_bound_validation_evidence_and_report() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    _attach_completed_mission_trajectory(snapshot)

    projection = _mission_audit_projection(snapshot, mission_id)

    assert verify_chain(snapshot["report"]["evidence"]["execution_chain"]) is True
    assert projection["evidence_and_chain_bound_to_mission"] is True
    assert projection["timeline_records_bound_to_mission"] is True
    assert projection["timeline_integrity_verified"] is True
    assert projection["goal_completion_events_verified"] is True
    assert projection["report_projection_valid"] is True
    assert projection["completed_mission_inspectable"] is True
    assert projection["evidence_records_bound_to_mission"] is True
    assert projection["validation_record_bound_to_mission"] is True
    assert projection["project_test_evidence_source_verified"] is True
    assert projection["project_test_evidence_sources"] == ["sandboxed-process:run_project_tests"]
    assert projection["project_test_execution_proof"]["exactly_one_actual_execution_verified"] is True
    assert projection["project_test_execution_proof"]["actual_process_start_verified"] is True
    assert projection["project_test_execution_proof"]["sandbox_process_evidence_record_count"] == 1
    assert projection["project_test_execution_proof"]["native_tool_result_record_count"] == 1
    assert projection["project_test_execution_proof"]["linked_result_record_count"] == 1
    assert projection["execution_chain_records_bound_to_mission"] is True
    assert projection["execution_chain_provenance_bound_to_mission"] is True
    assert projection["execution_chain_provenance_matches_payload"] is True
    assert projection["execution_chain_hash_valid"] is True
    assert projection["execution_chain_integrity_verified"] is True
    assert projection["report_digest_matches_canonical_body"] is True
    assert projection["report_sha256"] == snapshot["report"]["report_sha256"]
    assert projection["validation_sha256"] == _canonical_sha256(
        snapshot["report"]["mission_summary"]["verification"]
    )

    snapshot["timeline"][1]["data"] = {"nested": {"mission_id": "another-mission"}}
    nested_timeline_projection = _mission_audit_projection(snapshot, mission_id)
    assert nested_timeline_projection["timeline_records_bound_to_mission"] is False
    assert nested_timeline_projection["evidence_and_chain_bound_to_mission"] is False
    assert nested_timeline_projection["completed_mission_inspectable"] is False
    snapshot["timeline"][1].pop("data")

    snapshot["report"]["mission_summary"]["mission_id"] = "another-mission"
    _refresh_report_digest(snapshot)
    wrong_mission_projection = _mission_audit_projection(snapshot, mission_id)
    assert wrong_mission_projection["evidence_and_chain_bound_to_mission"] is False
    assert wrong_mission_projection["completed_mission_inspectable"] is False

    snapshot["report"]["mission_summary"]["mission_id"] = mission_id
    snapshot["evidence"][0]["provenance"]["mission_id"] = "another-mission"
    unbound_evidence_projection = _mission_audit_projection(snapshot, mission_id)
    assert unbound_evidence_projection["evidence_records_bound_to_mission"] is False
    assert unbound_evidence_projection["completed_mission_inspectable"] is False

    snapshot["evidence"][0]["provenance"]["mission_id"] = mission_id
    snapshot["report"]["evidence"]["execution_chain"][0]["evidence"]["mission_id"] = "another-mission"
    _refresh_report_digest(snapshot)
    contradictory_chain_projection = _mission_audit_projection(snapshot, mission_id)
    assert contradictory_chain_projection["execution_chain_records_bound_to_mission"] is False
    assert contradictory_chain_projection["evidence_and_chain_bound_to_mission"] is False

    snapshot["report"]["evidence"]["execution_chain"][0]["evidence"].pop("mission_id")
    _refresh_report_digest(snapshot)
    tool_results = snapshot["status"]["progress"]["model_loop"]["tool_results"]
    tool_results.append(dict(tool_results[0]))
    duplicate_execution_projection = _mission_audit_projection(snapshot, mission_id)
    assert duplicate_execution_projection["project_test_execution_proof"]["verified"] is False
    assert duplicate_execution_projection["project_test_execution_proof"]["linked_result_record_count"] == 2
    assert duplicate_execution_projection["completed_mission_inspectable"] is False

    tool_results.pop()
    snapshot["report"]["mission_summary"]["outcome"] = "PARTIALLY_VERIFIED"
    _refresh_report_digest(snapshot)
    tampered_report_projection = _mission_audit_projection(snapshot, mission_id)
    assert tampered_report_projection["report_digest_matches_canonical_body"] is True
    assert tampered_report_projection["report_projection_valid"] is False
    assert tampered_report_projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize(
    "tamper", ["invalid_hash", "inconsistent_payload", "provenance_mismatch"]
)
def test_mission_audit_projection_rejects_tampered_evidence_chain(tamper: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    chain = snapshot["report"]["evidence"]["execution_chain"]
    assert verify_chain(chain) is True

    if tamper == "invalid_hash":
        chain[0]["current_hash"] = "f" * 64
        assert verify_chain(chain) is False
    elif tamper == "inconsistent_payload":
        chain[0]["evidence"]["output_sha256"] = "d" * 64
        assert verify_chain(chain) is False
    else:
        snapshot["report"]["provenance"]["execution_chain"][0]["task_id"] = "different-task"
        assert verify_chain(chain) is True

    assert snapshot["report"]["evidence"]["execution_chain_integrity"] == "VALID"
    _refresh_report_digest(snapshot)
    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["execution_chain_integrity"] == "VALID"
    assert projection["execution_chain_hash_valid"] is (tamper == "provenance_mismatch")
    assert projection["execution_chain_integrity_verified"] is (tamper == "provenance_mismatch")
    if tamper == "provenance_mismatch":
        assert projection["execution_chain_provenance_matches_payload"] is False
        assert projection["project_test_execution_proof"]["verified"] is True
    else:
        assert projection["project_test_execution_proof"]["verified"] is False
    assert projection["report_projection_valid"] is False
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize("passed_state", ["false", "missing"])
def test_project_test_report_goal_evidence_requires_explicit_pass(passed_state: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    report_goal = snapshot["report"]["evidence"]["goal"][0]
    if passed_state == "false":
        report_goal["passed"] = False
    else:
        report_goal.pop("passed")

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["exactly_one_actual_execution_verified"] is False


def test_claimed_native_evidence_fails_even_with_a_valid_recomputed_chain() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    chain = snapshot["report"]["evidence"]["execution_chain"]
    claimed_native = {**chain[1], "verification": "claimed", "current_hash": ""}
    chain[1] = Evidence(**claimed_native).to_dict()
    snapshot["full_execution_chain"][1] = chain[1]
    snapshot["report"]["provenance"]["execution_chain"][1]["current_hash"] = chain[1]["current_hash"]
    _refresh_report_digest(snapshot)

    assert verify_chain(chain) is True
    projection = _mission_audit_projection(snapshot, mission_id)

    assert projection["execution_chain_hash_valid"] is True
    assert projection["execution_chain_provenance_matches_payload"] is True
    assert projection["project_test_execution_proof"]["verified"] is False
    assert projection["completed_mission_inspectable"] is False


def test_conflicting_split_results_with_same_call_id_fail_closed() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    progress = snapshot["status"]["progress"]
    original = progress["model_loop"]["tool_results"][0]
    conflict = {**original, "result": {**original["result"], "returncode": 1}}
    progress["tool_results"] = [conflict]

    projection = _mission_audit_projection(snapshot, mission_id)
    tool_projection = _tool_execution_projection(snapshot["status"])

    assert projection["project_test_execution_proof"]["result_record_count"] == 2
    assert projection["project_test_execution_proof"]["verified"] is False
    assert projection["project_test_execution_proof"]["exactly_one_actual_execution_verified"] is False
    assert tool_projection["duplicate_tool_call_ids"] is True
    assert projection["completed_mission_inspectable"] is False


@pytest.mark.parametrize(
    ("call_ok", "result_ok", "returncode"),
    [(False, True, 0), (True, False, 0), (True, True, 1)],
)
def test_inconsistent_or_failed_tool_result_cannot_verify_project_tests(
    call_ok: bool, result_ok: bool, returncode: int,
) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    call = snapshot["status"]["progress"]["model_loop"]["tool_results"][0]
    call["ok"] = call_ok
    call["result"]["ok"] = result_ok
    call["result"]["returncode"] = returncode

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["exactly_one_actual_execution_verified"] is False
    assert proof["unaccounted_successful_result_record_count"] == 1


@pytest.mark.parametrize("unclassified", [{}, {"ok": True, "tool_call_id": "unclassified-call"}])
def test_unclassified_durable_result_dict_blocks_project_test_proof(unclassified: dict) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["status"]["progress"]["tool_results"] = [unclassified]

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["exactly_one_actual_execution_verified"] is False


def test_project_test_result_must_match_the_recorded_tool_execution() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    progress = snapshot["status"]["progress"]
    call = progress["model_loop"]["tool_results"].pop()
    call["action_id"] = "unrecorded-action"
    call["result"]["action_id"] = "unrecorded-action"
    progress["tool_results"] = [call]

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["linked_result_record_count"] == 0
    assert proof["verified_linked_execution_count"] == 0


@pytest.mark.parametrize(
    "extra_result",
    [
        {
            "name": "run_project_tests",
            "tool_call_id": "extra-failed-call",
            "ok": False,
            "result": {"ok": False, "returncode": 1},
            "mission_id": "mission-acceptance-1",
            "request_id": "request-acceptance-1",
            "action_id": "extra-failed-action",
            "step_id": "extra-failed-step",
        },
        {
            "name": "run_project_tests",
            "tool_call_id": "extra-malformed-call",
            "ok": False,
            "result": "malformed-result-payload",
            "mission_id": "mission-acceptance-1",
            "request_id": "request-acceptance-1",
            "action_id": "extra-malformed-action",
            "step_id": "extra-malformed-step",
        },
    ],
)
def test_extra_failed_or_malformed_project_test_record_blocks_valid_success(
    extra_result: dict,
) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["status"]["progress"]["tool_results"] = [extra_result]

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["result_record_count"] == 2
    assert proof["verified"] is False
    assert proof["unaccounted_result_record_count"] == 1
    assert proof["all_project_test_results_accounted"] is False


@pytest.mark.parametrize(
    "mismatch", ["timeline_step_id", "timeline_data_step_id", "result_step_id"]
)
def test_tool_executed_step_id_must_match_project_test_result(mismatch: str) -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    call = snapshot["status"]["progress"]["model_loop"]["tool_results"][0]
    tool_executed_index = next(
        index for index, event in enumerate(snapshot["timeline"])
        if event.get("event") == "ToolExecuted"
    )
    if mismatch == "timeline_step_id":
        snapshot["timeline"][tool_executed_index]["step_id"] = "different-step"
    elif mismatch == "timeline_data_step_id":
        snapshot["timeline"][tool_executed_index]["data"]["step_id"] = "different-step"
    else:
        call["step_id"] = "different-step"
        call["result"]["step_id"] = "different-step"

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["linked_result_record_count"] == 0
    assert proof["unaccounted_result_record_count"] == 1


def test_orphan_tool_executed_timeline_event_blocks_valid_project_test_success() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    snapshot["timeline"].append({
        "event": "ToolExecuted",
        "mission_id": mission_id,
        "request_id": "request-acceptance-1",
        "step_id": "orphan-step",
        "data": {"action_id": "orphan-action", "status": "completed"},
    })

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["tool_executed_timeline_reconciled"] is False
    assert proof["unaccounted_tool_executed_event_count"] == 1
    assert proof["unaccounted_action_history_record_count"] == 0


def test_non_scalar_tool_executed_status_fails_closed() -> None:
    mission_id, snapshot = _linked_project_test_snapshot()
    tool_executed = next(
        event for event in snapshot["timeline"] if event.get("event") == "ToolExecuted"
    )
    tool_executed["data"]["status"] = ["completed"]

    proof = _mission_project_test_execution_proof(
        snapshot["status"], snapshot["timeline"], snapshot["evidence"],
        snapshot["report"]["evidence"]["goal"],
        snapshot["report"]["evidence"]["execution_chain"], mission_id,
        "request-acceptance-1", snapshot["report"]["evidence"]["execution_chain_integrity"],
    )

    assert proof["verified"] is False
    assert proof["tool_executed_timeline_reconciled"] is False
    assert proof["unaccounted_tool_executed_event_count"] == 1


def test_acceptance_restart_uses_owned_windows_job_and_never_pid_sweep() -> None:
    driver = (ROOT / "scripts" / "windows_desktop_acceptance.py").read_text(encoding="utf-8")
    powershell = (ROOT / "scripts" / "windows_installer_acceptance.ps1").read_text(encoding="utf-8")
    job_module = (ROOT / "scripts" / "windows_process_job.py").read_text(encoding="utf-8")

    assert "launch_bound_process_identity_unavailable" in driver
    assert "taskkill.exe\", \"/PID\", str(process_id), \"/T\", \"/F\"" not in driver
    assert "--installed-executable" in powershell
    assert "--launch-in-owned-job" in powershell
    assert "Start-Process -FilePath $exePath" not in powershell
    assert "installed_executable_fingerprint_unavailable" in driver
    assert "source_commit_identity_unavailable" in driver
    assert "process_tree_termination_verified" in driver
    assert "initial_application_process_not_running_from_installed_path" in driver
    assert "--mode full requires --installed-executable and --launch-in-owned-job" in driver
    assert '"renderer_reload_used": False' in driver
    assert "page.reload(" not in driver
    assert "taskkill.exe" not in powershell
    assert "Get-CimInstance" not in powershell
    assert "Stop-InstalledProcessTrees" not in powershell
    assert '$report.cleanup.taskkill_attempted = $false' in powershell
    assert "$report.cleanup.process_tree_termination_verified = $ownedJobStopped" in powershell
    assert "if ($ownedJobStopped)" in powershell
    for api in (
        "CreateProcessW", "AssignProcessToJobObject", "ResumeThread",
        "TerminateJobObject", "IsProcessInJob", "GetProcessTimes",
        "QueryInformationJobObject",
    ):
        assert api in job_module
    assert "_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in job_module
    assert "_CREATE_SUSPENDED" in job_module


def test_installer_is_started_and_cleaned_up_inside_its_owned_job() -> None:
    powershell = (ROOT / "scripts" / "windows_installer_acceptance.ps1").read_text(encoding="utf-8")
    job_module = (ROOT / "scripts" / "windows_process_job.py").read_text(encoding="utf-8")

    assert '"run-installer"' in powershell
    assert "windows_process_job.py" in powershell
    assert "Start-Process -FilePath $InstallerPath" not in powershell
    assert "Stop-Process -Id $installerProcess.Id" not in powershell
    assert "job_tree_termination_verified" in powershell
    assert "installer_process_tree_termination_verified" in powershell
    assert "def run_installer_in_owned_job(" in job_module
    assert "def run_process_in_owned_job(" in job_module
    assert "GetExitCodeProcess" in job_module


def test_windows_acceptance_script_returns_failure_exit_code_for_non_pass_status() -> None:
    powershell = (ROOT / "scripts" / "windows_installer_acceptance.ps1").read_text(encoding="utf-8")

    assert '$exitCode = if ($report.status -eq "PASS") { 0 } else { 1 }' in powershell
    assert "exit $exitCode" in powershell
    assert "exit 0" not in powershell


def test_checkpoint_diagnostics_expose_only_safe_budget_metadata() -> None:
    result = _safe_checkpoint_diagnostics({
        "checkpoint": {
            "status": "budget_blocked",
            "budget": "max_execution_steps",
            "limit": 18,
            "run_id": "private-run-id",
        }
    })

    assert result == {"status": "budget_blocked", "budget": "max_execution_steps", "limit": 18}
    assert "private-run-id" not in repr(result)


def test_qwen_action_diagnostics_reject_non_identifier_model_text() -> None:
    assert _safe_action_names(["mcp.discover", "arbitrary model text: secret"]) == [
        "mcp.discover",
        "<invalid_action_name>",
    ]


def test_qwen_planning_diagnostics_do_not_mutate_integrity_covered_progress(tmp_path: Path) -> None:
    actions = ["status", "mcp.discover", "mcp.invoke"]
    plan = Plan.initial("diagnostic fixture").replan(
        steps=tuple(
            PlanStep(f"step-{index}", action, action=action)
            for index, action in enumerate(actions, start=1)
        ),
        reason="test fixture",
    )
    mission = Mission.create(
        "diagnostic fixture", "diagnostic fixture", plan,
        request_id="qwen-diagnostic-integrity", owner_identity_ref="owner:1",
    )
    mission.progress["initial_model_response"] = {
        "tool_calls": [{"name": action} for action in actions]
    }
    mission.progress["planning_attempts"] = [{
        "proposed_tool_names": list(actions), "repair_requested": False,
    }]
    mission = MissionStore(tmp_path / "missions.sqlite3").save(mission)
    progress_before = json.loads(json.dumps(mission.progress))

    snapshot = _qwen_planning_diagnostics(mission, tuple(actions))

    assert mission.verify_integrity()
    assert mission.progress == progress_before
    assert snapshot["diagnostics"]["final_plan_complete"] is True
    assert snapshot["diagnostics"]["final_plan_mcp_discovery_before_invocation"] is True


def test_model_state_fetch_retries_are_bounded_and_auditable(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0
    state = {"manager": {"operation": {"status": "ready"}}, "models": []}

    def transient_failure(_page):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise RuntimeError("untrusted text must not be recorded")
        return state

    monkeypatch.setattr(windows_acceptance, "_model_state", transient_failure)
    monkeypatch.setattr(windows_acceptance, "_local_health_status", lambda _page: 200)
    monkeypatch.setattr(windows_acceptance.time, "sleep", lambda _seconds: None)
    progress: list[dict] = []

    result = windows_acceptance._wait_for_model(
        object(), lambda _state, _model, _operation: True,
        timeout=10, phase="test", progress=progress,
    )

    assert result is state
    assert attempts == 3
    phases = [item["phase"] for item in progress]
    assert phases[:3] == [
        "test_api_fetch_retry",
        "test_api_fetch_retry",
        "test_api_fetch_recovered",
    ]
    assert phases[3:] == ["test"]
    assert progress[0]["local_health_status"] == 200
    assert progress[2]["consecutive_failures"] == 2
    assert "untrusted text" not in repr(progress)


def test_model_state_fetch_fails_after_bounded_consecutive_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        windows_acceptance, "_model_state",
        lambda _page: (_ for _ in ()).throw(RuntimeError("private text")),
    )
    monkeypatch.setattr(windows_acceptance, "_local_health_status", lambda _page: None)
    monkeypatch.setattr(windows_acceptance.time, "sleep", lambda _seconds: None)
    progress: list[dict] = []

    with pytest.raises(RuntimeError, match="desktop_model_manager_api_unavailable_after_bounded_retries"):
        windows_acceptance._wait_for_model(
            object(), lambda _state, _model, _operation: False,
            timeout=60, phase="test", progress=progress,
        )

    assert len(progress) == MODEL_STATE_API_MAX_CONSECUTIVE_FAILURES == 5
    assert MODEL_STATE_API_MAX_TOTAL_FAILURES == 10
    assert all(item["phase"] == "test_api_fetch_retry" for item in progress)
    assert "private text" not in repr(progress)


def test_health_probe_refuses_non_loopback_url() -> None:
    class Page:
        url = "http://example.com:1234/"

    assert _local_health_status(Page()) is None


def _qwen_model_payload() -> dict:
    model = get_model("qwen3-4b-q4-k-m")
    return {key: getattr(model, key) for key in EXPECTED_QWEN3_4B_INSTALL_IDENTITY}


@pytest.mark.parametrize(
    "installed,installed_sha256,catalog_sha256",
    [
        (True, None, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (True, "0" * 64, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (False, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"], EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]),
        (True, EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"], "0" * 64),
    ],
)
def test_final_qwen_digest_gate_rejects_missing_or_mismatched_digest(
    installed, installed_sha256, catalog_sha256
) -> None:
    model = {
        **_qwen_model_payload(),
        "installed": installed,
        "installed_sha256": installed_sha256,
        "sha256": catalog_sha256,
    }

    digest_report = _qwen_installed_digest_report(model)
    assert digest_report["installed"] is installed
    assert digest_report["verified"] is False
    with pytest.raises(RuntimeError, match="qwen3_4b_installed_digest_missing_or_mismatched"):
        _require_qwen_installed_digest(digest_report)


def test_final_qwen_digest_gate_accepts_only_pinned_installed_digest() -> None:
    digest = EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"]
    model = {
        **_qwen_model_payload(),
        "installed": True,
        "installed_sha256": digest,
    }

    digest_report = _qwen_installed_digest_report(model)
    assert digest_report["matches_catalog"] is True
    assert digest_report["matches_pinned"] is True
    assert digest_report["verified"] is True
    _require_qwen_installed_digest(digest_report)


def test_qwen_snapshot_refreshes_from_final_post_activation_poll_state() -> None:
    initial_model = {
        **_qwen_model_payload(),
        "family": "Qwen3",
        "parameter_size": "4B",
        "compatible": True,
        "recommended": True,
        "installed": False,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": False,
        "active": False,
    }
    report = {"model_manager": {"catalog_loaded": True}}

    _refresh_qwen_model_snapshot(
        report, {"models": [initial_model]}, phase="initial_catalog_state"
    )
    assert report["model_manager"]["qwen3_4b"]["installed"] is False
    assert report["model_manager"]["qwen3_4b"]["installed_sha256"] is None

    final_model = {
        **initial_model,
        "installed": True,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": True,
        "active": True,
    }
    returned_model = _refresh_qwen_model_snapshot(
        report, {"models": [final_model]}, phase="post_activation_inference_poll"
    )

    assert returned_model is final_model
    assert report["model_manager"]["qwen3_4b_snapshot_phase"] == "post_activation_inference_poll"
    assert report["model_manager"]["qwen3_4b"] == {
        "model_id": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["model_id"],
        "display_name": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["display_name"],
        "family": "Qwen3",
        "parameter_size": "4B",
        "repository": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["repository"],
        "revision": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["revision"],
        "filename": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["filename"],
        "quantization": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["quantization"],
        "size_bytes": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["size_bytes"],
        "sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "compatible": True,
        "recommended": True,
        "installed": True,
        "installed_sha256": EXPECTED_QWEN3_4B_INSTALL_IDENTITY["sha256"],
        "selected": True,
        "active": True,
    }

    source = (ROOT / "scripts" / "windows_desktop_acceptance.py").read_text(encoding="utf-8")
    snapshot_phases = [
        'phase="post_install_verification_poll"',
        'phase="post_activation_poll"',
        'phase="post_install_activation_poll"',
        'phase="post_activation_inference_poll"',
    ]
    phase_positions = [source.index(phase) for phase in snapshot_phases]
    assert phase_positions == sorted(phase_positions)
    assert source.index('timeout=300, phase="real_local_inference"') < phase_positions[-1]
    assert phase_positions[-1] < source.index("_require_qwen_installed_digest(digest_verification)")
    assert '"qwen3_4b_model_manager":' in source
    assert '"qwen3_4b_installed_digest_matches_catalog_and_pin":' in source
    assert '"qwen3_4b_runtime_active":' in source
    assert '"real_qwen_local_inference":' in source


class _FakeDialog:
    def __init__(self, message: str, *, dialog_type: str = "confirm") -> None:
        self.message = message
        self.type = dialog_type
        self.accepted = False
        self.dismissed = False

    def accept(self) -> None:
        self.accepted = True

    def dismiss(self) -> None:
        self.dismissed = True


def test_qwen_install_consent_is_pinned_to_curated_model_identity() -> None:
    model = get_model("qwen3-4b-q4-k-m")
    catalog_identity = {
        key: getattr(model, key)
        for key in EXPECTED_QWEN3_4B_INSTALL_IDENTITY
    }

    assert EXPECTED_QWEN3_4B_INSTALL_IDENTITY == catalog_identity
    assert _build_expected_qwen_install_consent(_qwen_model_payload()) == (
        "تنزيل هذا الملف إلى جهازك؟\n\n"
        "Qwen3 4B · Q4_K_M\n"
        "unsloth/Qwen3-4B-GGUF@22c9fc8a8c7700b76a1789366280a6a5a1ad1120\n"
        "Qwen3-4B-Q4_K_M.gguf · 2.3 GiB\n"
        "الرخصة في بطاقة التحويل: Apache-2.0\n"
        "SHA-256: f6f851777709861056efcdad3af01da38b31223a3ba26e61a4f8bf3a2195813a\n\n"
        "سيُستخدم llama.cpp محليًا بعد التحقق. لا يبدأ التنزيل إلا بموافقتك."
    )


def test_matching_qwen_install_consent_is_accepted() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected)
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent, authorize_test_download=True)
    _require_qwen_install_consent(consent)

    assert dialog.accepted and not dialog.dismissed
    assert consent == {"seen": True, "accepted": True, "mismatch": False, "authorized": True}


def test_matching_qwen_install_consent_is_dismissed_without_explicit_opt_in() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected)
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent)

    assert dialog.dismissed and not dialog.accepted
    assert consent["authorized"] is False
    with pytest.raises(RuntimeError, match="qwen3_4b_test_download_explicit_opt_in_required"):
        _require_qwen_install_consent(consent)


def test_mismatched_qwen_install_consent_is_dismissed_and_fails_closed() -> None:
    expected = _build_expected_qwen_install_consent(_qwen_model_payload())
    dialog = _FakeDialog(expected.replace("2.3 GiB", "2.4 GiB"))
    consent = {"seen": False, "accepted": False, "mismatch": False}

    _handle_qwen_install_dialog(dialog, expected, consent, authorize_test_download=True)

    assert dialog.dismissed and not dialog.accepted
    with pytest.raises(RuntimeError, match="qwen3_4b_install_consent_mismatch"):
        _require_qwen_install_consent(consent)


def test_missing_qwen_install_consent_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="qwen3_4b_install_consent_missing"):
        _require_qwen_install_consent({"seen": False, "accepted": False, "mismatch": False, "authorized": True})


def test_qwen_install_consent_refuses_catalog_identity_drift() -> None:
    model = _qwen_model_payload()
    model["revision"] = "0" * 40

    assert _build_expected_qwen_install_consent(model) is None


def test_qwen_install_post_guard_requires_exact_explicit_authorization_and_loopback_route() -> None:
    origin = "http://127.0.0.1:4312"
    expected_id = "qwen3-4b-q4-k-m"
    consent = {"authorized": True, "seen": True, "accepted": True, "mismatch": False}
    request = _FakeInstallRequest(f"{origin}/api/public/desktop/models/{expected_id}/install")

    assert _is_expected_qwen_install_post_request(request, expected_id, origin)
    assert _may_continue_qwen_install_post(request, expected_id, origin, consent)
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "authorized": False})
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "accepted": False})
    assert not _may_continue_qwen_install_post(request, expected_id, origin, {**consent, "mismatch": True})
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"https://127.0.0.1:4312/api/public/desktop/models/{expected_id}/install"),
        expected_id,
        origin,
    )
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"{origin}/api/public/desktop/models/other-model/install"),
        expected_id,
        origin,
    )
    assert not _is_expected_qwen_install_post_request(
        _FakeInstallRequest(f"{origin}/api/public/desktop/models/{expected_id}/install", method="GET"),
        expected_id,
        origin,
    )


class _FakeInstallRequest:
    def __init__(
        self,
        url: str = "http://127.0.0.1:4312/api/public/desktop/models/qwen3-4b-q4-k-m/install",
        method: str = "POST",
    ) -> None:
        self.url = url
        self.method = method


class _FakeInstallResponse:
    request = _FakeInstallRequest()
    url = "http://127.0.0.1:4312/api/public/desktop/models/qwen3-4b-q4-k-m/install"

    def __init__(self, status: int, body: dict) -> None:
        self.status = status
        self._body = body

    def json(self) -> dict:
        return self._body


def test_qwen_install_post_rejects_unexpected_http_status() -> None:
    response = _FakeInstallResponse(409, {"ok": False, "error": "model_manager_busy"})

    with pytest.raises(RuntimeError, match="qwen3_4b_install_post_unexpected_http_status"):
        _validate_qwen_install_post_response(response, "qwen3-4b-q4-k-m")


@pytest.mark.parametrize(
    "body",
    [
        {"ok": True, "manager": {"operation": {"kind": "install", "model_id": "qwen3-4b-q4-k-m", "status": "idle"}}},
        {"ok": True, "manager": {"operation": {"kind": "install", "model_id": "qwen3-4b-q4-k-m"}}},
        {"ok": True, "manager": {"operation": {"kind": "activate", "model_id": "qwen3-4b-q4-k-m", "status": "downloading"}}},
    ],
)
def test_qwen_install_post_without_started_install_operation_fails_immediately(body: dict) -> None:
    response = _FakeInstallResponse(202, body)
    with pytest.raises(RuntimeError, match="qwen3_4b_install_operation_not_started"):
        _validate_qwen_install_post_response(response, "qwen3-4b-q4-k-m")


def _durable_preflight_acceptance_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    attempt_source: str = "mission_slice",
):
    from dataclasses import replace

    from agent.agent_core import AgentCore
    from agent.model_protocol import ModelTurn, ToolCallProposal
    from agent.mission_runtime import MissionRuntime
    from owner_session_testutils import (
        allow_owner_sessions,
        persist_canonical_scope,
        workspace_scope_context,
    )
    from runtime_authorization import make_test_snapshot, mission_model_tools
    from security.authorization import authorize_tool
    from security.authorization_context import AuthorizationContext
    from workspace import Workspace
    from workspace.process_sandbox import SandboxAvailability

    request_id = "acceptance-preflight-request"
    owner_token = "valid-acceptance-preflight-owner"
    allow_owner_sessions(monkeypatch, owner_token)
    persisted_scope = persist_canonical_scope(
        monkeypatch,
        tmp_path,
        owner_session_token=owner_token,
        target_id="test-target",
    )
    base_context, _policy_context = AgentCore._auth("run_project_tests", owner_token, request_id)
    context = replace(base_context, scope_snapshot=persisted_scope)
    assert authorize_tool(
        ["run_project_tests", "bounded-fixture"],
        context=context,
    ).allowed is True

    workspace_root = tmp_path / "acceptance-workspace"
    workspace_root.mkdir()
    store_path = tmp_path / "acceptance-missions.sqlite3"
    store = MissionStore(store_path)

    def authorize(mission, step):
        mission_context = AuthorizationContext.from_dict(mission.authorization_context)
        decision = authorize_tool(
            [step.action, "bounded-fixture"],
            context=mission_context,
        )
        return decision.allowed, decision.reason

    executor_calls: list[tuple[str, str, str]] = []

    def reject_before_process_start(mission, step, action_id):
        executor_calls.append((mission.mission_id, step.step_id, action_id))
        return {
            "success": False,
            "failure_class": "RESOURCE",
            "error": "process_sandbox_unavailable",
            "kind": "PROCESS_SANDBOX_UNAVAILABLE",
            "reason_code": "backend_unavailable",
            "detail_code": "windows_appcontainer_backend_unimplemented",
            "dispatch_attempted": False,
            "process_started": False,
            "process_start_confirmed": False,
        }

    runtime = MissionRuntime(
        store,
        executor=reject_before_process_start,
        authorizer=authorize,
        authorization_snapshot_factory=lambda mission: make_test_snapshot(
            mission,
            root=str(workspace_root),
        ),
        require_authorization_snapshot=True,
    )
    objective = "Run the bounded local project test under persisted Owner scope"
    plan = Plan.initial(objective).replan(
        steps=(
            PlanStep(
                "preflight-step",
                "Run the bounded local project test",
                action="run_project_tests",
                retry_policy={"arguments": {"query": "bounded-fixture"}},
            ),
        ),
        reason="acceptance preflight restart regression",
    )
    mission = runtime.create(
        objective,
        "Run the bounded local project test",
        plan,
        mission_id="acceptance-preflight-mission",
        request_id=request_id,
        owner_identity_ref="owner:1",
        authorization_context=context.to_dict(),
        scope_snapshot=workspace_scope_context(persisted_scope, workspace_root),
    )
    ready = store.load(mission.mission_id)
    assert ready is not None and ready.status is MissionStatus.READY
    ready_status = ready.to_dict()
    ready_status["queue"] = {"state": "queued"}
    ready_snapshot = {
        "status": ready_status,
        "timeline": ready.trajectory,
        "evidence": [],
        "report": {},
        "effects": [],
        "full_execution_chain": [],
        "full_execution_chain_status": "NOT_PRESENT",
    }

    if attempt_source == "mission_slice":
        blocked = runtime.run_slice(mission.mission_id)
    elif attempt_source == "model_turn":
        availability = SandboxAvailability(
            False,
            "windows-appcontainer-job",
            "backend_unavailable",
            "windows_appcontainer_backend_unimplemented",
            "required Windows process sandbox is unavailable",
        )
        monkeypatch.setattr(
            Workspace,
            "process_sandbox_availability",
            staticmethod(lambda: availability),
        )
        monkeypatch.setattr(
            runtime,
            "_execute_native_tool",
            lambda *_args, **_kwargs: pytest.fail("native preflight must block before tool dispatch"),
        )

        class OneProjectTestProposal:
            def complete(self, _messages, _tools, *, mission_id, run_id, turn_id, plan_version, timeout_seconds=None):
                proposal = ToolCallProposal.create(
                    "run_project_tests",
                    {"query": "bounded-fixture"},
                    mission_id=mission_id,
                    run_id=run_id,
                    turn_id=turn_id,
                    request_id=request_id,
                    plan_version=plan_version,
                    step_id="preflight-step",
                    tool_call_id="acceptance-preflight-tool-call",
                )
                return ModelTurn(turn_id, tool_calls=(proposal,))

        blocked = runtime.run_model_loop(
            mission.mission_id,
            OneProjectTestProposal(),
            tools=mission_model_tools("run_project_tests"),
            run_id="acceptance-preflight-run",
            max_turns=1,
        )
    else:
        raise AssertionError(f"unexpected preflight source: {attempt_source}")
    assert len(executor_calls) == (1 if attempt_source == "mission_slice" else 0)
    assert blocked.status is MissionStatus.RESOURCE_BLOCKED
    reopened_store = MissionStore(store_path)
    restored = reopened_store.load(mission.mission_id)
    assert restored is not None and restored.verify_integrity()
    blocked_status = restored.to_dict()
    blocked_status["queue"] = {"state": "failed"}
    blocked_snapshot = {
        "status": blocked_status,
        "timeline": restored.trajectory,
        "evidence": restored.evidence,
        "report": {},
        "effects": [],
        "full_execution_chain": [],
        "full_execution_chain_status": "NOT_PRESENT",
    }
    return mission.mission_id, ready_snapshot, blocked_snapshot


def _resign_preflight_snapshot(snapshot, *, mutate_mission=None, event_transform=None):
    corrupted = json.loads(json.dumps(snapshot))
    queue = corrupted["status"].get("queue")
    status_record = dict(corrupted["status"])
    status_record.pop("integrity_hash", None)
    status_record.pop("queue", None)
    mission = Mission.from_dict(status_record)
    if mutate_mission is not None:
        mutate_mission(mission)
    if event_transform is not None:
        original_events = list(mission.trajectory)
        mission.trajectory = []
        for original in original_events:
            transformed = event_transform(dict(original))
            if transformed is None:
                continue
            transformed_events = transformed if isinstance(transformed, list) else [transformed]
            for event in transformed_events:
                mission.emit(
                    EventType(event["event"]),
                    step_id=event.get("step_id", ""),
                    data=dict(event.get("data") or {}),
                )
    resigned_status = mission.to_dict()
    if queue is not None:
        resigned_status["queue"] = queue
    corrupted["status"] = resigned_status
    corrupted["timeline"] = resigned_status["trajectory"]
    corrupted["evidence"] = resigned_status["evidence"]
    return corrupted


def _public_project_scope_snapshot(snapshot: dict) -> dict:
    from dataclasses import replace

    from agent.agent_core import OWNER_UI_CONTROL_PLANE_CAPABILITIES
    from agent.mission import Mission
    from bridge import _public_project_owner_tool_scope
    from security.authorization_context import AuthorizationContext
    from security.mission_authorization import MissionAuthorizationSnapshot

    target_identity = "local-project:acceptance-project"
    scope_identity: dict[str, str] = {}

    def bind_public_project_scope(mission: Mission) -> None:
        context = AuthorizationContext.from_dict(dict(mission.authorization_context or {}))
        authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        workspace_root = str(Path(str(authorization.workspace_boundary.get("root", ""))).resolve())
        plan_actions = tuple(
            step.action for step in mission.plan.steps if step.action != "__planning_failure__"
        )
        public_scope_tools = _public_project_owner_tool_scope(mission.owner_instruction)
        authorized_tools = tuple(dict.fromkeys(
            (*plan_actions, *OWNER_UI_CONTROL_PLANE_CAPABILITIES)
        ))
        authorization = replace(
            authorization,
            target_identity=target_identity,
            allowed_actions=authorized_tools,
            allowed_tools=authorized_tools,
            network_boundary={"allowed": ()},
            data_boundary={"allowed": (target_identity,)},
            credential_boundary={"allowed": ()},
            workspace_boundary={"root": workspace_root},
            policy_version=context.policy_snapshot.policy_version,
            owner_approval=context.owner_evidence.proof_fingerprint,
            authorization_hash="",
        )
        mission.authorization_snapshot = authorization.to_dict()
        mission.authorization_context = replace(context, scope_snapshot=None).to_dict()
        mission.scope_snapshot = {
            "target_id": target_identity,
            "workspace_root": workspace_root,
            "scope": ["workspace"],
            "allowed_tools": public_scope_tools,
            "allowed_networks": [],
            "allowed_credentials": [],
        }
        scope_identity["id"] = (
            f"public-local-project-scope:{windows_acceptance._canonical_sha256(mission.scope_snapshot)}"
        )
        model_loop = mission.progress.get("model_loop")
        tool_results = model_loop.get("tool_results") if isinstance(model_loop, dict) else None
        if isinstance(tool_results, list):
            for result_record in tool_results:
                if isinstance(result_record, dict):
                    result_record["scope_snapshot_id"] = scope_identity["id"]

    def rebind_public_tool_proposal(event: dict) -> dict:
        if event.get("event") == "ToolProposed" and isinstance(event.get("data"), dict):
            data = dict(event["data"])
            data["scope_snapshot_id"] = scope_identity["id"]
            event["data"] = data
        return event

    return _resign_preflight_snapshot(
        snapshot,
        mutate_mission=bind_public_project_scope,
        event_transform=rebind_public_tool_proposal,
    )


def _public_project_expected_binding(snapshot: dict) -> dict:
    status = snapshot.get("status") if isinstance(snapshot, dict) else None
    scope = status.get("scope_snapshot") if isinstance(status, dict) else None
    target_identity = scope.get("target_id") if isinstance(scope, dict) else None
    workspace_root = scope.get("workspace_root") if isinstance(scope, dict) else None
    assert isinstance(target_identity, str) and target_identity.startswith("local-project:")
    assert isinstance(workspace_root, str) and workspace_root
    return {
        "expected_project_id": target_identity.removeprefix("local-project:"),
        "expected_project_root": Path(workspace_root),
    }


def _preflight_effect_inspection(mission_id: str, request_id: str, operation: str) -> dict:
    return {
        "effect_id": "fixture-effect-1",
        "mission_id": mission_id,
        "task_id": "acceptance-task",
        "task_version": 1,
        "execution_id": "acceptance-execution",
        "origin_request_id": request_id,
        "provider": "fixture-provider",
        "operation": operation,
        "state": "SUCCEEDED",
        "created_at": "2026-10-17T00:00:00+00:00",
        "updated_at": "2026-10-17T00:00:00+00:00",
        "idempotency_supported": False,
        "has_idempotency_key": False,
        "error_code": "",
        "requires_reconciliation": False,
        "owner_binding_status": "BOUND",
    }


def test_installed_app_restart_cycles_bind_expected_project_identity() -> None:
    import ast
    import inspect
    import textwrap

    source = textwrap.dedent(inspect.getsource(windows_acceptance._installed_app_mission))
    function = ast.parse(source)
    restart_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "restart_callback"
    ]

    assert len(restart_calls) == 2
    for call in restart_calls:
        keyword_values = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        assert ast.unparse(keyword_values["expected_project_id"]) == "project_id"
        assert ast.unparse(keyword_values["expected_project_root"]) == "project_root"

    basis_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_mission_restart_basis"
    ]
    assert basis_calls
    for call in basis_calls:
        keyword_values = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        assert ast.unparse(keyword_values["owner_database_path"]) == "owner_database_path"

    source_tree = ast.parse(Path(windows_acceptance.__file__).read_text(encoding="utf-8"))
    restart_functions = [
        node
        for node in ast.walk(source_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "restart_installed_application"
    ]
    assert len(restart_functions) == 1
    callback_basis_calls = [
        node
        for node in ast.walk(restart_functions[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_mission_restart_basis"
    ]
    assert len(callback_basis_calls) == 2
    for call in callback_basis_calls:
        keyword_values = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        assert ast.unparse(keyword_values["owner_database_path"]) == "owner_database_path"


def test_restart_diagnostic_code_is_restricted_to_static_allowlist() -> None:
    assert (
        windows_acceptance._safe_mission_restart_diagnostic_code("public_scope_allowlist_mismatch")
        == "public_scope_allowlist_mismatch"
    )
    assert windows_acceptance._safe_mission_restart_diagnostic_code(
        "Owner instruction: sensitive text"
    ) is None
    assert windows_acceptance._safe_mission_restart_diagnostic_code(
        "/private/workspace/project"
    ) is None


@pytest.mark.parametrize("attempt_source", ["mission_slice", "model_turn"])
def test_preflight_restart_basis_accepts_bound_public_project_scope_without_external_snapshot(
    attempt_source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent.agent_core import OWNER_UI_CONTROL_PLANE_CAPABILITIES

    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source=attempt_source,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    status = public_scope_snapshot["status"]
    plan_actions = [step["action"] for step in status["plan"]["steps"]]
    owner_scope_tools = status["scope_snapshot"]["allowed_tools"]
    authorized_tools = status["authorization_snapshot"]["allowed_tools"]
    assert set(plan_actions).issubset(set(owner_scope_tools))
    assert authorized_tools == list(dict.fromkeys(
        (*plan_actions, *OWNER_UI_CONTROL_PLANE_CAPABILITIES)
    ))
    assert set(authorized_tools).issubset(set(owner_scope_tools) | set(OWNER_UI_CONTROL_PLANE_CAPABILITIES))

    unbound_basis = windows_acceptance._mission_restart_basis(public_scope_snapshot, mission_id)
    assert unbound_basis["status"] == "BLOCKED"
    assert unbound_basis["kind"] == "NOT_RUN"
    assert windows_acceptance._mission_restart_basis(
        public_scope_snapshot,
        mission_id,
        expected_project_id="different-project",
        expected_project_root=expected_binding["expected_project_root"],
    )["status"] == "BLOCKED"
    other_project_root = tmp_path / "other-project"
    other_project_root.mkdir()
    assert windows_acceptance._mission_restart_basis(
        public_scope_snapshot,
        mission_id,
        expected_project_id=expected_binding["expected_project_id"],
        expected_project_root=other_project_root,
    )["status"] == "BLOCKED"

    basis = windows_acceptance._mission_restart_basis(
        public_scope_snapshot,
        mission_id,
        **expected_binding,
    )
    assert basis["status"] == "VERIFIED"
    assert basis["kind"] == "PREFLIGHT_BLOCK"
    assert basis["projection"]["dispatch_attempted"] is False
    assert basis["projection"]["process_started"] is False
    assert basis["projection"]["process_start_confirmed"] is False
    assert public_scope_snapshot["status"]["authorization_context"]["scope_snapshot"] is None
    assert public_scope_snapshot["status"]["scope_snapshot"]["scope"] == ["workspace"]
    restored_snapshot = json.loads(json.dumps(public_scope_snapshot))
    reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        public_scope_snapshot,
        restored_snapshot,
        mission_id,
        **expected_binding,
    )
    assert reconciliation["reconciled"] is True
    assert reconciliation["dispatch_attempted"] is False
    assert reconciliation["process_started"] is False
    assert reconciliation["process_start_confirmed"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_id", "local-project:other-project"),
        ("workspace_root", "/unrelated/workspace"),
        ("scope", ["workspace", "network"]),
        ("allowed_tools", ["status"]),
        ("allowed_tools", ["latest_intel", "local_security_check", "local_system_info", "run_project_tests", "status", "watch"]),
        ("allowed_networks", ["127.0.0.1"]),
        ("allowed_credentials", ["credential-ref"]),
    ],
)
def test_preflight_public_project_scope_tampering_fails_closed(
    field: str,
    value: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)

    def tamper_scope(mission: Mission) -> None:
        mission.scope_snapshot[field] = value

    tampered = _resign_preflight_snapshot(public_scope_snapshot, mutate_mission=tamper_scope)
    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"
    if field == "allowed_tools" and isinstance(value, list) and "watch" in value:
        assert basis["diagnostic_code"] == "public_scope_allowlist_mismatch"


@pytest.mark.parametrize(
    "corruption",
    [
        "authorization_owner_approval_mismatch",
        "authorization_hash_mismatch",
        "authorization_allowed_tools_expanded",
        "authorization_allowed_actions_expanded",
        "api_owner_factory_snapshot",
        "owner_evidence_request_mismatch",
        "owner_session_mismatch",
        "owner_identity_active_session_mismatch",
        "unexpected_external_scope_id",
    ],
)
def test_preflight_public_project_owner_binding_tampering_fails_closed(
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from bridge import Handler
    from security.mission_authorization import MissionAuthorizationSnapshot

    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)

    def tamper_owner_binding(mission: Mission) -> None:
        if corruption == "authorization_owner_approval_mismatch":
            authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
            mission.authorization_snapshot = replace(
                authorization,
                owner_approval="unrelated-owner-proof",
                authorization_hash="",
            ).to_dict()
        elif corruption == "authorization_hash_mismatch":
            mission.authorization_snapshot["allowed_tools"] = ["status"]
        elif corruption == "authorization_allowed_tools_expanded":
            authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
            extra_authorized_tool = next(
                tool for tool in mission.scope_snapshot["allowed_tools"]
                if tool not in authorization.allowed_tools
            )
            mission.authorization_snapshot = replace(
                authorization,
                allowed_tools=(*authorization.allowed_tools, extra_authorized_tool),
                authorization_hash="",
            ).to_dict()
        elif corruption == "authorization_allowed_actions_expanded":
            authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
            extra_authorized_action = next(
                tool for tool in mission.scope_snapshot["allowed_tools"]
                if tool not in authorization.allowed_actions
            )
            mission.authorization_snapshot = replace(
                authorization,
                allowed_actions=(*authorization.allowed_actions, extra_authorized_action),
                authorization_hash="",
            ).to_dict()
        elif corruption == "api_owner_factory_snapshot":
            api_authorization_factory = Handler._mission_snapshot_factory(
                None,
                mission.owner_identity_ref,
                mission.scope_snapshot,
            )
            mission.authorization_snapshot = api_authorization_factory(mission).to_dict()
        elif corruption == "owner_evidence_request_mismatch":
            mission.authorization_context["owner_evidence"]["request_id"] = "different-request"
        elif corruption == "owner_session_mismatch":
            mission.authorization_context["session_id"] = "different-session"
        elif corruption == "owner_identity_active_session_mismatch":
            authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
            mission.owner_identity_ref = "owner:2"
            mission.authorization_snapshot = replace(
                authorization,
                owner_identity="owner:2",
                authorization_hash="",
            ).to_dict()
        elif corruption == "unexpected_external_scope_id":
            mission.authorization_context["scope_snapshot_id"] = "unrelated-scope"

    tampered = _resign_preflight_snapshot(
        public_scope_snapshot,
        mutate_mission=tamper_owner_binding,
    )
    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"
    if corruption in {"authorization_allowed_tools_expanded", "authorization_allowed_actions_expanded"}:
        assert basis["diagnostic_code"] == "public_scope_allowlist_mismatch"
    if corruption == "api_owner_factory_snapshot":
        assert basis["diagnostic_code"] == "public_project_owner_binding_invalid"


def test_preflight_public_project_basis_requires_active_owner_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security.owner_password as owner_password

    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    monkeypatch.setattr(owner_password, "resolve_session", lambda _session_id: None)

    basis = windows_acceptance._mission_restart_basis(
        public_scope_snapshot,
        mission_id,
        **expected_binding,
    )
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_profile_owner_database_is_read_only_and_fresh_login_does_not_revive_preflight_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3
    from datetime import datetime, timedelta, timezone

    import core.db as core_db
    import security.owner_password as owner_password

    original_resolve_session = owner_password.resolve_session
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_snapshot)
    session_id = public_snapshot["status"]["authorization_context"]["owner_evidence"]["session_id"]

    owner_database_path = tmp_path / "installed-profile" / "userData" / "state" / "intel.sqlite3"
    owner_database_path.parent.mkdir(parents=True)
    monkeypatch.setattr(core_db, "DB_PATH", owner_database_path)
    monkeypatch.setattr(owner_password, "resolve_session", original_resolve_session)
    owner_password.create_owner_account(
        owner_password.OWNER_USERNAME,
        "ephemeral-acceptance-only-password",
    )
    now = datetime.now(timezone.utc)
    with sqlite3.connect(owner_database_path) as connection:
        connection.execute(
            "INSERT INTO owner_sessions "
            "(session_id, owner_id, created_at, authenticated_at, expires_at, status, auth_method) "
            "VALUES (?, 1, ?, ?, ?, 'active', ?)",
            (
                session_id,
                now.isoformat(),
                now.isoformat(),
                (now + timedelta(hours=8)).isoformat(),
                owner_password.AUTH_METHOD,
            ),
        )
        connection.commit()

    bytes_before_validation = owner_database_path.read_bytes()
    active_basis = windows_acceptance._mission_restart_basis(
        public_snapshot,
        mission_id,
        **expected_binding,
        owner_database_path=owner_database_path,
    )
    after_restart_snapshot = json.loads(json.dumps(public_snapshot))
    active_reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        public_snapshot,
        after_restart_snapshot,
        mission_id,
        **expected_binding,
        owner_database_path=owner_database_path,
    )
    assert active_basis["status"] == "VERIFIED"
    assert active_basis["kind"] == "PREFLIGHT_BLOCK"
    assert active_reconciliation["reconciled"] is True
    assert owner_database_path.read_bytes() == bytes_before_validation

    with sqlite3.connect(owner_database_path) as connection:
        connection.execute(
            "UPDATE owner_sessions SET status = 'revoked' WHERE session_id = ?",
            (session_id,),
        )
        connection.commit()
    bytes_before_rejected_validation = owner_database_path.read_bytes()
    revoked_basis = windows_acceptance._mission_restart_basis(
        public_snapshot,
        mission_id,
        **expected_binding,
        owner_database_path=owner_database_path,
    )
    revoked_reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        public_snapshot,
        after_restart_snapshot,
        mission_id,
        **expected_binding,
        owner_database_path=owner_database_path,
    )
    assert revoked_basis["status"] == "BLOCKED"
    assert revoked_basis["kind"] == "NOT_RUN"
    assert revoked_basis["diagnostic_code"] == "active_owner_session_binding_invalid"
    assert revoked_reconciliation["reconciled"] is False
    assert public_snapshot["status"]["status"] == "RESOURCE_BLOCKED"
    assert public_snapshot["status"]["evidence"] == []
    assert owner_database_path.read_bytes() == bytes_before_rejected_validation

    fresh_session = owner_password.login(
        owner_password.OWNER_USERNAME,
        "ephemeral-acceptance-only-password",
    )
    assert owner_password.resolve_session(
        fresh_session["session_id"],
        database_path=owner_database_path,
    ) is not None
    still_revoked_basis = windows_acceptance._mission_restart_basis(
        public_snapshot,
        mission_id,
        **expected_binding,
        owner_database_path=owner_database_path,
    )
    assert still_revoked_basis["status"] == "BLOCKED"
    assert public_snapshot["status"]["status"] == "RESOURCE_BLOCKED"


def test_preflight_public_project_basis_requires_project_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from security.mission_authorization import MissionAuthorizationSnapshot

    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    workspace_file = tmp_path / "not-a-workspace-directory"
    workspace_file.write_text("not a project directory", encoding="utf-8")

    def point_both_records_at_file(mission: Mission) -> None:
        authorization = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))
        mission.scope_snapshot["workspace_root"] = str(workspace_file)
        mission.authorization_snapshot = replace(
            authorization,
            workspace_boundary={"root": str(workspace_file)},
            authorization_hash="",
        ).to_dict()

    tampered = _resign_preflight_snapshot(
        public_scope_snapshot,
        mutate_mission=point_both_records_at_file,
    )
    expected_binding["expected_project_root"] = workspace_file
    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_current_result",
        "missing_result_ledger",
        "success_claimed",
        "duplicate_current_result",
        "cross_ledger_duplicate",
        "wrong_call_binding",
        "wrong_step_binding",
        "wrong_result_name",
        "changed_arguments",
        "wrong_scope_context_binding",
        "empty_scope_context_binding",
        "empty_authorization_context_binding",
        "wrong_error",
        "nonempty_result",
        "positive_dispatch_marker",
        "string_dispatch_marker",
        "integer_success_marker",
        "orphan_missing_tool_call_id",
        "orphan_missing_name",
        "orphan_missing_run_identity",
    ],
)
def test_preflight_model_turn_tool_result_must_match_failed_attempt(
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    identity_field = {
        "empty_scope_context_binding": "scope_snapshot_id",
        "empty_authorization_context_binding": "authorization_context_id",
    }.get(corruption)
    proposal_call_id = (
        public_scope_snapshot["status"]["progress"]["model_loop"]["tool_results"][0]["tool_call_id"]
    )

    def corrupt_proposal_event(event: dict) -> dict:
        data = event.get("data")
        if (
            identity_field
            and event.get("event") == "ToolProposed"
            and isinstance(data, dict)
            and data.get("tool_call_id") == proposal_call_id
        ):
            event["data"] = {**data, identity_field: ""}
        return event

    def corrupt_tool_result(mission: Mission) -> None:
        model_loop = mission.progress["model_loop"]
        records = model_loop["tool_results"]
        if corruption == "missing_current_result":
            records.clear()
        elif corruption == "missing_result_ledger":
            model_loop.pop("tool_results")
        elif corruption == "success_claimed":
            records[0]["ok"] = True
        elif corruption == "duplicate_current_result":
            records.append(dict(records[0]))
        elif corruption == "cross_ledger_duplicate":
            mission.progress["tool_results"] = [dict(records[0])]
        elif corruption == "wrong_call_binding":
            records[0]["tool_call_id"] = "unrelated-call"
        elif corruption == "wrong_step_binding":
            records[0]["step_id"] = "unrelated-step"
        elif corruption == "wrong_result_name":
            records[0]["name"] = "workspace_read"
        elif corruption == "changed_arguments":
            records[0]["arguments"] = {"query": "altered-fixture"}
        elif corruption == "wrong_scope_context_binding":
            records[0]["scope_snapshot_id"] = "unrelated-scope"
        elif corruption in {"empty_scope_context_binding", "empty_authorization_context_binding"}:
            field = (
                "scope_snapshot_id"
                if corruption == "empty_scope_context_binding"
                else "authorization_context_id"
            )
            records[0][field] = ""
        elif corruption == "wrong_error":
            records[0]["error"] = "process_sandbox_unavailable_but_dispatched"
        elif corruption == "nonempty_result":
            records[0]["result"] = {"process_started": True}
        elif corruption == "positive_dispatch_marker":
            records[0]["dispatch_attempted"] = True
        elif corruption == "string_dispatch_marker":
            records[0]["dispatch_attempted"] = "true"
        elif corruption == "integer_success_marker":
            records[0]["success"] = 1
        elif corruption in {
            "orphan_missing_tool_call_id",
            "orphan_missing_name",
            "orphan_missing_run_identity",
        }:
            orphan = dict(records[0])
            orphan.update(
                run_id="unrelated-run",
                turn_id="unrelated-turn",
                action_id="unrelated-action",
                step_id="unrelated-step",
                tool_call_id="unrelated-call",
                name="unrelated_tool",
            )
            if corruption == "orphan_missing_tool_call_id":
                orphan.pop("tool_call_id")
            elif corruption == "orphan_missing_name":
                orphan.pop("name")
            else:
                orphan.pop("run_id")
            records.append(orphan)

    tampered = _resign_preflight_snapshot(
        public_scope_snapshot,
        mutate_mission=corrupt_tool_result,
        event_transform=corrupt_proposal_event if identity_field else None,
    )
    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


@pytest.mark.parametrize("location", ["top_level", "progress", "model_loop"])
def test_preflight_rejects_explicit_null_tool_result_ledger(
    location: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    if location == "top_level":
        tampered = json.loads(json.dumps(public_scope_snapshot))
        tampered["status"]["tool_results"] = None
    else:
        def set_null_tool_results(mission: Mission) -> None:
            if location == "progress":
                mission.progress["tool_results"] = None
            else:
                mission.progress["model_loop"]["tool_results"] = None

        tampered = _resign_preflight_snapshot(
            public_scope_snapshot,
            mutate_mission=set_null_tool_results,
        )

    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_model_scope_identity_is_content_bound_for_public_local_scope() -> None:
    from types import SimpleNamespace

    from agent.mission_runtime import _model_scope_snapshot_identity

    scope = {
        "target_id": "local-project:identity-test",
        "workspace_root": "/tmp/identity-test",
        "scope": ["workspace"],
        "allowed_tools": ["run_project_tests"],
        "allowed_networks": [],
        "allowed_credentials": [],
    }
    mission = SimpleNamespace(scope_snapshot=scope)
    no_external_scope = SimpleNamespace(scope_snapshot=None)
    expected = f"public-local-project-scope:{windows_acceptance._canonical_sha256(scope)}"
    assert _model_scope_snapshot_identity(mission, no_external_scope) == expected

    changed_scope = {**scope, "allowed_networks": ["*"]}
    assert _model_scope_snapshot_identity(
        SimpleNamespace(scope_snapshot=changed_scope), no_external_scope
    ) != expected

    persisted_scope = SimpleNamespace(snapshot_id="persisted-owner-scope-1")
    assert _model_scope_snapshot_identity(
        mission,
        SimpleNamespace(scope_snapshot=persisted_scope),
    ) == "persisted-owner-scope-1"


def test_preflight_model_turn_rejects_untrusted_top_level_tool_result_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    tampered = json.loads(json.dumps(public_scope_snapshot))
    result_record = tampered["status"]["progress"]["model_loop"]["tool_results"][0]
    tampered["status"]["tool_results"] = [{**result_record, "ok": True}]

    basis = windows_acceptance._mission_restart_basis(tampered, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_preflight_projection_requires_and_validates_effect_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)

    missing_effects = json.loads(json.dumps(public_scope_snapshot))
    missing_effects.pop("effects")
    assert windows_acceptance._mission_restart_basis(
        missing_effects, mission_id, **expected_binding
    )["status"] == "BLOCKED"

    blocked_action_effect = json.loads(json.dumps(public_scope_snapshot))
    request_id = blocked_action_effect["status"]["request_id"]
    blocked_action_effect["effects"] = [
        _preflight_effect_inspection(mission_id, request_id, "run_project_tests")
    ]
    assert windows_acceptance._mission_restart_basis(
        blocked_action_effect, mission_id, **expected_binding
    )["status"] == "BLOCKED"

    unresolved_effect = json.loads(json.dumps(public_scope_snapshot))
    unresolved = _preflight_effect_inspection(
        mission_id,
        unresolved_effect["status"]["request_id"],
        "workspace_read",
    )
    unresolved["state"] = "AMBIGUOUS"
    unresolved["requires_reconciliation"] = True
    unresolved_effect["effects"] = [unresolved]
    assert windows_acceptance._mission_restart_basis(
        unresolved_effect, mission_id, **expected_binding
    )["status"] == "BLOCKED"


def test_preflight_reconciliation_binds_effect_and_tool_result_ledgers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    request_id = public_scope_snapshot["status"]["request_id"]
    before = json.loads(json.dumps(public_scope_snapshot))
    before["effects"] = [_preflight_effect_inspection(mission_id, request_id, "workspace_read")]
    after = json.loads(json.dumps(before))
    after["effects"][0]["updated_at"] = "2026-10-17T00:00:01+00:00"

    before_basis = windows_acceptance._mission_restart_basis(before, mission_id, **expected_binding)
    after_basis = windows_acceptance._mission_restart_basis(after, mission_id, **expected_binding)
    reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        before, after, mission_id, **expected_binding
    )
    assert before_basis["status"] == after_basis["status"] == "VERIFIED"
    assert reconciliation["reconciled"] is False
    assert "effects_sha256" in reconciliation["mismatched_fields"]


def test_preflight_accepts_bound_external_effect_reconciliation_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    request_id = public_scope_snapshot["status"]["request_id"]
    effect = _preflight_effect_inspection(mission_id, request_id, "workspace_read")
    reconciled_result = {
        "tool_call_id": "prior-reconciled-call",
        "name": "workspace_read",
        "arguments": {},
        "ok": True,
        "result": {
            "type": "external_effect_reconciled",
            "effect_id": effect["effect_id"],
            "effect_state": "SUCCEEDED",
        },
        "error": "",
        "mission_id": mission_id,
        "request_id": request_id,
        "plan_version": 1,
        "step_id": effect["task_id"],
    }

    def append_reconciled_result(mission: Mission) -> None:
        reconciled_result["plan_version"] = mission.plan.version
        mission.progress["model_loop"]["tool_results"].append(dict(reconciled_result))

    snapshot = _resign_preflight_snapshot(
        public_scope_snapshot,
        mutate_mission=append_reconciled_result,
    )
    snapshot["effects"] = [effect]

    basis = windows_acceptance._mission_restart_basis(snapshot, mission_id, **expected_binding)
    assert basis["status"] == "VERIFIED"
    assert basis["kind"] == "PREFLIGHT_BLOCK"


@pytest.mark.parametrize("corruption", ["missing_effect", "effect_state_mismatch"])
def test_preflight_rejects_unbound_external_effect_reconciliation_result(
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, blocked_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    public_scope_snapshot = _public_project_scope_snapshot(blocked_snapshot)
    expected_binding = _public_project_expected_binding(public_scope_snapshot)
    request_id = public_scope_snapshot["status"]["request_id"]
    effect = _preflight_effect_inspection(mission_id, request_id, "workspace_read")
    reconciled_result = {
        "tool_call_id": "prior-reconciled-call",
        "name": "workspace_read",
        "arguments": {},
        "ok": True,
        "result": {
            "type": "external_effect_reconciled",
            "effect_id": effect["effect_id"],
            "effect_state": "SUCCEEDED",
        },
        "error": "",
        "mission_id": mission_id,
        "request_id": request_id,
        "plan_version": 1,
        "step_id": effect["task_id"],
    }
    effects = [effect]
    if corruption == "missing_effect":
        effects = []
    else:
        reconciled_result["ok"] = False
        reconciled_result["error"] = "OWNER_CONFIRMED_NO_EFFECT"
        reconciled_result["result"]["effect_state"] = "FAILED"

    def append_reconciled_result(mission: Mission) -> None:
        reconciled_result["plan_version"] = mission.plan.version
        mission.progress["model_loop"]["tool_results"].append(dict(reconciled_result))

    snapshot = _resign_preflight_snapshot(
        public_scope_snapshot,
        mutate_mission=append_reconciled_result,
    )
    snapshot["effects"] = effects

    basis = windows_acceptance._mission_restart_basis(snapshot, mission_id, **expected_binding)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_external_scope_restart_basis_requires_active_owner_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security.owner_password as owner_password

    mission_id, _ready_snapshot, external_scope_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(owner_password, "resolve_session", lambda _session_id: None)

    basis = windows_acceptance._mission_restart_basis(external_scope_snapshot, mission_id)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_external_scope_cannot_satisfy_project_bound_restart_basis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, external_scope_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    public_snapshot_for_binding = _public_project_scope_snapshot(external_scope_snapshot)
    expected_binding = _public_project_expected_binding(public_snapshot_for_binding)

    basis = windows_acceptance._mission_restart_basis(
        external_scope_snapshot,
        mission_id,
        **expected_binding,
    )
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


def test_preflight_block_is_restart_basis_only_and_reconciles_durable_owner_scope(tmp_path, monkeypatch):
    mission_id, ready_snapshot, before_restart = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )

    ready_basis = windows_acceptance._mission_restart_basis(ready_snapshot, mission_id)
    before_basis = windows_acceptance._mission_restart_basis(before_restart, mission_id)
    after_restart = json.loads(json.dumps(before_restart))
    after_basis = windows_acceptance._mission_restart_basis(after_restart, mission_id)
    reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        before_restart,
        after_restart,
        mission_id,
    )

    assert ready_basis["status"] == "BLOCKED"
    assert ready_basis["kind"] == "NOT_RUN"
    assert before_restart["status"]["status"] == "RESOURCE_BLOCKED"
    assert before_basis["status"] == after_basis["status"] == "VERIFIED"
    assert before_basis["kind"] == after_basis["kind"] == "PREFLIGHT_BLOCK"
    assert before_basis["projection"]["mission_status"] == "RESOURCE_BLOCKED"
    assert before_basis["projection"]["attempt_id"] == after_basis["projection"]["attempt_id"]
    assert before_basis["projection"]["attempt_id"] == before_restart["status"]["checkpoint"]["attempt_id"]
    assert before_basis["projection"]["dispatch_attempted"] is False
    assert before_basis["projection"]["process_started"] is False
    assert before_basis["projection"]["process_start_confirmed"] is False
    assert reconciliation["reconciled"] is True
    assert reconciliation["dispatch_attempted"] is False
    assert reconciliation["process_started"] is False
    assert reconciliation["process_start_confirmed"] is False
    assert reconciliation["completion_events_absent"] is True
    assert before_restart["status"]["evidence"] == []
    assert not any(
        event["event"] in {"GoalVerified", "MissionCompleted"}
        for event in before_restart["timeline"]
    )


@pytest.mark.parametrize("attempt_source", ["mission_slice", "model_turn"])
def test_preflight_restart_basis_rejects_reason_kind_mismatch(
    attempt_source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, original = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source=attempt_source,
    )
    original_status = original["status"]
    original_attempt_id = original_status["checkpoint"]["attempt_id"]
    mismatched_kind = "PROCESS_SANDBOX_SETUP_FAILED"

    def mutate_mission(mission: Mission) -> None:
        mission.checkpoint["kind"] = mismatched_kind
        for record in mission.failures + mission.progress.get("resource_failures", []):
            if isinstance(record, dict) and record.get("attempt_id") == original_attempt_id:
                record["kind"] = mismatched_kind
        for transition in mission.transitions:
            data = transition.get("data") if isinstance(transition, dict) else None
            if isinstance(data, dict) and data.get("attempt_id") == original_attempt_id:
                data["kind"] = mismatched_kind

    def transform_event(event: dict) -> dict:
        if (
            event.get("event") in {"FailureDetected", "FailureDiagnosed"}
            and isinstance(event.get("data"), dict)
            and event["data"].get("attempt_id") == original_attempt_id
        ):
            event["data"]["kind"] = mismatched_kind
        return event

    corrupted = _resign_preflight_snapshot(
        original,
        mutate_mission=mutate_mission,
        event_transform=transform_event,
    )
    status = corrupted["status"]
    assert status["checkpoint"]["reason_code"] == "backend_unavailable"
    assert status["checkpoint"]["kind"] == mismatched_kind
    assert status["failures"][-1]["reason_code"] == "backend_unavailable"
    assert status["failures"][-1]["kind"] == mismatched_kind
    assert all(
        event["data"]["kind"] == mismatched_kind
        for event in status["trajectory"]
        if event["event"] in {"FailureDetected", "FailureDiagnosed"}
        and event.get("data", {}).get("attempt_id") == original_attempt_id
    )
    assert any(
        transition.get("data", {}).get("kind") == mismatched_kind
        and transition.get("data", {}).get("reason_code") == "backend_unavailable"
        for transition in status["transitions"]
        if transition.get("data", {}).get("attempt_id") == original_attempt_id
    )
    assert windows_acceptance._mission_record_integrity_verified(status) is True

    basis = windows_acceptance._mission_restart_basis(corrupted, mission_id)
    reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        original,
        corrupted,
        mission_id,
    )
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"
    assert reconciliation["reconciled"] is False


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_failure",
        "invalid_chain",
        "scope_expanded",
        "network_allowlist_expanded",
        "checkpoint_process_start_confirmed",
        "checkpoint_attempt_id_mismatch",
        "checkpoint_action_id_mismatch",
        "checkpoint_step_id_mismatch",
        "failure_process_start_confirmed",
        "failure_attempt_id_mismatch",
        "missing_run_slice_action_history",
        "evidence_same_action",
        "evidence_same_step",
        "evidence_missing_provenance",
        "evidence_endpoint_mismatch",
        "observation_process_start_confirmed",
        "observation_nested_process_start_confirmed",
        "observation_success_integer",
        "observation_dispatch_string",
        "observation_nested_process_started_integer",
        "observation_ok_integer",
        "observation_nested_ok_string",
        "observation_nested_status_success",
        "observation_nested_status_ok",
        "observation_nested_status_verified",
        "action_nested_success_string",
        "action_root_process_start_confirmed",
        "action_root_normalized_data_process_start_confirmed",
        "duplicate_failure_same_action",
        "diagnosis_process_start_confirmed",
        "diagnosis_attempt_id_mismatch",
        "duplicate_diagnosis_same_step",
        "other_action_process_start_confirmed",
        "duplicate_action_history_same_action",
    ],
)
def test_preflight_restart_basis_fails_closed_for_missing_corrupt_or_expanded_records(
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, before_restart = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    corrupted = json.loads(json.dumps(before_restart))
    if corruption == "missing_failure":
        corrupted["status"]["failures"] = []
    elif corruption == "invalid_chain":
        corrupted["full_execution_chain_status"] = "INVALID"
    elif corruption == "scope_expanded":
        corrupted["status"]["scope_snapshot"]["scope"] = ["workspace", "network"]
    elif corruption == "checkpoint_process_start_confirmed":
        corrupted["status"]["checkpoint"]["process_start_confirmed"] = True
    elif corruption == "checkpoint_attempt_id_mismatch":
        corrupted["status"]["checkpoint"]["attempt_id"] = "0" * 64
    elif corruption == "checkpoint_action_id_mismatch":
        corrupted["status"]["checkpoint"]["action_id"] = "unrelated-action"
    elif corruption == "checkpoint_step_id_mismatch":
        corrupted["status"]["checkpoint"]["step_id"] = "unrelated-step"
    elif corruption == "failure_process_start_confirmed":
        corrupted["status"]["failures"][-1]["process_start_confirmed"] = True
    elif corruption == "failure_attempt_id_mismatch":
        corrupted["status"]["failures"][-1]["attempt_id"] = "0" * 64
    elif corruption == "missing_run_slice_action_history":
        corrupted["status"]["action_history"] = []
    elif corruption in {"evidence_same_action", "evidence_same_step", "evidence_missing_provenance"}:
        checkpoint = corrupted["status"]["checkpoint"]
        if corruption == "evidence_same_action":
            provenance = {
                "mission_id": mission_id,
                "action_id": checkpoint["action_id"],
                "step_id": "unrelated-step",
            }
        elif corruption == "evidence_same_step":
            provenance = {
                "mission_id": mission_id,
                "action_id": "unrelated-action",
                "step_id": checkpoint["step_id"],
            }
        else:
            provenance = None
        evidence = {"criterion_id": "test-only-conflicting-record", "passed": True}
        if provenance is not None:
            evidence["provenance"] = provenance
        corrupted["status"]["evidence"] = [evidence]
        corrupted["evidence"] = [evidence]
    elif corruption == "evidence_endpoint_mismatch":
        corrupted["evidence"] = [{"criterion_id": "endpoint-only-record", "passed": True}]
    elif corruption == "observation_process_start_confirmed":
        corrupted["status"]["action_history"][0]["observation"]["process_start_confirmed"] = True
    elif corruption == "observation_nested_process_start_confirmed":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["normalized_data"]["process_start_confirmed"] = True
    elif corruption == "observation_success_integer":
        corrupted["status"]["action_history"][0]["observation"]["success"] = 1
    elif corruption == "observation_dispatch_string":
        corrupted["status"]["action_history"][0]["observation"]["dispatch_attempted"] = "false"
    elif corruption == "observation_nested_process_started_integer":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["normalized_data"]["process_started"] = 0
    elif corruption == "observation_ok_integer":
        corrupted["status"]["action_history"][0]["observation"]["ok"] = 1
    elif corruption == "observation_nested_ok_string":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["normalized_data"]["ok"] = "false"
    elif corruption == "observation_nested_status_success":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["status"] = "success"
    elif corruption == "observation_nested_status_ok":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["status"] = "ok"
    elif corruption == "observation_nested_status_verified":
        corrupted["status"]["action_history"][0]["observation"]["observation"]["status"] = "verified"
    elif corruption == "action_nested_success_string":
        corrupted["status"]["action_history"][0]["normalized_data"] = {"success": "false"}
    elif corruption == "action_root_process_start_confirmed":
        corrupted["status"]["action_history"][0]["process_start_confirmed"] = True
    elif corruption == "action_root_normalized_data_process_start_confirmed":
        corrupted["status"]["action_history"][0]["normalized_data"] = {"process_start_confirmed": True}
    elif corruption == "duplicate_failure_same_action":
        duplicate = dict(corrupted["status"]["failures"][-1])
        duplicate["process_start_confirmed"] = True
        corrupted["status"]["failures"].append(duplicate)
    elif corruption == "other_action_process_start_confirmed":
        corrupted["status"]["action_history"].append(
            {
                "action_id": "unrelated-action",
                "step_id": "unrelated-step",
                "status": "failed",
                "observation": {"normalized_data": {"process_started": True}},
            }
        )
    elif corruption == "duplicate_action_history_same_action":
        duplicate_action = json.loads(json.dumps(corrupted["status"]["action_history"][0]))
        corrupted["status"]["action_history"].append(duplicate_action)
    else:
        corrupted["status"]["scope_snapshot"]["allowed_networks"] = ["*"]
    queue = corrupted["status"].get("queue")
    status_without_integrity = dict(corrupted["status"])
    status_without_integrity.pop("integrity_hash", None)
    status_without_integrity.pop("queue", None)
    corrupted_mission = Mission.from_dict(status_without_integrity)
    if corruption in {"diagnosis_process_start_confirmed", "diagnosis_attempt_id_mismatch", "duplicate_diagnosis_same_step"}:
        diagnosis = next(event for event in corrupted_mission.trajectory if event["event"] == "FailureDiagnosed")
        diagnosis_data = dict(diagnosis["data"])
        if corruption == "diagnosis_attempt_id_mismatch":
            diagnosis_data["attempt_id"] = "0" * 64
        else:
            diagnosis_data["process_start_confirmed"] = True
        if corruption in {"diagnosis_process_start_confirmed", "diagnosis_attempt_id_mismatch"}:
            diagnosis_index = corrupted_mission.trajectory.index(diagnosis)
            corrupted_mission.trajectory = corrupted_mission.trajectory[:diagnosis_index]
        corrupted_mission.emit(
            EventType.FAILURE_DIAGNOSED,
            step_id=diagnosis.get("step_id", ""),
            data=diagnosis_data,
        )
    corrupted_status = corrupted_mission.to_dict()
    if queue is not None:
        corrupted_status["queue"] = queue
    corrupted["status"] = corrupted_status
    corrupted["timeline"] = corrupted_status["trajectory"]
    if corruption != "evidence_endpoint_mismatch":
        corrupted["evidence"] = corrupted_status["evidence"]

    basis = windows_acceptance._mission_restart_basis(corrupted, mission_id)
    reconciliation = windows_acceptance._mission_preflight_block_reconciliation(
        before_restart,
        corrupted,
        mission_id,
    )

    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"
    assert reconciliation["reconciled"] is False


@pytest.mark.parametrize(
    "corruption",
    [
        "model_turn_empty_run_turn",
        "model_turn_proposal_run_mismatch",
        "model_turn_proposal_turn_mismatch",
        "model_turn_proposal_call_mismatch",
        "model_turn_duplicate_proposal",
        "model_turn_missing_proposal",
        "model_turn_checkpoint_action_mismatch",
        "model_turn_checkpoint_step_mismatch",
        "model_turn_unexpected_action_history",
    ],
)
def test_model_turn_preflight_restart_basis_fails_closed_without_exact_proposal_binding(
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, original = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source="model_turn",
    )
    original_basis = windows_acceptance._mission_restart_basis(original, mission_id)
    assert original_basis["status"] == "VERIFIED"
    assert original_basis["projection"]["attempt_id"] == original["status"]["checkpoint"]["attempt_id"]

    new_attempt: dict[str, str] = {}

    def mutate_mission(mission: Mission) -> None:
        checkpoint = mission.checkpoint
        if corruption == "model_turn_empty_run_turn":
            previous_id = checkpoint["attempt_id"]
            checkpoint["run_id"] = ""
            checkpoint["turn_id"] = ""
            identity = {
                "attempt_source": "model_turn",
                "mission_id": mission.mission_id,
                "request_id": mission.request_id,
                "run_id": "",
                "turn_id": "",
                "blocked_tool_call_ids": checkpoint["blocked_tool_call_ids"],
                "blocked_action_ids": checkpoint["blocked_action_ids"],
                "blocked_step_ids": checkpoint["blocked_step_ids"],
            }
            replacement_id = _canonical_sha256(identity)
            checkpoint["attempt_id"] = replacement_id
            new_attempt.update(previous_id=previous_id, replacement_id=replacement_id)
            for records in (mission.failures, mission.progress.get("resource_failures", [])):
                for record in records:
                    if isinstance(record, dict) and record.get("attempt_id") == previous_id:
                        record.update(run_id="", turn_id="", attempt_id=replacement_id)
            for transition in mission.transitions:
                data = transition.get("data") if isinstance(transition, dict) else None
                if isinstance(data, dict) and data.get("attempt_id") == previous_id:
                    data.update(run_id="", turn_id="", attempt_id=replacement_id)
        elif corruption == "model_turn_checkpoint_action_mismatch":
            checkpoint["action_id"] = "unrelated-action"
        elif corruption == "model_turn_checkpoint_step_mismatch":
            checkpoint["step_id"] = "unrelated-step"
        elif corruption == "model_turn_unexpected_action_history":
            checkpoint = mission.checkpoint
            mission.action_history = [{
                "action_id": checkpoint["blocked_action_ids"][0],
                "step_id": checkpoint["blocked_step_ids"][0],
                "status": "failed",
                "observation": {
                    "dispatch_attempted": False,
                    "process_started": False,
                    "process_start_confirmed": False,
                    "success": False,
                },
            }]

    def transform_event(event: dict) -> dict | list[dict] | None:
        data = event.get("data", {})
        if corruption == "model_turn_empty_run_turn":
            if event.get("event") == "ToolProposed":
                data.update(run_id="", turn_id="")
            if data.get("attempt_id") == new_attempt.get("previous_id"):
                data.update(
                    run_id="",
                    turn_id="",
                    attempt_id=new_attempt["replacement_id"],
                )
        elif event.get("event") == "ToolProposed":
            if corruption == "model_turn_proposal_run_mismatch":
                data["run_id"] = "different-run"
            elif corruption == "model_turn_proposal_turn_mismatch":
                data["turn_id"] = "different-turn"
            elif corruption == "model_turn_proposal_call_mismatch":
                data["tool_call_id"] = "different-tool-call"
            elif corruption == "model_turn_duplicate_proposal":
                return [event, event]
            elif corruption == "model_turn_missing_proposal":
                return None
        event["data"] = data
        return event

    corrupted = _resign_preflight_snapshot(
        original,
        mutate_mission=mutate_mission,
        event_transform=transform_event,
    )
    basis = windows_acceptance._mission_restart_basis(corrupted, mission_id)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"


@pytest.mark.parametrize(
    ("mission_status", "report_http_status", "expected_missing_report"),
    [
        ("RESOURCE_BLOCKED", 404, True),
        ("READY", 404, False),
        ("RESOURCE_BLOCKED", 500, False),
    ],
)
def test_audit_snapshot_only_tolerates_missing_report_for_resource_blocked(
    mission_status: str,
    report_http_status: int,
    expected_missing_report: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_root = tmp_path / "disposable-profile"
    state = profile_root / "userData" / "state"
    (state / "workspaces").mkdir(parents=True)
    (state / "intel.sqlite3").write_bytes(b"")

    def fake_public_api(_page, _method, path, **_kwargs):
        if path.endswith("/status"):
            return {"http_status": 200, "body": {"status": {"status": mission_status}}}
        if path.endswith("/timeline"):
            return {"http_status": 200, "body": {"timeline": []}}
        if path.endswith("/evidence"):
            return {"http_status": 200, "body": {"evidence": []}}
        if path.endswith("/effects"):
            return {"http_status": 200, "body": {"effects": []}}
        if path.endswith("/report"):
            return {"http_status": report_http_status, "body": {"error": "report_not_available"}}
        raise AssertionError(f"unexpected audit path: {path}")

    monkeypatch.setattr(windows_acceptance, "_public_api", fake_public_api)
    if expected_missing_report:
        snapshot = windows_acceptance._mission_audit_snapshot(object(), "mission-404", profile_root)
        assert snapshot["report"] == {}
        assert snapshot["report_http_status"] == 404
        assert snapshot["report_missing_for_preflight"] is True
        assert snapshot["full_execution_chain_status"] == "NOT_PRESENT"
    else:
        with pytest.raises(windows_acceptance._MissionAuditSnapshotError):
            windows_acceptance._mission_audit_snapshot(object(), "mission-404", profile_root)


def test_live_restart_candidate_snapshot_includes_status_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, audit_snapshot = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
    )
    status = audit_snapshot["status"]
    candidate_without_effects = windows_acceptance._mission_restart_candidate_snapshot(
        status,
        audit_snapshot["full_execution_chain"],
        audit_snapshot["full_execution_chain_status"],
    )
    assert candidate_without_effects["evidence"] == status["evidence"]
    assert windows_acceptance._mission_restart_basis(candidate_without_effects, mission_id)["status"] == "BLOCKED"
    candidate = windows_acceptance._mission_restart_candidate_snapshot(
        status,
        audit_snapshot["full_execution_chain"],
        audit_snapshot["full_execution_chain_status"],
        effects=audit_snapshot["effects"],
    )
    assert candidate["effects"] == audit_snapshot["effects"]
    assert windows_acceptance._mission_restart_basis(candidate, mission_id)["status"] == "VERIFIED"

    status_without_evidence = dict(status)
    status_without_evidence.pop("evidence")
    incomplete_candidate = windows_acceptance._mission_restart_candidate_snapshot(
        status_without_evidence,
        audit_snapshot["full_execution_chain"],
        audit_snapshot["full_execution_chain_status"],
    )
    assert windows_acceptance._mission_restart_basis(incomplete_candidate, mission_id)["status"] == "BLOCKED"


@pytest.mark.parametrize(
    ("attempt_source", "corruption"),
    [
        ("mission_slice", "attempt_source_list"),
        ("model_turn", "failure_kind_list"),
        ("mission_slice", "full_chain_status_list"),
        ("mission_slice", "action_history_action_id_list"),
        ("mission_slice", "action_history_step_id_list"),
        ("mission_slice", "plan_step_id_list"),
        ("mission_slice", "timeline_event_name_list"),
    ],
)
def test_preflight_restart_basis_fails_closed_without_type_error_for_unhashable_values(
    attempt_source: str,
    corruption: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission_id, _ready_snapshot, original = _durable_preflight_acceptance_snapshots(
        tmp_path,
        monkeypatch,
        attempt_source=attempt_source,
    )
    attempt_id = original["status"]["checkpoint"]["attempt_id"]

    def mutate_mission(mission: Mission) -> None:
        if corruption == "attempt_source_list":
            mission.checkpoint["attempt_source"] = ["mission_slice"]
        elif corruption == "failure_kind_list":
            for record in mission.failures + mission.progress.get("resource_failures", []):
                if isinstance(record, dict) and record.get("attempt_id") == attempt_id:
                    record["kind"] = ["PROCESS_SANDBOX_UNAVAILABLE"]
        elif corruption == "action_history_action_id_list":
            action = mission.action_history[0]
            action["action_id"] = ["malformed-action"]
            observation = action.get("observation")
            if isinstance(observation, dict):
                observation["action_id"] = ["malformed-action"]
        elif corruption == "action_history_step_id_list":
            mission.action_history[0]["step_id"] = ["malformed-step"]
        elif corruption == "plan_step_id_list":
            mission.plan = replace(
                mission.plan,
                steps=(replace(mission.plan.steps[0], step_id=["malformed-step"]),),
            )
        elif corruption == "timeline_event_name_list":
            mission.trajectory[0]["event"] = ["MissionStarted"]

    corrupted = _resign_preflight_snapshot(original, mutate_mission=mutate_mission)
    if corruption == "full_chain_status_list":
        corrupted["full_execution_chain_status"] = ["NOT_PRESENT"]
    if corruption == "timeline_event_name_list":
        assert windows_acceptance._trajectory_timeline_integrity(
            corrupted["timeline"],
            mission_id,
            corrupted["status"]["request_id"],
        ) is False

    basis = windows_acceptance._mission_restart_basis(corrupted, mission_id)
    assert basis["status"] == "BLOCKED"
    assert basis["kind"] == "NOT_RUN"
