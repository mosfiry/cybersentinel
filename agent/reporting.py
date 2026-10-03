from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
import hashlib
import json

from security.mission_authorization import MissionAuthorizationSnapshot


_REPORT_SCHEMA = "cybersentinel.mission-report.v1"
_OWNER_INPUT_STATUSES = {"OWNER_INPUT_REQUIRED", "OWNER_REAUTH_REQUIRED"}
_FAILURE_STATUSES = {
    "AUTHORIZATION_BLOCKED",
    "SCOPE_BLOCKED",
    "RESOURCE_BLOCKED",
    "SAFETY_BLOCKED",
    "FAILED_RETRY_EXHAUSTED",
    "CANCELLED",
}
_TRUSTED_VERIFICATION_AUTHORITIES = {
    "deterministic_observation",
    "deterministic_tool_result",
}


def _dict_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item) for item in value]


def _safe_nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _status_value(value: Any) -> str:
    return str(getattr(value, "value", value) or "UNKNOWN").upper()


def _criterion_result(item: Mapping[str, Any]) -> str:
    if item.get("passed") is True:
        return "PASS"
    if item.get("passed") is False:
        return "FAIL"
    return "UNKNOWN"


def _is_trusted_goal_evidence(item: Mapping[str, Any]) -> bool:
    provenance = item.get("provenance")
    return (
        isinstance(provenance, Mapping)
        and provenance.get("verification_authority") in _TRUSTED_VERIFICATION_AUTHORITIES
    )


def _evidence_for_report(item: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(item)
    if _is_trusted_goal_evidence(item):
        result["report_verification"] = "TRUSTED_DETERMINISTIC_SOURCE"
    else:
        result["report_verification"] = "UNVERIFIED_PROVENANCE"
        if "passed" in result:
            result["claimed_passed"] = result.pop("passed")
    return result


def _owner_approval_status(mission: Any) -> dict[str, str]:
    status = _status_value(getattr(mission, "status", "UNKNOWN"))
    if status in _OWNER_INPUT_STATUSES:
        state = status
    else:
        raw = getattr(mission, "authorization_snapshot", None)
        if not isinstance(raw, dict):
            state = "NOT_RECORDED"
        else:
            try:
                snapshot = MissionAuthorizationSnapshot.from_dict(raw)
                owner_matches = snapshot.owner_identity == str(
                    getattr(mission, "owner_identity_ref", "") or ""
                )
                if snapshot.mission_id != str(getattr(mission, "mission_id", "")) or not owner_matches:
                    state = "INVALID"
                else:
                    state = "RECORDED" if snapshot.owner_approval else "NOT_RECORDED"
            except (KeyError, TypeError, ValueError, PermissionError):
                state = "INVALID"
    return {
        "status": state,
        "source": "mission_authorization_snapshot",
        "scope": "mission-level authorization only; action-level approval is not assessed",
        "current_authority": "not_assessed",
    }


def _tool_failures(mission: Any) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for item in _dict_records(getattr(mission, "failures", ())):
        failures.append(
            {
                "class": str(item.get("class") or "UNKNOWN"),
                "kind": str(item.get("kind") or ""),
                "provider": str(item.get("provider") or ""),
                "model": str(item.get("model") or ""),
                "step_id": str(item.get("step_id") or ""),
                "action_id": str(item.get("action_id") or ""),
                "tool_call_id": str(item.get("tool_call_id") or ""),
                "reason": str(item.get("reason_code") or item.get("class") or "failure recorded; detail omitted"),
            }
        )
    for item in _dict_records(getattr(mission, "action_history", ())):
        action_status = str(item.get("status") or "").casefold()
        if action_status in {"failed", "unknown", "ambiguous"}:
            failure = {
                "class": "TOOL",
                "kind": action_status.upper(),
                "provider": "",
                "model": "",
                "step_id": str(item.get("step_id") or ""),
                "action_id": str(item.get("action_id") or ""),
                "tool_call_id": "",
                "reason": "tool action did not complete successfully",
            }
            if failure not in failures:
                failures.append(failure)
    return failures


def _model_proposals(mission: Any) -> list[dict[str, Any]]:
    proposals: list[dict[str, Any]] = []
    for item in _dict_records(getattr(mission, "interpretations", ())):
        provenance = item.get("provenance")
        if not isinstance(provenance, Mapping) or provenance.get("proposal_origin") != "model":
            continue
        proposed = []
        for evidence in _dict_records(item.get("new_evidence", ())):
            candidate = dict(evidence)
            if "passed" in candidate:
                candidate["model_claimed_passed"] = candidate.pop("passed")
            candidate["verification"] = "UNVERIFIED_MODEL_PROPOSAL"
            proposed.append(candidate)
        if proposed:
            proposals.append(
                {
                    "observation_id": str(item.get("observation_id") or ""),
                    "summary": str(item.get("summary") or ""),
                    "proposed_evidence": proposed,
                    "verification": "UNVERIFIED_MODEL_PROPOSAL",
                }
            )
    return proposals


def build_mission_report(
    mission: Any,
    *,
    execution_evidence: Sequence[Mapping[str, Any]] = (),
    evidence_chain_integrity: str = "NOT_PRESENT",
) -> dict[str, Any]:
    """Build a conservative report; claims without deterministic provenance stay unverified."""
    mission_id = str(getattr(mission, "mission_id", ""))
    request_id = str(getattr(mission, "request_id", ""))
    mission_status = _status_value(getattr(mission, "status", "UNKNOWN"))
    raw_verification = getattr(mission, "verification_state", None)
    verification = dict(raw_verification) if isinstance(raw_verification, Mapping) else {}
    runtime_verified = verification.get("verified") is True
    evidence_count = _safe_nonnegative_int(verification.get("evidence_count", 0))
    stored_missing = _string_list(verification.get("missing_criteria", ()))
    goal_evidence = _dict_records(getattr(mission, "evidence", ()))
    trusted_goal_evidence = [item for item in goal_evidence if _is_trusted_goal_evidence(item)]
    unverified_goal_evidence = [item for item in goal_evidence if not _is_trusted_goal_evidence(item)]
    chain_evidence = [dict(item) for item in execution_evidence if isinstance(item, Mapping)]
    chain_status = str(evidence_chain_integrity or "UNKNOWN").upper()
    model_proposals = _model_proposals(mission)

    completion_criteria = _dict_records(getattr(mission, "completion_criteria", ()))
    required_criteria = [
        str(item.get("criterion_id") or "")
        for item in completion_criteria
        if item.get("required", True) is not False
    ]
    trusted_passed = {
        str(item.get("criterion_id") or "")
        for item in trusted_goal_evidence
        if item.get("passed") is True and item.get("criterion_id")
    }
    evidence_missing = [criterion_id or "unspecified" for criterion_id in required_criteria if criterion_id not in trusted_passed]
    missing_criteria = list(dict.fromkeys([*stored_missing, *evidence_missing]))
    verified_flag = bool(
        mission_status == "GOAL_COMPLETED"
        and runtime_verified
        and required_criteria
        and not missing_criteria
        and trusted_goal_evidence
    )

    evidence_payload = {
        "goal": [_evidence_for_report(item) for item in goal_evidence],
        "execution_chain": chain_evidence,
        "unverified_model_proposals": model_proposals,
    }
    digest = hashlib.sha256(
        json.dumps(
            evidence_payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    if mission_status == "RECOVERY_REQUIRED":
        outcome = "RECOVERY_REQUIRED"
    elif mission_status in _OWNER_INPUT_STATUSES:
        outcome = mission_status
    elif chain_status in {"INVALID", "UNREADABLE", "UNKNOWN"}:
        outcome = "UNKNOWN"
    elif verified_flag:
        outcome = "VERIFIED"
    elif mission_status in _FAILURE_STATUSES:
        outcome = "NOT_VERIFIED"
    elif trusted_goal_evidence or chain_evidence:
        outcome = "PARTIALLY_VERIFIED"
    else:
        outcome = "UNKNOWN"

    findings: list[dict[str, Any]] = []
    for item in goal_evidence:
        trusted = _is_trusted_goal_evidence(item)
        findings.append(
            {
                "criterion_id": str(item.get("criterion_id") or "unspecified"),
                "status": _criterion_result(item) if trusted else "UNVERIFIED_PROVENANCE",
                "claimed_result": None if trusted else _criterion_result(item),
                "source": str(item.get("source") or "unknown"),
                "confidence": item.get("confidence") if type(item.get("confidence")) is int and 0 <= item["confidence"] <= 10 else None,
                "evidence_hash": str(item.get("result_hash") or ""),
            }
        )
    for proposal in model_proposals:
        for item in proposal["proposed_evidence"]:
            findings.append(
                {
                    "criterion_id": str(item.get("criterion_id") or "unspecified"),
                    "status": "UNVERIFIED_MODEL_PROPOSAL",
                    "claimed_result": "PASS" if item.get("model_claimed_passed") is True else None,
                    "source": "model_proposal",
                    "confidence": None,
                    "evidence_hash": "",
                }
            )

    supporting = [dict(item) for item in trusted_goal_evidence if item.get("passed") is True]
    counter = [dict(item) for item in trusted_goal_evidence if item.get("passed") is False]
    for item in chain_evidence:
        relation = str(item.get("relation") or "").casefold()
        if relation in {"supports", "supporting", "support"}:
            supporting.append(dict(item))
        elif relation in {"contradicts", "counter", "counter_evidence"}:
            counter.append(dict(item))

    confidence_items = [
        {
            "source": str(item.get("source") or "unknown"),
            "confidence": item.get("confidence"),
            "evidence_id": str(item.get("evidence_id") or ""),
            "verification": "TRUSTED_SOURCE" if _is_trusted_goal_evidence(item) else "UNVERIFIED_PROVENANCE",
        }
        for item in [*goal_evidence, *chain_evidence]
        if type(item.get("confidence")) is int and 0 <= item["confidence"] <= 10
    ]

    unknown_states: list[dict[str, Any]] = []
    if outcome in {"UNKNOWN", "PARTIALLY_VERIFIED", "RECOVERY_REQUIRED", *_OWNER_INPUT_STATUSES}:
        unknown_states.append({"state": outcome, "mission_status": mission_status})
    if missing_criteria:
        unknown_states.append({"state": "MISSING_REQUIRED_EVIDENCE", "criteria": missing_criteria})
    if unverified_goal_evidence:
        unknown_states.append({"state": "UNVERIFIED_EVIDENCE_PROVENANCE", "count": len(unverified_goal_evidence)})
    if runtime_verified and not verified_flag:
        unknown_states.append({"state": "RUNTIME_VERIFICATION_NOT_SUPPORTED_BY_REPORT_EVIDENCE"})
    if chain_status in {"INVALID", "UNREADABLE", "UNKNOWN"}:
        unknown_states.append({"state": "EVIDENCE_CHAIN_" + chain_status})
    if not verification or "verified" not in verification:
        unknown_states.append({"state": "VERIFICATION_NOT_RECORDED"})

    limitations: list[str] = []
    if chain_status == "NOT_PRESENT":
        limitations.append("No durable execution evidence chain is present for this mission report.")
    elif chain_status != "VALID":
        limitations.append("Execution evidence-chain integrity is not established; verified reporting is withheld.")
    if not confidence_items:
        limitations.append("No per-item confidence values are available; no aggregate confidence is inferred.")
    else:
        limitations.append("Confidence is reported per evidence item only; no aggregate confidence is inferred.")
    if not counter:
        limitations.append("No counter-evidence is explicitly recorded; its absence is not evidence of absence.")
    limitations.append("Owner approval reflects only the mission authorization snapshot; action-level approvals are not assessed here.")
    if missing_criteria:
        limitations.append("Required verification criteria remain missing: " + ", ".join(missing_criteria))
    if unverified_goal_evidence:
        limitations.append("Evidence without deterministic verification provenance is shown as unverified and does not support a verified outcome.")
    if not required_criteria:
        limitations.append("No required completion criteria are available; the report cannot establish a verified outcome.")
    if model_proposals:
        limitations.append("Model-proposed evidence is preserved as unverified analysis and does not satisfy goal criteria.")

    provenance_records = [
        {
            "evidence_id": str(item.get("evidence_id") or ""),
            "source": str(item.get("source") or "unknown"),
            "sequence": item.get("sequence"),
            "previous_hash": str(item.get("previous_hash") or ""),
            "current_hash": str(item.get("current_hash") or ""),
            "mission_id": str(item.get("mission_id") or ""),
            "request_id": str(item.get("request_id") or ""),
            "task_id": str(item.get("task_id") or ""),
            "execution_id": str(item.get("execution_id") or ""),
            "worker_id": str(item.get("worker_id") or ""),
            "worker_instance_id": str(item.get("worker_instance_id") or ""),
            "runtime_generation": item.get("runtime_generation"),
            "lease_epoch": item.get("lease_epoch"),
            "task_version": item.get("task_version"),
            "authorization_hash": str(item.get("authorization_hash") or ""),
            "fence_id": str(item.get("fence_id") or ""),
        }
        for item in chain_evidence
    ]

    return {
        "schema_version": _REPORT_SCHEMA,
        "mission_summary": {
            "mission_id": mission_id,
            "request_id": request_id,
            "objective": str(getattr(mission, "objective", "")),
            "mission_status": mission_status,
            "outcome": outcome,
            "current_step": _safe_nonnegative_int(getattr(mission, "current_step", 0)),
            "iteration_count": _safe_nonnegative_int(getattr(mission, "iteration_count", 0)),
            "verification": {
                "verified": verified_flag if "verified" in verification else None,
                "runtime_reported_verified": runtime_verified if "verified" in verification else None,
                "missing_criteria": missing_criteria,
                "evidence_count": evidence_count,
                "trusted_evidence_count": len(trusted_goal_evidence),
                "unverified_evidence_count": len(unverified_goal_evidence),
                "required_criteria_count": len(required_criteria),
            },
        },
        "findings": findings,
        "evidence": {
            **evidence_payload,
            "digest_sha256": digest,
            "execution_chain_integrity": chain_status,
            "execution_chain_head": str(chain_evidence[-1].get("current_hash") or "") if chain_evidence else "",
        },
        "provenance": {
            "mission_id": mission_id,
            "request_id": request_id,
            "execution_chain": provenance_records,
        },
        "confidence": {
            "scale": "integer 0-10 per evidence item",
            "items": confidence_items,
            "aggregate": None,
        },
        "supporting_evidence": supporting,
        "counter_evidence": counter,
        "limitations": limitations,
        "tool_failures": _tool_failures(mission),
        "unknown_states": unknown_states,
        "owner_approval_status": _owner_approval_status(mission),
    }


__all__ = ["build_mission_report"]
