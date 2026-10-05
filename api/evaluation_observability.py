"""Read-only, Owner/Mission-scoped projection of persisted evaluation metrics.

Evaluation measurements are reported as recorded data only. This API does not
compute a policy verdict or expose prompts, provenance, provider responses, or
raw evidence identifiers.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.evidence import EvidenceChainStore
from evaluation.agent_evaluation import (
    EvaluationError,
    EvaluationIntegrityError,
    EvaluationMetric,
    EvaluationStore,
    StoredEvaluation,
)
from security.mission_authorization import MissionAuthorizationSnapshot
from agent.execution_fence import authorization_digest


MAX_EVALUATION_RUNS = EvaluationStore.MAX_ROWS
MAX_EVIDENCE_CHAIN_RECORDS = 10_000
MAX_EVIDENCE_CHAIN_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_REFS_PER_METRIC = 4
MAX_SUMMARY_BYTES = 16 * 1024
MAX_OWNER_DASHBOARD_MISSIONS = 10
MAX_OWNER_DASHBOARD_BYTES = 16 * 1024
_METRIC_UNITS = {
    EvaluationMetric.TASK_SUCCESS: "ratio",
    EvaluationMetric.EVIDENCE_QUALITY: "ratio",
    EvaluationMetric.HALLUCINATION: "ratio",
    EvaluationMetric.TOOL_CORRECTNESS: "ratio",
    EvaluationMetric.SKILL_USEFULNESS: "ratio",
    EvaluationMetric.MEMORY_USEFULNESS: "ratio",
    EvaluationMetric.LATENCY: "ms",
    EvaluationMetric.COST: "units",
    EvaluationMetric.RECOVERY: "ratio",
    EvaluationMetric.SAFETY_VIOLATIONS: "count",
    EvaluationMetric.TOKEN_USAGE: "tokens",
    EvaluationMetric.AGENT_COORDINATION: "ratio",
}


class MissionEvaluationSummaryError(ValueError):
    """A safe, sanitized evaluation projection error."""


class MissionEvaluationSummaryTooLarge(MissionEvaluationSummaryError):
    """An evaluation or evidence query exceeded a strict resource bound."""


class MissionEvaluationSummaryService:
    """Project verified EvaluationStore rows for one authorized Mission only."""

    def __init__(
        self,
        mission_service: Any,
        evaluation_store: EvaluationStore | None,
        *,
        evidence_db_path: str | Path,
    ):
        self.mission_service = mission_service
        self.evaluation_store = evaluation_store
        self.evidence_db_path = Path(evidence_db_path)

    @staticmethod
    def _empty_metrics() -> list[dict[str, Any]]:
        return [
            {
                "metric": metric.value,
                "status": "unavailable",
                "value": None,
                "unit": _METRIC_UNITS[metric],
                "verified_evidence_refs": [],
                "verified_evidence_ref_count": 0,
            }
            for metric in EvaluationMetric
        ]

    @staticmethod
    def _opaque_ref(owner_ref: str, mission_id: str, evidence_id: str) -> str:
        value = f"{owner_ref}\0{mission_id}\0{evidence_id}".encode("utf-8")
        return "evref_" + hashlib.sha256(value).hexdigest()

    def _verified_evidence_ids(self, mission: Any, owner_ref: str) -> tuple[set[str], str]:
        path = self.evidence_db_path
        if path.is_symlink() or not path.is_file():
            return set(), "unavailable"
        uri = path.resolve().as_uri() + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.execute("PRAGMA busy_timeout = 5000")
                connection.execute("BEGIN")
                sizes = connection.execute(
                    "SELECT length(payload) FROM evidence_chain ORDER BY sequence LIMIT ?",
                    (MAX_EVIDENCE_CHAIN_RECORDS + 1,),
                ).fetchall()
                if len(sizes) > MAX_EVIDENCE_CHAIN_RECORDS:
                    raise MissionEvaluationSummaryTooLarge("evaluation evidence exceeds the verification bound")
                total_bytes = sum(int(row[0] or 0) for row in sizes)
                if total_bytes > MAX_EVIDENCE_CHAIN_BYTES:
                    raise MissionEvaluationSummaryTooLarge("evaluation evidence exceeds the verification bound")
                rows = connection.execute(
                    "SELECT payload FROM evidence_chain ORDER BY sequence LIMIT ?",
                    (MAX_EVIDENCE_CHAIN_RECORDS + 1,),
                ).fetchall()
            records = [json.loads(row[0]) for row in rows]
        except MissionEvaluationSummaryTooLarge:
            raise
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError):
            return set(), "unavailable"
        if not all(isinstance(record, dict) for record in records):
            return set(), "integrity_unverified"
        if not EvidenceChainStore.verify_records(records, mission_store=None, require_execution_fence=False):
            return set(), "integrity_unverified"

        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
            expected_auth = authorization_digest(snapshot)
            raw_receipts = mission.progress.get("execution_evidence_refs", [])
            if not isinstance(raw_receipts, list) or len(raw_receipts) > 10_000:
                return set(), "integrity_unverified"
            receipt_by_id = {
                str(receipt.get("evidence_id")): receipt
                for receipt in raw_receipts
                if isinstance(receipt, dict) and isinstance(receipt.get("evidence_id"), str)
            }
        except (AttributeError, TypeError, ValueError, KeyError):
            return set(), "integrity_unverified"

        verified: set[str] = set()
        for record in records:
            if (
                record.get("mission_id") != mission.mission_id
                or record.get("request_id") != mission.request_id
                or record.get("authorization_hash") != expected_auth
                or not record.get("fence_id")
                or record.get("verification") not in {"observed", "verified"}
            ):
                continue
            evidence_id = record.get("evidence_id")
            if not isinstance(evidence_id, str) or evidence_id not in receipt_by_id:
                continue
            try:
                expected_receipt = EvidenceChainStore._receipt(record)
            except (KeyError, TypeError, ValueError):
                continue
            receipt = receipt_by_id[evidence_id]
            if all(receipt.get(name) == value for name, value in expected_receipt.items()):
                verified.add(evidence_id)
        return verified, "verified" if verified else "none"

    def get(self, mission_id: str, *, owner_session_token: str) -> dict[str, Any]:
        try:
            mission, owner_ref = self.mission_service.load_authorized_mission(
                mission_id, owner_session_token
            )
        except (KeyError, PermissionError):
            # Keep missing and foreign-owner Missions indistinguishable.
            raise KeyError("unknown_mission") from None
        if (
            mission.mission_id != mission_id
            or mission.owner_identity_ref != owner_ref
            or not mission.verify_integrity()
        ):
            raise MissionEvaluationSummaryError("mission_integrity_invalid")

        if self.evaluation_store is None:
            return {
                "status": "no_run",
                "run_count": 0,
                "run_count_capped": False,
                "verdict": "not_persisted",
                "evidence_status": "unavailable",
                "metrics": self._empty_metrics(),
            }
        try:
            rows = self.evaluation_store.list(
                owner_identity_ref=owner_ref,
                mission_id=mission_id,
                limit=MAX_EVALUATION_RUNS,
            )
        except EvaluationIntegrityError:
            raise MissionEvaluationSummaryError("evaluation_integrity_invalid") from None
        except (EvaluationError, sqlite3.Error):
            raise MissionEvaluationSummaryError("evaluation_store_unavailable") from None

        if not rows:
            return {
                "status": "no_run",
                "run_count": 0,
                "run_count_capped": False,
                "verdict": "not_persisted",
                "evidence_status": "unavailable",
                "metrics": self._empty_metrics(),
            }
        if len(rows) > MAX_EVALUATION_RUNS or any(
            item.run.owner_identity_ref != owner_ref or item.run.mission_id != mission_id
            for item in rows
        ):
            raise MissionEvaluationSummaryError("evaluation_scope_invalid")

        latest: StoredEvaluation = max(
            rows,
            key=lambda item: (
                datetime.fromisoformat(item.run.created_at.replace("Z", "+00:00")).astimezone(timezone.utc),
                item.evaluation_id,
            ),
        )
        verified_ids, evidence_status = self._verified_evidence_ids(mission, owner_ref)
        measures = latest.run.measurement_map()
        metrics: list[dict[str, Any]] = []
        for metric in EvaluationMetric:
            measurement = measures.get(metric)
            refs: list[str] = []
            if measurement is not None:
                verified_for_metric = [
                    reference
                    for reference in measurement.evidence_refs
                    if reference in verified_ids
                ]
                refs = [
                    self._opaque_ref(owner_ref, mission_id, reference)
                    for reference in verified_for_metric[:MAX_EVIDENCE_REFS_PER_METRIC]
                ]
            metrics.append({
                "metric": metric.value,
                "status": "recorded" if measurement is not None else "unavailable",
                "value": measurement.value if measurement is not None else None,
                "unit": measurement.unit if measurement is not None else _METRIC_UNITS[metric],
                "verified_evidence_refs": refs,
                "verified_evidence_ref_count": len(refs),
            })

        if evidence_status == "verified" and not any(
            item["verified_evidence_refs"] for item in metrics
        ):
            evidence_status = "none"

        result = {
            "status": "run_recorded",
            "run_count": min(len(rows), MAX_EVALUATION_RUNS),
            "run_count_capped": len(rows) == MAX_EVALUATION_RUNS,
            # No policy verdict is persisted by EvaluationStore; do not infer one.
            "verdict": "not_persisted",
            "evidence_status": evidence_status,
            "metrics": metrics,
        }
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_SUMMARY_BYTES:
            raise MissionEvaluationSummaryTooLarge("evaluation summary exceeds the response bound")
        return result

    def get_owner_dashboard(
        self,
        *,
        owner_session_token: str,
        limit: int = MAX_OWNER_DASHBOARD_MISSIONS,
    ) -> dict[str, Any]:
        """Aggregate latest persisted metrics for a small Owner-only Mission window.

        The response omits Mission identifiers, prompts, providers, and evidence
        references. It is a display-only mean, not a policy verdict.
        """
        if (
            not isinstance(owner_session_token, str)
            or not owner_session_token
            or len(owner_session_token) > 256
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_OWNER_DASHBOARD_MISSIONS
        ):
            raise ValueError("invalid_evaluation_dashboard_request")
        try:
            listed = self.mission_service.list_missions(
                owner_session_token=owner_session_token,
                limit=limit + 1,
            )
        except (KeyError, PermissionError):
            raise KeyError("owner_session_required") from None
        if not isinstance(listed, list) or len(listed) > limit + 1:
            raise MissionEvaluationSummaryError("mission_listing_invalid")
        capped = len(listed) > limit
        rows = listed[:limit]
        mission_ids: list[str] = []
        for row in rows:
            mission_id = row.get("mission_id") if isinstance(row, dict) else None
            if not isinstance(mission_id, str) or not mission_id or len(mission_id) > 128:
                raise MissionEvaluationSummaryError("mission_listing_invalid")
            if mission_id in mission_ids:
                raise MissionEvaluationSummaryError("mission_listing_invalid")
            mission_ids.append(mission_id)

        samples: dict[EvaluationMetric, list[float]] = {metric: [] for metric in EvaluationMetric}
        evaluated_missions = 0
        for mission_id in mission_ids:
            summary = self.get(mission_id, owner_session_token=owner_session_token)
            if summary.get("status") != "run_recorded":
                continue
            evaluated_missions += 1
            metrics = summary.get("metrics")
            if not isinstance(metrics, list) or len(metrics) != len(EvaluationMetric):
                raise MissionEvaluationSummaryError("evaluation_projection_invalid")
            for item in metrics:
                if not isinstance(item, dict):
                    raise MissionEvaluationSummaryError("evaluation_projection_invalid")
                try:
                    metric = EvaluationMetric(item.get("metric"))
                except (TypeError, ValueError):
                    raise MissionEvaluationSummaryError("evaluation_projection_invalid") from None
                value = item.get("value")
                if item.get("status") != "recorded":
                    continue
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise MissionEvaluationSummaryError("evaluation_projection_invalid")
                if metric is EvaluationMetric.EVIDENCE_QUALITY and (
                    summary.get("evidence_status") != "verified"
                    or item.get("verified_evidence_ref_count", 0) < 1
                ):
                    continue
                samples[metric].append(float(value))

        metrics_output = []
        for metric in EvaluationMetric:
            values = samples[metric]
            metrics_output.append({
                "metric": metric.value,
                "status": "recorded" if values else "unavailable",
                "value": round(sum(values) / len(values), 6) if values else None,
                "unit": _METRIC_UNITS[metric],
                "aggregation": "mean_of_latest_recorded_per_mission",
                "sample_mission_count": len(values),
            })
        result = {
            "status": "available" if evaluated_missions else "no_run",
            "mission_count": len(mission_ids),
            "mission_count_capped": capped,
            "evaluated_mission_count": evaluated_missions,
            "metrics": metrics_output,
            "verdict": "not_computed",
        }
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_OWNER_DASHBOARD_BYTES:
            raise MissionEvaluationSummaryTooLarge("evaluation dashboard exceeds the response bound")
        return result


__all__ = [
    "MAX_EVIDENCE_CHAIN_BYTES",
    "MAX_EVIDENCE_CHAIN_RECORDS",
    "MAX_EVIDENCE_REFS_PER_METRIC",
    "MAX_EVALUATION_RUNS",
    "MAX_OWNER_DASHBOARD_BYTES",
    "MAX_OWNER_DASHBOARD_MISSIONS",
    "MAX_SUMMARY_BYTES",
    "MissionEvaluationSummaryError",
    "MissionEvaluationSummaryService",
    "MissionEvaluationSummaryTooLarge",
]
