"""Deterministic, evidence-bounded evaluation of persisted Mission outcomes.

This recorder is deliberately not an LLM judge. It persists only objective
terminal/trajectory/receipt measurements; semantic quality, hallucination,
causality, cost, and safety claims remain unavailable unless another
independent evaluator is implemented.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.evidence import EvidenceChainStore
from agent.mission import Mission, MissionStatus
from agent.provider_api import MAX_PROVIDER_USAGE_BYTES
from agent.trajectory import EventType, verify_trajectory
from agent.execution_fence import authorization_digest
from evaluation.agent_evaluation import (
    EvaluationError,
    EvaluationMeasurement,
    EvaluationMetric,
    EvaluationRun,
    EvaluationStore,
    MAX_RECORDED_TOKEN_USAGE,
    StoredEvaluation,
)
from security.mission_authorization import MissionAuthorizationSnapshot


MAX_MISSION_EVALUATION_INPUT_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_CHAIN_RECORDS = 10_000
MAX_EVIDENCE_CHAIN_BYTES = 16 * 1024 * 1024
MAX_MISSION_RECEIPTS = 10_000
MAX_METRIC_EVIDENCE_REFS = 128
MAX_LATENCY_MS = 31 * 24 * 60 * 60 * 1000
MAX_MISSION_MODEL_TURNS = 2_048
MAX_SPECIALIST_GRAPH_TASKS = 256
MAX_SPECIALIST_GRAPH_AGENTS = 32
_EVALUABLE_TERMINAL_STATUSES = frozenset({
    MissionStatus.GOAL_COMPLETED,
    MissionStatus.AUTHORIZATION_BLOCKED,
    MissionStatus.SCOPE_BLOCKED,
    MissionStatus.RESOURCE_BLOCKED,
    MissionStatus.SAFETY_BLOCKED,
    MissionStatus.FAILED_RETRY_EXHAUSTED,
    MissionStatus.CANCELLED,
})


class MissionOutcomeRecorder:
    """Persist a limited deterministic outcome record after durable Mission completion.

    Callers must invoke ``record`` only after the Mission's authoritative store
    has committed its terminal state. The recorder reloads that state itself,
    checks the canonical Owner/Mission authorization binding and integrity, and
    uses an integrity-derived idempotency key so recovery cannot duplicate it.
    """

    def __init__(
        self,
        mission_store: Any,
        evaluation_store: EvaluationStore,
        *,
        evidence_db_path: str | Path,
    ) -> None:
        if not callable(getattr(mission_store, "load", None)):
            raise TypeError("mission_store must provide load")
        if not isinstance(evaluation_store, EvaluationStore) or evaluation_store._read_only:
            raise TypeError("evaluation_store must be a writable EvaluationStore")
        self.mission_store = mission_store
        self.evaluation_store = evaluation_store
        self.evidence_db_path = Path(evidence_db_path)

    def _load_verified_evidence(self, mission: Mission, expected_auth: str) -> tuple[list[str], int, bool]:
        receipts = mission.progress.get("execution_evidence_refs", [])
        if not isinstance(receipts, list) or len(receipts) > MAX_MISSION_RECEIPTS:
            return [], 0, False
        receipt_by_id: dict[str, dict[str, Any]] = {}
        for receipt in receipts:
            if not isinstance(receipt, dict):
                return [], len(receipts), False
            evidence_id = receipt.get("evidence_id")
            if not isinstance(evidence_id, str) or not evidence_id or evidence_id in receipt_by_id:
                return [], len(receipts), False
            receipt_by_id[evidence_id] = receipt

        path = self.evidence_db_path
        if not receipts:
            return [], 0, False
        if path.is_symlink() or not path.is_file():
            return [], len(receipts), False
        uri = path.resolve().as_uri() + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.execute("PRAGMA busy_timeout = 5000")
                sizes = connection.execute(
                    "SELECT length(payload) FROM evidence_chain ORDER BY sequence LIMIT ?",
                    (MAX_EVIDENCE_CHAIN_RECORDS + 1,),
                ).fetchall()
                if len(sizes) > MAX_EVIDENCE_CHAIN_RECORDS:
                    return [], len(receipts), False
                if sum(int(row[0] or 0) for row in sizes) > MAX_EVIDENCE_CHAIN_BYTES:
                    return [], len(receipts), False
                rows = connection.execute(
                    "SELECT payload FROM evidence_chain ORDER BY sequence LIMIT ?",
                    (MAX_EVIDENCE_CHAIN_RECORDS + 1,),
                ).fetchall()
            records = [json.loads(row[0]) for row in rows]
        except (sqlite3.Error, json.JSONDecodeError, TypeError, ValueError, OverflowError):
            return [], len(receipts), False
        if not all(isinstance(record, dict) for record in records):
            return [], len(receipts), False
        if not EvidenceChainStore.verify_records(records, mission_store=None, require_execution_fence=False):
            return [], len(receipts), False

        valid: set[str] = set()
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
            receipt = receipt_by_id.get(evidence_id) if isinstance(evidence_id, str) else None
            if receipt is None:
                continue
            try:
                expected_receipt = EvidenceChainStore._receipt(record)
            except (KeyError, TypeError, ValueError, OverflowError):
                continue
            if all(receipt.get(name) == value for name, value in expected_receipt.items()):
                valid.add(evidence_id)
        return sorted(valid), len(receipts), True

    @staticmethod
    def _latency_ms(trajectory: list[dict[str, Any]]) -> int | None:
        start_event: dict[str, Any] | None = None
        completed_event: dict[str, Any] | None = None
        for event in trajectory:
            if event.get("event") == EventType.MISSION_STARTED.value and start_event is None:
                start_event = event
            elif event.get("event") == EventType.MISSION_COMPLETED.value and start_event is not None:
                completed_event = event
        if start_event is None or completed_event is None:
            return None
        try:
            start = datetime.fromisoformat(str(start_event["timestamp"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(completed_event["timestamp"]).replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None:
                return None
            value = int((end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds() * 1000)
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        return value if 0 <= value <= MAX_LATENCY_MS else None

    @staticmethod
    def _provider_reported_token_usage(mission: Mission) -> int | None:
        progress = mission.progress
        loop = progress.get("model_loop") if isinstance(progress, dict) else None
        turns = loop.get("turns") if isinstance(loop, dict) else None
        if not isinstance(turns, list) or not turns or len(turns) > MAX_MISSION_MODEL_TURNS:
            return None
        total = 0
        for turn in turns:
            if not isinstance(turn, dict):
                return None
            usage = turn.get("usage")
            if not isinstance(usage, dict):
                return None
            try:
                if len(json.dumps(usage, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_PROVIDER_USAGE_BYTES:
                    return None
            except (TypeError, ValueError, UnicodeError, OverflowError):
                return None
            has_components = "prompt_tokens" in usage or "completion_tokens" in usage
            if has_components:
                prompt_tokens = usage.get("prompt_tokens")
                completion_tokens = usage.get("completion_tokens")
                if type(prompt_tokens) is not int or type(completion_tokens) is not int:
                    return None
                turn_tokens = prompt_tokens + completion_tokens
                reported_total = usage.get("total_tokens")
                if reported_total is not None and (
                    type(reported_total) is not int or reported_total != turn_tokens
                ):
                    return None
            else:
                turn_tokens = usage.get("total_tokens")
                if type(turn_tokens) is not int:
                    return None
            if turn_tokens < 0 or turn_tokens > MAX_RECORDED_TOKEN_USAGE:
                return None
            total += turn_tokens
            if total > MAX_RECORDED_TOKEN_USAGE:
                return None
        return total

    @staticmethod
    def _specialist_completion_ratio(mission: Mission) -> float | None:
        state = mission.agent_task_graph_state
        envelope = state.get("specialist_graph") if isinstance(state, dict) else None
        graph = envelope.get("graph") if isinstance(envelope, dict) else None
        tasks = graph.get("tasks") if isinstance(graph, dict) else None
        agents = graph.get("agents") if isinstance(graph, dict) else None
        if not isinstance(tasks, list) or not tasks or len(tasks) > MAX_SPECIALIST_GRAPH_TASKS:
            return None
        if not isinstance(agents, list) or not agents or len(agents) > MAX_SPECIALIST_GRAPH_AGENTS:
            return None
        agent_ids: set[str] = set()
        valid_agent_states = {"CREATED", "READY", "RUNNING", "WAITING", "BLOCKED", "COMPLETED", "FAILED", "CANCELLED"}
        for agent in agents:
            if not isinstance(agent, dict):
                return None
            agent_id = agent.get("agent_id")
            scope = agent.get("permission_scope")
            lifecycle = agent.get("lifecycle")
            if (
                not isinstance(agent_id, str)
                or not agent_id
                or agent_id in agent_ids
                or agent.get("mission_id") != mission.mission_id
                or agent.get("owner_identity_ref") != mission.owner_identity_ref
                or not isinstance(scope, dict)
                or scope.get("mission_id") != mission.mission_id
                or scope.get("owner_identity_ref") != mission.owner_identity_ref
                or not isinstance(lifecycle, str)
                or lifecycle not in valid_agent_states
            ):
                return None
            agent_ids.add(agent_id)
        task_ids: set[str] = set()
        valid_task_states = {"CREATED", "READY", "RUNNING", "WAITING", "BLOCKED", "COMPLETED", "FAILED", "CANCELLED"}
        for task in tasks:
            task_id = task.get("task_id") if isinstance(task, dict) else None
            assigned_agent_id = task.get("assigned_agent_id") if isinstance(task, dict) else None
            lifecycle = task.get("lifecycle") if isinstance(task, dict) else None
            if (
                not isinstance(task, dict)
                or task.get("mission_id") != mission.mission_id
                or not isinstance(task_id, str)
                or not task_id
                or task_id in task_ids
                or not isinstance(assigned_agent_id, str)
                or assigned_agent_id not in agent_ids
                or not isinstance(lifecycle, str)
                or lifecycle not in valid_task_states
            ):
                return None
            task_ids.add(task_id)
        completed = sum(task["lifecycle"] == "COMPLETED" for task in tasks)
        return completed / len(tasks)

    def record(self, mission_id: str) -> StoredEvaluation | None:
        if not isinstance(mission_id, str) or not mission_id or len(mission_id) > 256:
            raise EvaluationError("mission id is invalid")
        try:
            mission = self.mission_store.load(mission_id)
        except Exception as exc:
            raise EvaluationError("Mission outcome is unavailable") from exc
        if mission is None:
            raise EvaluationError("Mission outcome is unavailable")
        if mission.mission_id != mission_id or not mission.owner_identity_ref:
            raise EvaluationError("Mission outcome identity is invalid")
        try:
            size = len(json.dumps(mission.to_dict(), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvaluationError("Mission outcome is malformed") from exc
        if size > MAX_MISSION_EVALUATION_INPUT_BYTES:
            raise EvaluationError("Mission outcome exceeds the evaluation bound")
        if not mission.verify_integrity() or not mission.trajectory or not verify_trajectory(mission.trajectory):
            raise EvaluationError("Mission outcome integrity is invalid")
        if mission.status not in _EVALUABLE_TERMINAL_STATUSES:
            # Owner-input, reauthorization, and ambiguous recovery states are
            # resumable/reconcilable, not completed evaluation outcomes.
            return None
        try:
            created_at = str(mission.trajectory[-1]["timestamp"])
            parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if parsed_created_at.tzinfo is None:
                raise ValueError("timezone required")
        except (KeyError, TypeError, ValueError, IndexError) as exc:
            raise EvaluationError("Mission outcome timestamp is invalid") from exc
        snapshot_data = mission.authorization_snapshot
        if not isinstance(snapshot_data, dict):
            raise EvaluationError("Mission authorization binding is unavailable")
        try:
            snapshot = MissionAuthorizationSnapshot.from_dict(snapshot_data)
            valid, _reason = snapshot.validate_for_mission(
                mission_id=mission.mission_id,
                owner_identity=mission.owner_identity_ref,
                target_identity=snapshot.target_identity,
                version=snapshot.version,
                at=snapshot.created_at,
            )
            if not valid:
                raise EvaluationError("Mission authorization binding is invalid")
            expected_auth = authorization_digest(snapshot)
        except EvaluationError:
            raise
        except Exception as exc:
            raise EvaluationError("Mission authorization binding is invalid") from exc

        metrics = [EvaluationMeasurement(
            EvaluationMetric.TASK_SUCCESS,
            1.0 if (
                mission.status is MissionStatus.GOAL_COMPLETED
                and mission.verification_state.get("verified") is True
            ) else 0.0,
        )]
        evidence_ids, receipt_count, chain_valid = self._load_verified_evidence(mission, expected_auth)
        if (
            chain_valid
            and receipt_count > 0
            and evidence_ids
            and len(evidence_ids) <= MAX_METRIC_EVIDENCE_REFS
        ):
            metrics.append(EvaluationMeasurement(
                EvaluationMetric.EVIDENCE_QUALITY,
                len(evidence_ids) / receipt_count,
                tuple(evidence_ids),
            ))
        latency = self._latency_ms(mission.trajectory)
        if latency is not None:
            metrics.append(EvaluationMeasurement(EvaluationMetric.LATENCY, latency))
        token_usage = self._provider_reported_token_usage(mission)
        if token_usage is not None:
            metrics.append(EvaluationMeasurement(EvaluationMetric.TOKEN_USAGE, token_usage))
        coordination = self._specialist_completion_ratio(mission)
        if coordination is not None:
            metrics.append(EvaluationMeasurement(EvaluationMetric.AGENT_COORDINATION, coordination))

        trajectory_head = str(mission.trajectory[-1].get("event_hash", ""))
        not_measured = [
            "hallucination", "tool_correctness", "skill_usefulness", "memory_usefulness",
            "cost", "recovery", "safety_violations",
        ]
        if token_usage is None:
            not_measured.append("token_usage")
        if coordination is None:
            not_measured.append("agent_coordination")
        provenance = {
            "evaluator": "cybersentinel.mission-outcome.v1",
            "mission_integrity_sha256": mission.integrity_hash,
            "trajectory_head_sha256": trajectory_head,
            "evidence_chain_verified": chain_valid,
            "metric_definition_task_success": "terminal_goal_verifier_boolean_v1",
            "metric_definition_evidence_quality": "verified_fenced_receipt_integrity_ratio_v1_not_semantic_support",
            "metric_definition_latency": "MissionStarted_to_MissionCompleted_ms_v1",
            "metric_definition_token_usage": "sum_of_exact_provider_reported_token_counts_v1_not_attested_ground_truth",
            "metric_definition_agent_coordination": "completed_assigned_specialist_task_ratio_v1_not_semantic_quality",
            "not_measured": tuple(not_measured),
        }
        run = EvaluationRun(
            owner_identity_ref=mission.owner_identity_ref,
            mission_id=mission.mission_id,
            task_id="mission-outcome",
            case_id="terminal-mission-outcome",
            benchmark_version="mission-outcome-v1",
            provider_id="system-outcome-evaluator",
            model_id="deterministic-v1",
            measurements=tuple(metrics),
            provenance=provenance,
            created_at=created_at,
        )
        return self.evaluation_store.append(
            run,
            idempotency_key=f"mission-outcome-v1:{mission.integrity_hash}",
        )


__all__ = ["MissionOutcomeRecorder", "MAX_MISSION_EVALUATION_INPUT_BYTES"]
