"""Bounded recurring schedules composed from separately Owner-authorized Missions.

A recurring schedule never clones or reuses an authorization snapshot. The
Owner supplies a distinct READY Mission identity for every occurrence and for
each permitted retry. The scheduler requires identical objective, plan, scope,
Owner, and authorization bounds across the series, then delegates each run to
the existing one-shot MissionScheduler transaction and authorization checks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Any, Iterable

from .mission import MissionStatus
from .mission_worker import MissionScheduler, WorkerMissionState, _utc_datetime, _utc_text


class MissionSeriesScheduler(MissionScheduler):
    """Persistent finite recurrence over independently authorized Mission IDs."""

    def __init__(self, db_path, queue, *, mission_store=None, fault_injector=None):
        super().__init__(db_path, queue, mission_store=mission_store, fault_injector=fault_injector)
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS mission_schedule_series ("
                "series_id TEXT PRIMARY KEY, owner_identity_ref TEXT NOT NULL, interval_seconds INTEGER NOT NULL, "
                "retry_limit INTEGER NOT NULL, occurrence_mission_ids TEXT NOT NULL, retry_mission_ids TEXT NOT NULL, "
                "anchor_run_at TEXT NOT NULL, next_run_at TEXT NOT NULL, occurrence_index INTEGER NOT NULL, "
                "retry_cursor INTEGER NOT NULL, active_schedule_id TEXT NOT NULL DEFAULT '', "
                "active_mission_id TEXT NOT NULL DEFAULT '', active_kind TEXT NOT NULL DEFAULT '', "
                "state TEXT NOT NULL, failure_code TEXT NOT NULL DEFAULT '')"
            )

    @staticmethod
    def _bounds(snapshot) -> dict[str, Any]:
        return {
            "owner_identity": snapshot.owner_identity,
            "target_identity": snapshot.target_identity,
            "scope": list(snapshot.scope),
            "allowed_actions": list(snapshot.allowed_actions),
            "forbidden_actions": list(snapshot.forbidden_actions),
            "allowed_tools": list(snapshot.allowed_tools),
            "time_window": snapshot.time_window,
            "max_duration": snapshot.max_duration,
            "rate_limits": snapshot.rate_limits,
            "network_boundary": snapshot.network_boundary,
            "data_boundary": snapshot.data_boundary,
            "credential_boundary": snapshot.credential_boundary,
            "workspace_boundary": snapshot.workspace_boundary,
            "policy_version": snapshot.policy_version,
            "version": snapshot.version,
        }

    @staticmethod
    def _snapshot_for(mission):
        from security.mission_authorization import MissionAuthorizationSnapshot
        if not isinstance(mission.authorization_snapshot, dict):
            raise PermissionError("series occurrence requires its own Owner authorization snapshot")
        return MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot))

    @staticmethod
    def _is_ready(mission) -> bool:
        return (
            mission.status is MissionStatus.READY
            and not mission.progress.get("pause_requested")
            and not mission.progress.get("owner_cancel_requested")
            and not mission.progress.get("active_execution_claim")
            and str((mission.checkpoint or {}).get("status", "")) not in {"in_flight", "in_flight_parallel"}
        )

    def _validate_series_missions(
        self,
        mission_ids: tuple[str, ...],
        retry_ids: tuple[str, ...],
        *,
        owner_identity_ref: str,
        anchor_run_at: str,
        interval_seconds: int,
    ) -> None:
        if self.mission_store is None:
            raise PermissionError("recurring schedules require the authoritative MissionStore")
        all_ids = mission_ids + retry_ids
        if any(not item.strip() or len(item) > 128 for item in all_ids):
            raise ValueError("every occurrence and retry Mission ID must be 1-128 characters")
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("every occurrence and retry requires a distinct Mission identity")
        baseline = None
        baseline_scope_hash = None
        baseline_plan = None
        baseline_objective = None
        baseline_criteria = None
        baseline_skill_binding = None
        now = _utc_text(datetime.now(timezone.utc))
        with self._attached_transaction() as (db, queue_schema, mission_schema, owner_schema):
            for position, mission_id in enumerate(all_ids):
                mission, _encoded = self._load_mission(db, mission_schema, mission_id)
                if not mission.verify_integrity() or not self._is_ready(mission):
                    raise PermissionError("every series Mission must be integrity-valid and READY")
                if mission.owner_identity_ref != owner_identity_ref:
                    raise PermissionError("series occurrence Owner identity changed")
                snapshot = self._snapshot_for(mission)
                valid, reason = snapshot.validate_for_mission(
                    mission_id=mission.mission_id,
                    owner_identity=owner_identity_ref,
                    target_identity=snapshot.target_identity,
                    version=snapshot.version,
                    at=now,
                )
                if not valid:
                    raise PermissionError("series Mission authorization is invalid: " + reason)
                persisted = self._validate_snapshot(
                    mission,
                    db=db,
                    owner_schema=owner_schema,
                    owner_identity_ref=owner_identity_ref,
                    authorization_hash=snapshot.authorization_hash,
                    authorization_version=snapshot.version,
                    authorization_expires_at=snapshot.expires_at,
                    at=now,
                )
                if persisted.to_dict() != snapshot.to_dict():
                    raise PermissionError("series Mission authorization differs from its persisted snapshot")
                scope_hash = self._scope_snapshot_hash(mission)
                bounds = self._bounds(snapshot)
                criteria = json.dumps(mission.completion_criteria, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                if baseline is None:
                    baseline = bounds
                    baseline_scope_hash = scope_hash
                    baseline_plan = mission.plan.fingerprint
                    baseline_objective = mission.objective
                    baseline_criteria = criteria
                    baseline_skill_binding = mission.skill_binding
                elif (
                    bounds != baseline
                    or scope_hash != baseline_scope_hash
                    or mission.plan.fingerprint != baseline_plan
                    or mission.objective != baseline_objective
                    or criteria != baseline_criteria
                    or mission.skill_binding != baseline_skill_binding
                ):
                    raise PermissionError("series occurrence or retry changes Owner authorization, scope, task plan, criteria, or Skill binding")
                if position < len(mission_ids):
                    due = _utc_datetime(anchor_run_at, field_name="run_at") + timedelta(seconds=interval_seconds * position)
                else:
                    due = _utc_datetime(now, field_name="now")
                if due >= _utc_datetime(snapshot.expires_at, field_name="authorization_expires_at"):
                    raise PermissionError("series occurrence is outside its Owner authorization window")
                queue_row = db.execute(
                    f"SELECT state,lease_owner FROM {queue_schema}.mission_queue WHERE mission_id=?",
                    (mission_id,),
                ).fetchone()
                # An independently created, unqueued READY Mission is required.
                if queue_row is not None:
                    raise PermissionError("series Mission already has a queue record")

    def schedule_series(
        self,
        occurrence_mission_ids: Iterable[str],
        *,
        run_at: str,
        interval_seconds: int,
        owner_identity_ref: str,
        retry_mission_ids: Iterable[str] = (),
        schedule_id: str | None = None,
    ) -> dict[str, Any]:
        mission_ids = tuple(str(item) for item in occurrence_mission_ids)
        retry_ids = tuple(str(item) for item in retry_mission_ids)
        if not 2 <= len(mission_ids) <= 100:
            raise ValueError("a recurring series requires between 2 and 100 separately authorized occurrences")
        if not isinstance(interval_seconds, int) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if len(retry_ids) > 10:
            raise ValueError("at most 10 separately authorized retries are allowed per series")
        if not isinstance(owner_identity_ref, str) or not owner_identity_ref.strip():
            raise PermissionError("Owner identity is required for a recurring series")
        anchor = _utc_text(_utc_datetime(run_at, field_name="run_at"))
        series_id = schedule_id or ("series-" + uuid.uuid4().hex)
        if not series_id.strip() or len(series_id) > 72:
            raise ValueError("series_id must be a non-empty string of at most 72 characters")
        self._validate_series_missions(
            mission_ids, retry_ids,
            owner_identity_ref=owner_identity_ref,
            anchor_run_at=anchor,
            interval_seconds=interval_seconds,
        )
        with sqlite3.connect(self.db_path, timeout=30) as db:
            if db.execute("SELECT 1 FROM mission_schedule_series WHERE series_id=?", (series_id,)).fetchone():
                raise ValueError("series_id already exists")
            first_schedule_id = f"{series_id}:occ:1"
            db.execute(
                "INSERT INTO mission_schedule_series(series_id,owner_identity_ref,interval_seconds,retry_limit,occurrence_mission_ids,retry_mission_ids,anchor_run_at,next_run_at,occurrence_index,retry_cursor,active_schedule_id,active_mission_id,active_kind,state,failure_code) "
                "VALUES(?,?,?,?,?,?,?,?,0,0,?,?,?,'preparing','')",
                (series_id, owner_identity_ref, interval_seconds, len(retry_ids), json.dumps(mission_ids), json.dumps(retry_ids), anchor, anchor, first_schedule_id, mission_ids[0], "occurrence"),
            )
        try:
            self._ensure_child_schedule(first_schedule_id, mission_ids[0], anchor, owner_identity_ref)
            if not self._mark_series_scheduled(series_id, first_schedule_id, mission_ids[0], "occurrence"):
                return self.get_series(series_id)
        except Exception:
            self.cancel_scheduled(mission_ids[0])
            with sqlite3.connect(self.db_path, timeout=30) as db:
                db.execute("DELETE FROM mission_schedule_series WHERE series_id=?", (series_id,))
            raise
        return self.get_series(series_id)

    def _schedule_mission(self, schedule_id: str, mission_id: str, run_at: str, owner_identity_ref: str):
        mission = self.mission_store.load(mission_id)
        if mission is None:
            raise KeyError("series Mission disappeared before scheduling")
        snapshot = self._snapshot_for(mission)
        return super().schedule(
            mission_id,
            run_at=run_at,
            interval_seconds=None,
            retry_limit=0,
            schedule_id=schedule_id,
            owner_identity_ref=owner_identity_ref,
            authorization_snapshot=snapshot,
        )

    def _ensure_child_schedule(self, schedule_id: str, mission_id: str, run_at: str, owner_identity_ref: str):
        """Idempotently create or reattach the deterministic one-shot child schedule."""
        expected_run_at = _utc_text(_utc_datetime(run_at, field_name="run_at"))
        try:
            existing = super().get(schedule_id)
        except KeyError:
            existing = None
        if existing is None:
            try:
                return self._schedule_mission(schedule_id, mission_id, expected_run_at, owner_identity_ref)
            except sqlite3.IntegrityError:
                # Another worker may have committed the same deterministic ID.
                try:
                    existing = super().get(schedule_id)
                except KeyError:
                    raise
        if (
            existing.mission_id != mission_id
            or existing.next_run_at != expected_run_at
            or existing.interval_seconds is not None
            or existing.retry_limit != 0
        ):
            raise PermissionError("existing child schedule conflicts with the persisted series intent")
        return existing

    def get_series(self, series_id: str) -> dict[str, Any]:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute(
                "SELECT series_id,owner_identity_ref,interval_seconds,retry_limit,occurrence_mission_ids,retry_mission_ids,anchor_run_at,next_run_at,occurrence_index,retry_cursor,active_schedule_id,active_mission_id,active_kind,state,failure_code FROM mission_schedule_series WHERE series_id=?",
                (series_id,),
            ).fetchone()
        if row is None:
            raise KeyError("unknown recurring series")
        return {
            "series_id": row[0], "owner_identity_ref": row[1], "interval_seconds": row[2],
            "retry_limit": row[3], "occurrence_mission_ids": json.loads(row[4]),
            "retry_mission_ids": json.loads(row[5]), "anchor_run_at": row[6], "next_run_at": row[7],
            "occurrence_index": row[8], "retry_cursor": row[9], "active_schedule_id": row[10],
            "active_mission_id": row[11], "active_kind": row[12], "state": row[13], "failure_code": row[14],
        }

    def _write_series(self, series_id: str, *, occurrence_index: int, retry_cursor: int, next_run_at: str, active_schedule_id: str = "", active_mission_id: str = "", active_kind: str = "", state: str = "scheduled", failure_code: str = ""):
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.execute(
                "UPDATE mission_schedule_series SET occurrence_index=?,retry_cursor=?,next_run_at=?,active_schedule_id=?,active_mission_id=?,active_kind=?,state=?,failure_code=? WHERE series_id=? AND state IN ('scheduled','preparing')",
                (occurrence_index, retry_cursor, next_run_at, active_schedule_id, active_mission_id, active_kind, state, failure_code, series_id),
            )

    def _mark_series_scheduled(self, series_id: str, schedule_id: str, mission_id: str, kind: str) -> bool:
        with sqlite3.connect(self.db_path, timeout=30) as db:
            changed = db.execute(
                "UPDATE mission_schedule_series SET state='scheduled' WHERE series_id=? AND state='preparing' AND active_schedule_id=? AND active_mission_id=? AND active_kind=?",
                (series_id, schedule_id, mission_id, kind),
            )
        if changed.rowcount == 1:
            return True
        current = self.get_series(series_id)
        if current["state"] == "cancelled":
            self.cancel_scheduled(mission_id)
            return False
        if (
            current["state"] == "scheduled"
            and current["active_schedule_id"] == schedule_id
            and current["active_mission_id"] == mission_id
            and current["active_kind"] == kind
        ):
            return True
        raise RuntimeError("series child intent changed before its schedule was committed")

    def advance_series(self, *, now: str) -> list[dict[str, Any]]:
        now_text = _utc_text(_utc_datetime(now, field_name="now"))
        with sqlite3.connect(self.db_path) as db:
            ids = [row[0] for row in db.execute("SELECT series_id FROM mission_schedule_series WHERE state IN ('scheduled','preparing') ORDER BY next_run_at,series_id")]
        changes = []
        for series_id in ids:
            item = self.get_series(series_id)
            occurrence_index = int(item["occurrence_index"])
            retry_cursor = int(item["retry_cursor"])
            active_schedule_id = str(item["active_schedule_id"])
            active_mission_id = str(item["active_mission_id"])
            active_kind = str(item["active_kind"])
            next_run_at = str(item["next_run_at"])
            if item["state"] == "preparing":
                occurrence_ids = item["occurrence_mission_ids"]
                retry_ids = item["retry_mission_ids"]
                expected_mission_id = ""
                expected_schedule_id = ""
                if active_kind == "occurrence" and occurrence_index < len(occurrence_ids):
                    expected_mission_id = occurrence_ids[occurrence_index]
                    expected_schedule_id = f"{series_id}:occ:{occurrence_index + 1}"
                elif active_kind == "retry" and 1 <= retry_cursor <= len(retry_ids):
                    expected_mission_id = retry_ids[retry_cursor - 1]
                    expected_schedule_id = f"{series_id}:retry:{retry_cursor}"
                if (
                    not active_mission_id
                    or not active_schedule_id
                    or active_mission_id != expected_mission_id
                    or active_schedule_id != expected_schedule_id
                ):
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="prepared_child_intent_invalid")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
                try:
                    self._ensure_child_schedule(active_schedule_id, active_mission_id, next_run_at, item["owner_identity_ref"])
                except (PermissionError, ValueError, KeyError, sqlite3.IntegrityError):
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="prepared_schedule_invalid")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
                if not self._mark_series_scheduled(series_id, active_schedule_id, active_mission_id, active_kind):
                    changes.append({"series_id": series_id, "state": "cancelled"})
                    continue
                item = self.get_series(series_id)
                occurrence_index = int(item["occurrence_index"])
                retry_cursor = int(item["retry_cursor"])
                active_schedule_id = str(item["active_schedule_id"])
                active_mission_id = str(item["active_mission_id"])
                active_kind = str(item["active_kind"])
                next_run_at = str(item["next_run_at"])
            if active_schedule_id:
                try:
                    active_schedule = super().get(active_schedule_id)
                except KeyError:
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="active_schedule_missing")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
                if active_schedule.state is WorkerMissionState.SCHEDULED:
                    continue
                if active_schedule.state is not WorkerMissionState.COMPLETED:
                    state = "cancelled" if active_schedule.state is WorkerMissionState.CANCELLED else "needs_input"
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state=state, failure_code="child_schedule_not_dispatched")
                    changes.append({"series_id": series_id, "state": state})
                    continue
                mission = self.mission_store.load(active_mission_id)
                if mission is None:
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="active_mission_missing")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
                if not mission.is_terminal:
                    continue
                if mission.status is MissionStatus.GOAL_COMPLETED and mission.verify_integrity():
                    occurrence_index += 1
                    anchor = _utc_datetime(item["anchor_run_at"], field_name="series anchor")
                    next_run_at = _utc_text(anchor + timedelta(seconds=int(item["interval_seconds"]) * occurrence_index))
                    if occurrence_index >= len(item["occurrence_mission_ids"]):
                        self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="completed")
                        changes.append({"series_id": series_id, "state": "completed", "occurrences_completed": occurrence_index})
                        continue
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=0, next_run_at=next_run_at)
                    active_schedule_id = active_mission_id = active_kind = ""
                    retry_cursor = 0
                elif mission.status is MissionStatus.FAILED_RETRY_EXHAUSTED:
                    retries = item["retry_mission_ids"]
                    if retry_cursor >= len(retries):
                        self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="failed", failure_code="retry_limit_exhausted")
                        changes.append({"series_id": series_id, "state": "failed"})
                        continue
                    retry_id = retries[retry_cursor]
                    retry_cursor += 1
                    retry_schedule_id = f"{series_id}:retry:{retry_cursor}"
                    self._write_series(
                        series_id,
                        occurrence_index=occurrence_index,
                        retry_cursor=retry_cursor,
                        next_run_at=now_text,
                        active_schedule_id=retry_schedule_id,
                        active_mission_id=retry_id,
                        active_kind="retry",
                        state="preparing",
                    )
                    try:
                        self._ensure_child_schedule(retry_schedule_id, retry_id, now_text, item["owner_identity_ref"])
                    except (PermissionError, ValueError, KeyError, sqlite3.IntegrityError):
                        self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=now_text, state="needs_input", failure_code="retry_authorization_invalid")
                        changes.append({"series_id": series_id, "state": "needs_input"})
                        continue
                    if not self._mark_series_scheduled(series_id, retry_schedule_id, retry_id, "retry"):
                        changes.append({"series_id": series_id, "state": "cancelled"})
                        continue
                    changes.append({"series_id": series_id, "state": "retry_scheduled", "retry_mission_id": retry_id})
                    continue
                elif mission.status is MissionStatus.CANCELLED:
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="cancelled", failure_code="active_mission_cancelled")
                    changes.append({"series_id": series_id, "state": "cancelled"})
                    continue
                else:
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="mission_terminal_requires_owner_review")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
            if not active_schedule_id and occurrence_index < len(item["occurrence_mission_ids"]):
                if _utc_datetime(now_text, field_name="now") < _utc_datetime(next_run_at, field_name="next_run_at"):
                    continue
                mission_id = item["occurrence_mission_ids"][occurrence_index]
                child_id = f"{series_id}:occ:{occurrence_index + 1}"
                self._write_series(
                    series_id,
                    occurrence_index=occurrence_index,
                    retry_cursor=retry_cursor,
                    next_run_at=next_run_at,
                    active_schedule_id=child_id,
                    active_mission_id=mission_id,
                    active_kind="occurrence",
                    state="preparing",
                )
                try:
                    self._ensure_child_schedule(child_id, mission_id, next_run_at, item["owner_identity_ref"])
                except (PermissionError, ValueError, KeyError, sqlite3.IntegrityError):
                    self._write_series(series_id, occurrence_index=occurrence_index, retry_cursor=retry_cursor, next_run_at=next_run_at, state="needs_input", failure_code="occurrence_authorization_invalid")
                    changes.append({"series_id": series_id, "state": "needs_input"})
                    continue
                if not self._mark_series_scheduled(series_id, child_id, mission_id, "occurrence"):
                    changes.append({"series_id": series_id, "state": "cancelled"})
                    continue
                changes.append({"series_id": series_id, "state": "occurrence_scheduled", "occurrence": occurrence_index + 1})
        return changes

    def dispatch_due(self, *, now: str, limit: int = 100):
        self.advance_series(now=now)
        return super().dispatch_due(now=now, limit=limit)

    def cancel_series(self, series_id: str) -> dict[str, Any]:
        item = self.get_series(series_id)
        if item["state"] in {"completed", "cancelled", "failed", "needs_input"}:
            return item
        with sqlite3.connect(self.db_path, timeout=30) as db:
            db.execute(
                "UPDATE mission_schedule_series SET state='cancelled',failure_code='owner_cancelled' WHERE series_id=? AND state IN ('scheduled','preparing')",
                (series_id,),
            )
        if item["active_mission_id"] and item["active_schedule_id"]:
            try:
                child = super().get(item["active_schedule_id"])
                if child.state is WorkerMissionState.SCHEDULED:
                    self.cancel_scheduled(item["active_mission_id"])
            except KeyError:
                pass
        return self.get_series(series_id)


__all__ = ["MissionSeriesScheduler"]
