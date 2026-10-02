from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent.mission_worker import MissionQueue, MissionScheduler, WorkerMissionState


def _scheduler(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    return MissionScheduler(Path(tmp_path) / "scheduler.sqlite3", queue), queue


@pytest.mark.parametrize("bad", ["2026-01-01T00:00:00", "not-a-date", "", "   ", "2026-13-01T00:00:00+00:00", 12345])
def test_run_at_requires_timezone_aware_iso8601(tmp_path, bad):
    scheduler, _ = _scheduler(tmp_path)
    with pytest.raises(ValueError):
        scheduler.schedule("mission-x", run_at=bad)


def test_run_at_is_normalized_to_canonical_utc(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    offset = scheduler.schedule("mission-x", run_at="2026-01-01T02:00:00+02:00", schedule_id="s1")
    assert offset.next_run_at == "2026-01-01T00:00:00+00:00"
    zulu = scheduler.schedule("mission-y", run_at="2025-12-31T23:00:00Z", schedule_id="s2")
    assert zulu.next_run_at == "2025-12-31T23:00:00+00:00"


def test_dispatch_due_compares_parsed_instants_not_text(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    # 01:00+01:00 IS 00:00 UTC: raw text comparison would call it not due.
    scheduler.schedule("mission-a", run_at="2026-01-01T01:00:00+01:00", schedule_id="a")
    dispatched = scheduler.dispatch_due(now="2026-01-01T00:00:00+00:00")
    assert [item.schedule_id for item in dispatched] == ["a"]
    assert scheduler.get("a").state is WorkerMissionState.COMPLETED


def test_dispatch_due_skips_legacy_nonconforming_rows(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    scheduler.schedule("mission-legacy", run_at="2026-01-01T00:00:00+00:00", schedule_id="legacy")
    scheduler.schedule("mission-good", run_at="2026-01-01T00:00:00+00:00", schedule_id="good")
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute("UPDATE mission_schedules SET next_run_at='2026-01-01 00:00:00' WHERE schedule_id='legacy'")
    dispatched = scheduler.dispatch_due(now="2026-01-01T00:01:00+00:00")
    assert {item.schedule_id for item in dispatched} == {"good"}
    assert scheduler.get("legacy").state is WorkerMissionState.SCHEDULED


def test_dispatch_due_rejects_naive_now(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    with pytest.raises(ValueError):
        scheduler.dispatch_due(now="2026-01-01T00:00:00")


def test_recurring_next_run_is_canonical_utc(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    scheduler.schedule("mission-r", run_at="2026-01-01T00:00:00+00:00", interval_seconds=60, schedule_id="r")
    scheduler.dispatch_due(now="2026-01-01T00:01:00+00:00")
    assert scheduler.get("r").next_run_at == "2026-01-01T00:02:00+00:00"
    assert scheduler.get("r").state is WorkerMissionState.SCHEDULED


def test_mark_missed_is_fail_closed_for_legacy_rows(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    scheduler.schedule("mission-m", run_at="2026-01-01T00:00:00+00:00", schedule_id="m")
    with sqlite3.connect(scheduler.db_path) as db:
        db.execute("UPDATE mission_schedules SET next_run_at='2026-01-01 00:00:00' WHERE schedule_id='m'")
    item = scheduler.mark_missed("m", now="2026-01-02T00:00:00+00:00")
    assert item.state is WorkerMissionState.SCHEDULED


def test_mark_missed_transitions_only_when_instant_has_passed(tmp_path):
    scheduler, _ = _scheduler(tmp_path)
    scheduler.schedule("mission-m", run_at="2026-01-02T00:00:00+00:00", schedule_id="m")
    early = scheduler.mark_missed("m", now="2026-01-01T00:00:00+00:00")
    assert early.state is WorkerMissionState.SCHEDULED
    late = scheduler.mark_missed("m", now="2026-01-03T00:00:00+00:00")
    assert late.state is WorkerMissionState.SLEEPING
