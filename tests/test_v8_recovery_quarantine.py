from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from agent.mission import MissionStatus
from agent.mission_worker import MissionQueue, MissionWorker, WorkerMissionState


def test_recovery_required_releases_claim_and_stays_quarantined(tmp_path):
    queue = MissionQueue(Path(tmp_path) / "queue.sqlite3")
    started = datetime.now(timezone.utc)
    started_text = started.isoformat()
    queue.enqueue("ambiguous-mission", available_at=started_text)
    calls: list[str] = []

    class Runtime:
        def run_to_completion(self, mission_id, max_slices=None, heartbeat=None):
            calls.append(mission_id)
            return SimpleNamespace(
                status=MissionStatus.RECOVERY_REQUIRED,
                evidence=[],
                error="in-flight tool outcome is unknown",
            )

    worker = MissionWorker(queue, lambda: Runtime(), worker_id="recovery-worker")
    parked = worker.run_once(now=started_text)

    assert parked is not None
    assert parked.state is WorkerMissionState.WAITING_FOR_TOOL
    assert parked.last_error == "in-flight tool outcome is unknown"
    assert parked.lease_owner is None
    assert parked.lease_expires_at is None
    assert parked.claimed_at is None

    restart_time = (started + timedelta(hours=1)).isoformat()
    assert queue.recover_after_restart(now=restart_time) == []
    assert queue.claim_next(now=restart_time, worker_id="another-worker") is None
    assert worker.run_once(now=restart_time) is None
    assert queue.get("ambiguous-mission") == parked
    assert calls == ["ambiguous-mission"]
