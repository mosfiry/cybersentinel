from __future__ import annotations

import multiprocessing
import sqlite3
import threading
import time

import pytest

from security.dispatch_gate import DispatchGateCancelled, MissionDispatchGate


def _gate_with_cancel_state(db_path, mission_id, *, committed=False):
    queue_path = str(db_path) + ".queue.sqlite3"
    with sqlite3.connect(queue_path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS mission_queue "
            "(mission_id TEXT PRIMARY KEY, owner_cancel_requested INTEGER NOT NULL DEFAULT 0)"
        )
        db.execute(
            "INSERT OR REPLACE INTO mission_queue(mission_id,owner_cancel_requested) VALUES(?,?)",
            (mission_id, int(committed)),
        )
    return MissionDispatchGate(db_path, mission_id, cancellation_db_path=queue_path), queue_path


def _hold_request_until_cancel(db_path, mission_id, entered, socket_closed, errors):
    gate = MissionDispatchGate(db_path, mission_id)
    try:
        with gate.request_guard(timeout=5.0):
            entered.set()
            deadline = time.monotonic() + 5.0
            while not gate.cancel_signal.is_set() and time.monotonic() < deadline:
                time.sleep(0.005)
            if not gate.cancel_signal.is_set():
                errors.put("pending_marker_not_observed")
                return
            # Models the transport watcher closing its socket before the
            # request guard is released to the cancellation process.
            socket_closed.set()
        errors.put("ok")
    except BaseException as exc:
        errors.put(type(exc).__name__)


def _hold_send_guard(db_path, mission_id, entered, release_send, errors):
    gate = MissionDispatchGate(db_path, mission_id)
    try:
        with gate.send_guard(timeout=5.0):
            entered.set()
            if not release_send.wait(timeout=5.0):
                errors.put("send_release_timeout")
                return
        errors.put("send_finished")
    except BaseException as exc:
        errors.put(type(exc).__name__)


def test_owner_cancel_waits_for_cross_process_request_close_before_commit(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    db_path = tmp_path / "mission-store.sqlite3"
    mission_id = "mission-cross-process-dispatch"
    entered = ctx.Event()
    socket_closed = ctx.Event()
    errors = ctx.Queue()
    worker = ctx.Process(
        target=_hold_request_until_cancel,
        args=(str(db_path), mission_id, entered, socket_closed, errors),
    )
    worker.start()
    owner_gate = MissionDispatchGate(db_path, mission_id)
    created = False
    try:
        assert entered.wait(timeout=5)
        created = owner_gate.request_cancel()
        assert created is True
        with owner_gate.cancellation_guard(timeout=5.0):
            # Acquiring this cross-process lock proves the request's finally
            # path (including socket close) ran before Owner CAS finalization.
            assert socket_closed.is_set()
        worker.join(timeout=5)
        assert worker.exitcode == 0
        assert errors.get(timeout=1) == "ok"
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=2)
        if created:
            owner_gate.clear_cancel_request(created_by_this_call=True)


def test_cancel_commit_marker_waits_for_cross_process_socket_write(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    db_path = tmp_path / "mission-send-gate.sqlite3"
    mission_id = "mission-send-commit-order"
    entered = ctx.Event()
    release_send = ctx.Event()
    errors = ctx.Queue()
    worker = ctx.Process(
        target=_hold_send_guard,
        args=(str(db_path), mission_id, entered, release_send, errors),
    )
    worker.start()
    owner_gate = MissionDispatchGate(db_path, mission_id)
    cancel_results = []
    canceller = threading.Thread(
        target=lambda: cancel_results.append(owner_gate.request_cancel()),
        daemon=True,
    )
    try:
        assert entered.wait(timeout=5)
        canceller.start()
        deadline = time.monotonic() + 5.0
        while not owner_gate.intent_path.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert owner_gate.intent_path.exists()
        # Intent wakes transports, but the durable commit marker is serialized
        # after the already-started socket write leaves its critical section.
        assert not owner_gate.cancel_path.exists()
        assert canceller.is_alive()
        release_send.set()
        canceller.join(timeout=5)
        assert not canceller.is_alive()
        assert cancel_results == [True]
        assert owner_gate.cancel_path.exists()
        worker.join(timeout=5)
        assert worker.exitcode == 0
        assert errors.get(timeout=1) == "send_finished"
        with pytest.raises(DispatchGateCancelled):
            with owner_gate.send_guard(timeout=1.0):
                pytest.fail("socket write crossed the committed cancel marker")
    finally:
        release_send.set()
        if canceller.is_alive():
            canceller.join(timeout=5)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=2)
        if cancel_results == [True]:
            owner_gate.clear_cancel_request(created_by_this_call=True)


def test_owner_cancel_waits_for_cross_process_process_start_before_commit(tmp_path):
    gate, queue_path = _gate_with_cancel_state(
        tmp_path / "process-start-store.sqlite3", "mission-process-start-gate"
    )
    entered = threading.Event()
    release_start = threading.Event()
    result = []

    def start_process():
        with gate.process_start_guard(timeout=2):
            entered.set()
            assert release_start.wait(timeout=2)

    def cancel_owner():
        with gate.owner_cancel_guard(timeout=2):
            gate.reconcile_cancel_request()
            result.append(gate.request_cancel())
            with sqlite3.connect(queue_path) as db:
                db.execute(
                    "UPDATE mission_queue SET owner_cancel_requested=1 WHERE mission_id=?",
                    (gate.mission_id,),
                )

    starter = threading.Thread(target=start_process, daemon=True)
    canceller = threading.Thread(target=cancel_owner, daemon=True)
    starter.start()
    try:
        assert entered.wait(timeout=1)
        canceller.start()
        deadline = time.monotonic() + 1
        while not gate.intent_path.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert gate.intent_path.exists()
        assert not gate.cancel_path.exists()
        assert canceller.is_alive()
        release_start.set()
        starter.join(timeout=2)
        canceller.join(timeout=2)
        assert not starter.is_alive()
        assert not canceller.is_alive()
        assert result == [True]
        assert gate.cancel_path.exists()
        with pytest.raises(DispatchGateCancelled):
            with gate.process_start_guard(timeout=1):
                pytest.fail("process start crossed the committed Owner cancellation")
    finally:
        release_start.set()
        starter.join(timeout=2)
        canceller.join(timeout=2)
        if gate.cancel_path.exists():
            gate.clear_cancel_request(created_by_this_call=True)


def test_stale_cancel_markers_clear_only_after_queue_confirms_no_commit(tmp_path):
    db_path = tmp_path / "stale-marker-store.sqlite3"
    gate, _queue_path = _gate_with_cancel_state(db_path, "mission-stale-recovery")
    assert gate.request_cancel() is True
    restarted = MissionDispatchGate(
        db_path,
        gate.mission_id,
        cancellation_db_path=gate.cancellation_db_path,
    )

    with restarted.process_start_guard(timeout=1):
        pass

    assert not restarted.intent_path.exists()
    assert not restarted.cancel_path.exists()


def test_committed_cancel_marker_survives_restart_and_blocks_process_start(tmp_path):
    db_path = tmp_path / "committed-marker-store.sqlite3"
    gate, queue_path = _gate_with_cancel_state(db_path, "mission-committed-recovery")
    assert gate.request_cancel() is True
    with sqlite3.connect(queue_path) as db:
        db.execute(
            "UPDATE mission_queue SET owner_cancel_requested=1 WHERE mission_id=?",
            (gate.mission_id,),
        )
    restarted = MissionDispatchGate(
        db_path,
        gate.mission_id,
        cancellation_db_path=queue_path,
    )

    with pytest.raises(DispatchGateCancelled):
        with restarted.process_start_guard(timeout=1):
            pytest.fail("committed cancellation marker was reconciled away")
    assert restarted.cancel_path.exists()


def test_cancelled_mission_gate_rejects_new_requests_but_allows_cancel_notice(tmp_path):
    gate = MissionDispatchGate(tmp_path / "mission-store.sqlite3", "mission-gate-policy")
    assert gate.request_cancel() is True

    with pytest.raises(DispatchGateCancelled):
        with gate.request_guard(timeout=1.0):
            pytest.fail("regular MCP request crossed the Owner cancellation marker")

    # A cancellation notification is separately authorized by MCP scope checks.
    with gate.request_guard(allow_cancelled=True, timeout=1.0):
        pass


def test_refused_cancel_clears_only_its_own_pending_marker(tmp_path):
    gate = MissionDispatchGate(tmp_path / "mission-store.sqlite3", "mission-stale-cancel")
    created = gate.request_cancel()
    assert created is True
    with gate.cancellation_guard(timeout=1.0):
        gate.clear_cancel_request(created_by_this_call=created)
    assert not gate.cancel_signal.is_set()
    with gate.request_guard(timeout=1.0):
        pass
