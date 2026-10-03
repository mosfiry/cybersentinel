from __future__ import annotations

import signal
import threading
import time

import pytest

from agent.runtime_supervisor import RuntimeSupervisor, SupervisorState


class _Worker:
    def __init__(self, *, recover=None, run=None):
        self.worker_id = "reusable-name"
        self.recover_calls = 0
        self.run_calls = 0
        self._recover = recover
        self._run = run

    def recover_after_restart(self):
        self.recover_calls += 1
        if self._recover:
            return self._recover()
        return ["expired-lease"]

    def run_once(self):
        self.run_calls += 1
        if self._run:
            return self._run()
        return None


def test_start_recovers_before_running_and_reports_health():
    worker = _Worker()
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)
    assert supervisor.state is SupervisorState.STARTING

    health = supervisor.start()
    assert health["state"] == "RUNNING"
    assert health["worker_instance_id"] == worker.worker_id
    assert health["started_at"]
    assert health["recovered_expired_leases"] == 1
    assert worker.recover_calls == 1
    assert supervisor.start() == health
    assert worker.recover_calls == 1


def test_supervisor_assigns_unique_instance_identity_even_when_worker_name_reused():
    first_worker, second_worker = _Worker(), _Worker()
    first = RuntimeSupervisor(first_worker)
    second = RuntimeSupervisor(second_worker)

    assert first.worker_instance_id != second.worker_instance_id
    assert first_worker.worker_id == first.worker_instance_id
    assert second_worker.worker_id == second.worker_instance_id


def test_bounded_polling_transitions_running_to_draining_to_stopped():
    worker = _Worker()
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)

    health = supervisor.serve_forever(max_iterations=2)

    assert health["state"] == "STOPPED"
    assert health["poll_count"] == 2
    assert worker.recover_calls == 1
    assert worker.run_calls == 2


def test_request_stop_during_active_call_drains_without_claiming_another():
    entered = threading.Event()
    release = threading.Event()

    def blocking_run():
        entered.set()
        assert release.wait(timeout=2)
        return object()

    worker = _Worker(run=blocking_run)
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)
    thread = threading.Thread(target=supervisor.serve_forever)
    thread.start()
    assert entered.wait(timeout=2)
    supervisor.request_stop()
    release.set()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert supervisor.state is SupervisorState.STOPPED
    assert worker.run_calls == 1


def test_recovery_failure_fails_closed_and_worker_never_polls():
    worker = _Worker(recover=lambda: (_ for _ in ()).throw(OSError("db detail must not leak")))
    supervisor = RuntimeSupervisor(worker)

    with pytest.raises(OSError):
        supervisor.serve_forever()

    assert supervisor.state is SupervisorState.FAILED
    assert supervisor.health()["error_code"] == "OSError"
    assert "db detail" not in str(supervisor.health())
    assert worker.run_calls == 0


def test_worker_failure_is_observable_and_is_not_retried_by_supervisor():
    worker = _Worker(run=lambda: (_ for _ in ()).throw(RuntimeError("sensitive detail")))
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)

    with pytest.raises(RuntimeError):
        supervisor.serve_forever()

    assert supervisor.state is SupervisorState.FAILED
    assert supervisor.health()["error_code"] == "RuntimeError"
    assert "sensitive detail" not in str(supervisor.health())
    assert worker.run_calls == 1


def test_signal_handlers_request_graceful_stop_and_restore_previous_handlers():
    worker = _Worker()
    supervisor = RuntimeSupervisor(worker, poll_interval_seconds=0)

    with supervisor.install_signal_handlers():
        handler = signal.getsignal(signal.SIGTERM)
        handler(signal.SIGTERM, None)
        assert supervisor.state is SupervisorState.DRAINING
    assert signal.getsignal(signal.SIGTERM) is not handler


def test_invalid_poll_interval_and_transition_replay_are_rejected():
    with pytest.raises(ValueError):
        RuntimeSupervisor(_Worker(), poll_interval_seconds=-0.1)
    supervisor = RuntimeSupervisor(_Worker(), poll_interval_seconds=0)
    supervisor.serve_forever(max_iterations=0)
    assert supervisor.state is SupervisorState.STOPPED
    with pytest.raises(RuntimeError):
        supervisor.start()
