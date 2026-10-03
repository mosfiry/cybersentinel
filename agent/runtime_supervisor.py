from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
import os
import signal
import threading
import uuid
from typing import Any, Iterator


class SupervisorState(str, Enum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"
    RECOVERING = "RECOVERING"
    FAILED = "FAILED"


_ALLOWED_TRANSITIONS = {
    SupervisorState.STARTING: {SupervisorState.RECOVERING, SupervisorState.DRAINING, SupervisorState.FAILED},
    SupervisorState.RECOVERING: {SupervisorState.RUNNING, SupervisorState.DRAINING, SupervisorState.FAILED},
    SupervisorState.RUNNING: {SupervisorState.DRAINING, SupervisorState.FAILED},
    SupervisorState.DRAINING: {SupervisorState.STOPPED, SupervisorState.FAILED},
    SupervisorState.STOPPED: set(),
    SupervisorState.FAILED: set(),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RuntimeSupervisor:
    """Observable single-process supervisor for the durable MissionWorker.

    A supervisor owns one worker *instance* and never reuses that identity
    after process restart. Startup performs expired-lease recovery before the
    first queue poll. Shutdown stops new claims and drains the currently
    executing synchronous worker call before returning.
    """

    def __init__(self, worker: Any, *, poll_interval_seconds: float = 1.0):
        if not callable(getattr(worker, "run_once", None)):
            raise TypeError("worker must provide run_once")
        if poll_interval_seconds < 0:
            raise ValueError("poll_interval_seconds must be non-negative")
        self.worker = worker
        self.poll_interval_seconds = float(poll_interval_seconds)
        registered_instance = getattr(worker, "worker_instance_id", None)
        registered_generation = getattr(worker, "runtime_generation", None)
        if registered_instance and registered_generation is not None:
            self.worker_instance_id = str(registered_instance)
            self.runtime_generation: int | None = int(registered_generation)
        else:
            self.worker_instance_id = uuid.uuid4().hex
            self.runtime_generation = None
            try:
                self.worker.worker_id = self.worker_instance_id
            except (AttributeError, TypeError) as exc:
                raise TypeError("worker must allow a unique worker_id assignment") from exc
        self._state = SupervisorState.STARTING
        self._lock = threading.RLock()
        self._stop_requested = threading.Event()
        self._started_at: str | None = None
        self._last_poll_at: str | None = None
        self._recovered_count = 0
        self._error_code = ""
        self._poll_count = 0

    @property
    def state(self) -> SupervisorState:
        with self._lock:
            return self._state

    def _transition_locked(self, target: SupervisorState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self._state]:
            raise RuntimeError(f"invalid supervisor transition {self._state.value}->{target.value}")
        self._state = target

    def health(self) -> dict[str, Any]:
        """Return non-secret process health suitable for local probes/logging."""
        with self._lock:
            return {
                "state": self._state.value,
                "pid": os.getpid(),
                "worker_instance_id": self.worker_instance_id,
                "runtime_generation": self.runtime_generation,
                "started_at": self._started_at,
                "last_poll_at": self._last_poll_at,
                "poll_count": self._poll_count,
                "recovered_expired_leases": self._recovered_count,
                "error_code": self._error_code,
            }

    def start(self) -> dict[str, Any]:
        """Recover only expired leases, then expose RUNNING for polling."""
        with self._lock:
            if self._state is SupervisorState.RUNNING:
                return self.health()
            if self._state is SupervisorState.DRAINING:
                self._transition_locked(SupervisorState.STOPPED)
                return self.health()
            if self._state is not SupervisorState.STARTING:
                raise RuntimeError(f"supervisor cannot start from {self._state.value}")
            self._started_at = _utc_now()
            self._transition_locked(SupervisorState.RECOVERING)
        try:
            recover = getattr(self.worker, "recover_after_restart", None)
            recovered = recover() if callable(recover) else []
            with self._lock:
                self._recovered_count = len(recovered or ())
                if self._state is SupervisorState.DRAINING or self._stop_requested.is_set():
                    if self._state is SupervisorState.RECOVERING:
                        self._transition_locked(SupervisorState.DRAINING)
                    self._transition_locked(SupervisorState.STOPPED)
                else:
                    self._transition_locked(SupervisorState.RUNNING)
                return self.health()
        except Exception as exc:
            with self._lock:
                self._error_code = type(exc).__name__
                if self._state not in {SupervisorState.FAILED, SupervisorState.STOPPED}:
                    self._transition_locked(SupervisorState.FAILED)
                self._stop_requested.set()
            raise

    def request_stop(self) -> None:
        """Stop claiming new work; any current synchronous call is allowed to return."""
        self._stop_requested.set()
        with self._lock:
            if self._state in {SupervisorState.STARTING, SupervisorState.RECOVERING, SupervisorState.RUNNING}:
                self._transition_locked(SupervisorState.DRAINING)

    def run_once(self) -> Any:
        """Perform one bounded poll, preserving failure as FAILED."""
        if self.state is SupervisorState.STARTING:
            self.start()
        if self.state is not SupervisorState.RUNNING:
            raise RuntimeError(f"supervisor is not accepting polls: {self.state.value}")
        try:
            result = self.worker.run_once()
            with self._lock:
                self._last_poll_at = _utc_now()
                self._poll_count += 1
            return result
        except Exception as exc:
            with self._lock:
                self._error_code = type(exc).__name__
                if self._state in {SupervisorState.RUNNING, SupervisorState.DRAINING}:
                    self._transition_locked(SupervisorState.FAILED)
                self._stop_requested.set()
            raise

    def serve_forever(self, *, stop_event: threading.Event | None = None, max_iterations: int | None = None) -> dict[str, Any]:
        """Poll until signalled, bounded by max_iterations when used in tests."""
        if max_iterations is not None and max_iterations < 0:
            raise ValueError("max_iterations must be non-negative")
        iterations = 0
        try:
            self.start()
            while self.state is SupervisorState.RUNNING:
                if self._stop_requested.is_set() or (stop_event is not None and stop_event.is_set()):
                    self.request_stop()
                    break
                if max_iterations is not None and iterations >= max_iterations:
                    self.request_stop()
                    break
                result = self.run_once()
                iterations += 1
                if result is None and self.poll_interval_seconds:
                    self._stop_requested.wait(self.poll_interval_seconds)
        finally:
            stop = getattr(self.worker, "stop", None)
            stop_error: Exception | None = None
            if callable(stop):
                try:
                    stop()
                except Exception as exc:
                    stop_error = exc
            with self._lock:
                if stop_error is not None and self._state in {SupervisorState.RUNNING, SupervisorState.DRAINING}:
                    self._error_code = type(stop_error).__name__
                    self._transition_locked(SupervisorState.FAILED)
                if self._state is SupervisorState.RUNNING:
                    self._transition_locked(SupervisorState.DRAINING)
                if self._state is SupervisorState.DRAINING:
                    self._transition_locked(SupervisorState.STOPPED)
        return self.health()

    @contextmanager
    def install_signal_handlers(self) -> Iterator["RuntimeSupervisor"]:
        """Translate SIGINT/SIGTERM to a graceful drain (main thread only)."""
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("signal handlers must be installed from the main thread")
        signals = (signal.SIGINT, signal.SIGTERM)
        previous = {signum: signal.getsignal(signum) for signum in signals}

        def handle(signum: int, _frame: Any) -> None:
            self.request_stop()

        try:
            for signum in signals:
                signal.signal(signum, handle)
            yield self
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


__all__ = ["RuntimeSupervisor", "SupervisorState"]
