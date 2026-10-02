from __future__ import annotations

from math import isfinite
from pathlib import Path
from threading import Event, Lock, Thread, current_thread

from .mission_worker import MissionWorker, QueueItem


_ACTIVE_LOCK = Lock()
_ACTIVE_SUPERVISORS: dict[tuple[str, str], "MissionSupervisor"] = {}


class MissionSupervisor:
    """Explicit, stoppable lifecycle for repeatedly invoking a MissionWorker.

    Constructing or importing this module never starts work. Call ``start`` from
    a deliberately managed application lifecycle and ``stop`` during shutdown.
    A worker invocation is allowed to finish before graceful stop returns; the
    supervisor never acknowledges or rewrites a queue item itself.
    """

    def __init__(
        self,
        worker: MissionWorker,
        *,
        poll_interval: float = 0.1,
        max_backoff: float = 5.0,
        thread_name: str | None = None,
    ) -> None:
        if not isfinite(poll_interval) or poll_interval <= 0:
            raise ValueError("poll_interval must be finite and positive")
        if not isfinite(max_backoff) or max_backoff < poll_interval:
            raise ValueError("max_backoff must be greater than or equal to poll_interval")
        if not worker.worker_id.strip():
            raise ValueError("worker_id required")

        self.worker = worker
        self.poll_interval = float(poll_interval)
        self.max_backoff = float(max_backoff)
        self.thread_name = thread_name or f"mission-supervisor-{worker.worker_id}"
        self._registry_key = (str(Path(worker.queue.db_path).resolve()), worker.worker_id)
        self._lifecycle_lock = Lock()
        self._stop_event: Event | None = None
        self._thread: Thread | None = None
        self._last_exception: BaseException | None = None
        self._last_result: QueueItem | None = None
        self._poll_count = 0
        self._current_backoff = self.poll_interval
        self._state_lock = Lock()

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    @property
    def last_exception(self) -> BaseException | None:
        """The most recent loop failure; UNKNOWN/recovery failures stay observable."""
        with self._state_lock:
            return self._last_exception

    @property
    def last_error(self) -> str | None:
        error = self.last_exception
        return f"{type(error).__name__}: {error}" if error is not None else None

    @property
    def last_result(self) -> QueueItem | None:
        """Most recent claimed item's result; idle polls do not erase it."""
        with self._state_lock:
            return self._last_result

    @property
    def poll_count(self) -> int:
        with self._state_lock:
            return self._poll_count

    @property
    def current_backoff(self) -> float:
        with self._state_lock:
            return self._current_backoff

    def start(self) -> None:
        """Start one background loop; repeated or conflicting starts are rejected."""
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("mission supervisor is already running")
            with _ACTIVE_LOCK:
                active = _ACTIVE_SUPERVISORS.get(self._registry_key)
                if active is not None:
                    raise RuntimeError(
                        "a supervisor with this SQLite authority and worker_id is already running in this process"
                    )
                _ACTIVE_SUPERVISORS[self._registry_key] = self
            stop_event = Event()
            thread = Thread(target=self._run, args=(stop_event,), name=self.thread_name, daemon=True)
            self._stop_event = stop_event
            self._thread = thread
            try:
                thread.start()
            except BaseException:
                with _ACTIVE_LOCK:
                    if _ACTIVE_SUPERVISORS.get(self._registry_key) is self:
                        del _ACTIVE_SUPERVISORS[self._registry_key]
                self._thread = None
                self._stop_event = None
                raise

    def stop(self, timeout: float | None = None) -> bool:
        """Request graceful stop and join; return False if a worker call is still running.

        A timeout does not interrupt the active worker or alter/ack its queue row.
        Call ``stop`` again after the active invocation has completed if it returns
        False.
        """
        if timeout is not None and (not isfinite(timeout) or timeout < 0):
            raise ValueError("timeout must be finite and non-negative")
        with self._lifecycle_lock:
            thread = self._thread
            stop_event = self._stop_event
            if thread is None or not thread.is_alive():
                return True
            if stop_event is not None:
                stop_event.set()
        if thread is not current_thread():
            thread.join(timeout)
        return not thread.is_alive()

    def _record_exception(self, exc: BaseException) -> None:
        with self._state_lock:
            self._last_exception = exc

    def _record_result(self, result: QueueItem | None) -> None:
        with self._state_lock:
            self._poll_count += 1
            if result is not None:
                self._last_result = result

    def _record_backoff(self, delay: float) -> None:
        with self._state_lock:
            self._current_backoff = delay

    def _run(self, stop_event: Event) -> None:
        delay = self.poll_interval
        try:
            while not stop_event.is_set():
                try:
                    # Reap expired leases only. Clearing every active lease at
                    # each process start could steal a live competing worker's claim.
                    self.worker.queue.recover_expired()
                    result = self.worker.run_once()
                except Exception as exc:
                    # The supervisor records and backs off; it never converts an
                    # exception (especially an ambiguous effect) into a queue ack.
                    self._record_exception(exc)
                    if stop_event.wait(delay):
                        break
                    delay = min(self.max_backoff, delay * 2)
                    self._record_backoff(delay)
                    continue
                except BaseException as exc:
                    # Treat process-like exits as fatal to this loop, leaving the
                    # durable lease/intent for restart recovery rather than acking.
                    self._record_exception(exc)
                    break

                self._record_result(result)
                if result is None:
                    wait_for = delay
                    delay = min(self.max_backoff, delay * 2)
                    self._record_backoff(delay)
                else:
                    wait_for = self.poll_interval
                    delay = self.poll_interval
                    self._record_backoff(delay)
                if stop_event.wait(wait_for):
                    break
        finally:
            with _ACTIVE_LOCK:
                if _ACTIVE_SUPERVISORS.get(self._registry_key) is self:
                    del _ACTIVE_SUPERVISORS[self._registry_key]


__all__ = ["MissionSupervisor"]
