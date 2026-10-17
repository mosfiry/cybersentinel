from __future__ import annotations

"""Cross-process Mission dispatch gate for bounded external HTTP requests.

The gate is intentionally local-filesystem based. A Mission request holds the
shared request lock for its complete HTTP lifecycle and the send lock for each
socket write. Owner cancellation publishes an interrupt intent so transport
watchers can close active sockets, then commits the durable cancel marker under
the same send lock used by writers. The Owner's durable cancellation callback
runs only after the request has closed and released the request gate.
"""

from contextlib import contextmanager
import errno
import hashlib
import os
from pathlib import Path
import threading
import time
from typing import Any, Iterator


class DispatchGateCancelled(PermissionError):
    """Raised when a Mission HTTP request is fenced by Owner cancellation."""


_LOCAL_LOCKS: dict[str, threading.Lock] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()


def _local_lock_for(path: str) -> threading.Lock:
    with _LOCAL_LOCKS_GUARD:
        lock = _LOCAL_LOCKS.get(path)
        if lock is None:
            lock = threading.Lock()
            _LOCAL_LOCKS[path] = lock
        return lock


class DispatchCancelSignal:
    """Event-compatible view of a cross-process pending/cancelled marker."""

    def __init__(self, intent_path: Path, cancel_path: Path):
        self._intent_path = intent_path
        self._cancel_path = cancel_path

    def is_set(self) -> bool:
        # The intent marker is a cross-process interrupt signal, not the
        # linearization point. The durable cancel marker is written under the
        # per-send lock after any in-flight write exits.
        return os.path.lexists(self._intent_path) or os.path.lexists(self._cancel_path)


class MissionDispatchGate:
    """Serialize Mission HTTP requests with authenticated Owner cancellation.

    ``db_path`` must identify the MissionStore database shared by execution and
    cancellation processes. Normal request guards reject the durable pending
    marker. ``allow_cancelled=True`` is reserved for an already-authorized MCP
    cancellation notification after the Owner/Mission/Scope checks have run.
    """

    DEFAULT_TIMEOUT_SECONDS = 60.0
    MAX_TIMEOUT_SECONDS = 600.0

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        mission_id: str,
        *,
        cancellation_db_path: str | os.PathLike[str] | None = None,
    ):
        if not isinstance(mission_id, str) or not mission_id or len(mission_id) > 128:
            raise ValueError("Mission dispatch gate requires a bounded mission ID")
        if str(db_path).strip() == ":memory:":
            raise ValueError("Mission dispatch gate requires a durable shared database")
        database = Path(db_path).expanduser().resolve()
        if not database.name:
            raise ValueError("Mission dispatch gate requires a database path")
        self.mission_id = mission_id
        self.cancellation_db_path = (
            Path(cancellation_db_path).expanduser().resolve()
            if cancellation_db_path is not None
            else None
        )
        self.directory = database.parent / f".{database.name}.dispatch-gates"
        if self.directory.is_symlink():
            raise PermissionError("Mission dispatch gate directory cannot be a symlink")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise PermissionError("Mission dispatch gate directory cannot be a symlink")
        if not self.directory.is_dir():
            raise PermissionError("Mission dispatch gate directory is unavailable")
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            # Windows permissions are inherited from the protected app-data
            # parent; chmod is not a portable ACL management API.
            if os.name != "nt":
                raise

        key = hashlib.sha256(mission_id.encode("utf-8")).hexdigest()
        self.lock_path = self.directory / f"{key}.lock"
        self.send_lock_path = self.directory / f"{key}.send.lock"
        self.process_start_lock_path = self.directory / f"{key}.process-start.lock"
        self.owner_cancel_lock_path = self.directory / f"{key}.owner-cancel.lock"
        self.intent_path = self.directory / f"{key}.intent"
        self.cancel_path = self.directory / f"{key}.cancel"
        self.cancel_signal = DispatchCancelSignal(self.intent_path, self.cancel_path)
        self._local_lock = _local_lock_for(str(self.lock_path))
        self._send_local_lock = _local_lock_for(str(self.send_lock_path))
        self._process_start_local_lock = _local_lock_for(str(self.process_start_lock_path))
        self._owner_cancel_local_lock = _local_lock_for(str(self.owner_cancel_lock_path))

    @staticmethod
    def _try_os_lock(handle: Any) -> bool:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    return False
                raise
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    @staticmethod
    def _unlock_os_file(handle: Any) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _acquire_os_file(self, handle: Any, *, deadline: float) -> None:
        while True:
            if self._try_os_lock(handle):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Mission dispatch gate acquisition timed out")
            time.sleep(min(0.01, remaining))

    @contextmanager
    def _file_guard(
        self,
        path: Path,
        local_lock: threading.Lock,
        *,
        timeout: float | None = None,
    ) -> Iterator[None]:
        wait_seconds = self.DEFAULT_TIMEOUT_SECONDS if timeout is None else float(timeout)
        if not 0 < wait_seconds <= self.MAX_TIMEOUT_SECONDS:
            raise ValueError("Mission dispatch gate timeout is outside the allowed range")
        deadline = time.monotonic() + wait_seconds
        if not local_lock.acquire(timeout=wait_seconds):
            raise TimeoutError("Mission dispatch gate acquisition timed out")
        handle = None
        os_locked = False
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            handle = os.fdopen(fd, "r+b", buffering=0)
            if os.fstat(fd).st_size == 0:
                handle.write(b"\0")
                handle.flush()
            self._acquire_os_file(handle, deadline=deadline)
            os_locked = True
            yield
        finally:
            try:
                if os_locked and handle is not None:
                    self._unlock_os_file(handle)
            finally:
                if handle is not None:
                    handle.close()
                local_lock.release()

    def _owner_cancel_committed(self) -> bool | None:
        """Read the durable queue bit; unknown state must preserve the marker."""
        path = self.cancellation_db_path
        if path is None or not path.is_file():
            return None
        try:
            import sqlite3

            with sqlite3.connect(str(path), timeout=0.25) as db:
                row = db.execute(
                    "SELECT owner_cancel_requested FROM mission_queue WHERE mission_id=?",
                    (self.mission_id,),
                ).fetchone()
        except (OSError, sqlite3.Error):
            return None
        if row is None or type(row[0]) is not int or row[0] not in (0, 1):
            return None
        return bool(row[0])

    def _remove_cancel_markers(self) -> None:
        removed = False
        for marker in (self.cancel_path, self.intent_path):
            try:
                marker.unlink()
                removed = True
            except FileNotFoundError:
                pass
        if removed and os.name != "nt":
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def _reconcile_cancel_markers_locked(self) -> bool | None:
        """Caller holds owner_cancel_guard; clear only when durable state says not cancelled."""
        if not self.cancel_signal.is_set():
            return False
        committed = self._owner_cancel_committed()
        if committed is not False:
            return committed
        try:
            with self._file_guard(self.process_start_lock_path, self._process_start_local_lock):
                with self._file_guard(self.send_lock_path, self._send_local_lock):
                    # Recheck while both writer boundaries are excluded.
                    if self._owner_cancel_committed() is False:
                        self._remove_cancel_markers()
                        return False
        except TimeoutError as exc:
            raise DispatchGateCancelled("stale cancellation marker could not be reconciled") from exc
        return self._owner_cancel_committed()

    def reconcile_cancel_request(self) -> bool | None:
        """Reconcile markers while the caller holds ``owner_cancel_guard``.

        ``False`` means no durable cancellation is committed and stale markers
        were cleared; ``True`` means the queue bit is committed; ``None`` means
        the durable state is unavailable, so markers remain fail-closed.
        """
        return self._reconcile_cancel_markers_locked()

    def _reconcile_if_stale(self) -> None:
        if not self.cancel_signal.is_set():
            return
        try:
            with self.owner_cancel_guard(timeout=0.05):
                self._reconcile_cancel_markers_locked()
        except TimeoutError as exc:
            raise DispatchGateCancelled("Owner cancellation is being finalized") from exc

    @contextmanager
    def request_guard(
        self,
        *,
        allow_cancelled: bool = False,
        timeout: float | None = None,
    ) -> Iterator[None]:
        """Hold the local and OS lock through the complete HTTP request."""
        if not allow_cancelled:
            self._reconcile_if_stale()
        with self._file_guard(self.lock_path, self._local_lock, timeout=timeout):
            if self.cancel_signal.is_set() and not allow_cancelled:
                raise DispatchGateCancelled("Owner cancellation is pending for this Mission")
            yield

    @contextmanager
    def send_guard(
        self,
        *,
        allow_cancelled: bool = False,
        timeout: float | None = None,
    ) -> Iterator[None]:
        """Serialize one socket write against publication of the durable cancel marker."""
        if not allow_cancelled:
            self._reconcile_if_stale()
        with self._file_guard(self.send_lock_path, self._send_local_lock, timeout=timeout):
            if self.cancel_signal.is_set() and not allow_cancelled:
                raise DispatchGateCancelled("Owner cancellation is pending for this Mission")
            yield

    @contextmanager
    def process_start_guard(
        self,
        *,
        allow_cancelled: bool = False,
        timeout: float | None = None,
    ) -> Iterator[None]:
        """Serialize an OS process-start boundary against Owner cancellation."""
        if not allow_cancelled:
            self._reconcile_if_stale()
        with self._file_guard(
            self.process_start_lock_path,
            self._process_start_local_lock,
            timeout=timeout,
        ):
            if self.cancel_signal.is_set() and not allow_cancelled:
                raise DispatchGateCancelled("Owner cancellation is pending for this Mission")
            yield

    def request_cancel(self) -> bool:
        """Publish a fast interrupt signal, then linearize cancellation against socket writes."""
        intent_created = self._create_marker(self.intent_path, durable=False)
        with self._file_guard(self.process_start_lock_path, self._process_start_local_lock):
            with self._file_guard(self.send_lock_path, self._send_local_lock):
                cancel_created = self._create_marker(self.cancel_path, durable=True)
        return intent_created and cancel_created

    def clear_cancel_request(self, *, created_by_this_call: bool) -> None:
        """Remove only this attempt's marker when durable cancellation was refused."""
        if not created_by_this_call:
            return
        with self._file_guard(self.process_start_lock_path, self._process_start_local_lock):
            with self._file_guard(self.send_lock_path, self._send_local_lock):
                self._remove_cancel_markers()

    def _create_marker(self, path: Path, *, durable: bool) -> bool:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        try:
            os.write(fd, b"1")
            if durable:
                os.fsync(fd)
        finally:
            os.close(fd)
        if durable and os.name != "nt":
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return True

    @contextmanager
    def owner_cancel_guard(self, *, timeout: float | None = None) -> Iterator[None]:
        """Serialize the whole Owner-cancel attempt with crash-marker recovery."""
        with self._file_guard(
            self.owner_cancel_lock_path,
            self._owner_cancel_local_lock,
            timeout=timeout,
        ):
            yield

    @contextmanager
    def cancellation_guard(self, *, timeout: float | None = None) -> Iterator[None]:
        """Acquire the same cross-process gate while finalizing Owner cancellation."""
        with self.request_guard(
            allow_cancelled=True,
            timeout=timeout,
        ):
            yield
