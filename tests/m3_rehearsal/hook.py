"""Test-only guards for the isolated M3 cutover rehearsal.

This module is mounted read-only only by ``compose.m3-rehearsal.yaml``.
It must never be imported by the production application path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
import os
import time


STATE_ROOT = Path("/var/lib/cybersentinel")
CRASH_MARKER_NAME = ".m3-v16-crash-once"
DISPATCHED_MARKER_NAME = ".m3-v16-effect-dispatched"
RELEASE_MARKER_NAME = ".m3-v16-crash-release"
PROVIDER_MARKER_NAME = ".m3-v16-provider-violation"
CRASH_EXIT_CODE = 73
DEFAULT_LEASE_SECONDS = 5
DEFAULT_CRASH_WAIT_SECONDS = 45


class BlockedProviderRouter:
    """Fail closed on every provider call and leave an in-volume marker."""

    providers: tuple[Any, ...] = ()

    def __init__(self, marker_path: Path):
        self.marker_path = marker_path

    def _blocked(self, *_args: Any, **_kwargs: Any) -> Any:
        self.marker_path.write_text(
            "provider invocation forbidden in M3 rehearsal\n", encoding="utf-8"
        )
        raise RuntimeError("M3 non-production rehearsal forbids provider invocation")

    chat = _blocked
    tool_calling = _blocked
    generate = _blocked

    def status(self) -> list[Any]:
        return []


def _resolved(path: str | Path) -> Path:
    return Path(path).resolve(strict=False)


def validate_rehearsal_paths(
    *,
    state_root: str | Path,
    database_path: str | Path,
    crash_marker: str | Path,
    dispatched_marker: str | Path,
    release_marker: str | Path,
    provider_marker: str | Path,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    root = _resolved(state_root)
    database = _resolved(database_path)
    crash = _resolved(crash_marker)
    dispatched = _resolved(dispatched_marker)
    release = _resolved(release_marker)
    provider = _resolved(provider_marker)
    if root != STATE_ROOT:
        raise RuntimeError(
            "M3 rehearsal state root is not the expected container volume"
        )
    if root not in database.parents:
        raise RuntimeError(
            "M3 rehearsal database is outside the disposable state volume"
        )
    if crash.parent != root or crash.name != CRASH_MARKER_NAME:
        raise RuntimeError(
            "M3 rehearsal crash marker is outside its fixed state-volume path"
        )
    if dispatched.parent != root or dispatched.name != DISPATCHED_MARKER_NAME:
        raise RuntimeError(
            "M3 rehearsal dispatched marker is outside its fixed state-volume path"
        )
    if release.parent != root or release.name != RELEASE_MARKER_NAME:
        raise RuntimeError(
            "M3 rehearsal release marker is outside its fixed state-volume path"
        )
    if provider.parent != root or provider.name != PROVIDER_MARKER_NAME:
        raise RuntimeError(
            "M3 rehearsal provider marker is outside its fixed state-volume path"
        )
    return root, database, crash, dispatched, release, provider


def should_crash_after_dispatch(
    effect: Any,
    *,
    database_path: str | Path,
    state_root: str | Path,
    crash_marker: str | Path,
) -> bool:
    """Consume the one-shot marker only for the expected dispatched local watch."""
    root = _resolved(state_root)
    database = _resolved(database_path)
    marker = Path(crash_marker)
    if root != STATE_ROOT or root not in database.parents:
        raise RuntimeError(
            "M3 crash hook refused a database outside the disposable volume"
        )
    if (
        marker.is_symlink()
        or marker.parent.resolve(strict=False) != root
        or marker.name != CRASH_MARKER_NAME
    ):
        raise RuntimeError("M3 crash hook refused an unsafe marker path")
    if not marker.is_file():
        return False
    if getattr(effect, "provider", None) != "cybersentinel.local-state":
        return False
    if getattr(effect, "operation", None) != "watch":
        return False
    state = getattr(
        getattr(effect, "state", None), "value", getattr(effect, "state", None)
    )
    if state != "DISPATCHED":
        return False
    marker.unlink()
    return True


def wait_for_crash_release(
    *, state_root: str | Path, release_marker: str | Path, timeout_seconds: float
) -> bool:
    """Wait only for a bounded host release marker inside the state volume."""
    root = _resolved(state_root)
    marker = Path(release_marker)
    if (
        root != STATE_ROOT
        or marker.is_symlink()
        or marker.parent.resolve(strict=False) != root
        or marker.name != RELEASE_MARKER_NAME
    ):
        raise RuntimeError("M3 crash gate refused an unsafe release marker")
    if not 0 < timeout_seconds <= 60:
        raise ValueError("M3 crash wait must be between zero and sixty seconds")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if marker.is_file():
            marker.unlink()
            return True
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    return False


def wrap_worker_builder(
    builder: Callable[..., Any], *, lease_seconds: int
) -> Callable[..., Any]:
    if not 1 <= int(lease_seconds) <= 10:
        raise ValueError("M3 rehearsal lease must be between one and ten seconds")

    def build_mission_worker(*, worker_id: str = "worker") -> Any:
        worker = builder(worker_id=worker_id)
        worker.lease_seconds = int(lease_seconds)
        return worker

    return build_mission_worker


def install() -> None:
    """Install the provider and crash guards only in the explicit test overlay."""
    if os.environ.get("CYBERSENTINEL_M3_REHEARSAL") != "1":
        raise RuntimeError("M3 rehearsal hook requires explicit test-mode environment")
    state_root = Path(os.environ.get("CYBERSENTINEL_M3_STATE_ROOT", "")).resolve(
        strict=False
    )
    state_dir = Path(os.environ.get("CYBERSENTINEL_STATE_DIR", "")).resolve(
        strict=False
    )
    database_path = Path(os.environ.get("DB_PATH", "")).resolve(strict=False)
    lease_seconds = int(
        os.environ.get("CYBERSENTINEL_M3_LEASE_SECONDS", str(DEFAULT_LEASE_SECONDS))
    )
    crash_wait_seconds = float(
        os.environ.get(
            "CYBERSENTINEL_M3_CRASH_WAIT_SECONDS",
            str(DEFAULT_CRASH_WAIT_SECONDS),
        )
    )
    crash_marker = state_root / CRASH_MARKER_NAME
    dispatched_marker = state_root / DISPATCHED_MARKER_NAME
    release_marker = state_root / RELEASE_MARKER_NAME
    provider_marker = state_root / PROVIDER_MARKER_NAME
    root, database, crash, dispatched, release, provider = validate_rehearsal_paths(
        state_root=state_root,
        database_path=database_path,
        crash_marker=crash_marker,
        dispatched_marker=dispatched_marker,
        release_marker=release_marker,
        provider_marker=provider_marker,
    )
    if state_dir != root:
        raise RuntimeError(
            "M3 rehearsal state directory does not match its isolated volume"
        )
    if not 1 <= lease_seconds <= 10:
        raise RuntimeError("M3 rehearsal lease must be between one and ten seconds")
    if not 0 < crash_wait_seconds <= 60:
        raise RuntimeError(
            "M3 rehearsal crash wait must be between zero and sixty seconds"
        )

    import core.engine

    core.engine.RUNTIME.router = BlockedProviderRouter(provider)
    if tuple(core.engine.RUNTIME.router.providers) != ():
        raise RuntimeError("M3 rehearsal provider router is not empty")

    from agent.external_effects import ExternalEffectLedger

    original_mark_succeeded = ExternalEffectLedger.mark_succeeded

    def mark_succeeded(self: Any, effect_id: str, fence: Any, **kwargs: Any) -> Any:
        effect = self.get(effect_id)
        if effect is None:
            raise RuntimeError("M3 rehearsal crash hook could not read its effect")
        if should_crash_after_dispatch(
            effect,
            database_path=self.db_path,
            state_root=root,
            crash_marker=crash,
        ):
            if (
                dispatched.is_symlink()
                or dispatched.parent.resolve(strict=False) != root
            ):
                raise RuntimeError("M3 rehearsal dispatched marker path changed")
            dispatched.write_text(
                "local watch effect is DISPATCHED\n", encoding="utf-8"
            )
            if not wait_for_crash_release(
                state_root=root,
                release_marker=release,
                timeout_seconds=crash_wait_seconds,
            ):
                raise RuntimeError("M3 rehearsal host release timed out")
            os._exit(CRASH_EXIT_CODE)
        return original_mark_succeeded(self, effect_id, fence, **kwargs)

    ExternalEffectLedger.mark_succeeded = mark_succeeded

    # scripts.run_mission_worker imports this factory after sitecustomize runs.
    import bridge

    bridge.build_mission_worker = wrap_worker_builder(
        bridge.build_mission_worker,
        lease_seconds=lease_seconds,
    )
