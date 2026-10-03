from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


HOOK_DIR = Path(__file__).resolve().parent / "m3_rehearsal"
sys.path.insert(0, str(HOOK_DIR))
import hook  # noqa: E402


def _sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path]:
    state_root = tmp_path / "var" / "lib" / "cybersentinel"
    state_root.mkdir(parents=True)
    monkeypatch.setattr(hook, "STATE_ROOT", state_root)
    database = state_root / "intel.db"
    database.touch()
    marker = state_root / hook.CRASH_MARKER_NAME
    return state_root, database, marker


def test_path_validation_accepts_only_fixed_markers_inside_state_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, database, crash_marker = _sandbox(tmp_path, monkeypatch)
    provider_marker = state_root / hook.PROVIDER_MARKER_NAME

    assert hook.validate_rehearsal_paths(
        state_root=state_root,
        database_path=database,
        crash_marker=crash_marker,
        provider_marker=provider_marker,
    ) == (state_root, database, crash_marker, provider_marker)
    with pytest.raises(RuntimeError, match="provider marker is outside"):
        hook.validate_rehearsal_paths(
            state_root=state_root,
            database_path=database,
            crash_marker=crash_marker,
            provider_marker=tmp_path / "provider-violation",
        )


def test_crash_is_one_shot_after_exact_dispatched_local_watch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, database, marker = _sandbox(tmp_path, monkeypatch)
    marker.write_text("one shot\n", encoding="utf-8")
    effect = SimpleNamespace(
        provider="cybersentinel.local-state", operation="watch", state="DISPATCHED"
    )

    assert (
        hook.should_crash_after_dispatch(
            effect,
            database_path=database,
            state_root=state_root,
            crash_marker=marker,
        )
        is True
    )
    assert not marker.exists()
    assert (
        hook.should_crash_after_dispatch(
            effect,
            database_path=database,
            state_root=state_root,
            crash_marker=marker,
        )
        is False
    )


@pytest.mark.parametrize(
    "effect",
    [
        SimpleNamespace(
            provider="remote.provider", operation="watch", state="DISPATCHED"
        ),
        SimpleNamespace(
            provider="cybersentinel.local-state", operation="delete", state="DISPATCHED"
        ),
        SimpleNamespace(
            provider="cybersentinel.local-state", operation="watch", state="SUCCEEDED"
        ),
    ],
)
def test_wrong_provider_operation_or_state_never_crashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    effect: SimpleNamespace,
) -> None:
    state_root, database, marker = _sandbox(tmp_path, monkeypatch)
    marker.write_text("one shot\n", encoding="utf-8")

    assert (
        hook.should_crash_after_dispatch(
            effect,
            database_path=database,
            state_root=state_root,
            crash_marker=marker,
        )
        is False
    )
    assert marker.is_file()


def test_crash_hook_refuses_database_outside_state_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, _database, marker = _sandbox(tmp_path, monkeypatch)
    marker.write_text("one shot\n", encoding="utf-8")
    outside_database = tmp_path / "outside.sqlite3"
    outside_database.touch()
    effect = SimpleNamespace(
        provider="cybersentinel.local-state", operation="watch", state="DISPATCHED"
    )

    with pytest.raises(RuntimeError, match="outside the disposable volume"):
        hook.should_crash_after_dispatch(
            effect,
            database_path=outside_database,
            state_root=state_root,
            crash_marker=marker,
        )
    assert marker.is_file()


def test_crash_hook_refuses_symlink_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, database, marker = _sandbox(tmp_path, monkeypatch)
    outside_marker = tmp_path / "outside-marker"
    outside_marker.write_text("must not be consumed\n", encoding="utf-8")
    marker.symlink_to(outside_marker)
    effect = SimpleNamespace(
        provider="cybersentinel.local-state", operation="watch", state="DISPATCHED"
    )

    with pytest.raises(RuntimeError, match="unsafe marker path"):
        hook.should_crash_after_dispatch(
            effect,
            database_path=database,
            state_root=state_root,
            crash_marker=marker,
        )
    assert outside_marker.is_file()


@pytest.mark.parametrize(
    ("method_name", "arguments"),
    [
        ("chat", ([{"role": "user", "content": "blocked"}],)),
        ("tool_calling", ([{"role": "user", "content": "blocked"}], [])),
        ("generate", ([{"role": "user", "content": "blocked"}],)),
    ],
)
def test_blocked_provider_router_marks_attempt_and_fails_closed(
    tmp_path: Path, method_name: str, arguments: tuple[object, ...]
) -> None:
    marker = tmp_path / hook.PROVIDER_MARKER_NAME
    router = hook.BlockedProviderRouter(marker)

    assert router.providers == ()
    assert router.status() == []
    with pytest.raises(RuntimeError, match="forbids provider invocation"):
        getattr(router, method_name)(*arguments)
    assert marker.is_file()


def test_worker_builder_uses_only_bounded_test_lease() -> None:
    class Worker:
        lease_seconds = 120

    def build(*, worker_id: str) -> Worker:
        assert worker_id == "cybersentinel-worker"
        return Worker()

    rehearsal_builder = hook.wrap_worker_builder(build, lease_seconds=5)
    worker = rehearsal_builder(worker_id="cybersentinel-worker")
    assert worker.lease_seconds == 5
    assert Worker.lease_seconds == 120

    with pytest.raises(ValueError, match="between one and ten"):
        hook.wrap_worker_builder(build, lease_seconds=11)


def test_hook_installation_requires_explicit_test_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CYBERSENTINEL_M3_REHEARSAL", raising=False)
    with pytest.raises(RuntimeError, match="explicit test-mode"):
        hook.install()
