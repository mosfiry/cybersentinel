from __future__ import annotations

from types import SimpleNamespace

import pytest

import scripts.acceptance_process_tree as process_tree


@pytest.mark.parametrize(
    "timeout_seconds",
    (
        True,
        0.0,
        -1.0,
        float("inf"),
        float("-inf"),
        float("nan"),
        process_tree.MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS + 0.01,
        1e300,
    ),
)
def test_run_owned_command_rejects_timeout_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    timeout_seconds: float | bool,
) -> None:
    starts: list[tuple[object, object]] = []

    def fake_start(command, **kwargs):
        starts.append((command, kwargs))
        raise AssertionError("process start must not be reached")

    monkeypatch.setattr(process_tree, "start_owned_process", fake_start)

    with pytest.raises(ValueError, match="acceptance_process_timeout_invalid"):
        process_tree.run_owned_command(
            ["test-command"],
            cwd=tmp_path,
            timeout_seconds=timeout_seconds,
        )

    assert starts == []


def test_run_owned_command_accepts_existing_30_second_limit_and_short_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    events: list[tuple[str, float | None]] = []

    class FakeProcess:
        def wait(self, *, timeout: float) -> int:
            events.append(("wait", timeout))
            return 0

        def close(self) -> bool:
            events.append(("close", process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS))
            return True

    def fake_start(_command, **_kwargs):
        events.append(("start", None))
        return FakeProcess()

    monkeypatch.setattr(process_tree, "start_owned_process", fake_start)

    result = process_tree.run_owned_command(
        ["test-command"],
        cwd=tmp_path,
        timeout_seconds=process_tree.MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS,
    )

    assert result == 0
    assert events == [
        ("start", None),
        ("wait", 30.0),
        ("close", process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS),
    ]


def test_run_owned_command_timeout_closes_once_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    events: list[tuple[str, float | None]] = []

    class FakeProcess:
        def wait(self, *, timeout: float) -> int:
            events.append(("wait", timeout))
            raise process_tree.subprocess.TimeoutExpired(["test-command"], timeout)

        def close(self) -> bool:
            events.append(("close", process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS))
            return True

    def fake_start(_command, **_kwargs):
        events.append(("start", None))
        return FakeProcess()

    monkeypatch.setattr(process_tree, "start_owned_process", fake_start)

    with pytest.raises(process_tree.subprocess.TimeoutExpired):
        process_tree.run_owned_command(
            ["test-command"],
            cwd=tmp_path,
            timeout_seconds=process_tree.MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS,
        )

    assert events == [
        ("start", None),
        ("wait", process_tree.MAX_ACCEPTANCE_COMMAND_TIMEOUT_SECONDS),
        ("close", process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS),
    ]


def test_acceptance_wait_without_timeout_uses_300_second_bound() -> None:
    class FakeProcess:
        pid = 1234
        timeout: float | None = None

        def wait(self, *, timeout: float) -> int:
            self.timeout = timeout
            return 0

    process = FakeProcess()
    owned = process_tree._PosixOwnedProcess(process)

    assert owned.wait() == 0
    assert process.timeout == process_tree.MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS


def test_windows_acceptance_wait_without_timeout_uses_300_second_bound() -> None:
    class FakeJob:
        timeout: float | None = None

        def wait_current(self, timeout_seconds: float) -> bool:
            self.timeout = timeout_seconds
            return True

        def exit_code_current(self) -> int:
            return 0

    job = FakeJob()
    owned = process_tree._WindowsOwnedProcess(job, SimpleNamespace(process_id=5678))

    assert owned.wait() == 0
    assert job.timeout == process_tree.MAX_ACCEPTANCE_PROCESS_TIMEOUT_SECONDS


def test_posix_cleanup_fallbacks_share_one_five_second_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClock:
        now = 10.0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.now += seconds

    clock = FakeClock()
    monkeypatch.setattr(process_tree.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(process_tree.time, "sleep", clock.sleep)
    monkeypatch.setattr(process_tree, "signal", SimpleNamespace(SIGKILL=9, SIGTERM=15))

    class FakeCgroupScope:
        timeouts: list[float]

        def __init__(self) -> None:
            self.timeouts = []

        def cleanup(self, *, kill_if_populated: bool, timeout: float) -> None:
            assert kill_if_populated is True
            self.timeouts.append(timeout)
            if len(self.timeouts) == 1:
                clock.now += 1.0
            raise RuntimeError("cgroup cleanup did not finish")

    class FakeProcess:
        pid = 4321
        wait_timeouts: list[float]

        def __init__(self) -> None:
            self.wait_timeouts = []

        def wait(self, *, timeout: float) -> int:
            self.wait_timeouts.append(timeout)
            clock.now += 2.0 if len(self.wait_timeouts) == 1 else timeout
            raise process_tree.subprocess.TimeoutExpired(["owned-process"], timeout)

        def poll(self) -> None:
            return None

    cgroup = FakeCgroupScope()
    process = FakeProcess()
    owned = process_tree._PosixOwnedProcess(process, cgroup_scope=cgroup)
    signals: list[int] = []
    monkeypatch.setattr(owned, "_signal_group", lambda sig: signals.append(sig))
    monkeypatch.setattr(owned, "_group_exists", lambda: True)

    assert owned.terminate_tree(timeout_seconds=5.0) is False
    assert cgroup.timeouts == pytest.approx([5.0, 4.0])
    assert process.wait_timeouts == pytest.approx([4.0, 2.0])
    assert clock.now == pytest.approx(15.0)
    assert len(signals) == 2


def test_windows_acceptance_cleanup_timeout_is_capped_at_five_seconds() -> None:
    class FakeJob:
        timeout: float | None = None
        closed = False

        def terminate_owned_job(self, *, timeout_seconds: float) -> dict[str, bool]:
            self.timeout = timeout_seconds
            return {"termination_succeeded": True}

        def close(self) -> None:
            self.closed = True

    job = FakeJob()
    owned = process_tree._WindowsOwnedProcess(job, SimpleNamespace(process_id=5678))

    assert owned.terminate_tree(timeout_seconds=3600.0) is True
    assert job.timeout == process_tree.MAX_ACCEPTANCE_CLEANUP_TIMEOUT_SECONDS
    assert job.closed is True
