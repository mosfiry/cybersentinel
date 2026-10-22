from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from scripts.acceptance_process_tree import run_owned_command, start_owned_process
from scripts.run_mcp_mission_acceptance import _stop_fixture


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertions")


def _active_process(pid: int) -> bool:
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        fields = stat_path.read_text(encoding="ascii").split()
    except FileNotFoundError:
        return False
    return len(fields) < 3 or fields[2] != "Z"


def _wait_for_pid(path: Path, timeout: float = 3.0) -> int:
    # Publication is a closed record followed by rename. A newline also rejects
    # empty/partial records if a writer ever regresses to in-place publication.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            record = path.read_text(encoding="ascii")
        except (FileNotFoundError, UnicodeDecodeError):
            record = ""
        digits = record[:-1]
        if record.endswith("\n") and digits.isascii() and digits.isdecimal() and int(digits) > 0:
            return int(digits)
        # This only paces polling; readiness is the validated record, not time.
        time.sleep(0.02)
    raise AssertionError("complete valid child PID record was not published")


def _pid_publication_code(path: Path) -> str:
    # Same-directory replace publishes only after write_text closes the file.
    return (
        "from pathlib import Path\n"
        f"pid_path = Path({str(path)!r})\n"
        "pending = pid_path.with_suffix('.pid.tmp')\n"
        "pending.write_text(str(child.pid) + '\\n', encoding='ascii')\n"
        "pending.replace(pid_path)\n"
    )


def test_pid_writer_publishes_only_closed_complete_record(tmp_path, monkeypatch):
    path = tmp_path / "atomic.pid"
    original_replace = Path.replace
    publications = []

    def pause_before_publication(pending, destination):
        assert destination == path
        assert not path.exists()
        assert pending.read_bytes() == b"12345\n"
        with monkeypatch.context() as clock_patch:
            ticks = iter([0.0, 0.1, 1.0])
            clock_patch.setattr(time, "monotonic", lambda: next(ticks))
            clock_patch.setattr(time, "sleep", lambda _interval: None)
            with pytest.raises(AssertionError, match="complete valid child PID record"):
                _wait_for_pid(path, timeout=0.5)
        publications.append(destination)
        return original_replace(pending, destination)

    monkeypatch.setattr(Path, "replace", pause_before_publication)
    exec(_pid_publication_code(path), {"child": SimpleNamespace(pid=12345)})
    assert publications == [path]
    assert _wait_for_pid(path) == 12345
    assert not path.with_suffix('.pid.tmp').exists()


def test_pid_reader_waits_for_complete_valid_record(tmp_path, monkeypatch):
    path = tmp_path / "staged.pid"
    path.write_bytes(b"")  # The old reader observes existence before publication.
    stages = iter([b"123", b"12345", b"12345\n"])
    observed = []

    def publish_next_chunk(_interval):
        observed.append(path.read_bytes())
        path.write_bytes(next(stages))

    monkeypatch.setattr(time, "sleep", publish_next_chunk)
    assert _wait_for_pid(path) == 12345
    assert observed == [b"", b"123", b"12345"]


@pytest.mark.parametrize("record", [b"", b"123", b"0\n", b"-1\n", b"12x\n", b"1\n2\n", b"\xff\n"])
def test_pid_reader_never_accepts_invalid_or_incomplete_record(tmp_path, monkeypatch, record):
    path = tmp_path / "invalid.pid"
    path.write_bytes(record)
    clock = iter([0.0, 0.1, 1.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(time, "sleep", lambda _interval: None)
    with pytest.raises(AssertionError, match="complete valid child PID record"):
        _wait_for_pid(path, timeout=0.5)


def test_fixture_stop_terminates_owned_process_group_and_removes_readiness_file(tmp_path):
    child_pid_file = tmp_path / "child.pid"
    ready = tmp_path / "fixture-ready.json"
    ready.write_text("{}", encoding="utf-8")
    child_script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
        + _pid_publication_code(child_pid_file)
        + "time.sleep(60)"
    )
    process = start_owned_process(
        [sys.executable, "-c", child_script],
        cwd=tmp_path,
    )
    try:
        child_pid = _wait_for_pid(child_pid_file)
        assert _stop_fixture(process, ready) is True
        deadline = time.monotonic() + 2.0
        while _active_process(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _active_process(child_pid)
        assert not ready.exists()
    finally:
        process.close()


def test_timed_out_owned_command_kills_descendants(tmp_path):
    child_pid_file = tmp_path / "timeout-child.pid"
    command = [
        sys.executable,
        "-c",
        (
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            + _pid_publication_code(child_pid_file)
            + "time.sleep(60)"
        ),
    ]
    with pytest.raises(subprocess.TimeoutExpired):
        run_owned_command(command, cwd=tmp_path, timeout_seconds=0.3)

    child_pid = _wait_for_pid(child_pid_file)
    deadline = time.monotonic() + 2.0
    while _active_process(child_pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _active_process(child_pid)
