from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time

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


def _wait_for_file(path: Path, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.02)
    raise AssertionError("child PID record was not created")


def test_fixture_stop_terminates_owned_process_group_and_removes_readiness_file(tmp_path):
    child_pid_file = tmp_path / "child.pid"
    ready = tmp_path / "fixture-ready.json"
    ready.write_text("{}", encoding="utf-8")
    child_script = (
        "import subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        f"open({str(child_pid_file)!r},'w').write(str(child.pid)); "
        "time.sleep(60)"
    )
    process = start_owned_process(
        [sys.executable, "-c", child_script],
        cwd=tmp_path,
    )
    try:
        _wait_for_file(child_pid_file)
        child_pid = int(child_pid_file.read_text(encoding="ascii"))
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
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            f"open({str(child_pid_file)!r},'w').write(str(child.pid)); "
            "time.sleep(60)"
        ),
    ]
    with pytest.raises(subprocess.TimeoutExpired):
        run_owned_command(command, cwd=tmp_path, timeout_seconds=0.3)

    _wait_for_file(child_pid_file)
    child_pid = int(child_pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2.0
    while _active_process(child_pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _active_process(child_pid)
