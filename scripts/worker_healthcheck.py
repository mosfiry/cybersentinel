from __future__ import annotations

from pathlib import Path

EXPECTED_WORKER_ARGV = (
    b"python",
    b"-m",
    b"scripts.run_mission_worker",
    b"--worker-id",
    b"cybersentinel-worker",
    b"--poll-interval",
    b"1",
)
LIVE_PROCESS_STATES = {"R", "S", "D"}


def is_expected_worker_running(proc_root: Path = Path("/proc")) -> bool:
    """Return true only for the configured live worker directly owned by PID 1."""
    try:
        child_pids = (proc_root / "1/task/1/children").read_text(encoding="ascii").split()
    except OSError:
        return False

    for child_pid in child_pids:
        if not child_pid.isdecimal():
            continue
        child = proc_root / child_pid
        try:
            argv = [arg for arg in (child / "cmdline").read_bytes().split(b"\0") if arg]
            stat_line = (child / "stat").read_text(encoding="ascii")
        except OSError:
            continue

        # /proc/<pid>/stat's comm field may contain spaces or parentheses.
        closing_paren = stat_line.rfind(")")
        if closing_paren < 0:
            continue
        stat_fields = stat_line[closing_paren + 1 :].split()
        if not stat_fields or stat_fields[0] not in LIVE_PROCESS_STATES:
            continue
        if tuple(argv) == EXPECTED_WORKER_ARGV:
            return True
    return False


def main() -> int:
    return 0 if is_expected_worker_running() else 1


if __name__ == "__main__":
    raise SystemExit(main())
