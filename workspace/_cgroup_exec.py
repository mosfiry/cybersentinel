"""Trusted Linux cgroup trampoline; invoked only by LinuxBubblewrapBackend."""
from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        return 126
    procs_path = sys.argv[1]
    command = sys.argv[3:]
    if not command or not os.path.isabs(procs_path):
        return 126
    try:
        # The helper is trusted. The untrusted bwrap/test command cannot run
        # until this PID has entered the per-execution cgroup.
        with open(procs_path, "w", encoding="ascii") as stream:
            stream.write(str(os.getpid()))
        os.execvpe(command[0], command, os.environ)
    except BaseException:
        return 127
    return 127


if __name__ == "__main__":
    os._exit(main())
