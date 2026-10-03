"""Run the CyberSentinel durable mission worker as a supervised process.

Start from the repository root with ``python -m scripts.run_mission_worker``.
The process uses the existing local configuration and SQLite paths; it does
not create a cloud resource or deploy itself.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from agent.runtime_supervisor import RuntimeSupervisor, SupervisorState
from bridge import build_mission_worker


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the supervised CyberSentinel mission worker")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="seconds between idle queue polls")
    parser.add_argument("--max-polls", type=int, default=None, help="optional bounded poll count (for rehearsal)")
    parser.add_argument("--worker-id", default="worker", help="stable logical worker identity; use a distinct value for each concurrent process")
    args = parser.parse_args(argv)
    if args.poll_interval < 0 or (args.max_polls is not None and args.max_polls < 0):
        parser.error("poll interval and max polls must be non-negative")
    if not args.worker_id.strip() or len(args.worker_id) > 128:
        parser.error("worker ID must contain 1 to 128 non-whitespace characters")

    supervisor = RuntimeSupervisor(build_mission_worker(worker_id=args.worker_id), poll_interval_seconds=args.poll_interval)
    try:
        with supervisor.install_signal_handlers():
            print(json.dumps({"event": "worker_starting", **supervisor.health()}, sort_keys=True), flush=True)
            supervisor.start()
            print(json.dumps({"event": "worker_state", **supervisor.health()}, sort_keys=True), flush=True)
            supervisor.serve_forever(max_iterations=args.max_polls)
    except Exception as exc:
        print(json.dumps({"event": "worker_failed", **supervisor.health(), "error_type": type(exc).__name__}, sort_keys=True), file=sys.stderr, flush=True)
        return 1
    print(json.dumps({"event": "worker_stopped", **supervisor.health()}, sort_keys=True), flush=True)
    return 0 if supervisor.state is SupervisorState.STOPPED else 1


if __name__ == "__main__":
    raise SystemExit(main())
