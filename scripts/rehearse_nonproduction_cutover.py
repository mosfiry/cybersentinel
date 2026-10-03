#!/usr/bin/env python3
"""Run the M3 cutover rehearsal against a disposable local Docker Compose project."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.m3_rehearsal.runner import RehearsalRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="write the secret-free JSON result to this path"
    )
    args = parser.parse_args(argv)
    result = RehearsalRunner(output_path=args.output).run()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
