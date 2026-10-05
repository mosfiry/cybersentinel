#!/usr/bin/env python3
"""Compatibility entry point for the Windows real-local-model acceptance run."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    if os.name != "nt":
        print(json.dumps({"status": "NOT_RUN", "reason": "windows_only_entry_point; use local_model_acceptance.py for Linux"}, indent=2))
        raise SystemExit(2)
    from scripts.local_model_acceptance import main

    raise SystemExit(main())
