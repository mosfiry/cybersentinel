"""Python startup shim mounted only by the V16 test Compose overlay."""

from __future__ import annotations

import sys

from hook import install

try:
    install()
except Exception as exc:
    print(
        "M3 isolated rehearsal hook initialization failed: " + type(exc).__name__,
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(97) from None
