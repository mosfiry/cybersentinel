from __future__ import annotations

import pytest


def require_live_process_sandbox() -> None:
    """Skip process-execution integration tests only when the real backend is unavailable."""
    from workspace.process_sandbox import get_process_sandbox_backend

    availability = get_process_sandbox_backend().availability()
    if not availability.available:
        detail = availability.detail_code or availability.reason_code or "unavailable"
        pytest.skip(
            f"requires a live process sandbox ({availability.backend}:{detail}); "
            "no sandbox backend is simulated by this test helper"
        )
