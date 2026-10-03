from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest

from test_v13_e2e import _SITECUSTOMIZE


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "v9_scenario_runner.py"


def _run_v9_scenario(tmp_path: Path, scenario: str) -> dict:
    state_root = tmp_path / "isolated-state"
    state_root.mkdir(parents=True, exist_ok=True)
    home = state_root / "home"
    home.mkdir(parents=True, exist_ok=True)
    site_dir = tmp_path / "site"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="utf-8")
    provider_marker = state_root / "provider-call-forbidden.marker"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(state_root),
        "PYTHONPATH": os.pathsep.join((str(site_dir), str(ROOT / "tests"), str(ROOT))),
        "PYTHON_DOTENV_DISABLED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "DB_PATH": str(state_root / "db" / "runtime.sqlite3"),
        "OWNER_POLICY_STATE_PATH": str(state_root / "owner-policy.json"),
        "SCOPE_DB_PATH": str(state_root / "scope.sqlite3"),
        "TASK_DB_PATH": str(state_root / "tasks.sqlite3"),
        "MEMORY_DB_PATH": str(state_root / "memory.sqlite3"),
        "BRIDGE_HOST": "127.0.0.1",
        "BRIDGE_PORT": "0",
        "BRIDGE_TOKEN": secrets.token_urlsafe(36),
        "PUBLIC_WEB_ENABLED": "false",
        "LLM_BASE_URL": "",
        "LLM_API_KEY": "",
        "LLM_MODEL": "",
        "CYBERSENTINEL_V13_NO_PROVIDERS": "1",
        "CYBERSENTINEL_V13_CRASH_AFTER_WATCH": "0",
        "CYBERSENTINEL_V13_STATE_ROOT": str(state_root),
        "CYBERSENTINEL_V13_PROVIDER_MARKER": str(provider_marker),
    }
    completed = subprocess.run(
        [sys.executable, str(RUNNER), scenario],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"V9 {scenario!r} scenario failed with exit {completed.returncode}.\n"
            f"stdout tail:\n{completed.stdout[-4000:]}\n"
            f"stderr tail:\n{completed.stderr[-4000:]}"
        )
    if provider_marker.exists():
        pytest.fail("the application-global provider router was unexpectedly invoked")
    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        pytest.fail(f"V9 scenario emitted no JSON result: {type(exc).__name__}")
    assert payload.get("ok") is True, payload
    return payload


@pytest.mark.parametrize("scenario", ["happy", "crash"])
def test_v9_provider_mission_report_and_crash_recovery(tmp_path: Path, scenario: str) -> None:
    payload = _run_v9_scenario(tmp_path, scenario)

    assert payload["provider"] == {
        "name": "v9-loopback-fixture",
        "model": "v9-local-fixture",
        "transport": "OpenAI-compatible HTTP on 127.0.0.1",
        "request_count": 1,
    }
    assert payload["canonical_projection"]["mission_status"] == "GOAL_COMPLETED"
    assert payload["canonical_projection"]["finding_result"] == "PASS"
    assert payload["finding"]["result"] == "PASS"
    assert len(payload["finding"]["evidence_hash"]) == 64
    assert payload["report"] == {
        "mission_status": "GOAL_COMPLETED",
        "outcome": "VERIFIED",
        "verified": True,
        "finding_count": 2,
        "execution_chain_integrity": "VALID",
        "owner_approval_status": "RECORDED",
    }
    assert all(payload["integrity"].values())

    if scenario == "happy":
        assert payload["canonical_projection"]["queue"]["state"] == "completed"
        assert payload["canonical_projection"]["queue"]["attempts"] == 1
        assert payload["canonical_projection"]["watch_present_once"] is True
    else:
        recovery = payload["canonical_projection"]["crash_recovery"]
        assert recovery["quarantined"] is True
        assert recovery["generation_after_crash"] == 2
        assert recovery["owner_reconciliation_http_status"] == 200
        assert recovery["owner_resolution"] == "OWNER_CONFIRMED_APPLIED"
        assert recovery["owner_approval_event_count"] == 1
        assert recovery["dispatch_event_count"] == 1
        assert recovery["unique_watch_effect"] is True
        assert payload["canonical_projection"]["watch_present_once"] is True
