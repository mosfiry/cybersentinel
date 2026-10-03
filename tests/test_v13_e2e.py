from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "v13_scenario_runner.py"


_SITECUSTOMIZE = r'''from __future__ import annotations
import os
from pathlib import Path

state_root = Path(os.environ["CYBERSENTINEL_V13_STATE_ROOT"]).resolve()
provider_marker = Path(os.environ["CYBERSENTINEL_V13_PROVIDER_MARKER"]).resolve()

class _BlockedProviderRouter:
    providers = ()
    def _blocked(self, *_args, **_kwargs):
        provider_marker.parent.mkdir(parents=True, exist_ok=True)
        provider_marker.write_text("provider invocation forbidden in V13", encoding="utf-8")
        raise RuntimeError("V13 provider invocation forbidden")
    chat = _blocked
    tool_calling = _blocked
    generate = _blocked
    def status(self):
        return {"models": [], "provider_count": 0}

try:
    import core.engine
    core.engine.RUNTIME.router = _BlockedProviderRouter()
    if tuple(core.engine.RUNTIME.router.providers) != ():
        raise RuntimeError("provider router is not empty")

    if os.environ.get("CYBERSENTINEL_V13_CRASH_AFTER_WATCH") == "1":
        import os as _os
        from pathlib import Path as _Path
        from agent.external_effects import ExternalEffectLedger
        _original_mark_succeeded = ExternalEffectLedger.mark_succeeded
        def _crash_after_local_watch(self, effect_id, fence, **kwargs):
            ledger_path = _Path(self.db_path).resolve()
            if state_root not in ledger_path.parents:
                raise RuntimeError("crash hook refused a database outside tmp state")
            effect = self.get(effect_id)
            if effect is None:
                raise RuntimeError("crash hook could not read its effect")
            state = getattr(effect.state, "value", effect.state)
            if effect.provider == "cybersentinel.local-state" and effect.operation == "watch":
                if state != "DISPATCHED":
                    raise RuntimeError("crash hook expected a dispatched local watch effect")
                _os._exit(73)
            return _original_mark_succeeded(self, effect_id, fence, **kwargs)
        ExternalEffectLedger.mark_succeeded = _crash_after_local_watch

    pause_worker_id = os.environ.get("CYBERSENTINEL_V13_PAUSE_WORKER_ID", "")
    if pause_worker_id:
        import time
        from agent.mission_worker import MissionWorker

        _original_run_once = MissionWorker.run_once
        def _barrier_before_first_poll(self, *args, **kwargs):
            if self.worker_id == pause_worker_id and not getattr(self, "_v13_barrier_waited", False):
                self._v13_barrier_waited = True
                generation = str(self.runtime_generation)
                release = state_root / "worker-releases" / generation
                attempted = state_root / "worker-attempts" / generation
                deadline = time.monotonic() + 30
                while not release.is_file():
                    if time.monotonic() >= deadline:
                        raise RuntimeError("V13 worker barrier timed out")
                    time.sleep(0.01)
                try:
                    return _original_run_once(self, *args, **kwargs)
                finally:
                    attempted.parent.mkdir(parents=True, exist_ok=True)
                    attempted.write_text("attempted", encoding="utf-8")
            return _original_run_once(self, *args, **kwargs)
        MissionWorker.run_once = _barrier_before_first_poll
except BaseException as exc:
    import sys
    print("V13 isolated test hook initialization failed: " + type(exc).__name__, file=sys.stderr, flush=True)
    raise SystemExit(97)
'''


def _run_scenario(tmp_path: Path, scenario: str) -> dict:
    state_root = tmp_path / "isolated-state"
    state_root.mkdir(parents=True, exist_ok=True)
    home = state_root / "home"
    home.mkdir(parents=True, exist_ok=True)
    site_dir = tmp_path / "site"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "sitecustomize.py").write_text(_SITECUSTOMIZE, encoding="utf-8")
    provider_marker = state_root / "provider-call-forbidden.marker"
    bridge_token = secrets.token_urlsafe(36)

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(state_root),
        "PYTHONPATH": os.pathsep.join((str(site_dir), str(ROOT))),
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
        "BRIDGE_TOKEN": bridge_token,
        "PUBLIC_WEB_ENABLED": "false",
        "LLM_BASE_URL": "",
        "LLM_API_KEY": "",
        "LLM_MODEL": "",
        "CYBERSENTINEL_V13_NO_PROVIDERS": "1",
        "CYBERSENTINEL_V13_CRASH_AFTER_WATCH": "0",
        "CYBERSENTINEL_V13_STATE_ROOT": str(state_root),
        "CYBERSENTINEL_V13_PROVIDER_MARKER": str(provider_marker),
    }
    result = subprocess.run(
        [sys.executable, str(RUNNER), scenario],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"V13 scenario {scenario!r} failed with exit {result.returncode}.\n"
            f"stdout tail:\n{result.stdout[-4000:]}\n"
            f"stderr tail:\n{result.stderr[-4000:]}"
        )
    if provider_marker.exists():
        pytest.fail(f"V13 scenario {scenario!r} attempted to invoke a provider")
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        pytest.fail(f"V13 scenario {scenario!r} emitted no JSON result: {type(exc).__name__}")
    assert payload.get("ok") is True, payload
    assert payload.get("integrity", {}).get("mission_integrity_hash_present") is True
    assert payload.get("integrity", {}).get("trajectory_chain_valid") is True
    assert payload.get("integrity", {}).get("evidence_chain_valid") is True
    assert payload.get("integrity", {}).get("evidence_chain_count") is True
    assert len(str(payload.get("finding", {}).get("evidence_hash", ""))) == 64
    assert (state_root / "finding_claim.json").is_file()
    return payload


def test_v13_reproducible_live_owner_mission_lifecycle(tmp_path: Path) -> None:
    first = _run_scenario(tmp_path / "first", "happy")
    second = _run_scenario(tmp_path / "second", "happy")
    assert first["canonical_projection"] == second["canonical_projection"]
    projection = first["canonical_projection"]
    assert projection["mission_status"] == "GOAL_COMPLETED"
    assert projection["finding_result"] == "PASS"
    assert projection["queue"]["attempts"] == 1
    assert projection["queue"]["state"] == "completed"
    assert projection["watch_present_once"] is True
    assert projection["expired_session_boundary"] == {
        "expired_start_status": 403,
        "expired_read_status": 403,
        "queue_absent_after_denial": True,
        "fresh_login_succeeded": True,
    }


def test_v13_worker_crash_ambiguous_effect_restart_and_owner_approval(tmp_path: Path) -> None:
    result = _run_scenario(tmp_path, "crash")
    projection = result["canonical_projection"]
    assert projection["mission_status"] == "GOAL_COMPLETED"
    assert projection["finding_result"] == "PASS"
    assert projection["crash_recovery"]["quarantined"] is True
    assert projection["crash_recovery"]["generation_after_crash"] == 2
    assert projection["crash_recovery"]["queue_attempts_after_resume"] == 2
    assert projection["crash_recovery"]["owner_reconciliation_http_status"] == 200
    assert projection["crash_recovery"]["owner_resolution"] == "OWNER_CONFIRMED_APPLIED"
    assert projection["crash_recovery"]["owner_approval_event_count"] == 1
    assert projection["crash_recovery"]["dispatch_event_count"] == 1
    assert projection["crash_recovery"]["unique_watch_effect"] is True
    assert projection["watch_present_once"] is True


def test_v13_stale_worker_generation_cannot_dispatch(tmp_path: Path) -> None:
    result = _run_scenario(tmp_path, "stale")
    projection = result["canonical_projection"]
    assert projection["mission_status"] == "GOAL_COMPLETED"
    assert projection["queue"]["attempts"] == 1
    assert projection["workers"]["v13-worker"][0]["generation"] == 1
    assert projection["workers"]["v13-worker"][1]["generation"] == 2
    assert all(item["runtime_generation"] == 2 for item in projection["effect_projection"])
    assert all(item["worker_id"] == "v13-worker" for item in projection["effect_projection"])
    assert projection["stale_attempt"]["queue_attempts_before_replacement_release"] == 0
    assert projection["stale_attempt"]["effect_count_before_replacement_release"] == 0
    assert projection["watch_present_once"] is True


def test_v13_concurrent_workers_claim_and_apply_once(tmp_path: Path) -> None:
    result = _run_scenario(tmp_path, "concurrent")
    projection = result["canonical_projection"]
    assert projection["mission_status"] == "GOAL_COMPLETED"
    assert projection["queue"]["attempts"] == 1
    assert all(item["runtime_generation"] == 1 for item in projection["effect_projection"])
    assert len({item["worker_id"] for item in projection["effect_projection"]}) == 1
    assert projection["watch_present_once"] is True
    assert len([item for item in projection["effect_projection"] if item["operation"] == "watch"]) == 1
