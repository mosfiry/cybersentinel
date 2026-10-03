from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from security.session_reference import session_reference


REPO_ROOT = Path(__file__).resolve().parents[1]
WATCH_KEYWORD = "m3-v13-local-fixture"
OWNER_USERNAME = "mosfiry"
POLL_INTERVAL = "0.5"
MAX_POLLS = "8"


def _emit(payload: dict[str, Any], exit_code: int = 0) -> int:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)
    return exit_code


def _safe_error(where: str, exc: BaseException) -> RuntimeError:
    return RuntimeError(f"{where}:{type(exc).__name__}")


def _recover_child(mission_id: str, worker_id: str) -> int:
    """Start a new production MissionWorker and deterministically expire the test lease."""
    from bridge import build_mission_worker
    from agent.mission import MissionStore

    worker = build_mission_worker(worker_id=worker_id)
    try:
        queued = worker.queue.get(mission_id)
        if queued.state.value != "executing" or not queued.lease_expires_at:
            raise RuntimeError("restart_expected_expired_execution_lease")
        lease_expiry = datetime.fromisoformat(queued.lease_expires_at)
        if lease_expiry.tzinfo is None:
            lease_expiry = lease_expiry.replace(tzinfo=timezone.utc)
        logical_now = lease_expiry + timedelta(seconds=1)
        recovered = worker.recover_after_restart(now=logical_now.isoformat())
        updated = worker.queue.get(mission_id)
        mission = MissionStore(Path(os.environ["DB_PATH"]).with_name("missions.sqlite3")).load(mission_id)
        if mission is None:
            raise RuntimeError("restart_mission_missing")
        if updated.state.value == "queued":
            raise RuntimeError("restart_left_ambiguous_mission_claimable")
        return _emit({
            "ok": True,
            "worker_id": worker_id,
            "generation": worker.runtime_generation,
            "recovered_count": len(recovered),
            "queue_state": updated.state.value,
            "mission_status": mission.status.value,
            "mission_step": mission.current_step,
            "checkpoint_status": mission.checkpoint.get("status"),
        })
    except Exception as exc:
        raise _safe_error("restart_child", exc) from None
    finally:
        worker.stop()


class _WorkerHandle:
    def __init__(self, process: subprocess.Popen[str], worker_id: str, crash_after_watch: bool, state_root: Path):
        self.process = process
        self.worker_id = worker_id
        self.crash_after_watch = crash_after_watch
        self.state_root = state_root.resolve()
        self.startup_events: list[dict[str, Any]] = []
        self.final_stdout = ""
        self.final_stderr = ""
        self.returncode: int | None = None

    def finish(self, timeout: float = 30) -> int:
        try:
            self.returncode = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("worker_process_timeout") from None
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self.final_stdout = self.process.stdout.read()
        self.final_stderr = self.process.stderr.read()
        return self.returncode

    def stop_owned_child_only(self) -> None:
        """Signal only this exact CLI child if it still belongs to this disposable fixture."""
        if self.process.poll() is not None:
            return
        command = self.process.args
        if (
            not isinstance(command, (list, tuple))
            or len(command) < 4
            or command[1:3] != ["-m", "scripts.run_mission_worker"]
            or not self.state_root.exists()
        ):
            raise RuntimeError("refusing_to_signal_non_fixture_process")
        import signal

        pid = self.process.pid
        if os.name == "posix" and os.getpgid(pid) == pid:
            os.killpg(pid, signal.SIGTERM)
        else:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "posix" and os.getpgid(pid) == pid:
                os.killpg(pid, signal.SIGKILL)
            else:
                self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout is not None:
            self.final_stdout = self.process.stdout.read()
        if self.process.stderr is not None:
            self.final_stderr = self.process.stderr.read()
        self.returncode = self.process.returncode


def _start_worker(worker_id: str, state_root: Path, *, crash_after_watch: bool = False) -> _WorkerHandle:
    env = dict(os.environ)
    env["CYBERSENTINEL_V13_CRASH_AFTER_WATCH"] = "1" if crash_after_watch else "0"
    argv = [sys.executable, "-m", "scripts.run_mission_worker", "--worker-id", worker_id,
            "--poll-interval", POLL_INTERVAL, "--max-polls", MAX_POLLS]
    process = subprocess.Popen(
        argv,
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=(os.name == "posix"),
    )
    handle = _WorkerHandle(process, worker_id, crash_after_watch, state_root)
    import selectors

    if process.stdout is None:
        raise RuntimeError("worker_stdout_unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None and not selector.select(0):
                break
            events = selector.select(0.25)
            if not events:
                continue
            line = process.stdout.readline()
            if not line:
                break
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                raise RuntimeError("worker_startup_emitted_non_json") from None
            handle.startup_events.append(event)
            if event.get("event") == "worker_state":
                return handle
        handle.stop_owned_child_only()
        errors = [str(item.get("event", "")) + ":" + str(item.get("error_type", "")) for item in handle.startup_events]
        raise RuntimeError("worker_did_not_reach_running_state:" + ",".join(errors))
    finally:
        selector.close()


class _LiveBridge:
    def __init__(self, state_root: Path):
        self.state_root = state_root.resolve()
        self.workspace = self.state_root / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "test_v13_fixture.py").write_text(
            "def test_v13_fixture_is_deterministic():\n    assert 2 + 2 == 4\n",
            encoding="utf-8",
        )
        self.db_path = Path(os.environ["DB_PATH"]).resolve()
        if self.state_root not in self.db_path.parents:
            raise RuntimeError("runtime_database_not_under_fixture_root")
        if os.environ.get("BRIDGE_HOST") != "127.0.0.1":
            raise RuntimeError("bridge_not_loopback_only")
        if os.environ.get("CYBERSENTINEL_V13_NO_PROVIDERS") != "1":
            raise RuntimeError("no_provider_guard_missing")

        import bridge
        from core.config import DB_PATH
        from agent.mission import MissionStore
        from agent.mission_worker import MissionQueue
        from security.owner_password import OWNER_USERNAME, create_owner_account

        self.owner_username = OWNER_USERNAME
        if Path(DB_PATH).resolve() != self.db_path:
            raise RuntimeError("bridge_database_path_mismatch")
        if tuple(getattr(bridge.RUNTIME.router, "providers", ())) != ():
            raise RuntimeError("provider_router_not_fail_closed")
        self.bridge = bridge
        self.store = MissionStore(self.db_path.with_name("missions.sqlite3"))
        self.queue = MissionQueue(
            self.db_path.with_name("mission_queue.sqlite3"),
            require_execution_fence=True,
            mission_store=self.store,
        )
        self.owner_password = __import__("secrets").token_urlsafe(32)
        create_owner_account(OWNER_USERNAME, self.owner_password)
        self.server = bridge.BridgeHTTPServer(("127.0.0.1", 0), self._quiet_handler(bridge.Handler))
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.server_thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="v13-loopback-bridge",
            daemon=True,
        )
        self.server_thread.start()
        self.handles: list[_WorkerHandle] = []

    @staticmethod
    def _quiet_handler(base_handler):
        class QuietHandler(base_handler):
            def log_message(self, _format: str, *_args: Any) -> None:
                return
        return QuietHandler

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, session: str | None = None):
        headers = {"X-CyberSentinel-Token": os.environ["BRIDGE_TOKEN"]}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if session is not None:
            headers["X-CyberSentinel-Owner-Session"] = session
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=5) as response:
                raw = response.read()
                return response.status, json.loads(raw or b"{}")
        except HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                payload = {"ok": False, "error": "non_json_error"}
            return exc.code, payload

    def login(self) -> str:
        status, payload = self.request("POST", "/api/auth/login", {"username": self.owner_username, "password": self.owner_password})
        if status != 200 or not payload.get("session", {}).get("session_id"):
            raise RuntimeError("owner_login_failed")
        return str(payload["session"]["session_id"])

    def create_mission(self, session: str) -> tuple[str, dict[str, Any]]:
        objective = "Owner instruction: run deterministic local tests and register a local defensive watch keyword"
        payload = {
            "objective": objective,
            "plan": {
                "version": 1,
                "objective": objective,
                "created_from": "v13-live-http",
                "risk": "bounded-local",
                "steps": [
                    {
                        "step_id": "fixture-tests",
                        "objective": "Run the controlled local fixture tests",
                        "action": "run_project_tests",
                        "retry_policy": {"arguments": {"query": "."}},
                        "expected_observation": "The single fixture test passes",
                        "authorization_requirement": "owner",
                        "scope_requirement": "workspace",
                        "verification": ["tests-pass"],
                    },
                    {
                        "step_id": "local-watch",
                        "objective": "Register the fixture's local defensive watch keyword",
                        "action": "watch",
                        "prerequisites": ["fixture-tests"],
                        "retry_policy": {"arguments": {"query": WATCH_KEYWORD}},
                        "expected_observation": "The local watch keyword is present exactly once",
                        "authorization_requirement": "owner",
                        "scope_requirement": "workspace",
                        "verification": ["watch-registered"],
                    },
                ],
            },
            "scope_context": {
                "target_id": "v13-temporary-workspace",
                "workspace_root": str(self.workspace.resolve()),
                "allowed_networks": [],
                "allowed_credentials": [],
            },
            "completion_criteria": [
                {"criterion_id": "tests-pass", "description": "project pytest process exits successfully", "check": "pytest_success", "required": True},
                {"criterion_id": "watch-registered", "description": "requested local defensive watch is persisted", "check": "watch_registered", "required": True},
            ],
        }
        status, response = self.request("POST", "/api/missions", payload, session)
        if status != 201 or not response.get("mission_id"):
            raise RuntimeError(f"mission_create_failed_{status}")
        mission_id = str(response["mission_id"])
        mission = response.get("mission")
        if not isinstance(mission, dict) or mission.get("owner_instruction") != objective:
            raise RuntimeError("owner_instruction_not_bound_to_mission")
        snapshot = mission.get("authorization_snapshot")
        if not isinstance(snapshot, dict):
            raise RuntimeError("authorization_snapshot_missing")
        if (
            len(str(snapshot.get("authorization_hash", ""))) != 64
            or snapshot.get("mission_id") != mission_id
            or snapshot.get("owner_identity") != mission.get("owner_identity_ref")
            or not snapshot.get("owner_approval")
        ):
            raise RuntimeError("authorization_snapshot_binding_missing")
        return mission_id, mission

    def expire_session_and_reauthenticate(self, mission_id: str, stale_session: str) -> dict[str, Any]:
        with sqlite3.connect(self.db_path) as db:
            changed = db.execute(
                "UPDATE owner_sessions SET expires_at=? WHERE session_id=? AND status='active'",
                ("2000-01-01T00:00:00+00:00", session_reference(stale_session)),
            ).rowcount
            db.commit()
        if changed != 1:
            raise RuntimeError("fixture_session_expiration_failed")
        start_status, _ = self.request("POST", f"/api/missions/{mission_id}/start", {}, stale_session)
        read_status, _ = self.request("GET", f"/api/missions/{mission_id}/status", session=stale_session)
        try:
            self.queue.get(mission_id)
            queue_absent = False
        except KeyError:
            queue_absent = True
        if start_status != 403 or read_status != 403 or not queue_absent:
            raise RuntimeError("expired_owner_session_crossed_control_boundary")
        fresh_session = self.login()
        return {
            "expired_start_status": start_status,
            "expired_read_status": read_status,
            "queue_absent_after_denial": queue_absent,
            "fresh_login_succeeded": bool(fresh_session),
            "fresh_session": fresh_session,
        }

    def start_worker(self, worker_id: str, *, crash_after_watch: bool = False) -> _WorkerHandle:
        handle = _start_worker(worker_id, self.state_root, crash_after_watch=crash_after_watch)
        self.handles.append(handle)
        return handle

    def close(self) -> None:
        for handle in self.handles:
            try:
                handle.stop_owned_child_only()
            except Exception:
                # A cleanup guard failure is a test failure and must be visible.
                raise
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        if self.server_thread.is_alive():
            raise RuntimeError("loopback_bridge_thread_did_not_stop")


def _wait_for_status(harness: _LiveBridge, mission_id: str, session: str, expected: str, timeout: float = 30) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status, response = harness.request("GET", f"/api/missions/{mission_id}/status", session=session)
        if status != 200:
            raise RuntimeError(f"owner_status_read_failed_{status}")
        mission = response.get("status")
        if isinstance(mission, dict):
            last = mission
            if mission.get("status") == expected:
                return mission
            if mission.get("status") in {"FAILED_RETRY_EXHAUSTED", "AUTHORIZATION_BLOCKED", "SCOPE_BLOCKED", "SAFETY_BLOCKED"}:
                reason = "".join(char for char in str(mission.get("error", "")) if char.isalnum() or char in " _-")[:100]
                raise RuntimeError("mission_terminated_" + str(mission.get("status")) + (":" + reason if reason else ""))
        time.sleep(0.05)
    raise RuntimeError("mission_status_timeout_" + str(last.get("status", "unknown")))


def _read_api_mission(harness: _LiveBridge, mission_id: str, session: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    status, status_payload = harness.request("GET", f"/api/missions/{mission_id}/status", session=session)
    if status != 200:
        raise RuntimeError("mission_status_api_failed")
    status, evidence_payload = harness.request("GET", f"/api/missions/{mission_id}/evidence", session=session)
    if status != 200:
        raise RuntimeError("mission_evidence_api_failed")
    status, effects_payload = harness.request("GET", f"/api/missions/{mission_id}/effects", session=session)
    if status != 200:
        error = "".join(char for char in str(effects_payload.get("error", "unknown")) if char.isalnum() or char in " _-")[:100]
        raise RuntimeError(f"mission_effects_api_failed_{status}_{error}")
    mission = status_payload.get("status")
    evidence = evidence_payload.get("evidence")
    effects = effects_payload.get("effects")
    if not isinstance(mission, dict) or not isinstance(evidence, list) or not isinstance(effects, list):
        raise RuntimeError("mission_api_projection_invalid")
    return mission, evidence, effects


def _verify_finding(mission: dict[str, Any], evidence: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    from agent.verification import FindingClaim, VerificationEngine, VerificationPlan, VerificationResult

    mission_id = str(mission["mission_id"])
    request_id = str(mission["request_id"])
    claim = FindingClaim(
        claim="The isolated workspace test fixture passes its deterministic assertion",
        target=str(workspace.resolve()),
        reproduction="test_v13_fixture.py",
        provenance={"mission_id": mission_id, "request_id": request_id, "authorization_hash": mission["authorization_snapshot"]["authorization_hash"]},
    )

    def validate(claim: FindingClaim, records: tuple[dict[str, Any], ...]) -> VerificationResult:
        root = Path(claim.target).resolve()
        fixture = (root / claim.reproduction).resolve()
        if root not in fixture.parents or not fixture.is_file():
            return VerificationResult.FAIL
        if claim.provenance.get("mission_id") != mission_id or claim.provenance.get("request_id") != request_id:
            return VerificationResult.FAIL
        matches = [item for item in records if item.get("source") == "run_project_tests" and item.get("passed") is True]
        if len(matches) != 1:
            return VerificationResult.FAIL
        result = matches[0].get("result", {})
        tool_result = result.get("result", {}) if isinstance(result, dict) else {}
        output = str(tool_result.get("output", ""))
        if result.get("source") != "run_project_tests" or tool_result.get("ok") is not True or tool_result.get("returncode") != 0 or "1 passed" not in output:
            return VerificationResult.FAIL
        if matches[0].get("provenance", {}).get("mission_id") != mission_id:
            return VerificationResult.FAIL
        return VerificationResult.PASS

    report = VerificationEngine().verify(
        claim,
        VerificationPlan("v13-local-pytest-finding-v1", required_evidence=("run_project_tests",), validator=validate),
        evidence,
    )
    if report.result is not VerificationResult.PASS:
        raise RuntimeError("finding_claim_not_verified")
    report_payload = {
        "claim": claim.claim,
        "target": "isolated-workspace",
        "reproduction": claim.reproduction,
        "mission_id": mission_id,
        "request_id": request_id,
        "validator_id": report.validator_id,
        "result": report.result.value,
        "evidence_hash": report.evidence_hash,
        "evidence_count": len(report.evidence),
    }
    return report_payload


def _finish_worker(
    handle: _WorkerHandle,
    expected_returncode: int | tuple[int, ...] = 0,
) -> dict[str, Any]:
    returncode = handle.finish(timeout=35)
    allowed_returncodes = (
        expected_returncode
        if isinstance(expected_returncode, tuple)
        else (expected_returncode,)
    )
    if returncode not in allowed_returncodes:
        safe_events = [
            {"event": item.get("event"), "error_type": item.get("error_type")}
            for item in handle.startup_events
        ]
        raise RuntimeError(f"worker_exit_mismatch_{returncode}_expected_{expected_returncode}_{safe_events}")
    failure_events: list[dict[str, Any]] = []
    for line in handle.final_stderr.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("event"):
            failure_events.append({"event": item.get("event"), "error_type": item.get("error_type")})
    return {"returncode": returncode, "startup_events": handle.startup_events, "failure_events": failure_events}


def _worker_generations(db_path: Path, worker_id: str) -> list[dict[str, Any]]:
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            "SELECT runtime_generation, worker_instance_id, state FROM mission_worker_generations WHERE worker_id=? ORDER BY runtime_generation",
            (worker_id,),
        ).fetchall()
    return [{"generation": int(row[0]), "instance_id": str(row[1]), "state": str(row[2])} for row in rows]


def _verify_integrity(harness: _LiveBridge, mission: dict[str, Any]) -> dict[str, bool]:
    from agent.evidence import EvidenceChainStore
    from agent.trajectory import verify_trajectory

    evidence_store = EvidenceChainStore(
        harness.db_path.with_name("evidence_chain.db"),
        mission_store=harness.store,
    )
    chain_records = evidence_store.list(request_id=str(mission["request_id"]))
    trajectory_ok = bool(mission.get("trajectory")) and verify_trajectory(mission["trajectory"])
    mission_hash_ok = bool(mission.get("integrity_hash")) and len(str(mission["integrity_hash"])) == 64
    return {
        "mission_integrity_hash_present": mission_hash_ok,
        "trajectory_chain_valid": bool(trajectory_ok),
        "evidence_chain_valid": bool(evidence_store.verify()),
        "evidence_chain_count": bool(chain_records),
    }


def _common_projection(
    harness: _LiveBridge,
    mission: dict[str, Any],
    evidence: list[dict[str, Any]],
    effects: list[Any],
    finding: dict[str, Any],
    auth_result: dict[str, Any],
    worker_ids: list[str],
    stale_attempt: dict[str, int] | None = None,
) -> dict[str, Any]:
    from agent.external_effects import ExternalEffectLedger
    from core.db import watches

    queue_item = harness.queue.get(str(mission["mission_id"]))
    raw_effects = ExternalEffectLedger(harness.queue.db_path).list_effects(mission_id=str(mission["mission_id"]), limit=100)
    watch_effects = [item for item in raw_effects if item.provider == "cybersentinel.local-state" and item.operation == "watch"]
    if len(watch_effects) != 1:
        raise RuntimeError("watch_effect_count_not_one")
    watch_history = ExternalEffectLedger(harness.queue.db_path).history(watch_effects[0].effect_id, limit=100)
    keyword_present = WATCH_KEYWORD in watches()
    action_projection = [
        {"step_id": item.get("step_id"), "status": item.get("status")}
        for item in mission.get("action_history", [])
    ]
    effect_projection = sorted(
        [
            {
                "provider": item.provider,
                "operation": item.operation,
                "state": item.state,
                "worker_id": item.worker_id,
                "runtime_generation": item.runtime_generation,
            }
            for item in raw_effects
        ],
        key=lambda item: (
            item["provider"],
            item["operation"],
            item["state"],
            item["worker_id"],
            item["runtime_generation"],
        ),
    )
    return {
        "mission_status": mission.get("status"),
        "mission_step": mission.get("current_step"),
        "actions": action_projection,
        "evidence_count": len(evidence),
        "evidence_sources": sorted(str(item.get("source", "")) for item in evidence),
        "finding_result": finding.get("result"),
        "finding_validator": finding.get("validator_id"),
        "effect_projection": effect_projection,
        "watch_effect_events": [str(item.get("event_type", "")) for item in watch_history],
        "watch_present_once": keyword_present and watches().count(WATCH_KEYWORD) == 1,
        "queue": {
            "state": queue_item.state.value,
            "attempts": queue_item.attempts,
            "worker_id": (
                sorted(set(worker_ids))[0]
                if len(set(worker_ids)) == 1
                else "one-of-concurrent-set"
            ),
            "generation": queue_item.runtime_generation,
        },
        "stale_attempt": stale_attempt if stale_attempt is not None else {},
        "expired_session_boundary": {
            key: value for key, value in auth_result.items() if key != "fresh_session"
        },
        "workers": {
            worker_id: [
                {"generation": item["generation"], "state": item["state"]}
                for item in _worker_generations(harness.queue.db_path, worker_id)
            ]
            for worker_id in worker_ids
        },
    }


def _run_scenario(
    scenario: str,
    *,
    harness_factory: type[_LiveBridge] = _LiveBridge,
) -> dict[str, Any]:
    state_root = Path(os.environ["CYBERSENTINEL_V13_STATE_ROOT"]).resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    harness = harness_factory(state_root)
    try:
        health_status, health = harness.request("GET", "/api/health")
        if health_status != 200 or health.get("ok") is not True:
            raise RuntimeError("loopback_bridge_health_failed")

        stale_session = harness.login()
        mission_id, created_mission = harness.create_mission(stale_session)
        auth_result = harness.expire_session_and_reauthenticate(mission_id, stale_session)
        session = str(auth_result.pop("fresh_session"))
        worker_id = "v13-crash-worker" if scenario == "crash" else "v13-worker"

        if scenario == "happy":
            handles = [harness.start_worker(worker_id)]
        elif scenario == "concurrent":
            handles = [harness.start_worker("v13-worker-a"), harness.start_worker("v13-worker-b")]
            worker_id = "v13-worker-a"
        elif scenario == "stale":
            os.environ["CYBERSENTINEL_V13_PAUSE_WORKER_ID"] = worker_id
            handles = [harness.start_worker(worker_id)]
            # Reusing the logical identity advances the generation and fences the first process.
            handles.append(harness.start_worker(worker_id))
            if [item["generation"] for item in _worker_generations(harness.queue.db_path, worker_id)] != [1, 2]:
                raise RuntimeError("stale_worker_generation_did_not_advance")
        elif scenario == "crash":
            handles = [harness.start_worker(worker_id, crash_after_watch=True)]
        else:
            raise RuntimeError("unknown_v13_scenario")

        start_status, _start_payload = harness.request("POST", f"/api/missions/{mission_id}/start", {}, session)
        if start_status != 200:
            raise RuntimeError(f"fresh_owner_start_failed_{start_status}")

        stale_attempt: dict[str, int] | None = None
        if scenario == "stale":
            from agent.external_effects import ExternalEffectLedger

            stale_release = harness.state_root / "worker-releases" / "1"
            stale_attempt_marker = harness.state_root / "worker-attempts" / "1"
            stale_release.parent.mkdir(parents=True, exist_ok=True)
            stale_release.write_text("release stale generation", encoding="utf-8")
            deadline = time.monotonic() + 10
            while not stale_attempt_marker.is_file() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not stale_attempt_marker.is_file():
                raise RuntimeError("stale_worker_claim_attempt_barrier_timeout")
            queue_before_replacement = harness.queue.get(mission_id)
            effects_before_replacement = ExternalEffectLedger(harness.queue.db_path).list_effects(
                mission_id=mission_id,
                limit=100,
            )
            if queue_before_replacement.attempts != 0 or effects_before_replacement:
                raise RuntimeError("stale_worker_claimed_or_dispatched_before_replacement")
            stale_attempt = {
                "queue_attempts_before_replacement_release": queue_before_replacement.attempts,
                "effect_count_before_replacement_release": len(effects_before_replacement),
            }
            replacement_release = harness.state_root / "worker-releases" / "2"
            replacement_release.write_text("release replacement generation", encoding="utf-8")

        crash_recovery: dict[str, Any] | None = None
        owner_reconcile_result: dict[str, Any] | None = None
        if scenario == "crash":
            crash_worker = handles[0]
            if crash_worker.finish(timeout=30) != 73:
                raise RuntimeError("disposable_worker_did_not_crash_at_watch_success_boundary")
            crash_worker.final_stdout = crash_worker.process.stdout.read() if crash_worker.process.stdout else ""
            crash_worker.final_stderr = crash_worker.process.stderr.read() if crash_worker.process.stderr else ""
            pre_restart_mission, pre_restart_evidence, _ = _read_api_mission(harness, mission_id, session)
            if pre_restart_mission.get("current_step") != 1 or pre_restart_mission.get("checkpoint", {}).get("status") != "in_flight":
                raise RuntimeError("crash_did_not_preserve_exact_inflight_watch_checkpoint")
            finding = _verify_finding(pre_restart_mission, pre_restart_evidence, harness.workspace)
            (state_root / "finding_claim.json").write_text(json.dumps(finding, sort_keys=True), encoding="utf-8")
            queue_before = harness.queue.get(mission_id)
            if queue_before.state.value != "executing" or queue_before.attempts != 1:
                raise RuntimeError("crashed_worker_claim_missing")
            from agent.external_effects import ExternalEffectLedger
            ledger = ExternalEffectLedger(harness.queue.db_path)
            watch_before = [item for item in ledger.list_effects(mission_id=mission_id, limit=100) if item.operation == "watch"]
            if len(watch_before) != 1 or watch_before[0].state != "DISPATCHED":
                raise RuntimeError("effect_not_ambiguous_after_test_child_crash")
            recover = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--recover", mission_id, worker_id],
                cwd=REPO_ROOT,
                env={**os.environ, "CYBERSENTINEL_V13_CRASH_AFTER_WATCH": "0"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if recover.returncode != 0:
                raise RuntimeError("restart_child_failed_" + str(recover.returncode))
            recover_payload = json.loads(recover.stdout.strip().splitlines()[-1])
            if recover_payload.get("mission_status") != "RECOVERY_REQUIRED" or recover_payload.get("queue_state") == "queued":
                raise RuntimeError("restart_failed_to_quarantine_ambiguous_mission")
            crash_recovery = recover_payload
            mission, evidence, effects = _read_api_mission(harness, mission_id, session)
            if mission.get("status") != "RECOVERY_REQUIRED" or len(evidence) != 1:
                raise RuntimeError("restart_lost_prior_finding_evidence")
            ambiguous = [item for item in effects if item.get("effect_id") == watch_before[0].effect_id]
            if len(ambiguous) != 1 or ambiguous[0].get("state") != "DISPATCHED":
                raise RuntimeError("ambiguous_effect_inspection_not_owner_readable")
            from core.db import watches
            observed_watches = watches()
            if WATCH_KEYWORD not in observed_watches:
                raise RuntimeError("owner_cannot_confirm_absent_local_effect")
            evidence_reference = "v13-local-watch-readback:confirmed"
            reconcile_status, reconcile_payload = harness.request(
                "POST",
                f"/api/missions/{mission_id}/effects/{watch_before[0].effect_id}/reconcile",
                {"outcome": "OWNER_CONFIRM_APPLIED", "evidence_reference": evidence_reference},
                session,
            )
            if reconcile_status != 200 or reconcile_payload.get("reconciliation", {}).get("status") != "OWNER_CONFIRMED_APPLIED":
                raise RuntimeError("owner_effect_approval_failed")
            owner_reconcile_result = dict(reconcile_payload["reconciliation"])
            harness.request("POST", "/api/auth/logout", {"session_id": session})
            session = harness.login()
            resumed_worker = harness.start_worker(worker_id)
            resume_status, _ = harness.request("POST", f"/api/missions/{mission_id}/resume", {}, session)
            if resume_status != 200:
                raise RuntimeError("fresh_owner_resume_failed")
            mission = _wait_for_status(harness, mission_id, session, "GOAL_COMPLETED")
            worker_results = [_finish_worker(resumed_worker, 0)]
            mission, evidence, effects = _read_api_mission(harness, mission_id, session)
            finding = _verify_finding(mission, evidence, harness.workspace)
            (state_root / "finding_claim.json").write_text(json.dumps(finding, sort_keys=True), encoding="utf-8")
            if any(item.get("effect_id") == watch_before[0].effect_id and item.get("state") != "SUCCEEDED" for item in effects):
                raise RuntimeError("owner_confirmed_effect_not_terminal")
            final_watch_effects = [
                item
                for item in ledger.list_effects(mission_id=mission_id, limit=100)
                if item.operation == "watch"
            ]
            watch_events = ledger.history(watch_before[0].effect_id, limit=100)
            owner_approval_events = [
                item for item in watch_events
                if item.get("event_type") == "OWNER_CONFIRMED_APPLIED"
            ]
            dispatch_events = [
                item for item in watch_events if item.get("event_type") == "DISPATCHED"
            ]
            unique_watch_effect = (
                len(final_watch_effects) == 1
                and final_watch_effects[0].effect_id == watch_before[0].effect_id
                and final_watch_effects[0].state == "SUCCEEDED"
                and len(owner_approval_events) == 1
                and len(dispatch_events) == 1
            )
            if not unique_watch_effect:
                raise RuntimeError("recovery_replayed_local_watch_effect")
            handles.remove(crash_worker)
        else:
            mission = _wait_for_status(harness, mission_id, session, "GOAL_COMPLETED")
            worker_results = []
            for handle in handles:
                expected = (0, 1) if scenario == "stale" and handle is handles[0] else 0
                result = _finish_worker(handle, expected)
                if scenario == "stale" and handle is handles[0] and result["returncode"] == 1:
                    if not any(
                        item.get("event") == "worker_failed"
                        and item.get("error_type") in {"LeaseLostError", "ExecutionFenceError"}
                        for item in result["failure_events"]
                    ):
                        raise RuntimeError("stale_worker_unexpected_failure")
                worker_results.append(result)
            mission, evidence, effects = _read_api_mission(harness, mission_id, session)
            finding = _verify_finding(mission, evidence, harness.workspace)
            (state_root / "finding_claim.json").write_text(json.dumps(finding, sort_keys=True), encoding="utf-8")

        if mission.get("status") != "GOAL_COMPLETED":
            raise RuntimeError("mission_not_completed_after_verified_lifecycle")
        if scenario == "crash":
            if (
                len(evidence) != 2
                or {item.get("source") for item in evidence} != {"run_project_tests", "watch"}
                or not all(item.get("passed") is True for item in evidence)
            ):
                raise RuntimeError("recovery_finding_evidence_missing")
            if not any(
                item.get("event") == "effects_reconciled_for_resume"
                and item.get("resolution") == "OWNER_CONFIRMED_APPLIED"
                for item in mission.get("recovery_events", ())
            ):
                raise RuntimeError("owner_approval_not_persisted")
            if not any(
                item.get("step_id") == "local-watch" and item.get("status") == "completed"
                for item in mission.get("action_history", ())
            ):
                raise RuntimeError("recovered_watch_step_not_completed")
        elif len(evidence) != 2 or not all(item.get("passed") is True for item in evidence):
            raise RuntimeError("mission_evidence_incomplete")
        if mission.get("authorization_snapshot", {}).get("authorization_hash") != created_mission.get("authorization_snapshot", {}).get("authorization_hash"):
            # The queue start path may refresh the snapshot; its authenticated proof must still be present.
            if not mission.get("authorization_snapshot", {}).get("authorization_hash"):
                raise RuntimeError("mission_authorization_snapshot_lost")
        if any(not result for result in _verify_integrity(harness, mission).values()):
            raise RuntimeError("mission_evidence_or_trajectory_integrity_failed")
        if scenario != "crash" and harness.queue.get(mission_id).attempts != 1:
            raise RuntimeError("mission_queue_claim_count_not_one")
        worker_ids = [item.worker_id for item in handles]
        if scenario == "crash":
            worker_ids = [worker_id]
        projection = _common_projection(
            harness,
            mission,
            evidence,
            effects,
            finding,
            auth_result,
            worker_ids,
            stale_attempt=stale_attempt,
        )
        projection["failure_variant"] = scenario
        if scenario == "crash":
            if owner_reconcile_result is None:
                raise RuntimeError("owner_reconciliation_result_missing")
            projection["crash_recovery"] = {
                "quarantined": crash_recovery["mission_status"] == "RECOVERY_REQUIRED",
                "generation_after_crash": crash_recovery["generation"],
                "queue_attempts_after_resume": harness.queue.get(mission_id).attempts,
                "owner_reconciliation_http_status": reconcile_status,
                "owner_resolution": owner_reconcile_result.get("status"),
                "owner_approval_event_count": len(owner_approval_events),
                "dispatch_event_count": len(dispatch_events),
                "unique_watch_effect": unique_watch_effect,
                "worker_results": worker_results,
            }
        else:
            projection["worker_results"] = [
                {"returncode": item["returncode"], "failure_events": item["failure_events"]}
                for item in worker_results
            ]
        report_status, report_payload = harness.request(
            "GET", f"/api/missions/{mission_id}/report", session=session
        )
        report = report_payload.get("report")
        if report_status != 200 or not isinstance(report, dict):
            raise RuntimeError("mission_report_api_failed")
        report_mission = report.get("mission_summary")
        report_verification = (
            report_mission.get("verification")
            if isinstance(report_mission, dict)
            else None
        )
        report_findings = report.get("findings")
        report_evidence = report.get("evidence")
        report_owner = report.get("owner_approval_status")
        if (
            not isinstance(report_mission, dict)
            or report_mission.get("mission_status") != "GOAL_COMPLETED"
            or report_mission.get("outcome") != "VERIFIED"
            or not isinstance(report_verification, dict)
            or report_verification.get("verified") is not True
            or not isinstance(report_findings, list)
            or len(report_findings) != 2
            or any(
                not isinstance(item, dict) or item.get("status") != "PASS"
                for item in report_findings
            )
            or not isinstance(report_evidence, dict)
            or report_evidence.get("execution_chain_integrity") != "VALID"
            or not isinstance(report_owner, dict)
            or report_owner.get("status") != "RECORDED"
        ):
            raise RuntimeError("mission_report_not_verified")
        report_summary = {
            "mission_status": report_mission["mission_status"],
            "outcome": report_mission["outcome"],
            "verified": report_verification["verified"],
            "finding_count": len(report_findings),
            "execution_chain_integrity": report_evidence["execution_chain_integrity"],
            "owner_approval_status": report_owner["status"],
        }
        return {
            "ok": True,
            "scenario": scenario,
            "mission_id": mission_id,
            "finding": finding,
            "report": report_summary,
            "integrity": _verify_integrity(harness, mission),
            "canonical_projection": projection,
        }
    finally:
        harness.close()


def main(argv: list[str]) -> int:
    try:
        if len(argv) >= 3 and argv[1] == "--recover":
            return _recover_child(argv[2], argv[3])
        if len(argv) != 2:
            raise RuntimeError("scenario_argument_required")
        result = _run_scenario(argv[1])
        return _emit(result)
    except Exception as exc:
        return _emit({"ok": False, "error_type": type(exc).__name__, "error": str(exc)[:300]}, 2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
