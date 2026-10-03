"""Twelve-stage non-production M3 lifecycle rehearsal orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .host import (
    CRASH_EXIT_CODE,
    CRASH_MARKER,
    DISPATCHED_MARKER,
    HOST_RELEASE_SECONDS,
    LEASE_SECONDS,
    OWNER_USERNAME,
    PROVIDER_MARKER,
    RELEASE_MARKER,
    STATE_ROOT,
    STAGE_ORDER,
    DockerHost,
    RehearsalFailure,
    _free_loopback_port,
    _safe_environment,
)


class RehearsalRunner:
    def __init__(
        self, *, output_path: Path | None = None, port_picker=_free_loopback_port
    ):
        self.project = f"m3v16-{secrets.token_hex(6)}"
        self.image = f"cybersentinel-m3-v16:{self.project.rsplit('-', 1)[-1]}"
        self.bridge_token = secrets.token_urlsafe(32)
        self.owner_password = secrets.token_urlsafe(32)
        self.keyword = f"m3-v16-{secrets.token_hex(8)}"
        self.port = int(port_picker())
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.output_path = output_path
        self.env = _safe_environment(
            image=self.image, bridge_token=self.bridge_token, published_port=self.port
        )
        self.host = DockerHost(
            project=self.project,
            image=self.image,
            port=self.port,
            bridge_token=self.bridge_token,
            env=self.env,
        )
        self.owner_session = ""
        self.owner_id = 0
        self.mission_id = ""
        self.effect_id = ""
        self.worker1: subprocess.Popen[bytes] | None = None
        self.worker2: subprocess.Popen[bytes] | None = None
        self.lease_expires_at = ""
        self.stages: list[dict[str, Any]] = []
        self.started = time.monotonic()
        self.temp_path: Path | None = None

    def _compose_build(self) -> dict[str, Any]:
        self.host.compose("version", timeout=15)
        self.host.compose("config", "--quiet", timeout=30)
        self.host.image_built = True
        self.host.compose("build", "--quiet", "bridge", timeout=300)
        return {
            "project": self.project,
            "image": self.image,
            "compose_config_valid": True,
        }

    def _startup(self) -> dict[str, Any]:
        self.host.compose("up", "--detach", "--no-build", "bridge", timeout=90)
        bridge_id = self.host.compose("ps", "--quiet", "bridge", timeout=15)
        if not bridge_id:
            raise RehearsalFailure("bridge_container_missing")
        published = self.host.compose("port", "bridge", "8787", timeout=15)
        if not published.startswith("127.0.0.1:"):
            raise RehearsalFailure("bridge_not_loopback_published")
        running = self.host.docker(
            "inspect", "--format", "{{.State.Running}}", bridge_id
        )
        if running != "true":
            raise RehearsalFailure("bridge_not_running")
        return {"bridge_running": True, "published_loopback": True}

    def _http_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        session: str = "",
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any]:
        headers = {"X-CyberSentinel-Token": self.bridge_token}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if session:
            headers["X-CyberSentinel-Owner-Session"] = session
        request = Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urlopen(request, timeout=5) as response:
                status = int(response.status)
                raw = response.read()
        except HTTPError as exc:
            status = int(exc.code)
            raw = b""
            exc.close()
        except (URLError, TimeoutError, OSError) as exc:
            raise RehearsalFailure("bridge_request_failed") from exc
        if status not in expected:
            raise RehearsalFailure(f"bridge_http_{status}")
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("bridge_response_not_json") from exc
        if not isinstance(payload, dict) or payload.get("ok") is False:
            raise RehearsalFailure("bridge_response_not_ok")
        return payload

    def _health(self) -> dict[str, Any]:
        deadline = time.monotonic() + 45
        last_error = "bridge_health_timeout"
        while time.monotonic() < deadline:
            try:
                payload = self._http_json("GET", "/api/health", expected=(200,))
                if payload.get("ok") is True or payload.get("status") == "ok":
                    guard = self.host.provider_guard()
                    if not all(
                        guard.get(key) is True
                        for key in (
                            "rehearsal",
                            "providers_empty",
                            "router_empty",
                            "db_under_state",
                        )
                    ):
                        raise RehearsalFailure("provider_or_state_fence_failed")
                    return {
                        "health": "ok",
                        "provider_router_blocked": True,
                        "providers_empty": True,
                        "db_under_state_volume": True,
                    }
            except RehearsalFailure as exc:
                last_error = exc.reason
                if exc.reason not in {
                    "bridge_request_failed",
                    "bridge_http_503",
                    "bridge_response_not_json",
                }:
                    raise
            time.sleep(0.2)
        raise RehearsalFailure(last_error)

    def _owner_login(self) -> dict[str, Any]:
        self.host.bootstrap_owner(self.owner_password)
        payload = self._http_json(
            "POST",
            "/api/auth/login",
            {"username": OWNER_USERNAME, "password": self.owner_password},
            expected=(200,),
        )
        session = payload.get("session")
        if (
            not isinstance(session, dict)
            or not session.get("session_id")
            or not session.get("owner_id")
        ):
            raise RehearsalFailure("owner_login_payload_invalid")
        self.owner_session = str(session["session_id"])
        self.owner_id = int(session["owner_id"])
        return {
            "owner_authenticated": True,
            "owner_identity_id": self.owner_id,
            "session_secret_recorded": False,
        }

    def _create_mission(self) -> dict[str, Any]:
        objective = (
            "Record local runtime status and register one isolated "
            "local defensive watch."
        )
        payload = {
            "objective": objective,
            "plan": {
                "version": 1,
                "objective": objective,
                "created_from": "m3-v16-disposable-compose-rehearsal",
                "risk": "bounded-local",
                "steps": [
                    {
                        "step_id": "runtime-status",
                        "objective": (
                            "Record the local runtime status before the "
                            "controlled restart boundary"
                        ),
                        "action": "status",
                        "expected_observation": "The isolated local runtime responds",
                        "authorization_requirement": "owner",
                        "scope_requirement": "workspace",
                        "verification": ["mission-goal"],
                    },
                    {
                        "step_id": "local-watch",
                        "objective": (
                            "Register the one-run local defensive watch keyword"
                        ),
                        "action": "watch",
                        "prerequisites": ["runtime-status"],
                        "retry_policy": {"arguments": {"query": self.keyword}},
                        "expected_observation": "The exact local watch exists once",
                        "authorization_requirement": "owner",
                        "scope_requirement": "workspace",
                        "verification": ["mission-goal"],
                    },
                ],
            },
            "scope_context": {
                "target_id": self.project,
                "workspace_root": str(STATE_ROOT / "workspace"),
                "allowed_networks": [],
                "allowed_credentials": [],
            },
            "completion_criteria": [
                {
                    "criterion_id": "mission-goal",
                    "description": (
                        "The isolated runtime status was recorded before the "
                        "controlled local-watch recovery boundary"
                    ),
                    "required": True,
                }
            ],
        }
        payload_out = self._http_json(
            "POST",
            "/api/missions",
            payload,
            session=self.owner_session,
            expected=(201,),
        )
        mission = payload_out.get("mission")
        mission_id = str(payload_out.get("mission_id", ""))
        snapshot = (
            mission.get("authorization_snapshot") if isinstance(mission, dict) else None
        )
        if (
            not mission_id
            or not isinstance(snapshot, dict)
            or snapshot.get("mission_id") != mission_id
            or snapshot.get("owner_identity") != mission.get("owner_identity_ref")
            or not snapshot.get("owner_approval")
            or len(str(snapshot.get("authorization_hash", ""))) != 64
        ):
            raise RehearsalFailure("mission_owner_snapshot_binding_failed")
        self.mission_id = mission_id
        return {
            "mission_created": True,
            "owner_snapshot_bound": True,
            "mission_id": mission_id,
        }

    def _wait_for_generation(
        self, expected_generation: int, timeout: float = 20
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            process = self.worker1 if expected_generation == 1 else self.worker2
            if process is not None and process.poll() is not None:
                raise RehearsalFailure("worker_exited_before_expected_generation")
            last = self.host.state_probe(self.mission_id, self.keyword)
            generation = last.get("generation") or {}
            if generation.get("runtime_generation") == expected_generation:
                return last
            time.sleep(0.1)
        raise RehearsalFailure(f"worker_generation_{expected_generation}_timeout")

    def _wait_for_marker(
        self, name: str, timeout: float = HOST_RELEASE_SECONDS
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.host.marker_state(name)
            if state.get("exists") is True:
                return state
            if self.worker1 is not None and self.worker1.poll() is not None:
                raise RehearsalFailure("worker_exited_before_dispatch_barrier")
            time.sleep(0.1)
        raise RehearsalFailure("dispatch_barrier_timeout")

    def _worker_execution(self) -> dict[str, Any]:
        self.host.set_marker(CRASH_MARKER)
        self.worker1 = self.host.start_worker(f"{self.project}-worker-1")
        self._wait_for_generation(1)
        self._http_json(
            "POST",
            f"/api/missions/{self.mission_id}/start",
            {},
            session=self.owner_session,
        )
        barrier = self._wait_for_marker(DISPATCHED_MARKER)
        if barrier.get("symlink"):
            raise RehearsalFailure("dispatch_marker_symlink")
        return {
            "worker_generation": 1,
            "mission_started": True,
            "post_dispatch_barrier_reached": True,
        }

    def _queue_state(self) -> dict[str, Any]:
        probe = self.host.state_probe(self.mission_id, self.keyword)
        queue = probe.get("queue") or {}
        generation = probe.get("generation") or {}
        checks = {
            "queue_executing": queue.get("state") == "EXECUTING",
            "single_attempt": queue.get("attempts") == 1,
            "queue_generation_one": queue.get("runtime_generation") == 1,
            "lease_owned": queue.get("lease_owned") is True,
            "worker_generation_one": generation.get("runtime_generation") == 1,
            "worker_active": generation.get("state") == "ACTIVE",
            "mission_db_under_state": probe.get("db_under_state") is True,
            "queue_db_under_state": probe.get("queue_db_under_state") is True,
        }
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            raise RehearsalFailure(
                "pre_crash_queue_invariants_failed:" + ",".join(failed)
            )
        self.lease_expires_at = str(queue.get("lease_expires_at") or "")
        if not self.lease_expires_at:
            raise RehearsalFailure("pre_crash_lease_expiry_missing")
        return {
            "queue_state": queue["state"],
            "attempts": queue["attempts"],
            "worker_generation": generation["runtime_generation"],
            "lease_owned": True,
            "queue_and_mission_databases_in_ephemeral_volume": True,
        }

    def _status(self) -> dict[str, Any]:
        return self._http_json(
            "GET", f"/api/missions/{self.mission_id}/status", session=self.owner_session
        ).get("status", {})

    def _evidence(self) -> dict[str, Any]:
        mission = self._status()
        evidence_payload = self._http_json(
            "GET",
            f"/api/missions/{self.mission_id}/evidence",
            session=self.owner_session,
        )
        evidence = evidence_payload.get("evidence")
        effects_payload = self._http_json(
            "GET",
            f"/api/missions/{self.mission_id}/effects",
            session=self.owner_session,
        )
        effects = effects_payload.get("effects")
        probe = self.host.state_probe(self.mission_id, self.keyword)
        if (
            mission.get("status") != "RUNNING"
            or mission.get("current_step") != 1
            or str((mission.get("checkpoint") or {}).get("status", ""))
            not in {"in_flight", "in_flight_parallel"}
            or not isinstance(evidence, list)
            or len(evidence) != 1
            or not isinstance(effects, list)
            or len(effects) != 1
            or effects[0].get("state") != "DISPATCHED"
            or effects[0].get("operation") != "watch"
            or probe.get("watch_count") != 1
        ):
            raise RehearsalFailure("pre_crash_evidence_or_effect_invariant_failed")
        self.effect_id = str(effects[0].get("effect_id", ""))
        if not self.effect_id:
            raise RehearsalFailure("effect_id_missing")
        return {
            "mission_status": mission["status"],
            "completed_step_evidence_count": len(evidence),
            "current_step": mission["current_step"],
            "effect_state": effects[0]["state"],
            "local_watch_count": probe["watch_count"],
            "provider_violation_marker_absent": not self.host.marker_state(
                PROVIDER_MARKER
            ).get("exists"),
        }

    @staticmethod
    def _seconds_until(value: str) -> float:
        try:
            moment = datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise RehearsalFailure("lease_expiry_timestamp_invalid") from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return max(0.0, (moment - datetime.now(timezone.utc)).total_seconds())

    def _controlled_crash(self) -> dict[str, Any]:
        self.host.set_marker(RELEASE_MARKER)
        if self.worker1 is None:
            raise RehearsalFailure("initial_worker_missing")
        exit_code = self.host.wait_worker(
            self.worker1, timeout=HOST_RELEASE_SECONDS + 20
        )
        marker = self.host.marker_state(CRASH_MARKER)
        dispatched = self.host.marker_state(DISPATCHED_MARKER)
        probe = self.host.state_probe(self.mission_id, self.keyword)
        effect = next(
            (
                item
                for item in probe.get("effects", [])
                if item.get("effect_id") == self.effect_id
            ),
            {},
        )
        if (
            exit_code != CRASH_EXIT_CODE
            or marker.get("exists") is not False
            or dispatched.get("exists") is not True
            or effect.get("state") != "DISPATCHED"
        ):
            raise RehearsalFailure("controlled_crash_proof_failed")
        return {
            "exit_code": exit_code,
            "dispatch_marker_persisted": True,
            "crash_marker_consumed": True,
            "effect_still_dispatched": True,
        }

    def _restart(self) -> dict[str, Any]:
        wait_seconds = self._seconds_until(self.lease_expires_at) + 0.1
        if wait_seconds > LEASE_SECONDS + 2:
            raise RehearsalFailure("lease_expiry_wait_exceeded_bound")
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        self.worker2 = self.host.start_worker(f"{self.project}-worker-2")
        probe = self._wait_for_generation(2)
        return {
            "logical_worker_id_reused": True,
            "generation_before": 1,
            "generation_after": 2,
            "mission_status": (self._status()).get("status"),
            "queue_state": (probe.get("queue") or {}).get("state"),
        }

    def _recovery(self) -> dict[str, Any]:
        deadline = time.monotonic() + 20
        mission: dict[str, Any] = {}
        probe: dict[str, Any] = {}
        effects: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            mission = self._status()
            probe = self.host.state_probe(self.mission_id, self.keyword)
            effects = self._http_json(
                "GET",
                f"/api/missions/{self.mission_id}/effects",
                session=self.owner_session,
            ).get("effects", [])
            queue = probe.get("queue") or {}
            if (
                mission.get("status") == "RECOVERY_REQUIRED"
                and queue.get("state") == "WAITING_FOR_TOOL"
                and effects
                and effects[0].get("state") == "DISPATCHED"
                and probe.get("watch_count") == 1
            ):
                break
            time.sleep(0.1)
        if (
            not effects
            or effects[0].get("state") != "DISPATCHED"
            or probe.get("watch_count") != 1
        ):
            raise RehearsalFailure("restart_recovery_quarantine_not_observed")
        history = next(
            (
                item.get("events", [])
                for item in probe.get("effects", [])
                if item.get("effect_id") == self.effect_id
            ),
            [],
        )
        if sum(1 for event in history if event == "DISPATCHED") != 1:
            raise RehearsalFailure("effect_dispatch_count_not_one")
        observation_hash = secrets.token_hex(32)
        evidence_reference = f"m3-v16-local-watch-readback:{observation_hash}"
        reconciliation = self._http_json(
            "POST",
            f"/api/missions/{self.mission_id}/effects/{self.effect_id}/reconcile",
            {
                "outcome": "OWNER_CONFIRM_APPLIED",
                "evidence_reference": evidence_reference,
            },
            session=self.owner_session,
        ).get("reconciliation", {})
        if reconciliation.get("status") != "OWNER_CONFIRMED_APPLIED":
            raise RehearsalFailure("owner_reconciliation_not_applied")
        old_session = self.owner_session
        self._http_json(
            "POST", "/api/auth/logout", {"session_id": old_session}, expected=(200,)
        )
        login = self._http_json(
            "POST",
            "/api/auth/login",
            {"username": OWNER_USERNAME, "password": self.owner_password},
            expected=(200,),
        )
        fresh = login.get("session") or {}
        fresh_session = str(fresh.get("session_id", ""))
        if (
            not fresh_session
            or fresh_session == old_session
            or int(fresh.get("owner_id", -1)) != self.owner_id
        ):
            raise RehearsalFailure("same_owner_reauthorization_failed")
        self.owner_session = fresh_session
        self._http_json(
            "POST",
            f"/api/missions/{self.mission_id}/resume",
            {},
            session=self.owner_session,
        )
        deadline = time.monotonic() + 30
        final_mission: dict[str, Any] = {}
        final_queue: dict[str, Any] = {}
        final_probe: dict[str, Any] = {}
        while time.monotonic() < deadline:
            final_mission = self._status()
            final_probe = self.host.state_probe(self.mission_id, self.keyword)
            final_queue = final_probe.get("queue") or {}
            if (
                final_mission.get("status") == "GOAL_COMPLETED"
                and final_queue.get("state") == "COMPLETED"
            ):
                break
            if self.worker2 is not None and self.worker2.poll() is not None:
                raise RehearsalFailure("replacement_worker_exited_during_resume")
            time.sleep(0.1)
        final_effects = self._http_json(
            "GET",
            f"/api/missions/{self.mission_id}/effects",
            session=self.owner_session,
        ).get("effects", [])
        final_probe = self.host.state_probe(self.mission_id, self.keyword)
        final_effect = next(
            (
                item
                for item in final_probe.get("effects", [])
                if item.get("effect_id") == self.effect_id
            ),
            {},
        )
        event_types = final_effect.get("events", [])
        if (
            final_mission.get("status") != "GOAL_COMPLETED"
            or final_queue.get("state") != "COMPLETED"
            or len(final_effects) != 1
            or final_effects[0].get("state") != "SUCCEEDED"
            or final_probe.get("watch_count") != 1
            or sum(1 for event in event_types if event == "DISPATCHED") != 1
            or sum(1 for event in event_types if event == "OWNER_CONFIRMED_APPLIED")
            != 1
            or (final_probe.get("generation") or {}).get("runtime_generation") != 2
        ):
            raise RehearsalFailure("owner_reconciliation_or_no_duplicate_proof_failed")
        return {
            "restart_quarantine": "RECOVERY_REQUIRED",
            "owner_confirmed_applied": True,
            "fresh_same_owner_session": True,
            "final_mission_status": final_mission["status"],
            "final_queue_state": final_queue["state"],
            "final_worker_generation": 2,
            "dispatch_events": 1,
            "owner_confirmed_applied_events": 1,
            "effect_count": len(final_effects),
            "local_watch_count": final_probe["watch_count"],
            "no_duplicate_dispatch": True,
        }

    def _graceful_shutdown(self) -> dict[str, Any]:
        if self.worker2 is None:
            raise RehearsalFailure("replacement_worker_missing")
        worker_name = f"{self.project}-worker-2"
        self.host.docker("stop", "--time", "10", worker_name, timeout=15)
        worker_exit = self.host.wait_worker(self.worker2, timeout=15)
        probe = self.host.state_probe(self.mission_id, self.keyword)
        generation = probe.get("generation") or {}
        if worker_exit != 0 or generation.get("state") != "STOPPED":
            raise RehearsalFailure("worker_graceful_shutdown_failed")
        self.host.compose("stop", "--timeout", "10", "bridge", timeout=15)
        bridge_id = self.host.compose("ps", "--all", "--quiet", "bridge", timeout=15)
        bridge_exit = self.host.docker(
            "inspect", "--format", "{{.State.ExitCode}}", bridge_id
        )
        if bridge_exit != "0":
            raise RehearsalFailure("bridge_graceful_shutdown_failed")
        return {
            "worker_exit_code": worker_exit,
            "worker_generation_state": generation["state"],
            "bridge_exit_code": int(bridge_exit),
        }

    def _run_stage(self, name: str, operation) -> None:
        started = time.monotonic()
        try:
            evidence = operation()
            self.stages.append(
                {
                    "name": name,
                    "status": "PASS",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "evidence": evidence,
                }
            )
        except RehearsalFailure as exc:
            self.stages.append(
                {
                    "name": name,
                    "status": "FAIL",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "reason": exc.reason,
                }
            )
            raise
        except Exception as exc:
            self.stages.append(
                {
                    "name": name,
                    "status": "FAIL",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "reason": f"unexpected_{type(exc).__name__}",
                }
            )
            raise RehearsalFailure(f"unexpected_{type(exc).__name__}") from exc

    def _write_result(self, result: dict[str, Any]) -> None:
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if self.output_path is not None:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.output_path.write_text(rendered, encoding="utf-8")
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
        if summary_path:
            rows = [
                "## M3 V16 non-production rehearsal",
                "",
                (
                    f"**Result:** `{result['status']}` — production remains "
                    f"`{result['production_deployment']}`."
                ),
                "",
                "| Stage | Status | Evidence |",
                "|---|---|---|",
            ]
            for stage in result["stages"]:
                detail = stage.get("reason") or json.dumps(
                    stage.get("evidence", {}), sort_keys=True
                )
                rows.append(
                    f"| `{stage['name']}` | `{stage['status']}` | "
                    f"`{detail.replace('|', '/').replace('`', '')}` |"
                )
            rows.extend(
                [
                    "",
                    f"Cleanup: `{result['cleanup']['status']}`; resources "
                    f"remaining: `{result['cleanup'].get('leftovers', {})}`.",
                    "",
                ]
            )
            with Path(summary_path).open("a", encoding="utf-8") as stream:
                stream.write("\n".join(rows))

    def run(self) -> dict[str, Any]:
        success = False
        failure_reason = ""
        cleanup_result: dict[str, Any] = {
            "status": "FAIL",
            "leftovers": {},
            "errors": ["cleanup_not_run"],
        }
        try:
            self.temp_path = Path(tempfile.mkdtemp(prefix=f"{self.project}-"))
            docker_config = self.temp_path / "docker-config"
            docker_config.mkdir(mode=0o700)
            self.env["DOCKER_CONFIG"] = str(docker_config)
            operations = (
                ("deploy_build", self._compose_build),
                ("startup", self._startup),
                ("health", self._health),
                ("owner_login", self._owner_login),
                ("mission_creation", self._create_mission),
                ("worker_execution", self._worker_execution),
                ("queue_state", self._queue_state),
                ("evidence", self._evidence),
                ("controlled_crash", self._controlled_crash),
                ("same_identity_restart", self._restart),
                ("recovery_owner_reauthorization", self._recovery),
                ("graceful_shutdown", self._graceful_shutdown),
            )
            for name, operation in operations:
                self._run_stage(name, operation)
            success = True
        except RehearsalFailure as exc:
            failure_reason = exc.reason
        except Exception as exc:
            failure_reason = f"unexpected_{type(exc).__name__}"
        finally:
            completed_names = {stage["name"] for stage in self.stages}
            for name in STAGE_ORDER:
                if name not in completed_names:
                    self.stages.append({"name": name, "status": "NOT_RUN"})
            try:
                cleanup_result = self.host.cleanup()
            except Exception as exc:
                cleanup_result = {
                    "status": "FAIL",
                    "leftovers": {},
                    "errors": [f"cleanup_{type(exc).__name__}"],
                }
            if self.temp_path is not None:
                try:
                    shutil.rmtree(self.temp_path)
                except FileNotFoundError:
                    pass
                except OSError:
                    cleanup_result["status"] = "FAIL"
                    cleanup_result.setdefault("errors", []).append(
                        "temporary_directory_remained"
                    )
            cleanup_result["temporary_directory_removed"] = bool(
                self.temp_path is None or not self.temp_path.exists()
            )
            if not cleanup_result["temporary_directory_removed"]:
                cleanup_result["status"] = "FAIL"
                cleanup_result.setdefault("errors", []).append(
                    "temporary_directory_remained"
                )
        success = (
            success
            and cleanup_result.get("status") == "PASS"
            and all(stage.get("status") == "PASS" for stage in self.stages)
        )
        result = {
            "schema_version": 1,
            "project": self.project,
            "status": "PASS" if success else "FAIL",
            "production_deployment": "PRODUCTION_DEPLOYMENT_BLOCKED",
            "failure_reason": failure_reason,
            "stages": self.stages,
            "cleanup": cleanup_result,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "credentials_recorded": False,
        }
        self._write_result(result)
        return result
