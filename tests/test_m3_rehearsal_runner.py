from __future__ import annotations

import io
from pathlib import Path
import subprocess
from typing import Any

import pytest

from scripts.m3_rehearsal import runner as rehearsal
from scripts.m3_rehearsal import host as host_module
from scripts.m3_rehearsal.host import BASE_COMPOSE, OVERLAY_COMPOSE, PROVIDER_ENV_KEYS


class FakeHost:
    def __init__(self, cleanup_status: str = "PASS") -> None:
        self.cleanup_calls = 0
        self.cleanup_status = cleanup_status

    def cleanup(self) -> dict[str, Any]:
        self.cleanup_calls += 1
        return {
            "status": self.cleanup_status,
            "leftovers": {
                "containers": 0,
                "volumes": 0,
                "networks": 0,
                "image_tags": 0,
            },
            "errors": [],
        }


def _stub_stages(
    monkeypatch: pytest.MonkeyPatch,
    runner: rehearsal.RehearsalRunner,
) -> None:
    names = (
        "_compose_build",
        "_legacy_state_seed",
        "_startup",
        "_health",
        "_owner_login",
        "_create_mission",
        "_worker_execution",
        "_schema_upgrade",
        "_queue_state",
        "_evidence",
        "_controlled_crash",
        "_restart",
        "_recovery",
        "_graceful_shutdown",
        "_backup",
        "_restore",
    )
    for name in names:
        monkeypatch.setattr(runner, name, lambda name=name: {"completed": name})


def test_queue_state_failure_reports_only_static_invariant_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = rehearsal.RehearsalRunner(
        output_path=tmp_path / "result.json", port_picker=lambda: 32991
    )
    runner.mission_id = "synthetic-mission"
    probe = {
        "queue": {
            "state": "queue-state-secret",
            "attempts": 1,
            "runtime_generation": 1,
            "lease_owned": True,
            "lease_expires_at": "2099-01-01T00:00:00+00:00",
        },
        "generation": {"runtime_generation": 1, "state": "ACTIVE"},
        "db_under_state": True,
        "queue_db_under_state": True,
    }
    monkeypatch.setattr(runner.host, "state_probe", lambda *_args: probe)

    with pytest.raises(host_module.RehearsalFailure) as caught:
        runner._queue_state()

    assert caught.value.reason == "pre_crash_queue_invariants_failed:queue_executing"
    assert "queue-state-secret" not in caught.value.reason


def test_queue_state_accepts_persisted_lowercase_execution_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent.mission_worker import WorkerMissionState

    runner = rehearsal.RehearsalRunner(
        output_path=tmp_path / "result.json", port_picker=lambda: 32991
    )
    runner.mission_id = "synthetic-mission"
    probe = {
        "queue": {
            "state": WorkerMissionState.EXECUTING.value,
            "attempts": 1,
            "runtime_generation": 1,
            "lease_owned": True,
            "lease_expires_at": "2099-01-01T00:00:00+00:00",
        },
        "generation": {"runtime_generation": 1, "state": "ACTIVE"},
        "db_under_state": True,
        "queue_db_under_state": True,
    }
    monkeypatch.setattr(runner.host, "state_probe", lambda *_args: probe)

    result = runner._queue_state()

    assert result["queue_state"] == WorkerMissionState.EXECUTING.value
    assert runner.lease_expires_at == "2099-01-01T00:00:00+00:00"


def test_recovery_queue_status_constants_match_persisted_worker_enum() -> None:
    from agent.mission_worker import WorkerMissionState

    assert rehearsal.QUEUE_STATE_EXECUTING == WorkerMissionState.EXECUTING.value
    assert rehearsal.QUEUE_STATE_WAITING_FOR_TOOL == (
        WorkerMissionState.WAITING_FOR_TOOL.value
    )
    assert rehearsal.QUEUE_STATE_COMPLETED == WorkerMissionState.COMPLETED.value


def test_safe_environment_removes_ambient_provider_and_runtime_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_API_KEY", "ambient-provider-secret")
    monkeypatch.setenv("LOCAL_LLM_API_KEY", "ambient-local-secret")
    monkeypatch.setenv("COLAB_LLM_API_KEY", "ambient-colab-secret")
    monkeypatch.setenv("HF_LLM_API_KEY", "ambient-hf-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-openai-secret")
    monkeypatch.setenv("BRIDGE_TOKEN", "ambient-bridge-secret")
    monkeypatch.setenv("CYBERSENTINEL_OWNER_PHRASE", "ambient-owner-secret")
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker.example:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    monkeypatch.setenv("UNRELATED_API_KEY", "ambient-unrelated-secret")

    result = rehearsal._safe_environment(
        image="cybersentinel-m3-v16:abcdef012345",
        published_port=32991,
    )

    assert "BRIDGE_TOKEN" not in result
    assert result["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert "DOCKER_CONTEXT" not in result
    assert result["DB_PATH"] == "/var/lib/cybersentinel/intel.db"
    for key in PROVIDER_ENV_KEYS:
        assert key not in result
    for value in (
        "ambient-provider-secret",
        "ambient-local-secret",
        "ambient-colab-secret",
        "ambient-hf-secret",
        "ambient-openai-secret",
        "ambient-bridge-secret",
        "ambient-owner-secret",
        "ambient-unrelated-secret",
    ):
        assert value not in result.values()


def test_v16_mission_requests_independent_status_snapshot_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = rehearsal.RehearsalRunner(
        output_path=tmp_path / "v16-result.json", port_picker=lambda: 32991
    )
    runner.owner_session = "synthetic-owner-session"
    captured: dict[str, Any] = {}
    mission_id = "synthetic-mission"

    def fake_http_json(method: str, path: str, body: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        captured["method"] = method
        captured["path"] = path
        captured["body"] = body
        return {
            "mission_id": mission_id,
            "mission": {
                "owner_identity_ref": "owner-ref",
                "authorization_snapshot": {
                    "mission_id": mission_id,
                    "owner_identity": "owner-ref",
                    "owner_approval": "synthetic-approval",
                    "authorization_hash": "a" * 64,
                },
            },
        }

    monkeypatch.setattr(runner, "_http_json", fake_http_json)

    result = runner._create_mission()

    assert result["mission_created"] is True
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/missions"
    criterion = captured["body"]["completion_criteria"][0]
    assert criterion["criterion_id"] == "mission-goal"
    assert criterion["check"] == "status_snapshot"


def test_embedded_container_probe_programs_compile() -> None:
    programs = (
        host_module._BOOTSTRAP_OWNER,
        host_module._PROVIDER_GUARD,
        host_module._MARKER_PROBE,
        host_module._MARKER_CREATE,
        host_module._STATE_PROBE,
        host_module._LEGACY_MIGRATION_PROBE,
    )
    for index, program in enumerate(programs):
        compile(program, f"m3-v16-probe-{index}", "exec")


def test_compose_adapter_uses_fixed_files_argv_and_synthetic_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="validated\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    env = rehearsal._safe_environment(
        image="cybersentinel-m3-v16:abcdef012345",
        published_port=32991,
    )
    env["CYBERSENTINEL_SECRETS_DIR"] = "/tmp/m3v16-synthetic-secrets"
    host = rehearsal.DockerHost(
        project="m3v16-abcdef012345",
        image="cybersentinel-m3-v16:abcdef012345",
        port=32991,
        env=env,
    )

    assert host.compose("config", "--quiet") == "validated"
    argv, kwargs = calls[0]
    assert argv[:3] == ["docker", "compose", "--env-file"]
    assert "/dev/null" in argv
    repo_root = Path(__file__).resolve().parents[1]
    assert BASE_COMPOSE == repo_root / "compose.yaml"
    assert OVERLAY_COMPOSE == repo_root / "tests" / "compose.m3-rehearsal.yaml"
    assert str(BASE_COMPOSE) in argv
    assert str(OVERLAY_COMPOSE) in argv
    assert "m3v16-abcdef012345" in argv
    assert kwargs["env"]["CYBERSENTINEL_SECRETS_DIR"] == "/tmp/m3v16-synthetic-secrets"
    assert "BRIDGE_TOKEN" not in kwargs["env"]
    assert "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["capture_output"] is True


def test_one_off_worker_command_is_named_and_never_contains_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeProcess:
        def poll(self) -> None:
            return None

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeProcess:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    token = "synthetic-bridge-token"
    password = "synthetic-owner-password"
    env = rehearsal._safe_environment(
        image="cybersentinel-m3-v16:abcdef012345",
        published_port=32991,
    )
    env["SYNTHETIC_OWNER_PASSWORD"] = password
    host = rehearsal.DockerHost(
        project="m3v16-abcdef012345",
        image="cybersentinel-m3-v16:abcdef012345",
        port=32991,
        env=env,
    )

    process = host.start_worker("m3v16-abcdef012345-worker-1")
    argv = captured["argv"]
    assert process is host.worker_processes[0]
    assert host.worker_names == ["m3v16-abcdef012345-worker-1"]
    assert "run" in argv and "--rm" in argv and "--no-deps" in argv
    assert "--no-TTY" in argv and "--name" in argv
    assert "mission-worker" in argv
    assert "m3-v16-rehearsal-worker" in argv
    assert token not in argv and password not in argv
    assert captured["kwargs"]["stdout"] is subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is subprocess.DEVNULL


def test_http_failure_reason_does_not_include_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "response-body-secret"
    body = io.BytesIO(secret.encode())

    def fake_urlopen(request: Any, timeout: int) -> Any:
        raise rehearsal.HTTPError(
            request.full_url,
            403,
            "forbidden",
            {},
            body,
        )

    monkeypatch.setattr(rehearsal, "urlopen", fake_urlopen)
    runner = rehearsal.RehearsalRunner(port_picker=lambda: 32991)
    with pytest.raises(rehearsal.RehearsalFailure) as caught:
        runner._http_json("GET", "/api/missions/mission/status")
    assert str(caught.value) == "bridge_http_403"
    assert secret not in str(caught.value)
    assert body.closed


def test_success_records_all_v12_stages_and_cleans_temporary_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "v16-result.json"
    runner = rehearsal.RehearsalRunner(
        output_path=output,
        port_picker=lambda: 32991,
    )
    runner.host = FakeHost()
    _stub_stages(monkeypatch, runner)
    runner._write_result = lambda _result: output.write_text(
        "written", encoding="utf-8"
    )

    result = runner.run()

    assert result["status"] == "PASS"
    assert [stage["name"] for stage in result["stages"]] == list(rehearsal.STAGE_ORDER)
    assert all(stage["status"] == "PASS" for stage in result["stages"])
    assert result["cleanup"]["status"] == "PASS"
    assert result["cleanup"]["temporary_directory_removed"] is True
    assert runner.temp_path is not None and not runner.temp_path.exists()
    docker_config = Path(runner.env["DOCKER_CONFIG"])
    assert docker_config.parent == runner.temp_path
    assert not docker_config.exists()
    assert runner.host.cleanup_calls == 1
    assert output.read_text(encoding="utf-8") == "written"


def test_stage_failure_marks_later_stages_not_run_and_still_cleans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "failed-result.json"
    runner = rehearsal.RehearsalRunner(
        output_path=output,
        port_picker=lambda: 32991,
    )
    runner.host = FakeHost()
    _stub_stages(monkeypatch, runner)
    monkeypatch.setattr(
        runner,
        "_health",
        lambda: (_ for _ in ()).throw(rehearsal.RehearsalFailure("health_failed")),
    )
    runner._write_result = lambda result: output.write_text(
        json_summary(result), encoding="utf-8"
    )

    result = runner.run()

    assert result["status"] == "FAIL"
    assert result["failure_reason"] == "health_failed"
    assert [stage["name"] for stage in result["stages"][:4]] == [
        "deploy_build",
        "legacy_state_seed",
        "startup",
        "health",
    ]
    assert [stage["status"] for stage in result["stages"][:4]] == [
        "PASS",
        "PASS",
        "PASS",
        "FAIL",
    ]
    assert all(stage["status"] == "NOT_RUN" for stage in result["stages"][4:])
    assert result["cleanup"]["temporary_directory_removed"] is True
    assert runner.host.cleanup_calls == 1
    rendered = output.read_text(encoding="utf-8")
    assert runner.owner_password not in rendered
    assert runner.bridge_token not in rendered


def json_summary(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, sort_keys=True)


def test_cleanup_uses_only_the_unique_project_and_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []
    host = rehearsal.DockerHost(
        project="m3v16-abcdef012345",
        image="cybersentinel-m3-v16:abcdef012345",
        port=32991,
        env={},
    )
    host.image_built = True

    def fake_compose(*args: str, **_kwargs: Any) -> str:
        calls.append(("compose", args))
        return ""

    def fake_docker(*args: str, **_kwargs: Any) -> str:
        calls.append(("docker", args))
        return ""

    monkeypatch.setattr(host, "compose", fake_compose)
    monkeypatch.setattr(host, "docker", fake_docker)

    result = host.cleanup()

    assert result["status"] == "PASS"
    assert any(
        kind == "compose"
        and args[:2] == ("down", "--volumes")
        and "--remove-orphans" in args
        for kind, args in calls
    )
    label = "label=com.docker.compose.project=m3v16-abcdef012345"
    assert sum(label in args for _kind, args in calls) == 3
    assert any(
        kind == "docker"
        and args == ("image", "rm", "cybersentinel-m3-v16:abcdef012345")
        for kind, args in calls
    )


def test_compose_secrets_are_synthetic_files_inside_rehearsal_temp_directory(
    tmp_path: Path,
) -> None:
    runner = rehearsal.RehearsalRunner(port_picker=lambda: 32991)
    runner.temp_path = tmp_path

    runner._prepare_compose_secrets()

    directory = Path(runner.env["CYBERSENTINEL_SECRETS_DIR"])
    assert directory == tmp_path / "compose-secrets"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "bridge_token").read_text(encoding="utf-8").strip() == runner.bridge_token
    assert "BRIDGE_TOKEN" not in runner.env
    for name in ("llm_api_key", "local_llm_api_key", "colab_llm_api_key", "hf_llm_api_key"):
        assert (directory / name).read_bytes() == b""
        assert (directory / name).stat().st_mode & 0o777 == 0o444


def test_state_archive_adapter_streams_binary_output_to_private_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        kwargs["stdout"].write(b"synthetic-gzip-archive")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    archive = tmp_path / "state.tar.gz"
    host = rehearsal.DockerHost(
        project="m3v16-abcdef012345",
        image="cybersentinel-m3-v16:abcdef012345",
        port=32991,
        env={},
    )

    assert host.state_archive("backup", output_path=archive) == ""
    assert archive.read_bytes() == b"synthetic-gzip-archive"
    assert archive.stat().st_mode & 0o777 == 0o600
    assert captured["argv"][-3:] == [
        "workspace-init",
        "/app/scripts/state_archive.py",
        "backup",
    ]
    assert "--no-TTY" in captured["argv"] and "--no-deps" in captured["argv"]
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL


def test_failed_state_archive_command_removes_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        kwargs["stdout"].write(b"partial")
        return subprocess.CompletedProcess(argv, 2, stdout="", stderr="hidden")

    monkeypatch.setattr(subprocess, "run", fake_run)
    archive = tmp_path / "partial.tar.gz"
    host = rehearsal.DockerHost(
        project="m3v16-abcdef012345",
        image="cybersentinel-m3-v16:abcdef012345",
        port=32991,
        env={},
    )

    with pytest.raises(rehearsal.RehearsalFailure, match="state_archive_command_failed"):
        host.state_archive("backup", output_path=archive)

    assert not archive.exists()
