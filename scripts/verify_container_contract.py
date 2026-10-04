from __future__ import annotations

import json
import subprocess
import time
import sys
from pathlib import Path
from typing import Any

STATE_ROOT = Path("/var/lib/cybersentinel")
WORKSPACE = STATE_ROOT / "workspace"
STATE_PATH_VARIABLES = (
    "DB_PATH",
    "TASK_DB_PATH",
    "MEMORY_DB_PATH",
    "KNOWLEDGE_DB_PATH",
    "SCOPE_DB_PATH",
    "OWNER_POLICY_STATE_PATH",
)
SECRET_FILE_ENV = {
    "bridge_token": "BRIDGE_TOKEN_FILE",
    "llm_api_key": "LLM_API_KEY_FILE",
    "local_llm_api_key": "LOCAL_LLM_API_KEY_FILE",
    "colab_llm_api_key": "COLAB_LLM_API_KEY_FILE",
    "hf_llm_api_key": "HF_LLM_API_KEY_FILE",
}
DIRECT_SECRET_ENV_NAMES = (
    "BRIDGE_TOKEN",
    "LLM_API_KEY",
    "LOCAL_LLM_API_KEY",
    "COLAB_LLM_API_KEY",
    "HF_LLM_API_KEY",
)


def _run(*args: str) -> str:
    completed = subprocess.run(args, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def _container(service: str, *, include_stopped: bool = False) -> dict[str, Any]:
    args = ["docker", "compose", "ps"]
    if include_stopped:
        args.append("--all")
    args.extend(["--quiet", service])
    container_id = _run(*args)
    if not container_id:
        raise AssertionError(f"container not found for {service}")
    inspected = json.loads(_run("docker", "inspect", container_id))
    if len(inspected) != 1:
        raise AssertionError(f"expected one container for {service}")
    return inspected[0]


def _wait_healthy(service: str, timeout_seconds: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_state: dict[str, Any] = {}
    while time.monotonic() < deadline:
        container = _container(service)
        state = container["State"]
        health = state.get("Health")
        if health is None:
            raise AssertionError(f"{service} has no configured health check")
        status = health.get("Status")
        if status == "healthy":
            return container
        last_state = {"container": state.get("Status"), "health": health}
        if status == "unhealthy":
            raise AssertionError((service, last_state))
        time.sleep(2)
    raise AssertionError((service, "healthcheck timeout", last_state))


def _assert_hardened(container: dict[str, Any], service: str) -> dict[str, dict[str, Any]]:
    config = container["Config"]
    host = container["HostConfig"]
    assert config["User"] == "10001:10001", (service, config["User"])
    assert host["ReadonlyRootfs"] is True, service
    assert host.get("CapDrop") == ["ALL"], (service, host.get("CapDrop"))
    assert "no-new-privileges:true" in (host.get("SecurityOpt") or []), service
    mounts = {mount["Destination"]: mount for mount in container["Mounts"]}
    state_mount = mounts.get(str(STATE_ROOT))
    assert state_mount is not None, (service, sorted(mounts))
    assert state_mount["Type"] == "volume" and state_mount["RW"] is True, (service, state_mount)
    assert state_mount["Name"], service
    return mounts


def _assert_runtime_secrets(
    container: dict[str, Any], service: str, required: tuple[str, ...]
) -> None:
    config = container["Config"]
    environment = {
        entry.split("=", 1)[0]: entry.split("=", 1)[1]
        for entry in config.get("Env", [])
        if "=" in entry
    }
    mounts = {mount["Destination"]: mount for mount in container["Mounts"]}
    for name in DIRECT_SECRET_ENV_NAMES:
        assert name not in environment, (service, "inline secret leaked into container environment", name)
    for secret_name in required:
        env_name = SECRET_FILE_ENV[secret_name]
        target = f"/run/secrets/{secret_name}"
        assert environment.get(env_name) == target, (service, env_name, environment.get(env_name))
        mount = mounts.get(target)
        assert mount is not None and mount["RW"] is False, (service, target, mount)


def _exec_python(service: str, program: str) -> str:
    return _run(
        "docker",
        "compose",
        "exec",
        "--no-TTY",
        service,
        "/bin/sh",
        "/app/scripts/container_entrypoint.sh",
        "python",
        "-c",
        program,
    )


def main() -> int:
    bridge = _wait_healthy("bridge")
    worker = _wait_healthy("mission-worker")
    initializer = _container("workspace-init", include_stopped=True)

    bridge_mounts = _assert_hardened(bridge, "bridge")
    worker_mounts = _assert_hardened(worker, "mission-worker")
    init_mounts = _assert_hardened(initializer, "workspace-init")
    _assert_runtime_secrets(
        bridge,
        "bridge",
        ("bridge_token", "llm_api_key", "local_llm_api_key", "colab_llm_api_key", "hf_llm_api_key"),
    )
    _assert_runtime_secrets(
        worker,
        "mission-worker",
        ("llm_api_key", "local_llm_api_key", "colab_llm_api_key", "hf_llm_api_key"),
    )
    assert initializer["State"]["ExitCode"] == 0, initializer["State"]
    assert initializer["HostConfig"].get("NetworkMode") == "none", initializer["HostConfig"].get("NetworkMode")

    bridge_state = bridge_mounts[str(STATE_ROOT)]
    worker_state = worker_mounts[str(STATE_ROOT)]
    init_state = init_mounts[str(STATE_ROOT)]
    assert bridge_state["Name"] == worker_state["Name"] == init_state["Name"]
    assert str(WORKSPACE) not in bridge_mounts and str(WORKSPACE) not in worker_mounts

    published = bridge["HostConfig"].get("PortBindings") or {}
    mappings = published.get("8787/tcp") or []
    assert mappings and all(mapping["HostIp"] == "127.0.0.1" for mapping in mappings), published
    assert not (worker["HostConfig"].get("PortBindings") or {}), "worker must not publish ports"
    bridge_networks = bridge.get("NetworkSettings", {}).get("Networks", {})
    worker_networks = worker.get("NetworkSettings", {}).get("Networks", {})
    assert len(bridge_networks) == len(worker_networks) == 1
    assert set(bridge_networks) == set(worker_networks)
    assert next(iter(bridge_networks)).endswith("_cybersentinel")

    bridge_probe = f"""
import os
from pathlib import Path
state = Path(os.environ['CYBERSENTINEL_STATE_DIR']).resolve()
workspace = state / 'workspace'
assert os.getuid() == 10001 and os.getgid() == 10001
assert Path.cwd() == workspace.resolve(), (Path.cwd(), workspace)
for name in {STATE_PATH_VARIABLES!r}:
    path = Path(os.environ[name]).resolve()
    assert path.is_relative_to(state), (name, path)
workspace_probe = workspace / '.m3-v12-workspace-probe'
state_probe = state / '.m3-v12-state-probe'
workspace_probe.write_text('workspace-volume-ok', encoding='utf-8')
state_probe.write_text('state-volume-ok', encoding='utf-8')
try:
    Path('/app/.m3-v12-read-only-probe').write_text('must fail', encoding='utf-8')
except OSError:
    pass
else:
    Path('/app/.m3-v12-read-only-probe').unlink(missing_ok=True)
    raise AssertionError('application root unexpectedly writable')
"""
    worker_probe = f"""
import os
from pathlib import Path
state = Path(os.environ['CYBERSENTINEL_STATE_DIR']).resolve()
workspace = state / 'workspace'
assert os.getuid() == 10001 and os.getgid() == 10001
assert Path.cwd() == workspace.resolve(), (Path.cwd(), workspace)
assert (workspace / '.m3-v12-workspace-probe').read_text(encoding='utf-8') == 'workspace-volume-ok'
assert (state / '.m3-v12-state-probe').read_text(encoding='utf-8') == 'state-volume-ok'
(workspace / '.m3-v12-workspace-probe').unlink()
(state / '.m3-v12-state-probe').unlink()
"""
    _exec_python("bridge", bridge_probe)
    _exec_python("mission-worker", worker_probe)
    print("container health, mounts, UID, read-only root, loopback publish, private network, read-only secret files, and shared state/workspace contract: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.CalledProcessError) as exc:
        print(f"container contract verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
