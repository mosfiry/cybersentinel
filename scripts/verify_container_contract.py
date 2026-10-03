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
    assert initializer["State"]["ExitCode"] == 0, initializer["State"]

    bridge_state = bridge_mounts[str(STATE_ROOT)]
    worker_state = worker_mounts[str(STATE_ROOT)]
    init_state = init_mounts[str(STATE_ROOT)]
    assert bridge_state["Name"] == worker_state["Name"] == init_state["Name"]
    assert str(WORKSPACE) not in bridge_mounts and str(WORKSPACE) not in worker_mounts

    published = bridge["HostConfig"].get("PortBindings") or {}
    mappings = published.get("8787/tcp") or []
    assert mappings and all(mapping["HostIp"] == "127.0.0.1" for mapping in mappings), published
    assert not (worker["HostConfig"].get("PortBindings") or {}), "worker must not publish ports"

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
    print("container health, mount, UID, read-only root, loopback publish, and shared state/workspace contract: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.CalledProcessError) as exc:
        print(f"container contract verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
