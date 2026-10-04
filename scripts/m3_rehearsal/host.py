"""Isolated Docker Compose host adapter for the M3 V16 rehearsal."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = REPO_ROOT / "compose.yaml"
OVERLAY_COMPOSE = REPO_ROOT / "tests" / "compose.m3-rehearsal.yaml"
STATE_ROOT = Path("/var/lib/cybersentinel")
OWNER_USERNAME = "mosfiry"
WORKER_ID = "m3-v16-rehearsal-worker"
CRASH_MARKER = ".m3-v16-crash-once"
DISPATCHED_MARKER = ".m3-v16-effect-dispatched"
RELEASE_MARKER = ".m3-v16-crash-release"
PROVIDER_MARKER = ".m3-v16-provider-violation"
CRASH_EXIT_CODE = 73
LEASE_SECONDS = 5
HOST_RELEASE_SECONDS = 45
STAGE_ORDER = (
    "deploy_build",
    "legacy_state_seed",
    "startup",
    "health",
    "owner_login",
    "mission_creation",
    "worker_execution",
    "schema_upgrade",
    "queue_state",
    "evidence",
    "controlled_crash",
    "same_identity_restart",
    "recovery_owner_reauthorization",
    "graceful_shutdown",
    "backup",
    "restore",
)
PROVIDER_ENV_KEYS = (
    "LLM_BASE_URL",
    "LLM_API_KEY",
    "LLM_MODEL",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "LOCAL_LLM_BASE_URL",
    "LOCAL_LLM_API_KEY",
    "LOCAL_LLM_MODEL",
    "COLAB_LLM_BASE_URL",
    "COLAB_LLM_API_KEY",
    "COLAB_LLM_MODEL",
    "HF_LLM_BASE_URL",
    "HF_LLM_API_KEY",
    "HF_LLM_MODEL",
)

_BOOTSTRAP_OWNER = """import json,sys
from security.owner_password import create_owner_account
data=json.loads(sys.stdin.read())
create_owner_account(data['username'],data['password'])
print('{\"created\":true}')
"""
_PROVIDER_GUARD = """\
import json
import os
from pathlib import Path

from core.config import DB_PATH
from core.engine import RUNTIME

keys = (
    "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "LOCAL_LLM_BASE_URL", "LOCAL_LLM_API_KEY", "LOCAL_LLM_MODEL",
    "COLAB_LLM_BASE_URL", "COLAB_LLM_API_KEY", "COLAB_LLM_MODEL",
    "HF_LLM_BASE_URL", "HF_LLM_API_KEY", "HF_LLM_MODEL",
)
root = Path(os.environ.get("CYBERSENTINEL_M3_STATE_ROOT", "")).resolve()
db = Path(DB_PATH).resolve()
print(json.dumps({
    "rehearsal": os.environ.get("CYBERSENTINEL_M3_REHEARSAL") == "1",
    "providers_empty": all(not os.environ.get(key) for key in keys),
    "router_empty": not tuple(RUNTIME.router.providers),
    "db_under_state": db.parent == root,
}))
"""
_MARKER_PROBE = """import json,sys
from pathlib import Path
root=Path('/var/lib/cybersentinel')
allowed={'.m3-v16-crash-once','.m3-v16-effect-dispatched','.m3-v16-crash-release','.m3-v16-provider-violation'}
name=sys.argv[1]
if name not in allowed: raise SystemExit(2)
p=root/name
print(json.dumps({'exists':p.is_file(),'symlink':p.is_symlink()}))
"""
_MARKER_CREATE = """import sys
from pathlib import Path
root=Path('/var/lib/cybersentinel')
allowed={'.m3-v16-crash-once','.m3-v16-crash-release'}
name=sys.argv[1]
if name not in allowed: raise SystemExit(2)
p=root/name
if p.is_symlink() or p.exists(): raise SystemExit(3)
with p.open('x',encoding='utf-8') as f: f.write('host release marker\\n')
"""
_STATE_PROBE = """\
import json
import sqlite3
import sys
from pathlib import Path

from agent.external_effects import ExternalEffectLedger
from core.config import DB_PATH
from core.db import watches

mission_id, worker_id, keyword = sys.argv[1:4]
root = Path("/var/lib/cybersentinel").resolve()
base = Path(DB_PATH).resolve()
queue_path = base.with_name("mission_queue.sqlite3")
result = {
    "db_under_state": base.parent == root,
    "queue_db_under_state": queue_path.resolve().parent == root,
    "queue": None,
    "generation": None,
    "watch_count": sum(1 for item in watches() if item == keyword),
    "effects": [],
}
uri = f"file:{queue_path.as_posix()}?mode=ro"
with sqlite3.connect(uri, uri=True, timeout=5) as con:
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "SELECT state,attempts,lease_expires_at,lease_epoch,lease_owner,"
            "runtime_generation FROM mission_queue WHERE mission_id=?",
            (mission_id,),
        ).fetchone()
        if row is not None:
            fields = (
                "state", "attempts", "lease_expires_at", "lease_epoch",
                "runtime_generation",
            )
            result["queue"] = {key: row[key] for key in fields}
            result["queue"]["lease_owned"] = bool(row["lease_owner"])
    except sqlite3.OperationalError:
        pass
    try:
        row = con.execute(
            "SELECT runtime_generation,state FROM mission_worker_generations "
            "WHERE worker_id=? ORDER BY runtime_generation DESC LIMIT 1",
            (worker_id,),
        ).fetchone()
        if row is not None:
            result["generation"] = {
                "runtime_generation": int(row["runtime_generation"]),
                "state": row["state"],
            }
    except sqlite3.OperationalError:
        pass
ledger = ExternalEffectLedger(queue_path)
for effect in ledger.list_effects(mission_id=mission_id, limit=20):
    history = ledger.history(effect.effect_id, limit=100)
    result["effects"].append({
        "effect_id": effect.effect_id,
        "operation": effect.operation,
        "provider": effect.provider,
        "state": effect.state,
        "events": [str(item.get("event_type", "")) for item in history],
    })
print(json.dumps(result, sort_keys=True))
"""

_LEGACY_MIGRATION_PROBE = """\
import json
import sqlite3
from pathlib import Path

root = Path('/var/lib/cybersentinel')

with sqlite3.connect(root / 'intel.db') as db:
    db.row_factory = sqlite3.Row
    core_columns = {row[1] for row in db.execute('PRAGMA table_info(executions)')}
    core_row = db.execute(
        "SELECT source,status,error,cancel_requested,owner_session_id "
        "FROM executions WHERE request_id='v12-legacy-execution'"
    ).fetchone()
with sqlite3.connect(root / 'tasks.sqlite3') as db:
    db.row_factory = sqlite3.Row
    task_columns = {row[1] for row in db.execute('PRAGMA table_info(tasks)')}
    task_row = db.execute(
        "SELECT task_id,objective,task_version FROM tasks WHERE task_id='v12-legacy-task'"
    ).fetchone()
with sqlite3.connect(root / 'mission_queue.sqlite3') as db:
    db.row_factory = sqlite3.Row
    queue_columns = {row[1] for row in db.execute('PRAGMA table_info(mission_queue)')}
    queue_row = db.execute(
        "SELECT mission_id,attempts,last_error,lease_epoch,claim_fence_id "
        "FROM mission_queue WHERE mission_id='v12-legacy-queue'"
    ).fetchone()

checks = {
    'execution_columns_added': {'cancel_requested', 'owner_session_id'} <= core_columns,
    'execution_row_preserved': bool(core_row and core_row['source'] == 'v12-legacy-fixture' and core_row['status'] == 'completed' and core_row['error'] == 'preserve-me'),
    'task_version_column_added': 'task_version' in task_columns,
    'task_row_preserved': bool(task_row and task_row['objective'] == 'preserve legacy task' and task_row['task_version'] == 0),
    'queue_fence_columns_added': {'lease_epoch', 'runtime_generation', 'claim_phase', 'claim_fence_id', 'worker_instance_id'} <= queue_columns,
    'queue_row_preserved': bool(queue_row and queue_row['attempts'] == 4 and queue_row['last_error'] == 'preserve legacy queue row' and queue_row['lease_epoch'] == 0),
}
print(json.dumps({'checks': checks, 'all_passed': all(checks.values())}, sort_keys=True))
"""


class RehearsalFailure(RuntimeError):
    """A failure with a deliberately sanitized, non-secret reason code."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _safe_environment(
    *, image: str, published_port: int
) -> dict[str, str]:
    """Pass only a minimal environment to the disposable local Docker engine."""
    allowed_host_keys = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "TZ",
        "USER",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed_host_keys}
    # Force the disposable rehearsal onto the CI host's local Docker engine.
    env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    env.update(
        {
            "M3_REHEARSAL_IMAGE": image,
            "BRIDGE_PUBLISHED_PORT": str(published_port),
            "BRIDGE_HOST": "0.0.0.0",
            "PUBLIC_WEB_ENABLED": "0",
            "CYBERSENTINEL_STATE_DIR": str(STATE_ROOT),
            "DB_PATH": str(STATE_ROOT / "intel.db"),
        }
    )
    return env


class DockerHost:
    """Narrow command adapter; every command is argv-based and output-redacted."""

    def __init__(
        self,
        *,
        project: str,
        image: str,
        port: int,
        env: dict[str, str],
    ) -> None:
        self.project = project
        self.image = image
        self.env = env
        self.compose_base = [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "--project-directory",
            str(REPO_ROOT),
            "--project-name",
            project,
            "--file",
            str(BASE_COMPOSE),
            "--file",
            str(OVERLAY_COMPOSE),
        ]
        self.worker_names: list[str] = []
        self.worker_processes: list[subprocess.Popen[bytes]] = []
        self.image_built = False
        self.remove_image = True

    @staticmethod
    def _run(
        argv: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        input_text: str | None = None,
        check: bool = True,
    ) -> str:
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                input=input_text,
                stdin=None if input_text is not None else subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RehearsalFailure("docker_cli_unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise RehearsalFailure("docker_command_timeout") from exc
        except OSError as exc:
            raise RehearsalFailure("docker_command_os_error") from exc
        if check and completed.returncode != 0:
            raise RehearsalFailure(f"docker_command_exit_{completed.returncode}")
        return completed.stdout.strip()

    def compose(
        self,
        *args: str,
        timeout: int = 90,
        input_text: str | None = None,
        check: bool = True,
    ) -> str:
        return self._run(
            [*self.compose_base, *args],
            cwd=REPO_ROOT,
            env=self.env,
            timeout=timeout,
            input_text=input_text,
            check=check,
        )

    def docker(self, *args: str, timeout: int = 30, check: bool = True) -> str:
        return self._run(
            ["docker", *args],
            cwd=REPO_ROOT,
            env=self.env,
            timeout=timeout,
            check=check,
        )

    def start_worker(self, name: str) -> subprocess.Popen[bytes]:
        if not re.fullmatch(r"m3v16-[a-f0-9]{12}-worker-[12]", name):
            raise RehearsalFailure("unsafe_worker_name")
        command = [
            *self.compose_base,
            "run",
            "--rm",
            "--no-deps",
            "--no-TTY",
            "--name",
            name,
            "mission-worker",
            "python",
            "-m",
            "scripts.run_mission_worker",
            "--worker-id",
            WORKER_ID,
            "--poll-interval",
            "0.05",
            "--max-polls",
            "10000",
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=REPO_ROOT,
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as exc:
            raise RehearsalFailure("worker_start_failed") from exc
        self.worker_names.append(name)
        self.worker_processes.append(process)
        return process

    @staticmethod
    def wait_worker(process: subprocess.Popen[bytes], timeout: int) -> int:
        try:
            return int(process.wait(timeout=timeout))
        except subprocess.TimeoutExpired as exc:
            raise RehearsalFailure("worker_exit_timeout") from exc

    def bootstrap_owner(self, password: str) -> None:
        output = self.compose(
            "exec",
            "--no-TTY",
            "bridge",
            "python",
            "-c",
            _BOOTSTRAP_OWNER,
            input_text=json.dumps({"username": OWNER_USERNAME, "password": password}),
        )
        if output != '{"created":true}':
            raise RehearsalFailure("synthetic_owner_bootstrap_failed")

    def provider_guard(self) -> dict[str, Any]:
        output = self.compose(
            "exec", "--no-TTY", "bridge", "python", "-c", _PROVIDER_GUARD
        )
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("provider_guard_probe_invalid") from exc

    def set_marker(self, name: str) -> None:
        if name not in {CRASH_MARKER, RELEASE_MARKER}:
            raise RehearsalFailure("unsafe_marker_name")
        self.compose(
            "exec",
            "--no-TTY",
            "bridge",
            "python",
            "-c",
            _MARKER_CREATE,
            name,
        )

    def marker_state(self, name: str) -> dict[str, Any]:
        if name not in {
            CRASH_MARKER,
            DISPATCHED_MARKER,
            RELEASE_MARKER,
            PROVIDER_MARKER,
        }:
            raise RehearsalFailure("unsafe_marker_name")
        output = self.compose(
            "exec", "--no-TTY", "bridge", "python", "-c", _MARKER_PROBE, name
        )
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("marker_probe_invalid") from exc
        if result.get("symlink"):
            raise RehearsalFailure("marker_symlink_detected")
        return result

    def state_probe(self, mission_id: str, keyword: str) -> dict[str, Any]:
        output = self.compose(
            "exec",
            "--no-TTY",
            "bridge",
            "python",
            "-c",
            _STATE_PROBE,
            mission_id,
            WORKER_ID,
            keyword,
        )
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("state_probe_invalid") from exc

    def seed_legacy_state(self) -> dict[str, Any]:
        output = self.compose(
            "run",
            "--rm",
            "--no-deps",
            "--no-TTY",
            "--entrypoint",
            "python",
            "workspace-init",
            "/m3-rehearsal/prepare_legacy_state.py",
            timeout=30,
        )
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("legacy_fixture_result_invalid") from exc
        if result.get("legacy_rows_seeded") != 3:
            raise RehearsalFailure("legacy_fixture_seed_failed")
        return result

    def legacy_migration_probe(self) -> dict[str, Any]:
        output = self.compose(
            "exec", "--no-TTY", "bridge", "python", "-c", _LEGACY_MIGRATION_PROBE
        )
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RehearsalFailure("legacy_migration_probe_invalid") from exc
        if result.get("all_passed") is not True:
            raise RehearsalFailure("legacy_schema_upgrade_invariants_failed")
        return result

    def state_archive(
        self,
        command: str,
        *,
        input_path: Path | None = None,
        output_path: Path | None = None,
        timeout: int = 180,
    ) -> str:
        if command not in {"backup", "verify", "restore"}:
            raise RehearsalFailure("unsafe_state_archive_command")
        argv = [
            *self.compose_base,
            "run",
            "--rm",
            "--no-deps",
            "--no-TTY",
            "--entrypoint",
            "python",
            "workspace-init",
            "/app/scripts/state_archive.py",
            command,
        ]
        source = None
        destination = None
        created_path = False
        succeeded = False
        try:
            if input_path is not None:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                source = os.fdopen(os.open(input_path, flags), "rb")
            if output_path is not None:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                destination = os.fdopen(os.open(output_path, flags, 0o600), "wb")
                created_path = True
            completed = subprocess.run(
                argv,
                cwd=REPO_ROOT,
                env=self.env,
                stdin=source if source is not None else subprocess.DEVNULL,
                stdout=destination if destination is not None else subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            if destination is not None:
                destination.flush()
                os.fsync(destination.fileno())
            if completed.returncode != 0:
                raise RehearsalFailure("state_archive_command_failed")
            succeeded = True
            return completed.stdout.strip() if destination is None else ""
        except FileNotFoundError as exc:
            raise RehearsalFailure("state_archive_file_unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise RehearsalFailure("state_archive_command_timeout") from exc
        except OSError as exc:
            raise RehearsalFailure("state_archive_host_io_failed") from exc
        finally:
            if source is not None:
                source.close()
            if destination is not None:
                destination.close()
            if created_path and output_path is not None:
                if succeeded:
                    os.chmod(output_path, 0o600, follow_symlinks=False)
                else:
                    try:
                        output_path.unlink()
                    except FileNotFoundError:
                        pass

    def cleanup(self) -> dict[str, Any]:
        errors: list[str] = []
        if self.worker_names:
            for name in self.worker_names:
                self.docker("container", "rm", "--force", name, check=False)
        if self.image_built:
            self.compose(
                "down",
                "--volumes",
                "--remove-orphans",
                "--timeout",
                "10",
                timeout=30,
                check=False,
            )
            if self.remove_image:
                self.docker("image", "rm", self.image, check=False)
            for process in self.worker_processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            errors.append("worker_cli_process_remained")
            checks = (
                (
                    "containers",
                    [
                        "ps",
                        "--all",
                        "--quiet",
                        "--filter",
                        f"label=com.docker.compose.project={self.project}",
                    ],
                ),
                (
                    "volumes",
                    [
                        "volume",
                        "ls",
                        "--quiet",
                        "--filter",
                        f"label=com.docker.compose.project={self.project}",
                    ],
                ),
                (
                    "networks",
                    [
                        "network",
                        "ls",
                        "--quiet",
                        "--filter",
                        f"label=com.docker.compose.project={self.project}",
                    ],
                ),
                ("image_tags", ["image", "ls", "--quiet", self.image])
                if self.remove_image
                else ("image_tags", []),
            )
            leftovers: dict[str, int] = {}
            for label, args in checks:
                if not args:
                    leftovers[label] = 0
                    continue
                try:
                    output = self.docker(*args, check=False)
                    count = len([line for line in output.splitlines() if line.strip()])
                    leftovers[label] = count
                    if count:
                        errors.append(f"{label}_remain")
                except RehearsalFailure:
                    errors.append(f"{label}_verification_failed")
        else:
            leftovers = {"containers": 0, "volumes": 0, "networks": 0, "image_tags": 0}
        return {
            "status": "PASS" if not errors else "FAIL",
            "leftovers": leftovers,
            "errors": errors,
        }
