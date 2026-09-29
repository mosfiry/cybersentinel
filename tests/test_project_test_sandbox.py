from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import textwrap
import time

import pytest

import tools.registry as registry
from workspace.environment import ProcessResult


class _SubprocessWorkspace:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.command: tuple[str, ...] = ()

    def resolve(self, relative: str = ".") -> Path:
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise PermissionError("outside workspace")
        return candidate

    def develop(self, command, *, timeout=None, cwd="."):
        self.command = tuple(command)
        started = time.monotonic()
        completed = subprocess.run(
            command,
            cwd=self.resolve(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return ProcessResult(
            tuple(command),
            completed.stdout,
            completed.stderr,
            completed.returncode,
            False,
            time.monotonic() - started,
        )


def test_database_paths_default_to_repository_files_without_overrides():
    repository = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment.pop("CYBERSENTINEL_MEMORY_DB_PATH", None)
    environment.pop("CYBERSENTINEL_TASKS_DB_PATH", None)
    script = textwrap.dedent(
        """
        import sqlite3
        from pathlib import Path

        class _Result:
            def fetchall(self):
                return []

        class _Connection:
            def execute(self, *_args, **_kwargs):
                return _Result()
            def commit(self):
                pass
            def rollback(self):
                pass
            def close(self):
                pass

        sqlite3.connect = lambda *_args, **_kwargs: _Connection()
        from agent import memory, task_manager

        root = Path(memory.__file__).resolve().parents[1]
        assert memory.MEMORY_DB_PATH == root / "memory.sqlite3"
        assert task_manager.DB_PATH == root / "tasks.sqlite3"
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_sandbox_environment_uses_fixed_tmpfs_database_paths(monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_MEMORY_DB_PATH", "/workspace/host-memory.sqlite3")
    monkeypatch.setenv("CYBERSENTINEL_TASKS_DB_PATH", "/workspace/host-tasks.sqlite3")

    args = registry._sandbox_python_environment_args(Path("/usr"))

    assert args[args.index("CYBERSENTINEL_MEMORY_DB_PATH") + 1] == "/tmp/cybersentinel-pytest-memory.sqlite3"
    assert args[args.index("CYBERSENTINEL_TASKS_DB_PATH") + 1] == "/tmp/cybersentinel-pytest-tasks.sqlite3"
    assert "/workspace/host-memory.sqlite3" not in args
    assert "/workspace/host-tasks.sqlite3" not in args


def test_sandbox_environment_allows_only_prefix_library_path(tmp_path, monkeypatch):
    prefix = tmp_path / "python"
    library_dir = prefix / "lib"
    library_dir.mkdir(parents=True)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/host-only/untrusted-libraries")

    args = registry._sandbox_python_environment_args(prefix)

    assert "--clearenv" in args
    assert args[args.index("LD_LIBRARY_PATH") + 1] == str(library_dir)
    assert "/host-only/untrusted-libraries" not in args


def test_sandbox_environment_does_not_inherit_library_path_without_prefix_lib(tmp_path, monkeypatch):
    monkeypatch.setenv("LD_LIBRARY_PATH", "/host-only/untrusted-libraries")

    args = registry._sandbox_python_environment_args(tmp_path)

    assert "LD_LIBRARY_PATH" not in args
    assert "/host-only/untrusted-libraries" not in args


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (b"bwrap: unshare failed: Operation not permitted", "Unavailable: host denied required OS namespace isolation"),
        (b"python: error while loading shared libraries: libpython.so", "Unavailable: isolated Python runtime library path is unavailable"),
        (b"execvp python: No such file or directory", "Unavailable: isolated Python executable or dependency path is inaccessible"),
    ],
)
def test_sandbox_preflight_failure_reason_is_normalized(output, expected):
    reason = registry._sandbox_preflight_failure_reason(output)

    assert reason == expected
    assert output.decode("utf-8") not in reason


def test_project_tests_run_in_secret_filtered_readonly_networkless_sandbox(tmp_path, monkeypatch):
    if not registry._PROJECT_TEST_SANDBOX_AVAILABLE:
        assert not registry.get_tool("run_project_tests").available
        with pytest.raises(registry.ToolUnavailableError, match="Unavailable"):
            registry._run_project_tests(".", workspace=object())
        return

    root = tmp_path / "project"
    root.mkdir()
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "agent",
        root / "agent",
        ignore=registry._project_snapshot_ignore,
    )
    (root / "config").mkdir()
    (root / ".aws").mkdir()
    (root / ".ssh").mkdir()
    (root / ".env").write_text("ROOT_SECRET=must-not-copy\n", encoding="utf-8")
    (root / ".env.example").write_text("SAFE=example\n", encoding="utf-8")
    (root / "config" / ".env.local").write_text("NESTED_SECRET=must-not-copy\n", encoding="utf-8")
    (root / "credentials.pem").write_text("KEY=must-not-copy\n", encoding="utf-8")
    (root / ".aws" / "credentials").write_text("CLOUD_SECRET=must-not-copy\n", encoding="utf-8")
    (root / ".ssh" / "id_ed25519").write_text("SSH_SECRET=must-not-copy\n", encoding="utf-8")
    host_canary = Path("/tmp/cybersentinel-project-test-host-canary")
    host_canary.write_text("host-only", encoding="utf-8")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host_port = listener.getsockname()[1]

    (root / "conftest.py").write_text(
        "from pathlib import Path\n"
        "import os, socket\n"
        "from agent import memory, task_manager\n"
        "assert memory.MEMORY_DB_PATH == Path('/tmp/cybersentinel-pytest-memory.sqlite3')\n"
        "assert task_manager.DB_PATH == Path('/tmp/cybersentinel-pytest-tasks.sqlite3')\n"
        "assert Path('/tmp/cybersentinel-pytest-memory.sqlite3').is_file()\n"
        "assert Path('/tmp/cybersentinel-pytest-tasks.sqlite3').is_file()\n"
        "assert os.environ.get('CYBERSENTINEL_MEMORY_DB_PATH') == str(memory.MEMORY_DB_PATH)\n"
        "assert os.environ.get('CYBERSENTINEL_TASKS_DB_PATH') == str(task_manager.DB_PATH)\n"
        "assert not Path('/tmp/cybersentinel-project-test-host-canary').exists()\n"
        "assert not Path('/workspace/.env').exists()\n"
        "assert Path('/workspace/.env.example').exists()\n"
        "assert not Path('/workspace/config/.env.local').exists()\n"
        "assert not Path('/workspace/credentials.pem').exists()\n"
        "assert not Path('/workspace/.aws/credentials').exists()\n"
        "assert not Path('/workspace/.ssh/id_ed25519').exists()\n"
        "assert 'CYBERSENTINEL_HOST_SECRET' not in os.environ\n"
        "assert os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD') == '1'\n"
        "assert os.environ.get('PYTHONNOUSERSITE') == '1'\n"
        "try:\n"
        f"    socket.create_connection(('127.0.0.1', {host_port}), timeout=0.5)\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('host loopback remained reachable')\n"
        "try:\n"
        "    Path('/workspace/should-not-write').write_text('modified')\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('project snapshot is writable')\n",
        encoding="utf-8",
    )
    (root / "test_sample.py").write_text("def test_sandbox_temp_write(tmp_path):\n    marker = tmp_path / 'ok.txt'\n    marker.write_text('isolated')\n    assert marker.read_text() == 'isolated'\n", encoding="utf-8")
    monkeypatch.setenv("CYBERSENTINEL_HOST_SECRET", "host-env-canary")
    monkeypatch.setenv("CYBERSENTINEL_MEMORY_DB_PATH", "/workspace/host-memory.sqlite3")
    monkeypatch.setenv("CYBERSENTINEL_TASKS_DB_PATH", "/workspace/host-tasks.sqlite3")

    workspace = _SubprocessWorkspace(root)
    try:
        result = registry._run_project_tests(".", workspace=workspace)
    finally:
        listener.close()
        host_canary.unlink(missing_ok=True)

    assert result["ok"] is True, result["output"]
    assert "1 passed" in result["output"]
    assert workspace.command[0] == registry._PRLIMIT
    assert "--cpu=60" in workspace.command
    assert registry._BWRAP in workspace.command
    assert "/workspace" in workspace.command
    assert workspace.command[workspace.command.index("LD_LIBRARY_PATH") + 1] == str(Path(registry.sys.prefix).resolve() / "lib")
    workspace_mount = workspace.command.index("/workspace")
    assert workspace.command[workspace_mount - 2] == "--ro-bind"
    tmpfs = workspace.command.index("--tmpfs")
    assert workspace.command[tmpfs + 1] == "/tmp"
    assert not (root / "should-not-write").exists()
