from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
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


def test_project_tests_run_in_secret_filtered_readonly_networkless_sandbox(tmp_path, monkeypatch):
    if not registry._PROJECT_TEST_SANDBOX_AVAILABLE:
        assert not registry.get_tool("run_project_tests").available
        with pytest.raises(registry.ToolUnavailableError, match="Unavailable"):
            registry._run_project_tests(".", workspace=object())
        return

    root = tmp_path / "project"
    root.mkdir()
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
    assert not (root / "should-not-write").exists()
