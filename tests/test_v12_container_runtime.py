from __future__ import annotations

import os
import re
import select
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from http.client import HTTPConnection
from pathlib import Path
from urllib.request import urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _isolated_environment(state_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "BRIDGE_HOST",
        "BRIDGE_PORT",
        "BRIDGE_TOKEN",
        "BRIDGE_ALLOW_NON_LOOPBACK_BIND",
        "DB_PATH",
        "TASK_DB_PATH",
        "MEMORY_DB_PATH",
        "KNOWLEDGE_DB_PATH",
        "SCOPE_DB_PATH",
        "OWNER_POLICY_STATE_PATH",
        "PUBLIC_WEB_ENABLED",
        "PUBLIC_WEB_ORIGIN",
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_MODEL",
        "LOCAL_LLM_BASE_URL",
        "LOCAL_LLM_API_KEY",
        "LOCAL_LLM_MODEL",
        "COLAB_LLM_BASE_URL",
        "COLAB_LLM_API_KEY",
        "COLAB_LLM_MODEL",
        "HF_LLM_BASE_URL",
        "HF_LLM_API_KEY",
        "HF_LLM_MODEL",
    ):
        env.pop(name, None)
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "true",
            "DB_PATH": str(state_dir / "intel.db"),
            "TASK_DB_PATH": str(state_dir / "tasks.sqlite3"),
            "MEMORY_DB_PATH": str(state_dir / "memory.sqlite3"),
            "KNOWLEDGE_DB_PATH": str(state_dir / "knowledge.sqlite3"),
            "SCOPE_DB_PATH": str(state_dir / "scope.sqlite3"),
            "OWNER_POLICY_STATE_PATH": str(state_dir / "owner_policy_state.json"),
            "PUBLIC_WEB_ENABLED": "false",
        }
    )
    return env


def _run_config(*, host: str, allow: str = "false", token: str = "") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in ("BRIDGE_HOST", "BRIDGE_PORT", "BRIDGE_TOKEN", "BRIDGE_ALLOW_NON_LOOPBACK_BIND"):
        env.pop(name, None)
    env.update(
        {
            "PYTHON_DOTENV_DISABLED": "true",
            "BRIDGE_HOST": host,
            "BRIDGE_PORT": "8787",
            "BRIDGE_TOKEN": token,
            "BRIDGE_ALLOW_NON_LOOPBACK_BIND": allow,
        }
    )
    return subprocess.run(
        [sys.executable, "-c", "import core.config"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize("allow", ["", "false", "0", "no"])
def test_non_loopback_bridge_bind_requires_explicit_opt_in(allow: str) -> None:
    result = _run_config(host="0.0.0.0", allow=allow, token="test-bridge-token-that-is-long-enough-123456")
    assert result.returncode != 0
    assert "BRIDGE_ALLOW_NON_LOOPBACK_BIND" in result.stderr


def test_non_loopback_bridge_bind_requires_long_non_placeholder_token() -> None:
    weak = _run_config(host="0.0.0.0", allow="true", token="short")
    placeholder = _run_config(
        host="0.0.0.0",
        allow="true",
        token="REPLACE_WITH_A_RANDOM_BRIDGE_SECRET_123456789",
    )
    assert weak.returncode != 0
    assert "at least 32 characters" in weak.stderr
    assert placeholder.returncode != 0
    assert "non-placeholder" in placeholder.stderr


def test_non_loopback_bridge_bind_accepts_only_explicit_valid_container_config() -> None:
    allowed = _run_config(
        host="0.0.0.0",
        allow="true",
        token="ci-only-test-secret-not-a-credential-1234567890",
    )
    other_host = _run_config(
        host="192.0.2.10",
        allow="true",
        token="ci-only-test-secret-not-a-credential-1234567890",
    )
    default = _run_config(host="127.0.0.1")
    assert allowed.returncode == 0, allowed.stderr
    assert other_host.returncode != 0
    assert "must be 127.0.0.1" in other_host.stderr
    assert default.returncode == 0, default.stderr


def test_persistent_store_paths_can_be_redirected_to_one_state_volume(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    env = _isolated_environment(state_dir)
    env["STATE_DIR"] = str(state_dir)
    script = r"""
import os
import sqlite3
from pathlib import Path
import core.config as config
import agent.task_manager as task_manager
import agent.memory as memory
from knowledge import store as knowledge_store
from security import scope_store, owner_policy

state_dir = Path(os.environ["STATE_DIR"])
expected = {
    "core": state_dir / "intel.db",
    "tasks": state_dir / "tasks.sqlite3",
    "memory": state_dir / "memory.sqlite3",
    "knowledge": state_dir / "knowledge.sqlite3",
    "scope": state_dir / "scope.sqlite3",
    "policy": state_dir / "owner_policy_state.json",
}
actual = {
    "core": config.DB_PATH,
    "tasks": task_manager.DB_PATH,
    "memory": memory.MEMORY_DB_PATH,
    "knowledge": knowledge_store.DB_PATH,
    "scope": scope_store.SCOPE_DB_PATH,
    "policy": owner_policy.STATE_PATH,
}
assert actual == expected, (actual, expected)
knowledge_store.init_store()
owner_policy._save_state(owner_policy.load_state())
with sqlite3.connect(actual["core"]) as db:
    db.execute("CREATE TABLE IF NOT EXISTS isolated_probe (value INTEGER)")
for name in ("core", "tasks", "memory", "knowledge", "scope"):
    path = actual[name]
    assert path.exists(), (name, path)
    with sqlite3.connect(path) as db:
        db.execute("SELECT 1").fetchone()
assert actual["policy"].is_file()
print("isolated_state_paths_ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "isolated_state_paths_ok" in result.stdout
    assert set(path.name for path in state_dir.iterdir()) == {
        "intel.db",
        "tasks.sqlite3",
        "memory.sqlite3",
        "knowledge.sqlite3",
        "scope.sqlite3",
        "owner_policy_state.json",
    }


def test_bridge_sigterm_stops_cleanly_and_leaves_temporary_database_reopenable(tmp_path: Path) -> None:
    state_dir = tmp_path / "bridge-state"
    state_dir.mkdir()
    env = _isolated_environment(state_dir)
    env.update(
        {
            "BRIDGE_HOST": "127.0.0.1",
            "BRIDGE_PORT": "0",
            "BRIDGE_TOKEN": "test-only-local-bridge-token",
        }
    )
    child = subprocess.Popen(
        [sys.executable, str(ROOT / "bridge.py")],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        assert child.args == [sys.executable, str(ROOT / "bridge.py")]
        assert child.pid > 1
        assert Path(f"/proc/{child.pid}/cmdline").exists()
        deadline = time.monotonic() + 15
        port: int | None = None
        output: list[str] = []
        assert child.stdout is not None
        while time.monotonic() < deadline and port is None:
            if child.poll() is not None:
                output.extend(child.communicate(timeout=2)[0].splitlines())
                pytest.fail(f"bridge child exited before readiness: {output!r}")
            ready, _, _ = select.select([child.stdout], [], [], 0.1)
            if not ready:
                continue
            line = child.stdout.readline()
            output.append(line.rstrip("\n"))
            match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
            if match:
                port = int(match.group(1))
        assert port is not None, f"bridge child did not report its bound port: {output!r}"

        with urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3) as response:
            assert response.status == 200
            assert b'"ok": true' in response.read()

        # Signal only the exact child launched above, which has only temporary DB paths.
        child.send_signal(signal.SIGTERM)
        assert child.wait(timeout=10) == 0
    finally:
        if child.poll() is None:
            assert child.args == [sys.executable, str(ROOT / "bridge.py")]
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if child.stdout is not None:
            child.stdout.close()

    for name in ("intel.db", "tasks.sqlite3", "memory.sqlite3", "scope.sqlite3"):
        db_path = state_dir / name
        if not db_path.exists():
            continue
        with sqlite3.connect(db_path) as db:
            db.execute("SELECT 1").fetchone()


def test_bridge_server_close_waits_for_active_request_thread() -> None:
    from http.server import BaseHTTPRequestHandler

    from bridge import BridgeHTTPServer

    request_started = threading.Event()
    release_request = threading.Event()
    request_errors: list[Exception] = []

    class BlockingHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            request_started.set()
            if not release_request.wait(timeout=5):
                self.send_error(504)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"drained")

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = BridgeHTTPServer(("127.0.0.1", 0), BlockingHandler)
    serve_thread = threading.Thread(target=server.serve_forever, daemon=True)

    def make_request() -> None:
        client = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            client.request("GET", "/")
            response = client.getresponse()
            assert response.status == 200
            assert response.read() == b"drained"
        except Exception as exc:
            request_errors.append(exc)
        finally:
            client.close()

    request_thread = threading.Thread(target=make_request, daemon=True)
    close_thread: threading.Thread | None = None
    try:
        serve_thread.start()
        request_thread.start()
        assert request_started.wait(timeout=3), (
            serve_thread.is_alive(),
            request_thread.is_alive(),
            request_errors,
            server.server_address,
        )

        server.shutdown()
        serve_thread.join(timeout=3)
        assert not serve_thread.is_alive()

        close_thread = threading.Thread(target=server.server_close, daemon=True)
        close_thread.start()
        close_thread.join(timeout=0.05)
        assert close_thread.is_alive(), "server_close returned before the active handler drained"

        release_request.set()
        request_thread.join(timeout=3)
        close_thread.join(timeout=3)
        assert not request_thread.is_alive()
        assert not close_thread.is_alive()
        assert request_errors == []
    finally:
        release_request.set()
        if serve_thread.is_alive():
            server.shutdown()
        serve_thread.join(timeout=3)
        if close_thread is None:
            server.server_close()
        else:
            close_thread.join(timeout=3)
        request_thread.join(timeout=3)
