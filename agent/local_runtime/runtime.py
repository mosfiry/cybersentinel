from __future__ import annotations

import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from agent.model_router import ModelRouter
from agent.provider_api import ProviderCapabilities
from agent.providers import OpenAICompatibleProvider

from .catalog import ModelSpec


class RuntimeAdapter(Protocol):
    """Provider-neutral lifecycle contract for pluggable local inference engines."""

    def start(self, spec: ModelSpec, model_path: Path): ...
    def stop(self) -> None: ...


class LlamaCppRuntime:
    def __init__(self, runtime_dir: str | Path, *, startup_timeout: float = 180.0):
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.startup_timeout = startup_timeout
        self.process: subprocess.Popen | None = None
        self.provider: OpenAICompatibleProvider | None = None
        self.port: int | None = None
        self._api_key = ""

    def _binary(self) -> Path:
        names = ("llama-server.exe", "llama-server") if os.name == "nt" else ("llama-server",)
        for name in names:
            candidate = self.runtime_dir / name
            if candidate.is_file():
                return candidate
        raise FileNotFoundError("llama_runtime_not_installed")

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def start(self, spec: ModelSpec, model_path: Path) -> OpenAICompatibleProvider:
        self.stop()
        executable = self._binary()
        port = self._free_loopback_port()
        api_key = secrets.token_urlsafe(32)
        cpu_count = max(1, int(os.cpu_count() or 1))
        thread_count = max(1, min(cpu_count - 1 if cpu_count > 1 else 1, 16))
        arguments = [
            str(executable),
            "--model", str(model_path.resolve()),
            "--host", "127.0.0.1",
            "--port", str(port),
            "--alias", spec.model_id,
            "--ctx-size", str(spec.context_length),
            "--threads", str(thread_count),
            "--api-key", api_key,
            "--no-webui",
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt" and hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.process = subprocess.Popen(
            arguments,
            cwd=str(self.runtime_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        self.port = port
        self._api_key = api_key
        deadline = time.monotonic() + self.startup_timeout
        health_url = f"http://127.0.0.1:{port}/health"
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.stop()
                raise RuntimeError("llama_runtime_exited_before_ready")
            try:
                request = urllib.request.Request(
                    health_url,
                    headers={"Authorization": "Bearer " + api_key},
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.25)
        else:
            self.stop()
            raise TimeoutError("llama_runtime_startup_timeout")

        self.provider = OpenAICompatibleProvider(
            "local_llama_cpp",
            f"http://127.0.0.1:{port}/v1",
            spec.model_id,
            api_key,
            tool_calling=True,
            streaming=False,
            structured_output=False,
            priority=0,
        )
        self.provider.capabilities = ProviderCapabilities(
            generate=True,
            stream=False,
            tool_calling=True,
            structured_output=False,
            chat=True,
            native_chat=True,
            parallel_tool_calls=False,
            reasoning=False,
            reasoning_budget=False,
            long_context=False,
            vision=False,
        )
        return self.provider

    def stop(self) -> None:
        process = self.process
        self.process = None
        self.provider = None
        self.port = None
        self._api_key = ""
        if process is None or process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            pass

    def router(self, provider: OpenAICompatibleProvider) -> ModelRouter:
        return ModelRouter([provider])
