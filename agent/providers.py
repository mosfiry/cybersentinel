from __future__ import annotations

import json
import urllib.request
from typing import Any

from .provider_api import ProviderCapabilities, ProviderResponse, ToolCall


class OpenAICompatibleProvider:
    def __init__(self, name: str, base_url: str, model: str, api_key: str = "", *, tool_calling: bool = False, streaming: bool = False, structured_output: bool = False, priority: int = 100):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.failure_count = 0
        self.last_error = ""
        self.priority = priority
        self.capabilities = ProviderCapabilities(generate=True, stream=streaming, tool_calling=tool_calling, structured_output=structured_output, chat=True)

    def status(self) -> dict:
        return {
            "name": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "configured": bool(self.base_url and self.model),
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "priority": self.priority,
            "capabilities": self.capabilities.__dict__.copy(),
        }

    def _request(self, payload: dict[str, Any], timeout: int = 90) -> dict[str, Any]:
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode())
            self.last_error = ""
            return data
        except Exception as exc:
            self.failure_count += 1
            self.last_error = str(exc)[:500]
            raise

    def _normalize(self, data: dict[str, Any], capability: str) -> ProviderResponse:
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            function = raw.get("function") or {}
            name = function.get("name")
            if not isinstance(name, str):
                continue
            args = function.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append(ToolCall(name, args if isinstance(args, dict) else {}, str(raw.get("id") or "")))
        return ProviderResponse(
            text=str(message.get("content") or ""),
            tool_calls=calls,
            finish_reason=str(choice.get("finish_reason") or ("tool_calls" if calls else "stop")),
            provider=self.name,
            model=self.model,
            usage=data.get("usage") or {},
            capability=capability,
        )

    def generate(self, messages: list[dict], temperature: float = 0, **kwargs: Any) -> ProviderResponse:
        return self._normalize(self._request({"model": self.model, "messages": messages, "temperature": temperature, **kwargs}), "generate")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, **kwargs: Any) -> ProviderResponse:
        if not self.capabilities.tool_calling:
            raise NotImplementedError("native tool calling unavailable")
        return self._normalize(self._request({"model": self.model, "messages": messages, "temperature": temperature, "tools": tools, **kwargs}), "tool_calling")

    def chat(self, messages: list[dict], temperature: float = 0, timeout: int = 90) -> dict:
        return self.generate(messages, temperature=temperature, timeout=timeout).public()
