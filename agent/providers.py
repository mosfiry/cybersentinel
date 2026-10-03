from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .provider_api import MAX_PROVIDER_RESPONSE_BYTES, InvalidModelResponse, ProviderCapabilities, ProviderResponse, ToolCall


class OpenAICompatibleProvider:
    def __init__(self, name: str, base_url: str, model: str, api_key: str = "", *, tool_calling: bool = False, streaming: bool = False, structured_output: bool = False, priority: int = 100, parallel_tool_calls: bool = False, reasoning: bool = False, reasoning_budget: bool = False, long_context: bool = False, vision: bool = False):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.failure_count = 0
        self.last_error = ""
        self.priority = priority
        self.capabilities = ProviderCapabilities(generate=True, stream=streaming, tool_calling=tool_calling, structured_output=structured_output, chat=True, native_chat=True, parallel_tool_calls=parallel_tool_calls, reasoning=reasoning, reasoning_budget=reasoning_budget, long_context=long_context, vision=vision)

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
                raw_body = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                if not isinstance(raw_body, (bytes, bytearray)):
                    raise InvalidModelResponse("provider returned a non-byte response body", provider=self.name, model=self.model)
                if len(raw_body) > MAX_PROVIDER_RESPONSE_BYTES:
                    raise InvalidModelResponse("provider response exceeds the configured size limit", provider=self.name, model=self.model)
                try:
                    data = json.loads(bytes(raw_body).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise InvalidModelResponse("provider returned malformed JSON", provider=self.name, model=self.model) from exc
            if not isinstance(data, dict):
                raise InvalidModelResponse("provider returned a non-object response", provider=self.name, model=self.model)
            self.last_error = ""
            return data
        except urllib.error.HTTPError as exc:
            self.failure_count += 1
            self.last_error = f"HTTP {exc.code}"
            try:
                exc.close()
            except Exception:
                pass
            raise
        except Exception as exc:
            self.failure_count += 1
            self.last_error = type(exc).__name__
            raise

    def _normalize(self, data: dict[str, Any], capability: str) -> ProviderResponse:
        def invalid(message: str) -> InvalidModelResponse:
            return InvalidModelResponse(message, provider=self.name, model=self.model)

        if not isinstance(data, dict):
            raise invalid("provider returned a non-object response")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise invalid("provider returned no valid choice")
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            raise invalid("provider returned no valid message")
        raw_calls = message.get("tool_calls")
        if raw_calls is None:
            raw_calls = []
        if not isinstance(raw_calls, list):
            raise invalid("provider returned malformed tool calls")
        calls: list[ToolCall] = []
        for raw in raw_calls:
            if not isinstance(raw, dict):
                raise invalid("provider returned malformed tool call")
            function = raw.get("function")
            if not isinstance(function, dict):
                raise invalid("provider returned malformed tool function")
            name = function.get("name")
            if not isinstance(name, str) or not name.strip():
                raise invalid("provider returned a tool call without a valid name")
            args = function.get("arguments", {})
            if args is None:
                args = {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError) as exc:
                    raise invalid("provider returned malformed tool arguments") from exc
            if not isinstance(args, dict):
                raise invalid("provider tool arguments must be an object")
            calls.append(ToolCall(name, args, str(raw.get("id") or "")))
        finish_reason = choice.get("finish_reason")
        if finish_reason is not None and not isinstance(finish_reason, str):
            raise invalid("provider returned malformed finish reason")
        if finish_reason in {"tool_calls", "function_call"} and not calls:
            raise invalid("provider reported tool calls without a valid call")
        usage = data.get("usage")
        if usage is None:
            usage = {}
        if not isinstance(usage, dict):
            raise invalid("provider returned malformed usage metadata")
        content = message.get("content")
        if content is None:
            content = ""
        elif not isinstance(content, str):
            raise invalid("provider returned malformed text")
        return ProviderResponse(
            text=content,
            tool_calls=calls,
            finish_reason=str(finish_reason or ("tool_calls" if calls else "stop")),
            provider=self.name,
            model=self.model,
            usage=usage,
            capability=capability,
        )

    def generate(self, messages: list[dict], temperature: float = 0, timeout: int = 90, **kwargs: Any) -> ProviderResponse:
        payload = {"model": self.model, "messages": messages, "temperature": temperature, **kwargs}
        return self._normalize(self._request(payload, timeout=timeout), "generate")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, timeout: int = 90, **kwargs: Any) -> ProviderResponse:
        if not self.capabilities.tool_calling:
            raise NotImplementedError("native tool calling unavailable")
        payload = {"model": self.model, "messages": messages, "temperature": temperature, "tools": tools, **kwargs}
        return self._normalize(self._request(payload, timeout=timeout), "tool_calling")

    def chat(self, messages: list[dict], temperature: float = 0, timeout: int = 90) -> dict:
        return self.generate(messages, temperature=temperature, timeout=timeout).public()
