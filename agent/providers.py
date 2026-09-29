from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Iterable

from .context import sanitize_model_text
from .provider_api import ProviderCapabilities, ProviderResponse, ToolCall


class OpenAICompatibleProvider:
    """Synchronous OpenAI-compatible inference adapter with bounded HTTP calls."""

    def __init__(
        self,
        name: str,
        base_url: str,
        model: str,
        api_key: str = "",
        *,
        tool_calling: bool = False,
        streaming: bool = False,
        structured_output: bool = False,
        priority: int = 100,
        parallel_tool_calls: bool = False,
        reasoning: bool = False,
        reasoning_budget: bool = False,
        long_context: bool = False,
        vision: bool = False,
        profile_id: str | None = None,
        model_capabilities: Iterable[str] = (),
        cost_per_1k_tokens_usd: float | None = None,
    ):
        self.name = name
        self.profile_id = profile_id
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.failure_count = 0
        self.last_error = ""
        self.priority = priority
        self.model_capabilities = frozenset(str(item).strip().casefold() for item in model_capabilities if str(item).strip())
        self.cost_per_1k_tokens_usd = cost_per_1k_tokens_usd
        # This synchronous adapter does not implement streaming or provider-native
        # structured output, so those flags are never advertised. Critic output is
        # instead parsed and validated locally by ModelOrchestrator.
        self.capabilities = ProviderCapabilities(
            generate=True,
            stream=False,
            tool_calling=bool(tool_calling),
            structured_output=False,
            chat=True,
            native_chat=True,
            parallel_tool_calls=bool(parallel_tool_calls),
            reasoning=bool(reasoning),
            reasoning_budget=bool(reasoning_budget),
            long_context=bool(long_context),
            vision=bool(vision),
        )

    def status(self) -> dict:
        return {
            "name": sanitize_model_text(self.name)[:120],
            "model": sanitize_model_text(self.model)[:120],
            "configured": bool(self.base_url and self.model),
            "endpoint_configured": bool(self.base_url),
            "failure_count": self.failure_count,
            "last_error": sanitize_model_text(self.last_error)[:300],
            "priority": self.priority,
            "unsupported_capabilities": ["stream", "structured_output"],
            "capabilities": self.capabilities.__dict__.copy(),
            "model_capabilities": sorted(self.model_capabilities),
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
            with urllib.request.urlopen(req, timeout=max(1, int(timeout))) as response:
                data = json.loads(response.read().decode())
            self.last_error = ""
            return data
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            self.failure_count += 1
            self.last_error = sanitize_model_text(f"HTTP {exc.code}: {body[:450]}")
            raise
        except Exception as exc:
            self.failure_count += 1
            self.last_error = sanitize_model_text(str(exc))[:500]
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

    def generate(self, messages: list[dict], temperature: float = 0, *, timeout: int = 90, **kwargs: Any) -> ProviderResponse:
        payload = {"model": self.model, "messages": messages, "temperature": temperature, **kwargs}
        return self._normalize(self._request(payload, timeout=timeout), "generate")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, *, timeout: int = 90, **kwargs: Any) -> ProviderResponse:
        if not self.capabilities.tool_calling:
            raise NotImplementedError("native tool calling unavailable")
        payload = {"model": self.model, "messages": messages, "temperature": temperature, "tools": tools, **kwargs}
        return self._normalize(self._request(payload, timeout=timeout), "tool_calling")

    def chat(self, messages: list[dict], temperature: float = 0, timeout: int = 90, **kwargs: Any) -> dict:
        return self.generate(messages, temperature=temperature, timeout=timeout, **kwargs).public()
