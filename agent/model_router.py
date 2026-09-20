from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .provider_api import ProviderCapabilities, ProviderResponse, response_from_legacy
from .providers import OpenAICompatibleProvider


@dataclass
class ModelRouter:
    providers: list[Any]

    @classmethod
    def from_env(cls):
        providers = []
        for name in ("LOCAL", "COLAB", "HF"):
            base = os.getenv(f"{name}_LLM_BASE_URL", "").strip()
            model = os.getenv(f"{name}_LLM_MODEL", "").strip()
            key = os.getenv(f"{name}_LLM_API_KEY", "").strip()
            if base and model:
                native = os.getenv(f"{name}_LLM_TOOL_CALLING", "false").lower() == "true"
                providers.append(OpenAICompatibleProvider(name.lower(), base, model, key, capabilities=ProviderCapabilities(True, False, native, native)))
        base = os.getenv("LLM_BASE_URL", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        key = os.getenv("LLM_API_KEY", "").strip()
        if base and model and not providers:
            native = os.getenv("LLM_TOOL_CALLING", "false").lower() == "true"
            providers.append(OpenAICompatibleProvider("default", base, model, key, capabilities=ProviderCapabilities(True, False, native, native)))
        return cls(providers)

    def status(self):
        return [provider.status() for provider in self.providers]

    @staticmethod
    def _capabilities(provider: Any) -> ProviderCapabilities:
        value = getattr(provider, "capabilities", None)
        return value if isinstance(value, ProviderCapabilities) else ProviderCapabilities(generate=callable(getattr(provider, "chat", None)), stream=callable(getattr(provider, "stream", None)), tool_calling=callable(getattr(provider, "tool_calling", None)), structured_output=False)

    @staticmethod
    def _trusted(response: ProviderResponse, provider: Any, capability: str) -> dict[str, Any]:
        # Provider/model identity is always assigned by this router, never response metadata.
        response.provider = str(getattr(provider, "name", "unknown"))
        response.model = str(getattr(provider, "model", "unknown"))
        response.capability = capability
        response.request_metadata = {"router": "model-router", "capability": capability}
        return response.public()

    def _invoke(self, provider: Any, method: str, *args: Any, **kwargs: Any) -> ProviderResponse:
        fn = getattr(provider, method, None)
        if callable(fn):
            value = fn(*args, **kwargs)
            if isinstance(value, ProviderResponse):
                return value
            if isinstance(value, dict):
                return response_from_legacy(value, provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"), capability=method)
        if method == "generate" and callable(getattr(provider, "chat", None)):
            return response_from_legacy(provider.chat(*args, **kwargs), provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"), capability="generate")
        raise NotImplementedError(f"provider does not support {method}")

    def generate(self, messages: list[dict], temperature: float = 0, **kwargs: Any) -> dict[str, Any]:
        errors = []
        for provider in self.providers:
            if not self._capabilities(provider).generate:
                continue
            try:
                return self._trusted(self._invoke(provider, "generate", messages, temperature=temperature, **kwargs), provider, "generate")
            except Exception as exc:
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {type(exc).__name__}")
        raise RuntimeError("all model providers failed: " + "; ".join(errors) if errors else "no model provider configured")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, **kwargs: Any) -> dict[str, Any]:
        errors = []
        for provider in self.providers:
            if not self._capabilities(provider).tool_calling:
                continue
            try:
                return self._trusted(self._invoke(provider, "tool_calling", messages, tools, temperature=temperature, **kwargs), provider, "tool_calling")
            except Exception as exc:
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {type(exc).__name__}")
        if errors:
            raise RuntimeError("native tool providers failed: " + "; ".join(errors))
        raise NotImplementedError("no provider supports native tool calling")

    def stream(self, messages: list[dict], temperature: float = 0, **kwargs: Any):
        errors = []
        for provider in self.providers:
            if not self._capabilities(provider).stream:
                continue
            try:
                for event in provider.stream(messages, temperature=temperature, **kwargs):
                    if isinstance(event, dict) and event.get("event") in {"assistant.delta", "assistant.completed"}:
                        yield event
                return
            except Exception as exc:
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {type(exc).__name__}")
        if errors:
            raise RuntimeError("all streaming providers failed: " + "; ".join(errors))
        raise NotImplementedError("no provider supports streaming")

    def chat(self, messages: list[dict], temperature: float = 0) -> dict:
        return self.generate(messages, temperature=temperature)
