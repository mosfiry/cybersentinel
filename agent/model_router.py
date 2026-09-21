from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .provider_api import ProviderCapabilities, ProviderResponse, response_from_legacy
from .providers import OpenAICompatibleProvider


@dataclass
class ModelRouter:
    providers: list[Any]
    last_trace: list[dict[str, Any]] = None

    def __post_init__(self):
        self.last_trace = []

    @classmethod
    def from_env(cls):
        providers = []
        for position, name in enumerate(("LOCAL", "COLAB", "HF")):
            base = os.getenv(f"{name}_LLM_BASE_URL", "").strip()
            default_model = "Qwen/Qwen3-Coder-Next" if name == "LOCAL" else ""
            model = os.getenv(f"{name}_LLM_MODEL", default_model).strip()
            key = os.getenv(f"{name}_LLM_API_KEY", "").strip()
            if base and model:
                native = os.getenv(f"{name}_LLM_TOOL_CALLING", "false").lower() == "true"
                streaming = os.getenv(f"{name}_LLM_STREAMING", "false").lower() == "true"
                structured = os.getenv(f"{name}_LLM_STRUCTURED_OUTPUT", "false").lower() == "true"
                priority = int(os.getenv(f"{name}_LLM_PRIORITY", str(position * 100 + 10)))
                providers.append(OpenAICompatibleProvider(name.lower(), base, model, key, tool_calling=native, streaming=streaming, structured_output=structured, priority=priority))
        base = os.getenv("LLM_BASE_URL", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        key = os.getenv("LLM_API_KEY", "").strip()
        if base and model and not providers:
            native = os.getenv("LLM_TOOL_CALLING", "false").lower() == "true"
            streaming = os.getenv("LLM_STREAMING", "false").lower() == "true"
            structured = os.getenv("LLM_STRUCTURED_OUTPUT", "false").lower() == "true"
            providers.append(OpenAICompatibleProvider("default", base, model, key, tool_calling=native, streaming=streaming, structured_output=structured, priority=1000))
        providers.sort(key=lambda item: int(getattr(item, "priority", 100)))
        return cls(providers)

    def status(self):
        return [provider.status() for provider in self.providers]

    @staticmethod
    def _caps(provider: Any) -> ProviderCapabilities:
        value = getattr(provider, "capabilities", None)
        if isinstance(value, ProviderCapabilities):
            return value
        return ProviderCapabilities(generate=callable(getattr(provider, "generate", None)) or callable(getattr(provider, "chat", None)), tool_calling=callable(getattr(provider, "tool_calling", None)))

    @staticmethod
    def _trusted(response: ProviderResponse, provider: Any, capability: str) -> dict[str, Any]:
        response.provider = str(getattr(provider, "name", "unknown"))
        response.model = str(getattr(provider, "model", "unknown"))
        response.capability = capability
        return response.public()

    @staticmethod
    def _normalize(value: Any, provider: Any, capability: str) -> ProviderResponse:
        if isinstance(value, ProviderResponse):
            return value
        if isinstance(value, dict):
            return response_from_legacy(value, provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"), capability=capability)
        raise TypeError("provider returned unsupported response")

    def generate(self, messages: list[dict], temperature: float = 0, **kwargs: Any) -> dict[str, Any]:
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).generate:
                continue
            try:
                fn = getattr(provider, "generate", None) or getattr(provider, "chat", None)
                response = self._trusted(self._normalize(fn(messages, temperature=temperature, **kwargs), provider, "generate"), provider, "generate")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return response
            except Exception as exc:
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {type(exc).__name__}")
                self.last_trace.append({"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown"), "status": "failure", "failure_reason": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()})
        raise RuntimeError("all model providers failed: " + "; ".join(errors) if errors else "no model provider configured")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float = 0, **kwargs: Any) -> dict[str, Any]:
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).tool_calling:
                continue
            try:
                response = provider.tool_calling(messages, tools, temperature=temperature, **kwargs)
                result = self._trusted(self._normalize(response, provider, "tool_calling"), provider, "tool_calling")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return result
            except Exception as exc:
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {type(exc).__name__}")
                self.last_trace.append({"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown"), "status": "failure", "failure_reason": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()})
        if errors:
            raise RuntimeError("native tool providers failed: " + "; ".join(errors))
        raise NotImplementedError("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float = 0) -> dict:
        return self.generate(messages, temperature=temperature)
