from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .provider_api import CapabilityUnsupported, ContextOverflow, InvalidModelResponse, ModelRefusal, ProviderAuthenticationFailure, ProviderCapabilities, ProviderError, ProviderFailure, ProviderRateLimit, ProviderResponse, ProviderTimeout, ProviderUnavailable, response_from_legacy
from .providers import OpenAICompatibleProvider
from .planning import ReasoningProfile


@dataclass
class ModelProfile:
    provider: str
    model: str
    capabilities: dict[str, Any]
    tool_calling: bool = False
    streaming: bool = False
    context_limit: int | None = None
    reasoning: bool = False
    priority: int = 100
    enabled: bool = True
    health: str = "unknown"


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
        result = []
        for provider in self.providers:
            status = getattr(provider, "status", None)
            if callable(status):
                result.append(status())
            else:
                capabilities = getattr(provider, "capabilities", None)
                result.append({
                    "name": getattr(provider, "name", "unknown"),
                    "model": getattr(provider, "model", "unknown"),
                    "available": True,
                    "capabilities": getattr(capabilities, "__dict__", {}),
                })
        return result

    @property
    def profiles(self) -> list[ModelProfile]:
        return [ModelProfile(
            provider=str(getattr(provider, "name", "unknown")),
            model=str(getattr(provider, "model", "unknown")),
            capabilities=self._caps(provider).__dict__.copy(),
            tool_calling=self._caps(provider).tool_calling,
            streaming=self._caps(provider).stream,
            context_limit=getattr(provider, "context_limit", None),
            reasoning=self._caps(provider).reasoning,
            priority=int(getattr(provider, "priority", 100)),
            enabled=bool(getattr(provider, "enabled", True)),
            health=str(getattr(provider, "health", "unknown")),
        ) for provider in self.providers]

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
            response = value
        elif isinstance(value, dict):
            if value.get("refusal") or str(value.get("finish_reason", "")).lower() in {"refusal", "content_filter"}:
                raise ModelRefusal("model refusal", provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"))
            response = response_from_legacy(value, provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"), capability=capability)
        else:
            raise InvalidModelResponse("provider returned unsupported response", provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"))
        if str(response.finish_reason).lower() in {"refusal", "content_filter"}:
            raise ModelRefusal("model refusal", provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"))
        return response

    @staticmethod
    def _classify(exc: Exception, provider: Any) -> ProviderError:
        details = {"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown")}
        if isinstance(exc, ProviderError):
            return exc
        text = str(exc).lower()
        if isinstance(exc, TimeoutError) or "timeout" in text or "timed out" in text:
            return ProviderTimeout(str(exc) or "provider timeout", **details)
        if isinstance(exc, PermissionError) or "401" in text or "403" in text or "authentication" in text or "unauthorized" in text:
            return ProviderAuthenticationFailure(str(exc) or "provider authentication failed", **details)
        if "429" in text or "rate limit" in text or "too many requests" in text:
            return ProviderRateLimit(str(exc) or "provider rate limit", **details)
        if "context" in text and ("limit" in text or "length" in text or "overflow" in text or "token" in text):
            return ContextOverflow(str(exc) or "context limit exceeded", **details)
        if "refus" in text or "content filter" in text:
            return ModelRefusal(str(exc) or "model refusal", **details)
        if "unavailable" in text or "connection refused" in text or "not configured" in text:
            return ProviderUnavailable(str(exc) or "provider unavailable", **details)
        if isinstance(exc, (TypeError, ValueError)):
            return InvalidModelResponse(str(exc) or "invalid provider response", **details)
        return ProviderFailure(f"{type(exc).__name__}: {exc}", **details)

    def generate(self, messages: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.2
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not getattr(provider, "enabled", True):
                continue
            if not self._caps(provider).generate:
                continue
            try:
                fn = getattr(provider, "generate", None) or getattr(provider, "chat", None)
                response = self._trusted(self._normalize(fn(messages, temperature=temperature, **kwargs), provider, "generate"), provider, "generate")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return response
            except Exception as exc:
                failure = self._classify(exc, provider)
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {failure.kind.value}")
                self.last_trace.append({"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown"), "status": "failure", "failure_kind": failure.kind.value, "failure_reason": str(failure), "capabilities": self._caps(provider).__dict__.copy()})
        raise ProviderFailure("all model providers failed: " + "; ".join(errors) if errors else "no model provider configured")

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.1
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not getattr(provider, "enabled", True):
                continue
            if not self._caps(provider).tool_calling:
                continue
            try:
                response = provider.tool_calling(messages, tools, temperature=temperature, **kwargs)
                result = self._trusted(self._normalize(response, provider, "tool_calling"), provider, "tool_calling")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return result
            except Exception as exc:
                failure = self._classify(exc, provider)
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {failure.kind.value}")
                self.last_trace.append({"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown"), "status": "failure", "failure_kind": failure.kind.value, "failure_reason": str(failure), "capabilities": self._caps(provider).__dict__.copy()})
        if errors:
            raise ProviderFailure("native tool providers failed: " + "; ".join(errors))
        raise CapabilityUnsupported("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float | None = None, *, tools: list[dict] | None = None, reasoning_profile: ReasoningProfile | None = None) -> dict:
        if tools:
            return self.tool_calling(messages, tools, temperature=temperature, reasoning_profile=reasoning_profile)
        return self.generate(messages, temperature=temperature, reasoning_profile=reasoning_profile)
