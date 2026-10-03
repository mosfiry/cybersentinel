from __future__ import annotations

import os
import errno
import math
import time
import urllib.error
from dataclasses import dataclass
from typing import Any

from .provider_api import CapabilityUnsupported, InvalidModelResponse, ProviderAuthenticationFailure, ProviderCapabilities, ProviderError, ProviderFailure, ProviderResponse, ProviderTimeout, response_from_legacy, validate_provider_response
from .providers import OpenAICompatibleProvider
from .planning import ReasoningProfile


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
        name = str(getattr(provider, "name", "unknown") or "unknown")
        model = str(getattr(provider, "model", "unknown") or "unknown")
        if isinstance(value, ProviderResponse):
            response = value
        elif isinstance(value, dict):
            response = response_from_legacy(value, provider=name, model=model, capability=capability)
        else:
            raise InvalidModelResponse("provider returned unsupported response", provider=name, model=model)
        return validate_provider_response(response, provider=name, model=model)

    @staticmethod
    def _classify(exc: Exception, provider: Any) -> ProviderError:
        details = {"provider": str(getattr(provider, "name", "unknown") or "unknown"), "model": str(getattr(provider, "model", "unknown") or "unknown")}
        if isinstance(exc, ProviderError):
            if not exc.provider:
                exc.provider = details["provider"]
            if not exc.model:
                exc.model = details["model"]
            return exc
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code in {401, 403}:
                return ProviderAuthenticationFailure(f"HTTP {exc.code}", **details)
            return ProviderFailure(f"HTTP {exc.code}", **details)
        if isinstance(exc, urllib.error.URLError):
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError) or (isinstance(reason, OSError) and reason.errno == errno.ETIMEDOUT):
                return ProviderTimeout("provider transport timeout", **details)
            if isinstance(reason, PermissionError):
                return ProviderAuthenticationFailure("provider transport authentication failure", **details)
            return ProviderFailure("provider transport failure", **details)
        if isinstance(exc, TimeoutError):
            return ProviderTimeout("provider timeout", **details)
        if isinstance(exc, PermissionError):
            return ProviderAuthenticationFailure("provider authentication failed", **details)
        if isinstance(exc, (TypeError, ValueError, UnicodeError)):
            return InvalidModelResponse("invalid provider response", **details)
        return ProviderFailure(type(exc).__name__, **details)

    def generate(self, messages: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.2
        timeout = kwargs.pop("timeout", None)
        deadline = None
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("timeout must be a positive finite number")
            deadline = time.monotonic() + float(timeout)
        errors = []
        attempts: list[dict[str, str]] = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).generate:
                continue
            call_kwargs = dict(kwargs)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                call_kwargs["timeout"] = remaining
            try:
                fn = getattr(provider, "generate", None) or getattr(provider, "chat", None)
                response = self._trusted(self._normalize(fn(messages, temperature=temperature, **call_kwargs), provider, "generate"), provider, "generate")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return response
            except Exception as exc:
                failure = self._classify(exc, provider)
                attempt = {"provider": failure.provider or "unknown", "model": failure.model or "unknown", "kind": failure.kind.value}
                attempts.append(attempt)
                errors.append(f"{attempt['provider']}: {failure.kind.value}")
                self.last_trace.append({"provider": attempt["provider"], "model": attempt["model"], "status": "failure", "failure_kind": failure.kind.value, "error_type": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()})
        if deadline is not None and time.monotonic() >= deadline:
            raise ProviderTimeout("provider call deadline expired", attempts=attempts)
        raise ProviderFailure("all model providers failed: " + "; ".join(errors) if errors else "no model provider configured", attempts=attempts)

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.1
        timeout = kwargs.pop("timeout", None)
        deadline = None
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("timeout must be a positive finite number")
            deadline = time.monotonic() + float(timeout)
        errors = []
        attempts: list[dict[str, str]] = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).tool_calling:
                continue
            call_kwargs = dict(kwargs)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                call_kwargs["timeout"] = remaining
            try:
                response = provider.tool_calling(messages, tools, temperature=temperature, **call_kwargs)
                result = self._trusted(self._normalize(response, provider, "tool_calling"), provider, "tool_calling")
                self.last_trace.append({"provider": provider.name, "model": provider.model, "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return result
            except Exception as exc:
                failure = self._classify(exc, provider)
                attempt = {"provider": failure.provider or "unknown", "model": failure.model or "unknown", "kind": failure.kind.value}
                attempts.append(attempt)
                errors.append(f"{attempt['provider']}: {failure.kind.value}")
                self.last_trace.append({"provider": attempt["provider"], "model": attempt["model"], "status": "failure", "failure_kind": failure.kind.value, "error_type": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()})
        if deadline is not None and time.monotonic() >= deadline:
            raise ProviderTimeout("provider call deadline expired", attempts=attempts)
        if errors:
            raise ProviderFailure("native tool providers failed: " + "; ".join(errors), attempts=attempts)
        raise CapabilityUnsupported("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float | None = None, *, tools: list[dict] | None = None, reasoning_profile: ReasoningProfile | None = None) -> dict:
        if tools:
            return self.tool_calling(messages, tools, temperature=temperature, reasoning_profile=reasoning_profile)
        return self.generate(messages, temperature=temperature, reasoning_profile=reasoning_profile)
