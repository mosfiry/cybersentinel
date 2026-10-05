from __future__ import annotations

import os
import errno
import math
import time
import urllib.error
from dataclasses import dataclass
from typing import Any

from .provider_api import CapabilityUnsupported, InvalidModelResponse, ProviderAuthenticationFailure, ProviderCapabilities, ProviderError, ProviderFailure, ProviderRequestRejected, ProviderResponse, ProviderTimeout, response_from_legacy, validate_provider_response
from .providers import OpenAICompatibleProvider
from .planning import ReasoningProfile
from security.runtime_secrets import secret_env


@dataclass
class ModelRouter:
    providers: list[Any]
    last_trace: list[dict[str, Any]] = None

    def __post_init__(self):
        self.last_trace = []

    @property
    def context_length(self) -> int | None:
        if not self.providers:
            return None
        lengths: list[int] = []
        for provider in self.providers:
            value = getattr(provider, "context_length", None)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                # A fallback provider without a declared window prevents a safe shared budget.
                return None
            lengths.append(value)
        return min(lengths)

    @staticmethod
    def _context_length_from_env(variable: str) -> int | None:
        raw = os.getenv(variable, "").strip()
        if not raw:
            return None
        if not raw.isascii() or not raw.isdecimal():
            raise ValueError(f"{variable} must be a positive integer")
        value = int(raw)
        if value < 1:
            raise ValueError(f"{variable} must be a positive integer")
        return value

    @classmethod
    def from_env(cls):
        providers = []
        for position, name in enumerate(("LOCAL", "COLAB", "HF")):
            base = os.getenv(f"{name}_LLM_BASE_URL", "").strip()
            default_model = "Qwen/Qwen3-Coder-Next" if name == "LOCAL" else ""
            model = os.getenv(f"{name}_LLM_MODEL", default_model).strip()
            key = secret_env(f"{name}_LLM_API_KEY")
            if base and model:
                native = os.getenv(f"{name}_LLM_TOOL_CALLING", "false").lower() == "true"
                streaming = os.getenv(f"{name}_LLM_STREAMING", "false").lower() == "true"
                structured = os.getenv(f"{name}_LLM_STRUCTURED_OUTPUT", "false").lower() == "true"
                priority = int(os.getenv(f"{name}_LLM_PRIORITY", str(position * 100 + 10)))
                providers.append(OpenAICompatibleProvider(
                    name.lower(), base, model, key,
                    tool_calling=native,
                    streaming=streaming,
                    structured_output=structured,
                    priority=priority,
                    context_length=cls._context_length_from_env(f"{name}_LLM_CONTEXT_LENGTH"),
                ))
        base = os.getenv("LLM_BASE_URL", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        key = secret_env("LLM_API_KEY")
        if base and model and not providers:
            native = os.getenv("LLM_TOOL_CALLING", "false").lower() == "true"
            streaming = os.getenv("LLM_STREAMING", "false").lower() == "true"
            structured = os.getenv("LLM_STRUCTURED_OUTPUT", "false").lower() == "true"
            providers.append(OpenAICompatibleProvider(
                "default", base, model, key,
                tool_calling=native,
                streaming=streaming,
                structured_output=structured,
                priority=1000,
                context_length=cls._context_length_from_env("LLM_CONTEXT_LENGTH"),
            ))
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
                return ProviderAuthenticationFailure(f"HTTP {exc.code}", status_code=exc.code, **details)
            if exc.code == 408:
                return ProviderTimeout(f"HTTP {exc.code}", status_code=exc.code, **details)
            if exc.code == 429:
                return ProviderFailure(f"HTTP {exc.code}", status_code=exc.code, **details)
            if 400 <= exc.code < 500:
                return ProviderRequestRejected(f"HTTP {exc.code}", status_code=exc.code, **details)
            return ProviderFailure(f"HTTP {exc.code}", status_code=exc.code, **details)
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

    @staticmethod
    def _aggregate_failure(message: str, attempts: list[dict[str, str]]) -> ProviderError:
        kinds = {str(item.get("kind", "")) for item in attempts}
        status_codes = [str(item.get("http_status", "")) for item in attempts]
        status_code = None
        if attempts and all(code.isdigit() for code in status_codes) and len(set(status_codes)) == 1:
            status_code = int(status_codes[0])
        kwargs: dict[str, Any] = {"attempts": attempts}
        if status_code is not None:
            kwargs["status_code"] = status_code
        if kinds == {"TIMEOUT"}:
            return ProviderTimeout(message, **kwargs)
        if kinds == {"PROVIDER_FAILURE"} or kinds.intersection({"PROVIDER_FAILURE", "TIMEOUT"}):
            return ProviderFailure(message, **kwargs)
        if kinds == {"AUTHENTICATION_FAILURE"}:
            return ProviderAuthenticationFailure(message, **kwargs)
        if kinds == {"REQUEST_REJECTED"}:
            rejected_message = f"provider request rejected (HTTP {status_code})" if status_code is not None else message
            return ProviderRequestRejected(rejected_message, **kwargs)
        if kinds == {"INVALID_MODEL_RESPONSE"}:
            return InvalidModelResponse(message, **kwargs)
        return InvalidModelResponse("provider attempts failed without a retryable error", attempts=attempts)

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
                if failure.status_code is not None:
                    attempt["http_status"] = str(failure.status_code)
                attempts.append(attempt)
                errors.append(f"{attempt['provider']}: {failure.kind.value}")
                trace = {"provider": attempt["provider"], "model": attempt["model"], "status": "failure", "failure_kind": failure.kind.value, "error_type": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()}
                if failure.status_code is not None:
                    trace["http_status"] = failure.status_code
                self.last_trace.append(trace)
        if deadline is not None and time.monotonic() >= deadline:
            raise ProviderTimeout("provider call deadline expired", attempts=attempts)
        if errors:
            raise self._aggregate_failure("all model providers failed", attempts)
        raise ProviderFailure("no model provider configured")

    def generate_for_provider(
        self,
        provider_name: str,
        model_name: str,
        messages: list[dict],
        temperature: float | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Call only the provider/model pair already bound to this Mission.

        Unlike :meth:`generate`, this method deliberately has no fallback loop.
        A missing provider, model mismatch, or unsupported generation capability
        is a closed failure; callers must not silently move Mission context to a
        different configured provider.
        """
        name = str(provider_name or "")
        model = str(model_name or "")
        if not name or not model:
            raise CapabilityUnsupported("Mission has no bound provider identity")
        matches = [
            provider for provider in self.providers
            if str(getattr(provider, "name", "")) == name
            and str(getattr(provider, "model", "")) == model
        ]
        if len(matches) != 1:
            raise CapabilityUnsupported("bound provider/model is unavailable")
        provider = matches[0]
        if not self._caps(provider).generate:
            raise CapabilityUnsupported(
                "bound provider does not support generation",
                provider=name,
                model=model,
            )
        if temperature is None:
            temperature = 0.2
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)) or not math.isfinite(temperature):
            raise ValueError("temperature must be finite")
        timeout = kwargs.get("timeout")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        fn = getattr(provider, "generate", None) or getattr(provider, "chat", None)
        if not callable(fn):
            raise CapabilityUnsupported("bound provider has no generation method", provider=name, model=model)
        try:
            response = fn(messages, temperature=temperature, **kwargs)
            return self._trusted(self._normalize(response, provider, "generate"), provider, "generate")
        except Exception as exc:
            raise self._classify(exc, provider) from exc

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
                if failure.status_code is not None:
                    attempt["http_status"] = str(failure.status_code)
                attempts.append(attempt)
                errors.append(f"{attempt['provider']}: {failure.kind.value}")
                trace = {"provider": attempt["provider"], "model": attempt["model"], "status": "failure", "failure_kind": failure.kind.value, "error_type": type(exc).__name__, "capabilities": self._caps(provider).__dict__.copy()}
                if failure.status_code is not None:
                    trace["http_status"] = failure.status_code
                self.last_trace.append(trace)
        if deadline is not None and time.monotonic() >= deadline:
            raise ProviderTimeout("provider call deadline expired", attempts=attempts)
        if errors:
            raise self._aggregate_failure("native tool providers failed", attempts)
        raise CapabilityUnsupported("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float | None = None, *, tools: list[dict] | None = None, reasoning_profile: ReasoningProfile | None = None) -> dict:
        if tools:
            return self.tool_calling(messages, tools, temperature=temperature, reasoning_profile=reasoning_profile)
        return self.generate(messages, temperature=temperature, reasoning_profile=reasoning_profile)
