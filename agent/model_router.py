from __future__ import annotations

import os
import errno
import math
import time
import urllib.error
from dataclasses import dataclass, field
from typing import Any

from .provider_api import CapabilityUnsupported, HardwareRequirements, InvalidModelResponse, ProviderAuthenticationFailure, ProviderCapabilities, ProviderDeployment, ProviderError, ProviderFailure, ProviderRequestRejected, ProviderResponse, ProviderTimeout, response_from_legacy, validate_provider_response
from .providers import OpenAICompatibleProvider
from .planning import ReasoningProfile
from security.runtime_secrets import secret_env


@dataclass
class ModelRouter:
    providers: list[Any]
    last_trace: list[dict[str, Any]] = field(default_factory=list)
    allow_cross_deployment_fallback: bool = False

    def __post_init__(self):
        if not isinstance(self.allow_cross_deployment_fallback, bool):
            raise ValueError("allow_cross_deployment_fallback must be boolean")
        self.last_trace = []

    @staticmethod
    def _deployment(provider: Any) -> ProviderDeployment:
        metadata = getattr(provider, "metadata", None)
        raw = getattr(metadata, "deployment", getattr(provider, "deployment", ProviderDeployment.UNKNOWN))
        try:
            return ProviderDeployment(raw)
        except (TypeError, ValueError):
            return ProviderDeployment.UNKNOWN

    def _routable_providers(self, capability: str) -> tuple[list[Any], list[Any]]:
        eligible = [
            provider for provider in self.providers
            if bool(getattr(self._caps(provider), capability, False))
        ]
        if not eligible or self.allow_cross_deployment_fallback:
            return eligible, []
        primary = self._deployment(self.providers[0]) if self.providers else ProviderDeployment.UNKNOWN
        if primary == ProviderDeployment.UNKNOWN:
            allowed = [provider for provider in eligible if provider is self.providers[0]]
        else:
            allowed = [provider for provider in eligible if self._deployment(provider) == primary]
        allowed_ids = {id(provider) for provider in allowed}
        return allowed, [provider for provider in eligible if id(provider) not in allowed_ids]

    @staticmethod
    def _deployment_trace(provider: Any, *, capability: str) -> dict[str, Any]:
        return {
            "provider": str(getattr(provider, "name", "unknown"))[:128],
            "model": str(getattr(provider, "model", "unknown"))[:256],
            "status": "skipped",
            "reason": "deployment_boundary",
            "capability": capability,
            "deployment": ModelRouter._deployment(provider).value,
        }

    def _routing_traces(
        self, candidates: list[Any], blocked: list[Any], *, capability: str
    ) -> list[dict[str, Any]]:
        traces = [self._deployment_trace(provider, capability=capability) for provider in blocked]
        if self.allow_cross_deployment_fallback and self.providers:
            primary = self._deployment(self.providers[0])
            for provider in candidates:
                deployment = self._deployment(provider)
                if deployment != primary:
                    traces.append({
                        "status": "explicit_cross_deployment_fallback_enabled",
                        "capability": capability,
                        "from_deployment": primary.value,
                        "to_deployment": deployment.value,
                        "provider": str(getattr(provider, "name", "unknown"))[:128],
                    })
        return traces

    @property
    def context_length(self) -> int | None:
        if not self.providers:
            return None
        if self.allow_cross_deployment_fallback:
            candidates = self.providers
        else:
            primary = self._deployment(self.providers[0])
            candidates = (
                [self.providers[0]]
                if primary == ProviderDeployment.UNKNOWN
                else [provider for provider in self.providers if self._deployment(provider) == primary]
            )
        lengths: list[int] = []
        for provider in candidates:
            value = getattr(provider, "context_length", None)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                # Any provider reachable under the deployment policy can be the active route.
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

    @staticmethod
    def _provider_variable(prefix: str, suffix: str) -> str:
        return f"{prefix}_LLM_{suffix}" if prefix else f"LLM_{suffix}"

    @classmethod
    def _provider_label_from_env(cls, prefix: str, suffix: str) -> str | None:
        variable = cls._provider_variable(prefix, suffix)
        value = os.getenv(variable, "").strip()
        return value or None

    @classmethod
    def _provider_integer_from_env(
        cls, prefix: str, suffix: str, *, zero_means_unset: bool = False
    ) -> int | None:
        variable = cls._provider_variable(prefix, suffix)
        raw = os.getenv(variable, "").strip()
        if not raw:
            return None
        if not raw.isascii() or not raw.isdecimal():
            raise ValueError(f"{variable} must be a positive integer")
        value = int(raw)
        if zero_means_unset and value == 0:
            return None
        if value < 1 or value > 1_000_000:
            raise ValueError(f"{variable} must be a positive integer")
        return value

    @classmethod
    def _deployment_from_env(cls, prefix: str) -> ProviderDeployment:
        variable = cls._provider_variable(prefix, "DEPLOYMENT")
        raw = os.getenv(variable, "unknown").strip().lower()
        try:
            return ProviderDeployment(raw)
        except ValueError as exc:
            raise ValueError(f"{variable} must be local, remote, or unknown") from exc

    @classmethod
    def _provider_metadata_kwargs(cls, prefix: str) -> dict[str, Any]:
        hardware = HardwareRequirements(
            accelerator=(cls._provider_label_from_env(prefix, "ACCELERATOR") or "unknown").lower(),
            min_ram_gib=cls._provider_integer_from_env(prefix, "MIN_RAM_GIB"),
            min_vram_gib=cls._provider_integer_from_env(prefix, "MIN_VRAM_GIB", zero_means_unset=True),
            min_cpu_cores=cls._provider_integer_from_env(prefix, "MIN_CPU_CORES"),
            min_disk_gib=cls._provider_integer_from_env(prefix, "MIN_DISK_GIB"),
        )
        return {
            "model_version": cls._provider_label_from_env(prefix, "MODEL_VERSION"),
            "quantization": cls._provider_label_from_env(prefix, "QUANTIZATION"),
            "deployment": cls._deployment_from_env(prefix),
            "hardware_requirements": hardware,
            "reasoning": os.getenv(cls._provider_variable(prefix, "REASONING"), "false").strip().lower() == "true",
            "reasoning_budget": os.getenv(cls._provider_variable(prefix, "REASONING_BUDGET"), "false").strip().lower() == "true",
            "parallel_tool_calls": os.getenv(cls._provider_variable(prefix, "PARALLEL_TOOL_CALLS"), "false").strip().lower() == "true",
            "long_context": os.getenv(cls._provider_variable(prefix, "LONG_CONTEXT"), "false").strip().lower() == "true",
            "vision": os.getenv(cls._provider_variable(prefix, "VISION"), "false").strip().lower() == "true",
        }

    @staticmethod
    def _cross_deployment_fallback_from_env() -> bool:
        variable = "LLM_ALLOW_CROSS_DEPLOYMENT_FALLBACK"
        raw = os.getenv(variable, "false").strip().lower()
        if raw not in {"true", "false"}:
            raise ValueError(f"{variable} must be true or false")
        return raw == "true"

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
                    **cls._provider_metadata_kwargs(name),
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
                **cls._provider_metadata_kwargs(""),
            ))
        providers.sort(key=lambda item: int(getattr(item, "priority", 100)))
        return cls(
            providers,
            allow_cross_deployment_fallback=cls._cross_deployment_fallback_from_env(),
        )

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
        candidates, blocked = self._routable_providers("generate")
        self.last_trace = self._routing_traces(candidates, blocked, capability="generate")
        for provider in candidates:
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
        if blocked:
            raise CapabilityUnsupported("no generation provider available within deployment policy")
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
        candidates, blocked = self._routable_providers("tool_calling")
        self.last_trace = self._routing_traces(candidates, blocked, capability="tool_calling")
        for provider in candidates:
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
        if blocked:
            raise CapabilityUnsupported("no native tool provider available within deployment policy")
        raise CapabilityUnsupported("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float | None = None, *, tools: list[dict] | None = None, reasoning_profile: ReasoningProfile | None = None) -> dict:
        if tools:
            return self.tool_calling(messages, tools, temperature=temperature, reasoning_profile=reasoning_profile)
        return self.generate(messages, temperature=temperature, reasoning_profile=reasoning_profile)
