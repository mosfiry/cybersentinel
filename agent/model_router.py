from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .provider_api import CapabilityUnsupported, InvalidModelResponse, ProviderAuthenticationFailure, ProviderCapabilities, ProviderError, ProviderFailure, ProviderResponse, ProviderTimeout, response_from_legacy
from .providers import OpenAICompatibleProvider
from .planning import ReasoningProfile


PROFILE_ORDER = ("local", "colab", "hf", "default")


class ModelSelectionError(ValueError):
    """Safe, stable selection error intended for authenticated API responses."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _safe_model_label(value: Any) -> str:
    text = str(value or "").replace("\x00", " ")
    text = re.sub(r"https?://\S+", "[endpoint omitted]", text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[redacted]", text)
    text = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120] or "Configured model"


def _is_private_literal_endpoint(base_url: Any) -> bool:
    """Classify only literal loopback/private IPs; never resolve hostnames."""
    try:
        parsed = urlsplit(str(base_url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        host = parsed.hostname.casefold().rstrip(".")
        if host == "localhost" or host.endswith(".localhost"):
            return True
        address = ipaddress.ip_address(host.split("%", 1)[0])
        return bool(address.is_loopback or address.is_private)
    except (TypeError, ValueError):
        return False


def _optional_nonnegative_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 and parsed < float("inf") else None


def _capability_summary(provider: Any) -> dict[str, bool]:
    capabilities = ModelRouter._caps(provider)
    return {
        "generate": bool(capabilities.generate),
        "tool_calling": bool(capabilities.tool_calling),
        "native_chat": bool(capabilities.native_chat),
        "structured_output": bool(capabilities.structured_output),
        "stream": bool(capabilities.stream),
        "long_context": bool(capabilities.long_context),
    }


def _profile_material(profile_id: str, provider: Any) -> dict[str, Any]:
    raw_base = str(getattr(provider, "base_url", "") or "")
    try:
        parsed = urlsplit(raw_base)
        endpoint = {
            "scheme": parsed.scheme.lower(),
            "host": (parsed.hostname or "").lower(),
            "port": parsed.port,
            "path": parsed.path.rstrip("/"),
        }
    except ValueError:
        endpoint = {"invalid": True}
    return {
        "id": profile_id,
        "model": str(getattr(provider, "model", "") or ""),
        "endpoint": endpoint,
        "priority": int(getattr(provider, "priority", 100)),
        "capabilities": _capability_summary(provider),
        "model_capabilities": sorted(str(item) for item in getattr(provider, "model_capabilities", ())),
        "cost_per_1k_tokens_usd": getattr(provider, "cost_per_1k_tokens_usd", None),
    }


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass
class ModelRouter:
    providers: list[Any]
    last_trace: list[dict[str, Any]] | None = None
    configured_profiles: dict[str, Any] = field(default_factory=dict)
    selected_profile_id: str | None = None

    def __post_init__(self):
        self.last_trace = []
        configured = dict(self.configured_profiles or {})
        for provider in self.providers:
            profile_id = getattr(provider, "profile_id", None)
            if isinstance(profile_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id) and profile_id != "auto":
                configured.setdefault(str(profile_id), provider)
        valid = {
            str(key): provider
            for key, provider in configured.items()
            if isinstance(key, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", key)
            and key != "auto"
        }
        ordered = [key for key in PROFILE_ORDER if key in valid]
        ordered.extend(sorted(
            (key for key in valid if key not in PROFILE_ORDER),
            key=lambda key: (int(getattr(valid[key], "priority", 100)), key),
        ))
        self.configured_profiles = {key: valid[key] for key in ordered}

    @classmethod
    def from_env(cls):
        providers = []
        configured_profiles: dict[str, Any] = {}
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
                profile_id = name.lower()
                provider = OpenAICompatibleProvider(
                    profile_id, base, model, key,
                    tool_calling=native, streaming=streaming,
                    structured_output=structured, priority=priority,
                    profile_id=profile_id,
                    model_capabilities=os.getenv(f"{name}_LLM_CAPABILITIES", "").split(","),
                    cost_per_1k_tokens_usd=_optional_nonnegative_float(os.getenv(f"{name}_LLM_COST_PER_1K_TOKENS_USD", "")),
                )
                providers.append(provider)
                configured_profiles[profile_id] = provider

        base = os.getenv("LLM_BASE_URL", "").strip()
        model = os.getenv("LLM_MODEL", "").strip()
        key = os.getenv("LLM_API_KEY", "").strip()
        if base and model:
            native = os.getenv("LLM_TOOL_CALLING", "false").lower() == "true"
            streaming = os.getenv("LLM_STREAMING", "false").lower() == "true"
            structured = os.getenv("LLM_STRUCTURED_OUTPUT", "false").lower() == "true"
            default_provider = OpenAICompatibleProvider(
                "default", base, model, key,
                tool_calling=native, streaming=streaming,
                structured_output=structured, priority=1000,
                profile_id="default",
                model_capabilities=os.getenv("LLM_CAPABILITIES", "").split(","),
                cost_per_1k_tokens_usd=_optional_nonnegative_float(os.getenv("LLM_COST_PER_1K_TOKENS_USD", "")),
            )
            configured_profiles["default"] = default_provider
            # Preserve the established automatic order: the generic LLM profile
            # joins auto failover only when no named profile is configured.
            if not providers:
                providers.append(default_provider)

        # Numbered OpenAI-compatible profiles let operators add providers without
        # changing MissionRuntime or orchestration code. Non-OpenAI providers can
        # register through ModelRouter's provider interface.
        dynamic_profiles: dict[int, str] = {}
        for env_name in os.environ:
            match = re.fullmatch(r"MODEL_PROFILE_(\d+)_ID", env_name)
            if match:
                dynamic_profiles[int(match.group(1))] = os.environ.get(env_name, "").strip()
        for position, profile_id in sorted(dynamic_profiles.items()):
            if (
                not profile_id
                or profile_id == "auto"
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id)
                or profile_id in configured_profiles
            ):
                continue
            prefix = f"MODEL_PROFILE_{position}"
            profile_base = os.getenv(f"{prefix}_BASE_URL", "").strip()
            profile_model = os.getenv(f"{prefix}_MODEL", "").strip()
            if not profile_base or not profile_model:
                continue
            provider = OpenAICompatibleProvider(
                profile_id,
                profile_base,
                profile_model,
                os.getenv(f"{prefix}_API_KEY", "").strip(),
                tool_calling=os.getenv(f"{prefix}_TOOL_CALLING", "false").lower() == "true",
                priority=int(os.getenv(f"{prefix}_PRIORITY", str(500 + position))),
                profile_id=profile_id,
                model_capabilities=os.getenv(f"{prefix}_CAPABILITIES", "").split(","),
                cost_per_1k_tokens_usd=_optional_nonnegative_float(os.getenv(f"{prefix}_COST_PER_1K_TOKENS_USD", "")),
            )
            providers.append(provider)
            configured_profiles[profile_id] = provider

        providers.sort(key=lambda item: int(getattr(item, "priority", 100)))
        return cls(providers, configured_profiles=configured_profiles)

    def catalog(self) -> list[dict[str, Any]]:
        """Return safe, browser-facing options; credentials and endpoint URLs stay server-side."""
        result: list[dict[str, Any]] = [{
            "id": "auto",
            "label": "Automatic · configured failover order",
            "mode": "auto",
        }]
        profile_ids = list(PROFILE_ORDER)
        profile_ids.extend(key for key in self.configured_profiles if key not in PROFILE_ORDER)
        for profile_id in profile_ids:
            provider = self.configured_profiles.get(profile_id)
            if provider is None:
                continue
            result.append({
                "id": profile_id,
                "label": f"{profile_id} · {_safe_model_label(getattr(provider, 'model', ''))}",
                "model": _safe_model_label(getattr(provider, "model", "")),
                "mode": "explicit",
                "adapter": "openai_compatible_http",
                "private_endpoint": _is_private_literal_endpoint(getattr(provider, "base_url", "")),
                "capabilities": _capability_summary(provider),
                "model_capabilities": sorted(str(item) for item in getattr(provider, "model_capabilities", ())),
            })
        return result

    def with_model_selection(
        self,
        profile_id: str,
        *,
        expected_fingerprint: str | None = None,
    ) -> tuple["ModelRouter", dict[str, str]]:
        """Resolve only catalog IDs; explicit choices are pinned to one provider."""
        if type(profile_id) is not str or len(profile_id) > 64:
            raise ModelSelectionError("invalid_model_id")
        if profile_id == "auto":
            automatic_material = []
            for index, provider in enumerate(self.providers):
                known_id = next((key for key, item in self.configured_profiles.items() if item is provider), None)
                automatic_material.append(_profile_material(known_id or f"auto-{index}", provider))
            metadata = {
                "mode": "auto",
                "profile_id": "auto",
                "profile_fingerprint": _fingerprint(automatic_material),
            }
            return self, metadata
        if profile_id == "auto" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id):
            raise ModelSelectionError("invalid_model_id")
        provider = self.configured_profiles.get(profile_id)
        if provider is None:
            raise ModelSelectionError("selected_model_unavailable" if expected_fingerprint else "invalid_model_id")
        fingerprint = _fingerprint(_profile_material(profile_id, provider))
        if expected_fingerprint and expected_fingerprint != fingerprint:
            raise ModelSelectionError("selected_model_configuration_changed")
        if self.selected_profile_id == profile_id and self.providers == [provider]:
            selected_router = self
        else:
            selected_router = ModelRouter(
                [provider],
                configured_profiles=self.configured_profiles,
                selected_profile_id=profile_id,
            )
        return selected_router, {
            "mode": "explicit",
            "profile_id": profile_id,
            "profile_fingerprint": fingerprint,
        }

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
        if isinstance(value, ProviderResponse):
            return value
        if isinstance(value, dict):
            return response_from_legacy(value, provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"), capability=capability)
        raise InvalidModelResponse("provider returned unsupported response", provider=getattr(provider, "name", "unknown"), model=getattr(provider, "model", "unknown"))

    @staticmethod
    def _classify(exc: Exception, provider: Any) -> ProviderError:
        details = {"provider": getattr(provider, "name", "unknown"), "model": getattr(provider, "model", "unknown")}
        if isinstance(exc, ProviderError):
            return exc
        if isinstance(exc, TimeoutError):
            return ProviderTimeout(str(exc) or "provider timeout", **details)
        if isinstance(exc, PermissionError):
            return ProviderAuthenticationFailure(str(exc) or "provider authentication failed", **details)
        if isinstance(exc, (TypeError, ValueError)):
            return InvalidModelResponse(str(exc) or "invalid provider response", **details)
        return ProviderFailure(f"{type(exc).__name__}: {exc}", **details)

    def _failure_message(self, errors: list[str], *, capability: str) -> str:
        if self.selected_profile_id:
            return f"selected model profile '{self.selected_profile_id}' failed; automatic failover is disabled"
        if errors:
            return f"{capability}: " + "; ".join(errors)
        return "no model provider configured"

    def generate(self, messages: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.2
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).generate:
                continue
            try:
                fn = getattr(provider, "generate", None) or getattr(provider, "chat", None)
                response = self._trusted(self._normalize(fn(messages, temperature=temperature, **kwargs), provider, "generate"), provider, "generate")
                self.last_trace.append({"provider": _safe_model_label(getattr(provider, "name", "unknown")), "model": _safe_model_label(getattr(provider, "model", "unknown")), "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return response
            except Exception as exc:
                failure = self._classify(exc, provider)
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {failure.kind.value}")
                self.last_trace.append({"provider": _safe_model_label(getattr(provider, "name", "unknown")), "model": _safe_model_label(getattr(provider, "model", "unknown")), "status": "failure", "failure_kind": failure.kind.value, "failure_reason": _safe_model_label(str(failure)), "capabilities": self._caps(provider).__dict__.copy()})
        raise ProviderFailure(self._failure_message(errors, capability="all model providers failed"))

    def tool_calling(self, messages: list[dict], tools: list[dict], temperature: float | None = None, *, reasoning_profile: ReasoningProfile | None = None, **kwargs: Any) -> dict[str, Any]:
        if reasoning_profile is not None:
            temperature = reasoning_profile.temperature
        if temperature is None:
            temperature = 0.1
        errors = []
        self.last_trace = []
        for provider in self.providers:
            if not self._caps(provider).tool_calling:
                continue
            try:
                response = provider.tool_calling(messages, tools, temperature=temperature, **kwargs)
                result = self._trusted(self._normalize(response, provider, "tool_calling"), provider, "tool_calling")
                self.last_trace.append({"provider": _safe_model_label(getattr(provider, "name", "unknown")), "model": _safe_model_label(getattr(provider, "model", "unknown")), "status": "success", "capabilities": self._caps(provider).__dict__.copy()})
                return result
            except Exception as exc:
                failure = self._classify(exc, provider)
                errors.append(f"{getattr(provider, 'name', 'unknown')}: {failure.kind.value}")
                self.last_trace.append({"provider": _safe_model_label(getattr(provider, "name", "unknown")), "model": _safe_model_label(getattr(provider, "model", "unknown")), "status": "failure", "failure_kind": failure.kind.value, "failure_reason": _safe_model_label(str(failure)), "capabilities": self._caps(provider).__dict__.copy()})
        if self.selected_profile_id and not errors:
            raise CapabilityUnsupported(f"selected model profile '{self.selected_profile_id}' does not support native tool calling")
        if errors:
            raise ProviderFailure(self._failure_message(errors, capability="native tool providers failed"))
        raise CapabilityUnsupported("no provider supports native tool calling")

    def chat(self, messages: list[dict], temperature: float | None = None, *, tools: list[dict] | None = None, reasoning_profile: ReasoningProfile | None = None) -> dict:
        if tools:
            return self.tool_calling(messages, tools, temperature=temperature, reasoning_profile=reasoning_profile)
        return self.generate(messages, temperature=temperature, reasoning_profile=reasoning_profile)
