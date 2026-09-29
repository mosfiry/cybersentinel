from __future__ import annotations

"""Capability-driven model collaboration; model output remains untrusted data."""

import hashlib
import inspect
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .context import sanitize_model_data, sanitize_model_text
from .model_router import ModelRouter
from .provider_api import CapabilityUnsupported, ProviderError, ProviderFailure, ProviderFailureKind


TASK_CAPABILITIES = frozenset({
    "reasoning", "coding", "security_analysis", "web_analysis",
    "planning", "summarization", "critique",
})
TRANSPORT_CAPABILITIES = frozenset({
    "structured_output", "tool_calling", "streaming", "long_context",
})
MODEL_CAPABILITIES = TASK_CAPABILITIES | TRANSPORT_CAPABILITIES
PREFERENCES = frozenset({"fast", "balanced", "deep", "local"})


def _hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_label(value: Any) -> str:
    text = str(value or "unknown")
    text = re.sub(r"https?://\S+", "[endpoint omitted]", text, flags=re.IGNORECASE)
    text = re.sub(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[redacted]", text)
    text = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:120] or "unknown"


def _safe_text(value: Any, limit: int = 500) -> str:
    return sanitize_model_text(str(value or ""))[:limit]


def _integer_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _optional_float_env(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if math.isfinite(value) and value >= 0 else None


@dataclass(frozen=True)
class ModelCapabilities:
    """Registered task capabilities plus transport features actually implemented."""

    task_capabilities: frozenset[str] = frozenset()
    structured_output: bool = False
    tool_calling: bool = False
    streaming: bool = False
    long_context: bool = False

    def supports(self, capability: str) -> bool:
        if capability in self.task_capabilities:
            return True
        return bool(getattr(self, capability, False)) if capability in TRANSPORT_CAPABILITIES else False

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_capabilities": sorted(self.task_capabilities),
            "structured_output": self.structured_output,
            "tool_calling": self.tool_calling,
            "streaming": self.streaming,
            "long_context": self.long_context,
        }

    @classmethod
    def from_provider(cls, provider: Any) -> "ModelCapabilities":
        declared = getattr(provider, "model_capabilities", ())
        if isinstance(declared, str):
            declared = declared.split(",")
        if not isinstance(declared, (tuple, list, set, frozenset)):
            declared = ()
        tasks = frozenset(
            str(item).strip().casefold()
            for item in declared
            if str(item).strip().casefold() in TASK_CAPABILITIES
        )
        transport = ModelRouter._caps(provider)
        return cls(
            task_capabilities=tasks,
            structured_output=bool(transport.structured_output),
            tool_calling=bool(transport.tool_calling and callable(getattr(provider, "tool_calling", None))),
            streaming=bool(transport.stream),
            long_context=bool(transport.long_context),
        )


@dataclass(frozen=True)
class ModelProfile:
    profile_id: str
    provider: Any = field(compare=False, repr=False)
    provider_name: str = "unknown"
    model_name: str = "unknown"
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    priority: int = 100
    private_endpoint: bool = False
    cost_per_1k_tokens_usd: float | None = None

    @classmethod
    def from_provider(cls, provider: Any, profile_id: str) -> "ModelProfile":
        raw_cost = getattr(provider, "cost_per_1k_tokens_usd", None)
        try:
            cost = float(raw_cost) if raw_cost is not None else None
        except (TypeError, ValueError):
            cost = None
        if cost is not None and (not math.isfinite(cost) or cost < 0):
            cost = None
        base_url = getattr(provider, "base_url", "")
        try:
            from .model_router import _is_private_literal_endpoint
            private = _is_private_literal_endpoint(base_url)
        except Exception:
            private = False
        return cls(
            profile_id=str(profile_id),
            provider=provider,
            provider_name=_safe_label(getattr(provider, "name", profile_id)),
            model_name=_safe_label(getattr(provider, "model", "unknown")),
            capabilities=ModelCapabilities.from_provider(provider),
            priority=int(getattr(provider, "priority", 100)),
            private_endpoint=private,
            cost_per_1k_tokens_usd=cost,
        )

    @property
    def independence_key(self) -> tuple[str, str]:
        return self.provider_name.casefold(), self.model_name.casefold()


@dataclass(frozen=True)
class ModelBudget:
    preference: str
    max_model_profiles: int
    max_calls: int
    max_total_tokens: int
    max_output_tokens_per_call: int
    time_budget_seconds: int
    max_parallelism: int = 1
    max_retries: int = 0
    max_cost_usd: float | None = None

    @classmethod
    def for_preference(cls, preference: str, *, policy_max_models: int | None = None) -> "ModelBudget":
        if preference not in PREFERENCES:
            raise ValueError("invalid_model_preference")
        presets = {
            "fast": (1, 16_000, 768, 25),
            "balanced": (2, 48_000, 1_024, 60),
            "deep": (4, 96_000, 1_536, 90),
            "local": (2, 48_000, 1_024, 60),
        }
        models, tokens, output_tokens, seconds = presets[preference]
        policy_cap = policy_max_models or _integer_env("CYBERSENTINEL_MAX_MODEL_PROFILES", 4, 1, 4)
        time_cap = _integer_env("CYBERSENTINEL_MODEL_TIME_BUDGET_SECONDS", 90, 5, 300)
        token_cap = _integer_env("CYBERSENTINEL_MODEL_TOKEN_BUDGET", tokens, 1_024, 250_000)
        cost_cap = _optional_float_env("CYBERSENTINEL_MODEL_MAX_COST_USD")
        maximum = max(1, min(models, int(policy_cap), 4))
        return cls(
            preference=preference,
            max_model_profiles=maximum,
            max_calls=maximum + 2,
            max_total_tokens=token_cap,
            max_output_tokens_per_call=min(output_tokens, token_cap),
            time_budget_seconds=min(seconds, time_cap),
            max_parallelism=1,
            max_retries=0,
            max_cost_usd=cost_cap,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "preference": self.preference,
            "max_model_profiles": self.max_model_profiles,
            "max_calls": self.max_calls,
            "max_total_tokens": self.max_total_tokens,
            "max_output_tokens_per_call": self.max_output_tokens_per_call,
            "time_budget_seconds": self.time_budget_seconds,
            "max_parallelism": self.max_parallelism,
            "max_retries": self.max_retries,
            "max_cost_usd": self.max_cost_usd,
        }


@dataclass(frozen=True)
class ModelRequest:
    request_id: str
    mission_id: str
    task_id: str
    objective: str
    messages: tuple[dict[str, Any], ...]
    tools: tuple[dict[str, Any], ...]
    context_hash: str
    context_provenance: tuple[dict[str, Any], ...]
    preference: str
    task_capabilities: frozenset[str]
    budget: ModelBudget
    require_tool_calling: bool = False


@dataclass(frozen=True)
class ModelResponse:
    content: str
    tool_calls: tuple[dict[str, Any], ...]
    provider: str
    model: str
    usage: dict[str, Any]
    orchestration: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "tool_calls": list(self.tool_calls),
            "provider": self.provider,
            "model": self.model,
            "usage": dict(self.usage),
            "orchestration": dict(self.orchestration),
        }


@dataclass(frozen=True)
class ModelInvocation:
    role: str
    profile_id: str
    provider: str
    model: str
    status: str
    context_hash: str
    request_hash: str
    response_hash: str = ""
    failure_kind: str = ""
    elapsed_ms: int = 0
    input_tokens_estimated: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "profile_id": self.profile_id,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "context_hash": self.context_hash,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "failure_kind": self.failure_kind,
            "elapsed_ms": self.elapsed_ms,
            "input_tokens_estimated": self.input_tokens_estimated,
            "output_tokens": self.output_tokens,
            "output_trust": "untrusted_model_output",
        }


@dataclass(frozen=True)
class CriticReport:
    hypothesis: str
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    confidence: float
    required_validation: tuple[str, ...]
    decision: str
    unverified_evidence_ids: tuple[str, ...] = ()
    authority: str = "diagnostic_only"
    confidence_trust: str = "untrusted_model_claim"

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "MODEL_CRITIC_REPORT",
            "hypothesis": _safe_text(self.hypothesis, 600),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "missing_evidence": [_safe_text(item, 300) for item in self.missing_evidence],
            "confidence": self.confidence,
            "confidence_trust": self.confidence_trust,
            "required_validation": [_safe_text(item, 300) for item in self.required_validation],
            "decision": self.decision,
            "unverified_evidence_ids": list(self.unverified_evidence_ids),
            "authority": self.authority,
            "semantic_truth_claimed": False,
            "can_change_authorization_or_completion": False,
        }


class ModelOrchestrationError(RuntimeError):
    pass


def _parse_critic(content: str, verified_evidence_ids: Iterable[str]) -> CriticReport:
    try:
        raw = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("critic_output_not_json") from exc
    required = {
        "hypothesis", "supporting_evidence", "contradicting_evidence",
        "missing_evidence", "confidence", "required_validation", "decision",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("critic_output_schema_mismatch")
    def strings(name: str, *, max_items: int, max_length: int) -> tuple[str, ...]:
        value = raw[name]
        if not isinstance(value, list) or len(value) > max_items or any(type(item) is not str or not item.strip() or len(item) > max_length for item in value):
            raise ValueError("critic_output_schema_mismatch")
        return tuple(item.strip() for item in value)
    hypothesis = raw["hypothesis"]
    confidence = raw["confidence"]
    decision = raw["decision"]
    if type(hypothesis) is not str or not hypothesis.strip() or len(hypothesis) > 2_000:
        raise ValueError("critic_output_schema_mismatch")
    if type(confidence) not in (float, int) or not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
        raise ValueError("critic_output_schema_mismatch")
    if type(decision) is not str or decision not in {"accept", "challenge", "insufficient_evidence", "reject"}:
        raise ValueError("critic_output_schema_mismatch")
    supporting_claims = strings("supporting_evidence", max_items=32, max_length=128)
    contradicting_claims = strings("contradicting_evidence", max_items=32, max_length=128)
    missing = strings("missing_evidence", max_items=16, max_length=500)
    validation = strings("required_validation", max_items=16, max_length=500)
    verified = {str(item) for item in verified_evidence_ids if str(item)}
    claimed_ids = (*supporting_claims, *contradicting_claims)
    return CriticReport(
        hypothesis=hypothesis.strip(),
        supporting_evidence=tuple(item for item in supporting_claims if item in verified),
        contradicting_evidence=tuple(item for item in contradicting_claims if item in verified),
        missing_evidence=missing,
        confidence=float(confidence),
        required_validation=validation,
        decision=decision,
        unverified_evidence_ids=tuple(dict.fromkeys(item for item in claimed_ids if item not in verified)),
    )


def _task_capabilities(objective: str) -> frozenset[str]:
    text = objective.casefold()
    requested: set[str] = {"reasoning"}
    if any(word in text for word in ("security", "cyber", "vulnerab", "exploit", "threat", "أمن", "ثغرة", "تهديد")):
        requested.add("security_analysis")
    if any(word in text for word in ("code", "coding", "repository", "repo", "implement", "test", "source", "شفرة", "مستودع", "نفّذ")):
        requested.add("coding")
    if any(word in text for word in ("web", "website", "research", "search", "internet", "ويب", "بحث")):
        requested.add("web_analysis")
    if any(word in text for word in ("summarize", "summary", "تلخيص", "لخّص")):
        requested.add("summarization")
    return frozenset(requested)


def _token_estimate(messages: Iterable[dict[str, Any]]) -> int:
    payload = json.dumps(list(messages), ensure_ascii=False, default=str)
    # Conservative, tokenizer-independent estimate used only for request budgets.
    return max(1, math.ceil(len(payload.encode("utf-8")) / 2))


class ModelOrchestrator:
    """Runs bounded, sequential model collaboration over one immutable input context."""

    def __init__(self, router: ModelRouter, *, policy_max_models: int | None = None, per_call_timeout_seconds: int = 30):
        self.router = router
        self.policy_max_models = policy_max_models
        self.per_call_timeout_seconds = max(1, min(int(per_call_timeout_seconds), 120))

    def profiles(self, *, local_only: bool = False) -> list[ModelProfile]:
        result: list[ModelProfile] = []
        seen: set[int] = set()
        configured = getattr(self.router, "configured_profiles", {})
        reverse_ids = {id(provider): key for key, provider in configured.items()}
        for index, provider in enumerate(getattr(self.router, "providers", ())):
            if id(provider) in seen:
                continue
            seen.add(id(provider))
            profile_id = str(getattr(provider, "profile_id", None) or reverse_ids.get(id(provider)) or getattr(provider, "name", f"provider-{index}"))
            if profile_id == "auto" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_id):
                profile_id = f"provider-{index}"
            profile = ModelProfile.from_provider(provider, profile_id)
            if local_only and not profile.private_endpoint:
                continue
            if ModelRouter._caps(provider).generate or ModelRouter._caps(provider).tool_calling:
                result.append(profile)
        return sorted(result, key=lambda item: (item.priority, item.profile_id))

    @staticmethod
    def _invoke(profile: ModelProfile, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]], timeout: int, max_tokens: int) -> dict[str, Any]:
        provider = profile.provider
        caps = ModelRouter._caps(provider)
        native = bool(tools and caps.tool_calling and callable(getattr(provider, "tool_calling", None)))
        fn = getattr(provider, "tool_calling", None) if native else (getattr(provider, "generate", None) or getattr(provider, "chat", None))
        if not callable(fn):
            raise CapabilityUnsupported("provider has no synchronous inference method", provider=profile.provider_name, model=profile.model_name)
        try:
            signature = inspect.signature(fn)
            supports_kwargs = any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values())
            if not supports_kwargs and "timeout" not in signature.parameters:
                raise CapabilityUnsupported("provider adapter does not implement bounded timeout", provider=profile.provider_name, model=profile.model_name)
        except (TypeError, ValueError):
            # C-extension/builtin methods must still be called with the declared timeout contract.
            supports_kwargs = True
        kwargs: dict[str, Any] = {"temperature": 0.0, "timeout": timeout, "max_tokens": max_tokens}
        if native:
            raw = fn(messages, tools, **kwargs)
            capability = "tool_calling"
        else:
            raw = fn(messages, **kwargs)
            capability = "generate"
        response = ModelRouter._normalize(raw, provider, capability)
        ModelRouter._trusted(response, provider, capability)
        return sanitize_model_data(response.public())

    @staticmethod
    def _role_message(instruction: str, payload: Any | None = None) -> dict[str, str]:
        body = sanitize_model_text(instruction)
        if payload is not None:
            safe_payload = sanitize_model_data(payload)
            body += "\n\n[UNTRUSTED_MODEL_ANALYSIS]\n" + json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, default=str)[:12_000]
        return {"role": "user", "content": body}

    @staticmethod
    def _independent(profile: ModelProfile, others: Iterable[ModelProfile]) -> bool:
        return all(profile.independence_key != other.independence_key and profile.provider is not other.provider for other in others)

    @staticmethod
    def _profile_cost_order(profile: ModelProfile) -> tuple[int, float, int, str]:
        rate = profile.cost_per_1k_tokens_usd
        return (0 if rate is not None else 1, rate if rate is not None else math.inf, profile.priority, profile.profile_id)

    def _record_call(
        self,
        profile: ModelProfile,
        role: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        request: ModelRequest,
        deadline: float,
        *,
        calls: int,
        profiles_used: set[str],
        tokens_used: int,
        cost_reserved: float,
    ) -> tuple[dict[str, Any] | None, ModelInvocation, int, float]:
        started = time.monotonic()
        input_tokens = _token_estimate(messages)
        remaining = deadline - started
        failure_kind = ""
        response: dict[str, Any] | None = None
        output_tokens = 0
        status = "failed"
        request_hash = _hash({"messages": messages, "tools": tools})
        response_hash = ""
        profile_cap = request.budget.max_model_profiles
        try:
            if calls >= request.budget.max_calls:
                raise ProviderFailure("model call budget exhausted", provider=profile.provider_name, model=profile.model_name)
            if profile.profile_id not in profiles_used and len(profiles_used) >= profile_cap:
                raise ProviderFailure("model profile budget exhausted", provider=profile.provider_name, model=profile.model_name)
            if remaining <= 0:
                raise TimeoutError("model orchestration time budget exhausted")
            if tokens_used + input_tokens > request.budget.max_total_tokens:
                raise ProviderFailure("model token budget exhausted", provider=profile.provider_name, model=profile.model_name)
            rate = profile.cost_per_1k_tokens_usd
            if request.budget.max_cost_usd is not None:
                if rate is None:
                    raise ProviderFailure("model cost is unknown under a configured cost ceiling", provider=profile.provider_name, model=profile.model_name)
                upper_bound = ((input_tokens + request.budget.max_output_tokens_per_call) * rate) / 1000
                if cost_reserved + upper_bound > request.budget.max_cost_usd:
                    raise ProviderFailure("model cost budget exhausted", provider=profile.provider_name, model=profile.model_name)
            timeout = max(1, min(self.per_call_timeout_seconds, int(math.ceil(remaining))))
            response = self._invoke(
                profile,
                json.loads(json.dumps(messages, ensure_ascii=False, default=str)),
                tools=json.loads(json.dumps(tools, ensure_ascii=False, default=str)),
                timeout=timeout,
                max_tokens=request.budget.max_output_tokens_per_call,
            )
            elapsed = time.monotonic() - started
            if elapsed > remaining:
                response = None
                raise TimeoutError("model returned after request deadline")
            status = "success"
            response_hash = _hash({"content": response.get("content", ""), "tool_calls": response.get("tool_calls", ())})
            usage = response.get("usage", {}) if isinstance(response.get("usage"), dict) else {}
            output_tokens = int(usage.get("completion_tokens", 0) or 0)
            if output_tokens <= 0:
                output_tokens = max(1, math.ceil(len(str(response.get("content", "")).encode("utf-8")) / 2))
            if tokens_used + input_tokens + output_tokens > request.budget.max_total_tokens:
                response = None
                status = "failed"
                failure_kind = "TOKEN_BUDGET_EXCEEDED"
            else:
                tokens_used += input_tokens + output_tokens
                if rate is not None:
                    cost_reserved += ((input_tokens + output_tokens) * rate) / 1000
        except Exception as exc:
            if isinstance(exc, ProviderError):
                failure_kind = exc.kind.value
            elif isinstance(exc, TimeoutError):
                failure_kind = ProviderFailureKind.TIMEOUT.value
            else:
                failure_kind = type(exc).__name__[:80]
            response = None
        elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
        if response is not None:
            usage = response.get("usage", {}) if isinstance(response.get("usage"), dict) else {}
            reported_input = int(usage.get("prompt_tokens", 0) or 0)
            if reported_input > 0:
                input_tokens = reported_input
            reported_output = int(usage.get("completion_tokens", 0) or 0)
            if reported_output > 0:
                output_tokens = reported_output
        invocation = ModelInvocation(
            role=role,
            profile_id=profile.profile_id,
            provider=profile.provider_name,
            model=profile.model_name,
            status=status,
            context_hash=request.context_hash,
            request_hash=request_hash,
            response_hash=response_hash if response is not None else "",
            failure_kind=failure_kind,
            elapsed_ms=elapsed_ms,
            input_tokens_estimated=input_tokens,
            output_tokens=output_tokens if response is not None else 0,
        )
        return response, invocation, tokens_used, cost_reserved

    def _single_profile_mode(self, request: ModelRequest, profiles: list[ModelProfile]) -> ModelResponse:
        invocations: list[ModelInvocation] = []
        start = time.monotonic()
        deadline = start + request.budget.time_budget_seconds
        used: set[str] = set()
        tokens = 0
        cost = 0.0
        final: dict[str, Any] | None = None
        for profile in profiles[:request.budget.max_model_profiles]:
            used.add(profile.profile_id)
            final, record, tokens, cost = self._record_call(
                profile, "single_model_inference", list(request.messages), list(request.tools), request,
                deadline, calls=len(invocations), profiles_used=used, tokens_used=tokens, cost_reserved=cost,
            )
            invocations.append(record)
            if final is not None:
                break
        metadata = self._metadata(
            request, invocations, status="single_model" if final else "provider_unavailable",
            structural_critic="not_run", cost_estimate_usd=cost if request.budget.max_cost_usd is not None else None,
            cost_budget_enforced=request.budget.max_cost_usd is not None,
        )
        if final is None:
            return ModelResponse("", (), "unavailable", "unavailable", {}, metadata)
        return ModelResponse(
            str(final.get("content", "") or ""), tuple(final.get("tool_calls") or ()),
            str(final.get("provider", "unknown")), str(final.get("model", "unknown")),
            dict(final.get("usage") or {}), metadata,
        )

    @staticmethod
    def _metadata(request: ModelRequest, invocations: list[ModelInvocation], *, status: str, **extra: Any) -> dict[str, Any]:
        return {
            "record_type": "MODEL_ORCHESTRATION",
            "status": status,
            "request_id": request.request_id,
            "mission_id": request.mission_id,
            "task_id": request.task_id,
            "context_hash": request.context_hash,
            "context_provenance": [dict(item) for item in request.context_provenance],
            "preference": request.preference,
            "task_capabilities": sorted(request.task_capabilities),
            "budget": request.budget.to_dict(),
            "cost_budget_enforced": request.budget.max_cost_usd is not None,
            "require_tool_calling": request.require_tool_calling,
            "max_parallelism_used": 1,
            "invocations": [item.to_dict() for item in invocations],
            "model_outputs_are_evidence": False,
            **extra,
        }

    def orchestrate(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        objective: str,
        request_id: str = "",
        mission_id: str = "",
        task_id: str = "",
        context_hash: str = "",
        context_provenance: Iterable[dict[str, Any]] = (),
        preference: str = "balanced",
        verified_evidence_ids: Iterable[str] = (),
        require_tool_calling: bool = False,
    ) -> dict[str, Any]:
        if preference not in PREFERENCES:
            raise ValueError("invalid_model_preference")
        budget = ModelBudget.for_preference(preference, policy_max_models=self.policy_max_models)
        profiles = self.profiles(local_only=preference == "local")
        has_tool_profile = any(profile.capabilities.tool_calling for profile in profiles)
        if not profiles or (require_tool_calling and not has_tool_profile):
            empty_request = ModelRequest(
                request_id, mission_id, task_id, objective, tuple(messages), tuple(tools), context_hash,
                tuple(context_provenance), preference, _task_capabilities(objective), budget,
                require_tool_calling=bool(require_tool_calling),
            )
            metadata = self._metadata(empty_request, [], status="no_provider", structural_critic="not_run")
            metadata["reason"] = (
                "no_local_tool_calling_profile" if preference == "local" and require_tool_calling
                else "no_local_model_profile" if preference == "local"
                else "no_tool_calling_profile" if require_tool_calling
                else "no_configured_model_profile"
            )
            return ModelResponse("", (), "unavailable", "unavailable", {}, metadata).to_dict()
        task_caps = _task_capabilities(objective)
        safe_messages = sanitize_model_data(messages)
        safe_tools = sanitize_model_data(tools)
        request = ModelRequest(
            request_id=str(request_id), mission_id=str(mission_id), task_id=str(task_id), objective=sanitize_model_text(objective),
            messages=tuple(json.loads(json.dumps(safe_messages, ensure_ascii=False, default=str))),
            tools=tuple(json.loads(json.dumps(safe_tools, ensure_ascii=False, default=str))),
            context_hash=str(context_hash or _hash(safe_messages)),
            context_provenance=tuple(sanitize_model_data(item) for item in context_provenance if isinstance(item, dict)),
            preference=preference,
            task_capabilities=task_caps,
            budget=budget,
            require_tool_calling=bool(require_tool_calling),
        )
        has_task_roles = any(profile.capabilities.task_capabilities for profile in profiles)
        if budget.max_model_profiles == 1 or not has_task_roles:
            eligible = [profile for profile in profiles if profile.capabilities.tool_calling] if require_tool_calling else profiles
            return self._single_profile_mode(request, eligible).to_dict()

        inference_profiles = [profile for profile in profiles if profile.capabilities.task_capabilities]
        primary_caps = {"reasoning", "planning"} | set(task_caps)
        primary_candidates = [
            p for p in inference_profiles
            if p.capabilities.task_capabilities.intersection(primary_caps)
            and (not require_tool_calling or p.capabilities.tool_calling)
        ]
        primary_candidates.sort(key=lambda p: (
            0 if p.capabilities.task_capabilities.intersection(task_caps - {"reasoning"}) else 1,
            0 if "planning" in p.capabilities.task_capabilities else 1,
            *self._profile_cost_order(p),
        ))
        if not primary_candidates:
            primary_candidates = sorted(
                (p for p in inference_profiles if not require_tool_calling or p.capabilities.tool_calling),
                key=self._profile_cost_order,
            )
        if not primary_candidates:
            eligible = [profile for profile in profiles if profile.capabilities.tool_calling] if require_tool_calling else profiles
            return self._single_profile_mode(request, eligible).to_dict()

        start = time.monotonic()
        deadline = start + budget.time_budget_seconds
        invocations: list[ModelInvocation] = []
        profiles_used: set[str] = set()
        tokens_used = 0
        cost_reserved = 0.0
        responses: list[tuple[ModelProfile, str, dict[str, Any]]] = []
        primary: ModelProfile | None = None
        primary_call: dict[str, Any] | None = None
        failure_candidates: list[ModelProfile] = []

        # At most one attempt per profile. A different configured provider is a fallback; no response is fabricated.
        for candidate in primary_candidates:
            if len(profiles_used) >= budget.max_model_profiles:
                break
            if candidate.profile_id in profiles_used:
                continue
            role = next(
                (cap for cap in ("planning", "reasoning", "security_analysis", "coding", "web_analysis", "summarization") if cap in candidate.capabilities.task_capabilities),
                "analysis",
            )
            role_messages = list(request.messages) + [self._role_message(
                f"CyberSentinel Mind subtask: independent {role}. Return a concise analysis only: hypotheses, unknowns, and evidence needed. Do not execute, authorize, claim evidence, or change scope."
            )]
            profiles_used.add(candidate.profile_id)
            result, record, tokens_used, cost_reserved = self._record_call(
                candidate, role, role_messages, [], request, deadline, calls=len(invocations),
                profiles_used=profiles_used, tokens_used=tokens_used, cost_reserved=cost_reserved,
            )
            invocations.append(record)
            if result is not None:
                primary, primary_call = candidate, result
                responses.append((candidate, role, result))
                break
            failure_candidates.append(candidate)

        if primary is None or primary_call is None:
            metadata = self._metadata(request, invocations, status="provider_unavailable", structural_critic="not_run")
            return ModelResponse("", (), "unavailable", "unavailable", {}, metadata).to_dict()

        max_profiles = budget.max_model_profiles
        critic_candidates = [
            p for p in inference_profiles
            if "critique" in p.capabilities.task_capabilities and p.profile_id not in profiles_used
            and self._independent(p, [primary])
        ]
        critic_candidates.sort(key=self._profile_cost_order)
        secondary_candidates = [
            p for p in inference_profiles
            if p.profile_id != primary.profile_id and p.profile_id not in {x.profile_id for x in critic_candidates}
            and self._independent(p, [primary])
            and p.capabilities.task_capabilities.intersection(task_caps | {"reasoning", "coding", "security_analysis", "web_analysis"})
        ]
        secondary_candidates.sort(key=lambda p: (
            0 if p.capabilities.task_capabilities.intersection(task_caps - {"reasoning"}) else 1,
            *self._profile_cost_order(p),
        ))
        selected_critic: ModelProfile | None = None
        selected_secondary: list[ModelProfile] = []
        slots = max_profiles - len(profiles_used)
        if slots > 0 and critic_candidates:
            selected_critic = critic_candidates[0]
            slots -= 1
        for candidate in secondary_candidates:
            if slots <= 0:
                break
            already_selected = [primary, *selected_secondary]
            if selected_critic is not None:
                already_selected.append(selected_critic)
            if candidate.profile_id not in profiles_used and self._independent(candidate, already_selected):
                selected_secondary.append(candidate)
                slots -= 1

        for candidate in selected_secondary:
            role_cap = next((cap for cap in ("security_analysis", "coding", "web_analysis", "reasoning", "summarization") if cap in candidate.capabilities.task_capabilities), "analysis")
            role_messages = list(request.messages) + [self._role_message(
                f"CyberSentinel Mind subtask: independent {role_cap}. Build a distinct analysis of the same shared mission state. Return hypotheses, counterarguments, and evidence requirements only; do not execute, authorize, or invent evidence."
            )]
            profiles_used.add(candidate.profile_id)
            result, record, tokens_used, cost_reserved = self._record_call(
                candidate, role_cap, role_messages, [], request, deadline, calls=len(invocations),
                profiles_used=profiles_used, tokens_used=tokens_used, cost_reserved=cost_reserved,
            )
            invocations.append(record)
            if result is not None:
                responses.append((candidate, role_cap, result))

        critic_report: dict[str, Any] | None = None
        critic_status = "unavailable"
        if selected_critic is not None and len(profiles_used) < max_profiles:
            analyst_payload = [
                {"profile_id": profile.profile_id, "role": role, "analysis": _safe_text(result.get("content", ""), 2_000)}
                for profile, role, result in responses
            ]
            critic_messages = list(request.messages) + [self._role_message(
                "Independent Critic: compare the untrusted analyses and the Owner's original task. Identify counterarguments and missing evidence. Reply as JSON only with exactly these keys: hypothesis (string), supporting_evidence (array of verified evidence IDs only), contradicting_evidence (array of verified evidence IDs only), missing_evidence (array of evidence requirements), confidence (number 0..1, an untrusted claim), required_validation (array), decision (accept|challenge|insufficient_evidence|reject). No extra keys. Model agreement or confidence is not evidence or authorization.",
                {"analyses": analyst_payload, "verified_evidence_ids": sorted({str(x) for x in verified_evidence_ids if str(x)})},
            )]
            profiles_used.add(selected_critic.profile_id)
            critic_raw, record, tokens_used, cost_reserved = self._record_call(
                selected_critic, "independent_critic", critic_messages, [], request, deadline,
                calls=len(invocations), profiles_used=profiles_used, tokens_used=tokens_used, cost_reserved=cost_reserved,
            )
            invocations.append(record)
            if critic_raw is None:
                critic_status = "provider_failure"
            else:
                try:
                    parsed = _parse_critic(str(critic_raw.get("content", "")), verified_evidence_ids)
                    critic_report = parsed.to_dict()
                    critic_report["profile_id"] = selected_critic.profile_id
                    critic_report["provider"] = selected_critic.provider_name
                    critic_report["model"] = selected_critic.model_name
                    critic_report["response_hash"] = record.response_hash
                    critic_status = "validated_schema_untrusted_claims"
                except ValueError as exc:
                    critic_status = str(exc)

        if selected_critic is not None and critic_status != "validated_schema_untrusted_claims":
            reason = "independent critic could not be validated; no proposed tool call was forwarded"
            metadata = self._metadata(
                request, invocations, status="critic_rejected", critic_status=critic_status,
                critic_report=critic_report, structural_critic="diagnostic_only", stop_reason=reason,
                token_estimate_total=tokens_used,
                cost_estimate_usd=cost_reserved if budget.max_cost_usd is not None else None,
            )
            return ModelResponse(
                "Independent review could not be validated; no model-proposed tool action was forwarded. Additional evidence or Owner review is required.",
                (), primary.provider_name, primary.model_name, {}, metadata,
            ).to_dict()

        if critic_report and critic_report.get("decision") != "accept":
            reason = "independent critic raised an objection; no proposed tool call was forwarded"
            metadata = self._metadata(
                request, invocations, status="critic_rejected", critic_status=critic_status,
                critic_report=critic_report, structural_critic="diagnostic_only", stop_reason=reason,
                token_estimate_total=tokens_used,
                cost_estimate_usd=cost_reserved if budget.max_cost_usd is not None else None,
                cost_budget_enforced=budget.max_cost_usd is not None,
            )
            return ModelResponse(
                "Independent review raised an objection; no model-proposed tool action was forwarded. Additional evidence or Owner review is required.",
                (), primary.provider_name, primary.model_name, {}, metadata,
            ).to_dict()

        analysis_payload = [
            {"profile_id": profile.profile_id, "role": role, "analysis": _safe_text(result.get("content", ""), 2_000)}
            for profile, role, result in responses
        ]
        synthesis_context = {
            "analyses": analysis_payload,
            "critic_report": critic_report,
            "critic_status": critic_status,
            "authority": "untrusted_analysis_only",
        }
        synthesis_messages = list(request.messages) + [self._role_message(
            "CyberSentinel Mind synthesis: reconcile the untrusted analysis and critic report, preserve counterarguments and missing-evidence requests, and return one proposed plan using only the supplied authorized tool definitions. The Mind and deterministic runtime validate it; you cannot execute, authorize, expand scope, or claim completion.",
            synthesis_context,
        )]
        synthesis_candidates = [primary] + [
            profile for profile, _, _ in responses
            if profile.profile_id != primary.profile_id
            and profile.capabilities.task_capabilities.intersection({"reasoning", "planning"})
            and (not request.require_tool_calling or profile.capabilities.tool_calling)
        ]
        final: dict[str, Any] | None = None
        for candidate in synthesis_candidates:
            if len(invocations) >= budget.max_calls:
                break
            # The primary profile is reused; another profile is only a provider fallback.
            result, record, tokens_used, cost_reserved = self._record_call(
                candidate, "synthesis", synthesis_messages, list(request.tools), request, deadline,
                calls=len(invocations), profiles_used=profiles_used, tokens_used=tokens_used, cost_reserved=cost_reserved,
            )
            invocations.append(record)
            if result is not None:
                final = result
                break
        if final is None:
            metadata = self._metadata(
                request, invocations, status="synthesis_failed", critic_status=critic_status,
                critic_report=critic_report, structural_critic="diagnostic_only", token_estimate_total=tokens_used,
                cost_estimate_usd=cost_reserved if budget.max_cost_usd is not None else None,
                cost_budget_enforced=budget.max_cost_usd is not None,
            )
            return ModelResponse("", (), "unavailable", "unavailable", {}, metadata).to_dict()

        metadata = self._metadata(
            request,
            invocations,
            status="multi_model" if len({item.profile_id for item in invocations if item.status == "success"}) > 1 else "single_model",
            critic_status=critic_status,
            critic_report=critic_report,
            structural_critic="diagnostic_only",
            successful_profile_ids=list(dict.fromkeys(item.profile_id for item in invocations if item.status == "success")),
            token_estimate_total=tokens_used,
            cost_estimate_usd=cost_reserved if budget.max_cost_usd is not None else None,
            cost_budget_enforced=budget.max_cost_usd is not None,
            retries_used=0,
            fallback_used=bool(failure_candidates),
        )
        return ModelResponse(
            str(final.get("content", "") or ""), tuple(final.get("tool_calls") or ()),
            str(final.get("provider", "unknown")), str(final.get("model", "unknown")),
            dict(final.get("usage") or {}), metadata,
        ).to_dict()


__all__ = [
    "CriticReport", "MODEL_CAPABILITIES", "ModelBudget", "ModelCapabilities",
    "ModelInvocation", "ModelOrchestrationError", "ModelOrchestrator", "ModelProfile",
    "ModelRequest", "ModelResponse", "PREFERENCES", "TASK_CAPABILITIES", "TRANSPORT_CAPABILITIES",
]
