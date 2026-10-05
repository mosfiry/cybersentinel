from __future__ import annotations

import json
import urllib.error
import io
from typing import Any
from urllib.parse import urlsplit

from security.pinned_http import PinnedRequestError, pinned_http_request

from .provider_api import (
    MAX_PROVIDER_ARGUMENT_BYTES,
    MAX_PROVIDER_RESPONSE_BYTES,
    MAX_PROVIDER_TOOL_CALLS,
    MAX_PROVIDER_TOOL_NAME_CHARS,
    HardwareRequirements,
    InvalidModelResponse,
    ProviderCapabilities,
    ProviderDeployment,
    ProviderMetadata,
    ProviderResponse,
    ToolCall,
    enforce_json_byte_limit,
    validate_provider_response,
)


class OpenAICompatibleProvider:
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
        context_length: int | None = None,
        model_version: str | None = None,
        quantization: str | None = None,
        deployment: ProviderDeployment | str = ProviderDeployment.UNKNOWN,
        hardware_requirements: HardwareRequirements | None = None,
    ):
        self.name = name
        self.base_url = base_url.rstrip("/")
        parsed_base = urlsplit(self.base_url)
        if parsed_base.query or parsed_base.username is not None or parsed_base.password is not None or parsed_base.fragment:
            raise ValueError("provider base_url must not contain credentials, query parameters, or a fragment")
        self.model = model
        self.api_key = api_key
        if context_length is not None and (isinstance(context_length, bool) or not isinstance(context_length, int) or context_length < 1):
            raise ValueError("context_length must be a positive integer")
        self.context_length = context_length
        self.failure_count = 0
        self.last_error = ""
        self.priority = priority
        self.capabilities = ProviderCapabilities(generate=True, stream=streaming, tool_calling=tool_calling, structured_output=structured_output, chat=True, native_chat=True, parallel_tool_calls=parallel_tool_calls, reasoning=reasoning, reasoning_budget=reasoning_budget, long_context=long_context, vision=vision)
        self.model_version = model_version
        self.quantization = quantization
        self.deployment = ProviderDeployment(deployment)
        self.hardware_requirements = (
            hardware_requirements if hardware_requirements is not None else HardwareRequirements()
        )
        _ = self.metadata  # Validate the complete metadata contract at construction time.

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self.name,
            model_identity=self.model,
            capabilities=self.capabilities,
            context_length=self.context_length,
            model_version=self.model_version,
            quantization=self.quantization,
            deployment=self.deployment,
            hardware_requirements=self.hardware_requirements,
        )

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
            "metadata": self.metadata.public(),
        }

    def _request(self, payload: dict[str, Any], timeout: int = 90) -> dict[str, Any]:
        url = self.base_url + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        try:
            response = pinned_http_request(
                url,
                method="POST",
                headers=headers,
                body=json.dumps(payload).encode(),
                timeout=timeout,
                max_response_bytes=MAX_PROVIDER_RESPONSE_BYTES,
                allow_loopback=True,
            )
            if response.status >= 400:
                raise urllib.error.HTTPError(
                    url,
                    response.status,
                    "provider returned an HTTP error",
                    response.headers,
                    io.BytesIO(response.body),
                )
            raw_body = response.body
            if not isinstance(raw_body, (bytes, bytearray)):
                raise InvalidModelResponse("provider returned a non-byte response body", provider=self.name, model=self.model)
            try:
                data = json.loads(bytes(raw_body).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise InvalidModelResponse("provider returned malformed JSON", provider=self.name, model=self.model) from exc
            if not isinstance(data, dict):
                raise InvalidModelResponse("provider returned a non-object response", provider=self.name, model=self.model)
            self.last_error = ""
            return data
        except PinnedRequestError as exc:
            self.failure_count += 1
            if str(exc) == "HTTP response exceeds the configured size limit":
                self.last_error = "InvalidModelResponse"
                raise InvalidModelResponse("provider response exceeds the configured size limit", provider=self.name, model=self.model) from exc
            self.last_error = type(exc).__name__
            raise
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
        if not isinstance(raw_calls, list) or len(raw_calls) > MAX_PROVIDER_TOOL_CALLS:
            raise invalid("provider returned malformed tool calls")
        calls: list[ToolCall] = []
        for raw in raw_calls:
            if not isinstance(raw, dict):
                raise invalid("provider returned malformed tool call")
            function = raw.get("function")
            if not isinstance(function, dict):
                raise invalid("provider returned malformed tool function")
            name = function.get("name")
            if not isinstance(name, str) or len(name) > MAX_PROVIDER_TOOL_NAME_CHARS or not name.strip():
                raise invalid("provider returned a tool call without a valid name")
            args = function.get("arguments", {})
            if args is None:
                args = {}
            if isinstance(args, str):
                enforce_json_byte_limit(
                    args,
                    max_bytes=MAX_PROVIDER_ARGUMENT_BYTES,
                    message="provider returned oversized or malformed tool arguments",
                    provider=self.name,
                    model=self.model,
                )
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError) as exc:
                    raise invalid("provider returned malformed tool arguments") from exc
            if not isinstance(args, dict):
                raise invalid("provider tool arguments must be an object")
            call_id = raw.get("id", "")
            if call_id is None:
                call_id = ""
            if not isinstance(call_id, str):
                raise invalid("provider returned malformed tool-call identity")
            calls.append(ToolCall(name, args, call_id))
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
        return validate_provider_response(ProviderResponse(
            text=content,
            tool_calls=calls,
            finish_reason=str(finish_reason or ("tool_calls" if calls else "stop")),
            provider=self.name,
            model=self.model,
            usage=usage,
            capability=capability,
        ), provider=self.name, model=self.model)

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
