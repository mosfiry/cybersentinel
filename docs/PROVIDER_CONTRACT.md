# LLM provider contract

## Authority boundary

The model is an intelligence component. It may return text or propose tool calls; it is not an authorization principal and does not grant execution authority. A model response is normalized into `ProviderResponse`/`ToolCall` by `agent/provider_api.py`, then consumed by `MissionRuntime`. Tool execution still requires the mission-bound Owner authorization snapshot, unique tool-call identity, valid one-use execution proof, and final tool-registry enforcement. Provider selection or a successful completion response cannot satisfy mission evidence criteria.

## Implemented interface

`ProviderCapabilities` carries flags for generation, streaming, native tool calls, structured output, reasoning, long context, vision, and related features. In the current router, only `generate` and `tool_calling` are operation-selection gates. Several other fields are descriptive declarations, not proof that a streaming/structured-output/vision/reasoning implementation exists. `ProviderResponse` normalizes text, tool calls, finish reason, provider/model labels, usage, and requested capability. Typed failures distinguish unsupported capability, general provider failure, malformed response, timeout, and authentication failure.

`OpenAICompatibleProvider` sends requests to `{base_url}/chat/completions`. Its implemented operations are synchronous `generate`/`chat` and optional native `tool_calling` when explicitly configured. It does not implement streaming, and its structured-output, vision, reasoning, long-context, and parallel-tool flags are declarations only; do not set or rely on them as verified functionality unless a concrete adapter and tests establish that support. This is an OpenAI-compatible protocol adapter, not proof that every named model/provider behaves identically.

`ModelRouter` sorts configured adapters by priority. For each request it selects the first adapter that declares the requested capability; on a provider error it records a trace and tries the next adapter that supports that same operation. It does not downgrade native tool calling to ordinary text generation: if no configured provider supports tool calls it raises `CapabilityUnsupported`, and failures of native-tool-capable providers raise a typed `ProviderFailure`. This prevents a provider outage from silently changing the execution protocol.

## Environment configuration

`ModelRouter.from_env()` recognizes provider-prefixed groups in priority order by default:

| Prefix | Configuration |
|---|---|
| `LOCAL_LLM_*` | `BASE_URL`, `MODEL`, optional `API_KEY`, `TOOL_CALLING`, `STREAMING`, `STRUCTURED_OUTPUT`, `PRIORITY` |
| `COLAB_LLM_*` | Same fields |
| `HF_LLM_*` | Same fields |
| `LLM_*` | Generic OpenAI-compatible fallback, used only when none of the prefixed providers is configured |

An adapter is configured only when both base URL and model are non-empty. Native tool calling defaults to false unless explicitly set. `*_LLM_STREAMING` and `*_LLM_STRUCTURED_OUTPUT` currently set descriptive flags only; streaming is not implemented and structured-output behavior is not independently enforced by the adapter. The default provider priority is the order shown above; explicit priority overrides it. Secrets belong in server environment configuration and are never part of browser request payloads.

## Security and truthfulness invariants

- Provider names, model names, and returned text are untrusted response metadata; the router normalizes labels from the configured adapter.
- Capability selection changes which provider is asked, not the Owner's authorized actions or target scope.
- Every proposed tool call is independently checked by MissionRuntime and the registry; provider output cannot bypass plan prerequisites or proof consumption.
- External provider text, usage, and response success are not system evidence and cannot mark a goal complete.
- If the requested capability is unavailable or all compatible adapters fail, the request fails explicitly; the runtime must not claim the model operation succeeded.

## Verified tests and limits

Current deterministic tests cover priority/failover traces, provider-label normalization, native-tool capability rejection, native provider failure without text-generation downgrade, and adversarial provider responses (`tests/test_phase21_provider_compaction.py`, `tests/test_phase6a1_hardening.py`, `tests/test_v44_architecture.py`, and `tests/test_v45_adversarial.py`). These are mock-provider tests, not live connectivity tests.

The repository currently implements an OpenAI-compatible HTTP adapter and generic environment-based routing. It does **not** contain separately verified native integrations for DeepSeek, Qwen3, or H3, nor a provider-isolated multi-agent expert dispatcher. Do not claim such integrations or capabilities until a specific adapter is configured, tested, and validated against its service. Provider credentials, network reachability, timeout behavior against a real service, and model-quality claims remain deployment-specific and unverified by the local test suite.
