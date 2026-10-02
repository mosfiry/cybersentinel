# Provider Failure Model — V9

Status: VERIFIED at 2eeefc2d (CI green). Model failure is DATA: every failure is
classified, persisted on the mission, and routed through bounded recovery. A
provider failure never becomes fake success or false completion — this invariant
is pinned by tests, not asserted by prose.

## Taxonomy (source: agent/provider_api.py ProviderFailureKind)

| Source kind | Mission §14 label | Meaning | Recorded as |
| --- | --- | --- | --- |
| TIMEOUT | MODEL_TIMEOUT | Transport timeout at provider boundary | ProviderTimeout; classified from TimeoutError by ModelRouter._classify |
| INVALID_MODEL_RESPONSE | MODEL_SCHEMA_FAILURE | Invalid JSON / malformed / schema-violating response | InvalidModelResponse; also from TypeError/ValueError at the router boundary |
| CAPABILITY_UNSUPPORTED | MODEL_REJECT | Provider cannot serve the requested capability (e.g. native tool calling) | CapabilityUnsupported; RouterNativeModel falls back to generate() ONLY for this kind |
| PROVIDER_FAILURE | MODEL_PROVIDER_FAILURE | Provider unavailable / all providers failed / unclassified transport error | ProviderFailure; router raises when every provider fails |
| AUTHENTICATION_FAILURE | MODEL_PROVIDER_FAILURE (auth subcase) | Provider credentials rejected | ProviderAuthenticationFailure (from PermissionError) |
| (runtime exception) | MODEL_RUNTIME_FAILURE | Any other exception at the router boundary | ModelRouter._classify wraps as PROVIDER_FAILURE with type name in the message |
| (deterministic) | DETERMINISTIC_VALIDATION_FAILURE | Tool/validation failure that is a factual observation | Never provider failure; a failed tool result is a failure observation and NEVER verification evidence (tests/test_failure_recovery_replan.py) |

## Persistence as data (source: agent/mission_runtime.py run_model_loop)

On ProviderError the runtime appends to mission.failures AND
progress["model_failures"] a record {"class": PROVIDER, "kind", "reason",
"turn_id", "run_id"}, sets mission.error = "model provider failure: <kind>",
increments retry_count, emits FAILURE_DETECTED/FAILURE_DIAGNOSED, and applies
the bounded RecoveryPolicy action: RETRY -> mission READY; REPLAN -> REPLANNING;
FAIL -> FAILED_RETRY_EXHAUSTED (terminal, honest).

## Reliability behaviors verified by tests/test_provider_failure_model.py

- provider unavailable, timeout, malformed response, invalid schema, duplicate/
  malformed tool calls: classified and recorded; retry exhaustion is terminal
  FAILED_RETRY_EXHAUSTED — never fake success (11 tests).
- failover across providers with a per-provider failure trace (last_trace).
- all-providers-failed raises ProviderFailure (no silent degradation).
- native adapter fallback ONLY on CAPABILITY_UNSUPPORTED; real provider failures
  propagate and are never disguised as generate() responses.
- baseline ambiguity tests (tools, side effects) remain the authority on
  deterministic-vs-ambiguous failure; provider failures are deterministic.

## Honest limits

- Streaming partial responses are NOT VERIFIED (no streaming provider path is
  exercised by the suite; OpenAICompatibleProvider has a streaming capability
  flag but no implemented stream parser in this lineage).
- Rate-limit-specific classification is NOT VERIFIED: HTTP 429 surfaces as the
  generic PROVIDER_FAILURE classification of urllib HTTPError; no dedicated
  RATE_LIMITED kind exists. Recorded as a design gap, not a claim.
