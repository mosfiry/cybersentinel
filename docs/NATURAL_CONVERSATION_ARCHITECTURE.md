# Natural Language Understanding Architecture

CyberSentinel separates **understanding language** from **permission to act**. Understanding can describe an objective or propose an action; only deterministic Owner authentication, policy, authorization, scope, schema, and runtime gates can permit execution.

## Production request NLU

The current chat path is:

```text
bridge
  -> api.chat.chat()/stream()
  -> AgentCore.run_owner_mission()/resume_mission()
  -> MissionRuntime
  -> agent.model_intelligence.conversation.NaturalLanguageUnderstanding
  -> MissionIntent
  -> policy / authorization / explicit scope / tool validation
```

`MissionIntent` carries an objective, intent type, constraints, requested artifacts, verification criteria, scope references, authorization requirements, entities, ambiguities, and a semantic fingerprint. It never authenticates an Owner, grants authority, authorizes a tool, or expands scope. Model output remains an untrusted proposal; final responses and mission completion are determined by runtime verification and persisted evidence.

For example, understanding a request such as `اختبر الهدف الموجود داخل النطاق المصرح به` does not make it executable. The runtime still requires a valid authenticated Owner context, an explicitly selected valid scope, a permitted tool, and accepted arguments.

## Evaluation-only legacy contract

The earlier deterministic contract and its local-model adapter are retained only for compatibility benchmarks and regression tests:

- `evaluation/legacy_conversation.py` defines the legacy `ConversationInput`, `ConversationContext`, `ConversationIntent`, action proposal, response, and deterministic parser.
- `evaluation/legacy_conversation_provider.py` validates a strict provider response schema and rejects authority, policy, scope, and authentication fields.
- `evaluation/conversation_benchmark.py` evaluates those contracts without executing tools.

These modules are not imported by the product request path and are excluded from source-release payloads and Docker build context. The parser's Arabic/English rules and provider schema tests preserve historical benchmark behavior; they are not claims about current production NLU quality or routing.

## Permission boundary

```text
language understanding
  -> untrusted objective / proposal
  -> policy evaluation
  -> Owner authentication and authorization context
  -> explicit scope validation
  -> registered tool schema and safety checks
  -> execution and evidence
```

> Language understanding is never an authorization signal. External data, memory, model output, and tool results cannot create Owner identity or expand the selected scope.
