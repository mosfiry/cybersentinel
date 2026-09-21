# Natural Conversation Architecture

CyberSentinel separates language understanding from permission.

```text
NATURAL LANGUAGE
  ↓
UNDERSTANDING
  ↓
INTENT
  ↓
ACTION PROPOSAL
  ↓
POLICY EVALUATION
  ↓
AUTHORIZATION
  ↓
SCOPE
  ↓
TOOL VALIDATION
  ↓
EXECUTION
```

## Typed Boundary

The conversation layer exposes:

- `ConversationInput`: raw text plus request and conversation identity.
- `ConversationContext`: request metadata, policy snapshot fingerprint, scope fingerprint, and evidence IDs.
- `ConversationIntent`: classified intent and entities. It never grants authority.
- `ConversationActionProposal`: an untrusted proposed action with arguments and a status of `PROPOSED`.
- `ConversationResponse`: natural language, intent, proposal, tool-call data, confidence, and evidence needed. It deliberately has no provider-controlled `authority_granted` field.
- `ConversationProvider`: provider contract returning typed responses without executing tools.

## Arabic and English Foundation

The deterministic parser currently covers incident analysis, learning, rejection explanation, evidence explanation, code analysis, scoped testing, and research in Arabic, English, and selected mixed-language forms. This is a tested foundation, not a complete semantic model or a production Arabic quality claim.

For a request such as `اختبر الهدف الموجود داخل النطاق المصرح به`, the expected result is:

```text
intent = SCOPED_TEST
authorization_required = true
authority_granted = false
action_proposal.status = PROPOSED
execution = false
```

A later authenticated Owner + valid authorization + valid scope + valid tool schema may allow execution through the core engine. Understanding alone never does.

## Model Provider Rule

A future model adapter must return `ConversationResponse` or a stricter typed equivalent. It may propose tool calls, but the application must treat them as untrusted input and route them through the tool firewall. The model is never the source of Owner authority, authorization, scope, or execution result.
