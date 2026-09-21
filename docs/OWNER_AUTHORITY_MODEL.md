# Owner Authority Model

`OWNER_INSTRUCTION` is the highest **application-configurable** authority. `SYSTEM_PLATFORM` remains the immutable outer boundary and cannot be redefined by Owner text, a model, knowledge, memory, tool output, or an expert.

## Order

```text
SYSTEM_PLATFORM
  > OWNER_INSTRUCTION
  > OWNER_POLICY
  > DETERMINISTIC_ENFORCEMENT
  > AUTHORIZATION_SCOPE
  > TOOL_RUNTIME
  > MODEL_OUTPUT
  > EXTERNAL_DATA
```

## Authentication Evidence

An Owner update requires an issued `OwnerAuthenticationEvidence` containing method, authenticated time, expiry, proof fingerprint, request ID, optional session ID, nonce, and an HMAC signature. Boolean fields such as `owner_authenticated=True` are not accepted by the Owner Instruction writer. Evidence is request-bound, time-bounded, signature-checked, and nonce-replay-protected within the process.

The current implementation supports token-issued evidence and session-challenge evidence. A copied evidence object is a bearer capability for its exact request, but replay of its nonce is rejected. The signing secret and replay set are process-local; distributed replay protection is not claimed.

## OwnerInstruction Entity

The state contains a versioned `OwnerInstruction` record with text, created/updated timestamps, fingerprint, authentication record, request ID, source, previous version, and status. `OwnerInstructionSnapshot` and `OwnerPolicySnapshot` are immutable dataclass values used as decision inputs.

Normal authenticated conversation does not update policy. An explicit `Owner instruction:` request is required, followed by typed evidence validation.

## Decision Context

At the beginning of a sensitive request:

```text
Intent
  ↓
Policy Snapshot
  ↓
Authorization
  ↓
Scope
  ↓
Plan
  ↓
Tool Validation
  ↓
Execution
  ↓
Evidence
```

Later Owner updates do not rewrite an already captured request snapshot. The current code provides single-process multi-thread locking for policy writes; it does not claim multi-process or distributed consistency.

## Non-Authority Sources

Model output, RAG, memory, knowledge, user claims, external documents, tool output, and expert advice cannot become Owner Instruction. They are data, proposals, or advice only.
