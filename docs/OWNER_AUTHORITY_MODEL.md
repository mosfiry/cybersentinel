# Owner Authority Model

## Normative instruction precedence

The Owner's explicit direction is the highest normative instruction source:

```text
OWNER_INSTRUCTION (900)
  > SYSTEM_PLATFORM (800)
  > OWNER_POLICY (600)
  > DETERMINISTIC_ENFORCEMENT (500)
  > AUTHORIZATION_SCOPE (400)
  > TOOL_RUNTIME (300)
  > MODEL_OUTPUT (200)
  > EXTERNAL_DATA (100)
```

This ordering resolves **instruction and policy-source precedence only**. An authority rank is not an execution capability, an authentication credential, a selected scope, or an authorization decision. `SYSTEM_PLATFORM` is the second normative source; platform/runtime invariants are enforced separately as unconditional gates and cannot be waived by any instruction.

## Non-overridable execution gates

Every relevant operation must pass all applicable gates:

1. Valid, request-bound `OwnerAuthenticationEvidence` from the Owner authentication path.
2. An explicitly Owner-selected, valid `ScopeSnapshot` for scope-bound operations.
3. Tool authorization and `ToolSpec`/argument-boundary checks.
4. A supported process sandbox and workspace/resource boundary.
5. Owner cancellation and execution-fence checks, including transport send boundaries.
6. Evidence provenance and integrity checks.

A failed gate denies the operation even when the Owner instruction requests it. Model output, external data, memory, tool output, and a natural-language claim cannot manufacture a gate result. The authority snapshot records these as `NON_OVERRIDABLE_EXECUTION_GATES` and explicitly records that Owner rank grants no execution permission.

## Authentication evidence

An Owner update requires an issued `OwnerAuthenticationEvidence` containing method, authenticated time, expiry, proof fingerprint, request ID, optional session ID, nonce, and an HMAC signature. Boolean fields such as `owner_authenticated=True` and client-supplied mappings are not accepted by the Owner Instruction writer. Evidence is request-bound, time-bounded, signature-checked, and nonce-replay-protected within the process.

The current evidence source is `username_password`, backed by the server-managed Owner session. The policy reference module also requires typed, request-bound evidence; it does not authenticate a session by inspecting client claims. The signing secret and replay set are process-local; serialized worker validation checks the exact request, evidence fingerprint, expiry, and active Owner session. Distributed replay protection is not claimed.

## OwnerInstruction snapshots and request context

The state contains a versioned `OwnerInstruction` record with text, timestamps, fingerprint, authentication record, request ID, source, previous version, and status. `OwnerInstructionSnapshot` and `OwnerPolicySnapshot` are immutable decision inputs. A later Owner update does not rewrite a request snapshot already captured.

A natural-language instruction can state the desired policy or objective, but cannot itself create a `ScopeSnapshot`, authorize a tool, start a process, disable cancellation, or attest evidence. Those are separate runtime decisions.

## Code boundaries and status

`security/authority.py` exports descriptive precedence metadata; no tool authorization decision is made by comparing enum numbers. `security/owner_charter.py` is a policy reference model and is not imported by the live request/authorization path; its result is not execution permission. Live authorization is enforced by `AuthorizationContext`, `security/authorization.py`, the tool registry, and the governed runtime/sandbox/transport boundaries.

The CI test workflow runs `python -m pytest -q`, including regressions for the numeric order and the independent authentication/scope gates. The keyword-based `owner-charter-audit` workflow is only a human-review inventory, not semantic proof.