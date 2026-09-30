# IDOR/BOLA differential validation: blocker and next interface

## Decision at `d419a4868e43d254ea13b5b95b6824e8da1e01fc`

**Do not implement or report a validated IDOR/BOLA finding yet.** The repository does not currently provide source-backed, persisted evidence for a paired, authenticated two-synthetic-account comparison. A deterministic validator built now would have no trustworthy evidence to consume and would risk turning metadata or model claims into a false security finding.

This is an evidence-source blocker, not a negative test result and not evidence that the target is safe.

## Audit findings

- `tools/scoped_http_probe.py` performs one scope-authorized, credential-free `GET`. It returns bounded metadata (`status`, content type, byte count, truncation flag, and a digest of capped response bytes), not a response body or authenticated-principal identity. It has no account selector or credential input.
- `tests/test_scoped_http_probe.py` verifies the one-request transport and explicitly checks that no `Authorization` or `Cookie` header is sent and that response content is not returned. It does not create two authenticated identities or persist paired resource responses.
- Mission action history can persist the probe's returned observation, but that observation is not sufficient to establish who authenticated, which same resource ID was requested by each principal, or whether the second principal received the first principal's protected content.
- `agent/evidence.py` provides a generic hash-linked `EvidenceChainStore`. Its current workspace-event adapter records workspace operations; the scoped GET result is not appended there as an HTTP exchange. A hash chain alone would not establish that a record came from a trusted authenticated replay producer.
- `docs/CURRENT_RUNTIME_TRUTH.md` at the base commit explicitly marks the complete replayable HTTP evidence chain, Computer/Phone Vaults, worker secret resolver, authenticated two-synthetic-account BOLA/IDOR flow, deterministic independent verifier, persisted Finding, and disclosure approval workflow as **not implemented**. It also states that no disclosure path exists.

Therefore there are no valid persisted inputs from which an independent differential validator could establish disclosure. LLM agreement, confidence, a successful unauthenticated GET, equal response hashes, or a model-supplied identity/resource assertion must not fill that gap.

## Smallest safe next interface proposal (not implemented here)

Keep the validator a **pure, read-only consumer** of verified persisted evidence. Do not widen `scoped_http_probe`, add a tool, add an HTTP method, or grant network/credential permissions as part of this proposal.

1. **Trusted evidence producer contract, future prerequisite:** a separately reviewed Owner-authorized replay boundary may produce two immutable exchange records for an explicitly synthetic test case. It must bind each exchange to the Owner authorization and persisted scope snapshot, target, mission/request, fixed `GET`, canonical endpoint and *same resource ID*, unique replay/action ID, and one of two distinct opaque synthetic-account references. The producer must establish the account-to-principal binding and which account owns the synthetic canary resource; caller/model-provided labels alone are not proof.
2. **Persistence/read contract:** an append-only store exposes `get_verified_exchange(evidence_id)` (and, if useful, a case-level pair lookup) that verifies trusted producer provenance and the evidence chain before returning records. Exchange records carry bounded request/response metadata and the complete, non-truncated synthetic response material—or a deterministic, independently verifiable representation sufficient to prove the canary disclosure. Persist only opaque secret references; never persist credential values, authorization headers, cookies, or tokens. A trusted producer signature/provenance check is required in addition to a content hash.
3. **Validator contract, only after 1–2 exist:** `validate_synthetic_idor_case(store, case_id)` reads exactly the persisted source records and returns a deterministic enum/result with evidence IDs and explicit missing/mismatch reasons. It must fail closed unless the two trusted records share the same case, Owner authorization, scope snapshot, target, canonical resource ID and method; have distinct trusted synthetic principals; establish that principal A is entitled and principal B is not; and demonstrate that B's complete response contains the same unique synthetic canary content observed for A. Only that source-backed predicate may produce `VALIDATED_CROSS_ACCOUNT_DISCLOSURE`. No LLM confidence/agreement input is part of the contract.

The replay boundary, Vault, producer provenance, persisted exchange schema, and any future permission changes require their own explicit design and authorization before implementation. Until then, keep the current GET-only probe unchanged and report this capability as **blocked / not validated**, not as pass or finding.

## Verification boundary for this task

Any tests added later must use synthetic values only, a local deterministic fixture, and Owner-authorized evidence creation. They must cover missing, incomplete, mismatched, truncated, wrong-resource, same-principal, untrusted-producer, and no-canary cases, plus one persisted positive pair. This task intentionally adds no such fabricated pair and no validator implementation.
