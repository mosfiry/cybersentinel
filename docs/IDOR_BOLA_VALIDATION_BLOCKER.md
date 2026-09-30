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

## Scoped HTTP metadata-to-EvidenceChain assessment at `97fefca01ce2e33ab4b4cadeb85d5e0018720b8a`

**Decision: no-go for appending a scoped-HTTP evidence record in this slice.** The current runtime could construct a descriptive, metadata-only row, but the existing chain cannot establish trusted response provenance or preserve the requested replay contract. Adding one as generic `observed` evidence would risk being read as stronger or more replayable than it is. No probe, registry, permission, persistence, or credential behavior is changed.

### Field-by-field source audit

| Requested field | Current source | Gap / safe conclusion |
|---|---|---|
| Method | `_perform_get` sends a fixed `GET` request. | Source-backed in the probe implementation, but not returned in its result or included in an EvidenceChain record. |
| Canonical URL | `_scope_authorized_url` returns the resolver's canonical URL before `_perform_get`. | Not returned or persisted. Persisting the full URL is not demonstrably secret-free: query values are user/model supplied, and the redactor recognizes only common credential forms. It cannot safely turn an arbitrary secret into `secret_ref`; no secret resolver/Vault is present. |
| Response status and content type | Parsed from response headers. | Returned as bounded metadata, with content type sanitized/truncated; response headers themselves are not retained. |
| Byte count and body hash | Calculated over the bytes retained by `_read_body`. | For oversized responses, both describe only the first 65,536 bytes; `truncated` signals this. The full body and a digest of the complete body are unavailable. |
| Response timestamp | No response-observation timestamp is captured by the probe. | `EvidenceChainStore.append` supplies its own timestamp when absent; that is append time, not the time the response was observed. |
| Request ID | The governed registry validates and receives the request ID. | It is not passed to the probe handler or present in the probe result. |
| Target / scope snapshot references | Strict `scope_context` includes `target_id` and `scope_snapshot_id`; the registry validates the persisted snapshot. | Available at dispatch, but not passed into the handler result or written to the EvidenceChain. |
| Authenticated account principal / complete exchange | The probe sends no `Authorization` or `Cookie` header and returns no body. | The authenticated principal cannot be observed; complete consequential request/response material cannot be persisted, and only a capped body digest is returned. Do not invent an account identity, headers, or body. |

### Why the existing chain is insufficient for this record

- `EvidenceChainStore.append` sanitizes a generic record and calculates a SHA-256 hash linked to the previous row. `verify_chain` checks sequence, previous-hash continuity, and each row's hash. This is hash-chain integrity checking, not trusted-producer authentication; the SQLite schema has no update/delete guard or externally anchored signed head.
- The registry's `ExecutionAuthorizationProof` is HMAC-signed before dispatch and binds the authorized tool call, arguments, request/mission, and scope context. It does **not** bind response status, response bytes/hash, response timestamp, or a post-response observation. Reusing that pre-dispatch proof would not authenticate the response record.
- The probe handler currently receives only the argument and strict scope context; the registry does not pass the request ID or `EvidenceChainStore` into this scope-required handler. The generic append API accepts caller-supplied `source`/`verification` fields and does not verify that a record originated from the probe.
- A chain entry could be labelled `metadata_only` and `replayable=false`, but that label would not fix the missing source authentication, response timestamp, complete exchange, or safe canonical-URL storage. The chain's generic evidence shape also has no enforced type contract that prevents consumers from treating an `observed` row as replay evidence.

Accordingly, a successful `EvidenceChainStore.verify()` would prove only that the stored rows are internally hash-consistent; it would not prove that this metadata was produced by the governed GET or bind the row cryptographically to its actual response. Do not represent a metadata row as a replayable or independently verified exchange, and do not add fabricated body, timestamp, account, or `secret_ref` values.

### Minimum prerequisite before revisiting

A separately reviewed post-response evidence boundary must safely canonicalize/redact the requested URL without persisting secret material; capture an actual observation timestamp and the exact bounded-response/truncation semantics; bind request ID, action/tool-call ID, target, and persisted snapshot fingerprint from validated dispatch context; and cryptographically authenticate the **resulting response envelope**, not only the pre-dispatch authorization. The append/read path must verify producer authentication as well as chain integrity and must prevent or detect rewriting of the chain head. Until then, the GET-only probe remains an observation-only metadata tool and does not meet the complete replay requirement.
