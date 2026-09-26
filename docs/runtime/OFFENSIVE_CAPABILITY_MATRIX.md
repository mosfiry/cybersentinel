# Offensive Capability Matrix — CyberSentinel X

Branch: `security/b3-four-layer-intent` · Last verified CI: 1303 passed / 1 skipped / 0 failed at `3a41b43ea7ff` (2026-09-26).

This matrix separates REASONING capability from EXECUTABLE capability and states the exact authorization path each capability requires. A capability is LIVE only when the live runtime can reach it through the full chain:

Owner-authenticated mission → typed proposal → deterministic validation → scope firewall → existing proof chain (OWNER_INSTRUCTION authority) → tools.registry.execute → evidence → reasoning feedback.

The authority hierarchy is immutable:
OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY > DETERMINISTIC_ENFORCEMENT > AUTHORIZATION_SCOPE > TOOL_RUNTIME > MODEL_OUTPUT > EXTERNAL_DATA.

## Capability matrix

| Capability | Module | Kind | Executable path | Authorization | Scope | Evidence | Status |
| --- | --- | --- |---| --- | --- | --- | --- |
| Offensive reasoning (hypotheses, campaigns, adaptation) | agent/offensive_mind.py | REASONING | n/a (feeds the bridge) | n/a — reasoning is never authority | n/a | n/a | LIVE (composed by agent/offensive_bridge.py; feedback loop tested) |
| Offensive planning / ScopeGuard | cyber/offensive.py | DETERMINISTIC GUARD | n/a (enforced by the bridge) | mandatory for network actions | typed ScopeSnapshot; canonical url only | guard decision in the bridge record | LIVE (enforced by the bridge; battery-tested) |
| Local process observation | tools/registry.py `local_process_info` + security/tool_adapter.py LocalProcessInfoAdapter | EXECUTABLE (local, read-only) | bridge → proof → registry → real `ps` execution | MissionAuthorizationSnapshot + ExecutionAuthorizationProof (MISSION_BOUND) | not network; mission-bound | adapter evidence envelope | LIVE |
| Scoped HTTP observation | tools/registry.py `scoped_http_probe` (real bounded GET) | EXECUTABLE (network, read-only) | bridge → ScopeGuard → owner AuthorizationDecision → proof → registry scope re-resolution → bounded GET | AuthorizationDecision + ExecutionAuthorizationProof (MISSION_BOUND or OWNER_DIRECT) | typed ScopeSnapshot persisted in the scope store; redirects observed, never followed | adapter evidence envelope | LIVE |
| Scoped DNS observation | tools/registry.py `scoped_dns_lookup` (real bounded resolution at a single seam) | EXECUTABLE (network, read-only) | bridge → ScopeGuard → owner AuthorizationDecision → proof → registry scope re-resolution → bounded resolution of the canonical url's host | AuthorizationDecision + ExecutionAuthorizationProof (MISSION_BOUND or OWNER_DIRECT) | typed ScopeSnapshot persisted in the scope store; the canonical url's host is the only name resolved; resolved addresses are observed data, never targets | adapter evidence envelope | LIVE |
| Scoped TLS observation | tools/registry.py `scoped_tls_observation` (real verifying TLS handshake at a single seam) | EXECUTABLE (network, read-only) | bridge → ScopeGuard → owner AuthorizationDecision → proof → registry scope re-resolution → bounded verifying handshake against the canonical host/port | AuthorizationDecision + ExecutionAuthorizationProof | typed ScopeSnapshot; SNI is ALWAYS the canonical host (never an input); certificate CN/SAN/issuer/resolved endpoints are observed data, never targets; explicit ports must be inside the scope asset's `ports` set | adapter evidence envelope | LIVE |
| Port & service enumeration / technology fingerprinting | not present | EXECUTABLE (planned) | — | — | — | — | PLANNED (not registered; not claimed) |
| Reverse engineering / artifact analysis (PE/ELF metadata, strings, imports, entropy) | static malware triage exists (cyber/malware.py) | ANALYSIS (local) | not wired into the bridge | — | — | — | ANALYSIS-ONLY (no execution claim) |
| Vulnerability validation (bounded proof of finding) | not present | EXECUTABLE (planned) | — | — | — | — | PLANNED |
| Dynamic malware analysis | not present | EXECUTABLE (planned, sandbox-bound) | DynamicAnalysisBackend interface only; NEVER execute samples on the host | — | — | — | PLANNED (interface not yet designed in code) |
| Credential access / secret recording in evidence | deliberately NOT implemented | — | — | — | — | — | NOT IMPLEMENTED BY DESIGN: secrets are never recorded in evidence plaintext; fingerprints/redaction only. This intentionally overrides mission item 16 pending an explicit Owner instruction to the contrary. |

## Verified invariants (tested)

- INV-OFF-1: a proposal is untrusted input; every binding is recomputed from typed owner-side state.
- INV-OFF-2: network actions without a typed ScopeSnapshot, or outside its authorized assets, are rejected before proof derivation; the executed argument is the guard's canonical url.
- INV-OFF-3: the bridge has no execution surface of its own; the only handler path is tools.registry.execute.
- INV-OFF-4: the bridge never mints authority; the proof is derived from the mission's owner-authorized snapshot; scope-bound tools additionally require a typed Owner AuthorizationDecision (verified by the registry, not trusted from the caller).
- INV-OFF-5: feedback is reasoning input only; observed endpoints (redirects, DNS results) can never widen scope.
- INV-OFF-6: every rejection is fail-closed; no partial execution.
- INV-OFF-7: dry-run performs validation, scope, authorization, and preparation, and never executes.
- Catalog/runtime disjointness is preserved: catalog definitions never become executable by registration; `nmap`-style catalog-only tools are rejected (tested).

## Evidence for LIVE status

- tests/test_offensive_bridge.py (17 tests): live reachability through the real registry for both adapters, the feedback loop into OffensiveMind.adapt, and 13 negatives asserting zero execution attempts (execute spy and handler spy empty).
- tests/test_scoped_http_probe.py (9 tests): real handler bounds at its single network seam — no redirect following, hard timeout, hard size cap, fail-closed classification, argument validation, no authority keys in observations.
- tests/test_scoped_dns_lookup.py (15 tests): real handler bounds at its single DNS seam (deduplication, deterministic ordering, hard record cap, fail-closed resolver errors, argument validation before the seam, no authority keys), plus live bridge reachability with a real typed Owner AuthorizationDecision and a persisted scope snapshot, observed-address scope-smuggling rejection, wrong-tool decision rejection at proof derivation, dry-run. No test performs a real network call.
- tests/test_scoped_tls_observation.py (25 tests): real handler bounds at its single TLS seam (negotiated version/cipher from the actual handshake result, SHA-256 fingerprint over DER bytes, sorted+deduped capped SANs, verification failure ≠ handshake success, distinct fail-closed classifications TLS_ARGUMENT_INVALID / TLS_CONNECTION_FAILED / TLS_TIMEOUT / TLS_HANDSHAKE_FAILED / TLS_CERTIFICATE_INVALID, argument validation before the seam, no authority or secret/session keys, catalog/runtime disjointness), plus live bridge reachability with a real typed Owner AuthorizationDecision and a persisted scope snapshot, dry-run, and negatives (no scope snapshot, no owner decision, model-supplied arbitrary hostname, DNS-derived IP target, wrong port outside the scope asset's ports, SAN scope-smuggling, wrong-tool decision at proof derivation, tampered plan hash, unregistered tool) — every negative proven pre-network (execute spy and TLS seam empty). No test performs a real network call.
- CI: 1303 passed / 1 skipped / 0 failed at `3a41b43ea7ff`.
