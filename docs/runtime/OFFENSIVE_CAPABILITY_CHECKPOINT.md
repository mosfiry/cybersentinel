# Offensive Capability Checkpoint — CyberSentinel X

BRANCH: security/b3-four-layer-intent

LAST VERIFIED CI: diagnostics/ci-1d7590a9434d.md — result SUCCESS — 1342 passed / 1 skipped / 0 failed

STAGE: Offensive Capability Activation — P0 COMPLETE (live bridge + real scoped_http_probe), P1 COMPLETE (real scoped_dns_lookup + real scoped_tls_observation; HTTP observation is the LIVE scoped_http_probe from P0), P1-D COMPLETE (real scoped_port_observation); technology fingerprinting observation family NOT STARTED

---

## MILESTONE P0 (COMPLETE — see OFFENSIVE_CAPABILITY_MATRIX.md)

STARTING HEAD: 35eb390bd5c9a032849921a8bc875d9947661043 · FINAL HEAD: a01fd4fd13089b318a814a57d8a0992e5938719a (docs at 3a59418b5652) · CI 1263/1 green at a01fd4fd1308.

- Source archaeology proved agent/offensive_mind.py and cyber/offensive.py were TEST-ONLY (dead from runtime); scoped_http_probe was a PLACEHOLDER handler.
- agent/offensive_bridge.py: typed OffensiveActionProposal → deterministic validation → mission identity binding (mission/request/plan fingerprint/live run) → ScopeGuard scope firewall (canonical url becomes the executed argument) → ExecutionAuthorizationProof.derive over the existing owner chain → ToolAdapter nine-phase contract → tools.registry.execute → structured record → feedback event for OffensiveMind.adapt. INV-OFF-1..7 documented and tested.
- scoped_http_probe placeholder replaced with a REAL bounded observation: one GET, redirects observed and never followed, 10s timeout, 64KB cap, body hashed and never returned, deterministic fail-closed error classification, single network seam (_probe_fetch) fakeable in tests.
- Registry reconstruction discipline: tools/registry.py rebuilt byte-exact from commit patches; every intermediate blob SHA verified before editing.

Commits (P0): 47965e7ef12c, 672508a3b10e, c3e653166211, 2b46af6b66b4, 701ceef96735, 35eb390bd5c9 (CI 1254/1), 0f79f84f8ad1, a01fd4fd1308 (CI 1263/1), 3a59418b5652 (docs).

---

## MILESTONE P1 (COMPLETE): real scoped_dns_lookup — bounded DNS observation

STARTING HEAD (this milestone): b139c07c2c3ec787ec7308184cae92ad3fe62695 (feat commit) — session resumed from root checkpoint 098b9cfe5c26 (CI 1263/1 green; marker b5fe9cd97e96 verified).

FINAL HEAD: 45fefef721aecc22fa3f84b8ff223c1fe00a918b

LAST VERIFIED CI: diagnostics/ci-45fefef721ae.md — result SUCCESS — 1278 passed / 1 skipped / 0 failed (feat commit b139c07c2c3e green at 1263/1; test commit 9852e2ef0545 RED 2 failed — both test-side defects, production correctly fail-closed; fix commit 45fefef721ae GREEN 1278/1).

### Commits (this milestone)

1. b139c07c2c3e — feat(tools): add bounded scoped_dns_lookup observation tool (scope-bound, owner-decision bound) with live bridge adapter — tools/registry.py real handler (_scoped_dns_lookup: the canonical url's host is the only name resolved; dedup + deterministic ordering; hard record cap 32; fail-closed DNS_FAILED / DNS_ARGUMENT_INVALID; single DNS seam _dns_resolve) + agent/offensive_bridge.py ScopedDnsLookupAdapter (same contract as the probe adapter; registry scope re-resolution + decision binding). CI 1263/1 green.
2. 9852e2ef0545 — test(offensive): adversarial + live-bridge battery for scoped_dns_lookup (CI RED: 2 failed / 1276 — test-side defects only: the wrong-tool decision is rejected even earlier, at proof derivation, raising ExecutionProofError PROOF_BINDING_MISMATCH instead of returning a REJECTED record; the observed-address test used the counting fixture's empty records instead of the real handler with the faked seam).
3. 45fefef721ae — test(offensive): fix dns battery (CI GREEN 1278/1).

### Engineering note (byte-exactness discipline, resumed session)

The local workspace had been reset between sessions. tools/registry.py (20-commit chain, final blob 6a794f848f3e11b63c4fa2001a5ae75db1d8b461), agent/offensive_bridge.py (4-commit chain, blob 1fb3695a34f553e6f24b5b6117dbe80b5b7f1c31) and docs/runtime/OFFENSIVE_CAPABILITY_MATRIX.md (blob e6dbc0b02579e2078761b7fe5b9140edbb3977f3) were rebuilt byte-exact from commit patches with EVERY intermediate blob SHA verified before any edit.

### Current tests

- tests/test_offensive_bridge.py — 17 tests (unchanged, green)
- tests/test_scoped_http_probe.py — 9 tests (unchanged, green)
- tests/test_scoped_dns_lookup.py — 15 tests (P1; unchanged, green)
- tests/test_scoped_tls_observation.py — 25 tests (NEW, P1-B): handler bounds at the faked single TLS seam + live bridge reachability + dry-run + ten negatives, all proven pre-network (execute spy and TLS seam empty)

## KNOWN RISKS / LIMITATIONS

- The bridge binds scope context and the AuthorizationDecision onto the scoped adapter instance before adapter.run; adapter instances are not thread-safe and must be single-use per execution.
- Missions without a request id cannot execute scope-bound tools through MISSION_BOUND registry checks requiring a decision.
- The DNS observation's time bound is enforced by the registry executor (spec timeout / adapter timeout_seconds = 10); the single seam (socket.getaddrinfo) has no per-call timeout parameter — the executor bound is the bound. The TLS observation's connect+handshake bound is likewise the executor timeout (the seam passes it to socket.create_connection; the TLS handshake inherits the socket timeout).
- The TLS observation targets the default TLS port (443) unless the canonical url carries an explicit port; an explicit port is executed ONLY if the scope asset's `ports` set authorizes it (otherwise the registry scope resolver rejects pre-network). IP-literal targets require the IP to be an in-scope asset — a DNS-resolved address is never authorization.
- Credential access is deliberately NOT implemented; secrets are never recorded in evidence plaintext (recorded safety decision pending explicit Owner override).
- Technology fingerprinting, filesystem artifact metadata, binary static analysis families are NOT STARTED; port & service observation is LIVE as scoped_port_observation (single-port banner read only — no multi-port enumeration, no scanning); nothing beyond the matrix is claimed.

## MILESTONE P1-B (COMPLETE): real scoped_tls_observation — bounded verifying TLS observation

STARTING HEAD (this milestone): 6c3b2971 (marker; session resumed from root checkpoint 6ce6b9215f88, CI 1278/1 green).

FINAL HEAD: 3a41b43ea7ff5fdc06c36112722f05945cdc17e7

LAST VERIFIED CI: diagnostics/ci-3a41b43ea7ff.md — result SUCCESS — 1303 passed / 1 skipped / 0 failed (feat commit 4b1549c141b green at 1278/1; test commit 3a41b43ea7ff green at 1303/1 — 25 new tests, first-run green).

### Commits (this milestone)

1. 4b1549c141b — feat(tools): scoped_tls_observation real handler (_tls_observation: verifying handshake under ssl.create_default_context() — CERT_REQUIRED, check_hostname=True, semantics FIXED and documented, never relaxed; SNI is ALWAYS the canonical host, never an input; port derived deterministically from the canonical url — explicit ports must be inside the scope asset's `ports` set or the registry scope resolver rejects; SHA-256 fingerprint over the DER bytes; sorted+deduped SANs capped at 32; distinct fail-closed classifications TLS_ARGUMENT_INVALID / TLS_CONNECTION_FAILED / TLS_TIMEOUT / TLS_HANDSHAKE_FAILED / TLS_CERTIFICATE_INVALID / TLS_RUNTIME_ERROR; handshake success and certificate validity classified SEPARATELY; single TLS seam _tls_connect; no session/key material ever recorded) + ScopedTlsObservationAdapter in agent/offensive_bridge.py. CI 1278/1 green.
2. 3a41b43ea7ff — test(offensive): adversarial + live-bridge battery (25 tests; no real network — the single TLS seam is faked). CI 1303/1 green.

### Verification semantics (documented, fixed)

- The handshake runs under ssl.create_default_context(): certificate verification is ON by construction and is never relaxed to make an observation succeed.
- A successful handshake under this context yields verification_result TLS_CERTIFICATE_VALID; a completed-but-untrusted chain yields TLS_CERTIFICATE_INVALID (never success); an early handshake failure yields TLS_HANDSHAKE_FAILED with TLS_CERTIFICATE_UNAVAILABLE.
- tls_version and cipher are read from the ACTUALLY negotiated socket (sock.version()/sock.cipher()), never inferred from hostname, certificate text, model reasoning, or external intelligence.
- OBSERVATION ≠ AUTHORIZATION is proven adversarially: certificate SAN entries and resolved endpoints can never widen scope (both smuggle attempts rejected pre-network).

### Engineering note

The workspace had been reset between sessions again; tools/registry.py (21-commit chain, blob bc1e731455...), agent/offensive_bridge.py (5-commit chain, blob 3dbee8a4cd...), and both docs files were rebuilt byte-exact from commit patches with EVERY intermediate blob SHA verified before any edit.

## MILESTONE P1-D (COMPLETE): real scoped_port_observation — bounded port & service observation

STARTING HEAD (this milestone): 126266992ce3 (session resumed after Mission 1 closure: PR #20 merged, main at fe1820947b7290284a3b8e972e46d1271f216a99; the pending production push from the prior session was verified ABSENT at the branch tip, so P1-D was implemented fresh).

FINAL HEAD: 1d7590a9434d (plus the CHECKPOINT.md session record at c855f9df819b and this docs commit)

LAST VERIFIED CI: diagnostics/ci-1d7590a9434d.md — result SUCCESS — 1342 passed / 1 skipped / 0 failed (feat commit a9a3e7bd0db4 green at 1315/1).

### Commits (this milestone)

1. a9a3e7bd0db4 — feat(tools): scoped_port_observation real handler (_scoped_port_observation: ONE plain TCP connect + ONE passive recv banner read, cap SCOPED_PORT_BANNER_MAX_BYTES=128, settimeout min(timeout,2.0), sends_payload: False — nothing is ever written to the wire; host and port derived ONLY from the ScopeGuard's canonical url; banner bytes are observed data — sha256 over raw bytes + printable-filtered rendering with an explicit truncated flag; silent service is data, not failure; deterministic fail-closed classifications PORT_ARGUMENT_INVALID / PORT_TIMEOUT / PORT_CONNECT_FAILED / PORT_RUNTIME_ERROR; single TCP seam _port_observe; registered as a scope_required, owner+decision-bound network-read tool) + ScopedPortObservationAdapter in agent/offensive_bridge.py. CI 1315/1 green.
2. c9dff24ec7ee — test(tools): adversarial + live-bridge battery (27 tests; no real network — the single TCP seam is faked).
3. 1d7590a9434d — fix(tests): battery self-review (second-pass attacker review folded in): seam restored via monkeypatch instead of a leaky direct module assignment (cross-test mutation risk), banner-cap printable assertion corrected. CI 1342/1 green.

### Observation semantics (documented, fixed)

- Exactly one connect and one passive read: an observation, never a scan. No multi-port enumeration exists anywhere in the runtime.
- The executed argument is the ScopeGuard's canonical url; explicit ports execute ONLY inside the scope asset's 'ports' set (registry scope resolver rejects pre-network otherwise); observed banner content (including any hostnames) can never widen scope.
- Everything the service sends is OBSERVED data: hashed, size-capped, printable-rendered, never authority (INV-OFF-2/5 retested for this family).

## NEXT_ACTION

1. P1-E (next NEW capability): technology fingerprinting, if designed as a bounded, owner-authorized, scope-bound observation derived ONLY from already-observed data (banner/response headers), with a single fakeable seam, adapter reuse, adversarial + live bridge battery, CI green, checkpoint update — or the next item per this checkpoint. Keep catalog/registry disjoint; do NOT touch main; no reset/rebase/squash/force-push; no scheduler/DAG/worker runtime.

## EXACT RESUME POINT

HEAD c855f9df819b (CHECKPOINT.md P1-D session record) plus this docs commit, CI green 1342/1 at 1d7590a9434d (verify diagnostics/ci-c855f9df819b.md lands green too — docs-only commit). Resume at NEXT_ACTION step 1 (technology fingerprinting family). Do not touch main; no reset/rebase/squash/force-push.
