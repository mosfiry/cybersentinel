# Cyber Intelligence Layer — Coverage Map & Acceptance Matrix (2026-09-22)

Expert 1 scope only: cyber specialization. General architecture, runtime
unification and authorization infrastructure remain Expert 2 territory;
this layer integrates with, and never overrides, the typed AuthorizationContext
gates in security/.

## Scope boundary (stated plainly)

Implemented: defensive/research cyber reasoning — knowledge model with
provenance, multi-hypothesis discipline, attack-chain reconstruction from
evidence, source-conflict handling, anti-hallucination classification, and a
multi-dimensional benchmark.

NOT implemented, deliberately: autonomous weaponized exploitation against
real Internet targets (CVE -> Internet scanning -> exploitation ->
persistence -> exfiltration). The platform is a research and defense system;
execution against any target requires typed Owner authorization and a scope
snapshot, enforced outside this layer. This is consistent with the existing
security architecture and is not a coverage gap to be closed later.

## Architecture added

- cyber/knowledge_model.py — typed entities (ACTOR, CAMPAIGN, MALWARE, TOOL,
  TECHNIQUE, VULNERABILITY, PRODUCT, VERSION, IOC, CVE, CWE, ADVISORY, PATCH,
  COMMIT, EXPLOIT_PRIMITIVE, ATTACK_CHAIN, EVIDENCE, DETECTION, MITIGATION...),
  typed relations (USES, TARGETS, EXPLOITS, AFFECTS, PATCHES, PRECEDES, ENABLES,
  REQUIRES, DEPENDS_ON, OBSERVED_IN, ATTRIBUTED_TO, DETECTED_BY, MITIGATED_BY,
  CONTRADICTS, SUPPORTS), mandatory Provenance (source, uri, timestamp,
  source_class REAL/PARTIAL/SYNTHETIC/FIXTURE/UNVERIFIED, confidence),
  ClaimClass gate (VERIFIED / SUPPORTED / INFERRED / HYPOTHESIS / UNKNOWN).
  Queries are relation-traversal based; a decoy entity whose *name* embeds a
  real CVE id cannot poison query results (proven by test).
- cyber/reasoning.py — MultiHypothesisEngine (likelihood updates, explicit
  elimination, dominance margin — one observation never crowns a hypothesis;
  discriminator suggestion by expected separation), AttackChainReconstructor
  (canonical OBSERVATION->...->IMPACT stages, per-edge evidence/confidence/
  source/status, missing evidence => UNKNOWN, never fabricated),
  SourceConflictEngine (disagreeing sources stay UNRESOLVED without a decisive
  provenance-weight margin; both values retained), CyberClaimGate (fabricated
  identifiers => UNKNOWN with "refusing to invent"; single-source facts flagged).
- cyber/benchmark.py — multi-dimensional scoring (accuracy per dimension,
  unsupported-claim count; no single score), dev cases only, holdout discipline
  documented.

## Provenance model

Every ClaimEdge requires Provenance{source, uri, retrieved_at, source_class,
confidence}. VERIFIED requires >= 2 independent REAL sources. SYNTHETIC and
FIXTURE sources can never produce VERIFIED (proven by test). No corpus
ingestion exists yet, so all data currently in tests is FIXTURE-labeled
fixture material — no synthetic corpus is described as real.

## Coverage matrix (honest)

| Capability | Status | Evidence |
|---|---|---|
| Cyber knowledge model + typed graph | VERIFIED (unit/integration tests, green CI) | tests/test_cyber_knowledge_model.py |
| Provenance discipline | VERIFIED | provenance-mandatory + multi-source tests |
| Anti-hallucination gate | VERIFIED (MOCK-VERIFIED at model layer: scripted cases) | tests/test_cyber_reasoning.py |
| Multi-hypothesis reasoning | VERIFIED (deterministic engine tests) | tests/test_cyber_reasoning.py |
| Attack-chain reconstruction (analysis) | VERIFIED | chain discipline tests |
| Source conflict engine | VERIFIED | conflict tests |
| Benchmark (dev cases) | VERIFIED; holdout set NOT YET BUILT | tests/test_cyber_benchmark.py |
| Live threat-intel ingestion (NVD/CISA/ATT&CK feeds) | UNVERIFIED — REAL SOURCE INGESTION NOT BUILT; no network in CI. Schema and provenance model are ready for it. | — |
| ATT&CK deep reasoning (purpose/prereqs/detections per technique) | PARTIAL — relation traversal exists; no ingested ATT&CK corpus yet | — |
| Vulnerability research / patch-diff reasoning | PARTIAL — chain and primitive representation exist; no automated patch-diff analysis yet | — |
| Malware analysis knowledge layer | NOT BUILT | — |
| Reverse-engineering reasoning | NOT BUILT | — |
| Incident-response case engine | NOT BUILT (Case representation exists conceptually in the knowledge model entities) | — |
| Detection-engineering rule generation (Sigma/YARA concepts) | PARTIAL — DETECTION entity + DETECTED_BY traversal; no rule generation yet | — |
| Threat hunting loop | NOT BUILT | — |
| Adversary emulation planning (authorized scope only) | NOT BUILT (OffensiveMind covers scoped engagement planning; integration not extended) | — |
| Cyber reasoning memory | NOT BUILT | — |
| Holdout evaluation set | NOT BUILT | — |

## Remaining gaps / residual risks

1. No real data source ingestion yet — everything is FIXTURE-labeled. Any
   future corpus must pass schema validation, provenance, dedup, timestamp,
   source classification before entering the graph.
2. Detection rule generation, malware/RE/IR/hunting layers are unbuilt.
3. The benchmark measures engine discipline on dev cases only; without a
   holdout set, benchmark numbers must not be read as final capability.
4. Integration with OffensiveMind and MissionRuntime is via the shared
   AuthorizationContext philosophy; no direct integration point was needed
   yet (documented, not improvised).
