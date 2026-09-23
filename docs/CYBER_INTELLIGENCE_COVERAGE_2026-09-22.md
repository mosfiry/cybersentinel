# Cyber Intelligence Coverage Map — 2026-09-22 (Expert 1)

Honest, verifiable statement of what the cyber-intelligence layer covers,
what it does NOT, and how each capability is enforced by tests that fail
if a boundary is removed.

## Layers

| Layer | File | What it does | Honesty gate |
|---|---|---|---|
| Knowledge model | `cyber/knowledge_model.py` | Typed entities + provenance-carrying claims + traversal-only queries | Provenance required; VERIFIED needs 2 independent REAL sources; no keyword matching |
| Reasoning | `cyber/reasoning.py` | Multi-hypothesis engine, attack-chain reconstruction, source conflicts, claim gate | UNRESOLVED without decisive weight gap; fabricated IDs refused |
| Reasoning engine | `cyber/reasoning_engine.py` | Hypothesis fanout (FAST→EXHAUSTIVE), adversarial self-critique, evidence-gated voting | Diminishing-returns stop; critique gates |
| Benchmark | `cyber/benchmark.py` | Multi-dimensional scoring on dev cases only | Holdout discipline; no score without evidence |
| Offensive planning | `cyber/offensive.py` | ScopeGuard + execution planning from campaigns | Execution only via `security.authorization` (Expert 2); poison-immune scope snapshots |
| Case engine | `cyber/case_engine.py` | Case representation, traceable conclusions, ID validation | Conclusions refuse untraceable/contradicted evidence; invented IDs refused |
| Mission adapter | `cyber/mission_adapter.py` | Read-only MissionRuntime → case bridge | Poison-stripping; no mutation of mission state |
| Intel ingest | `cyber/intel_ingest.py` | ATT&CK STIX + NVD ingestion | Fabricated IDs refused WITHOUT echoing them back; authority keys stripped; source-class confidence caps |
| Malware triage | `cyber/malware.py` | Evidence-cited static triage of passive samples | Capabilities cite artifact fields; family attribution threshold-gated; authority keys stripped |
| Incident response | `cyber/incident_response.py` | Evidence-driven containment/block recommendations | SUPPORTED evidence required; authority always "NONE - execution requires security.authorization" |
| Threat hunting | `cyber/hunting.py` | Hypothesis-driven traversal hunts | NO_DETECTIONS records "absence of evidence is NOT evidence of absence" (also for unanswerable hunts) |
| Fusion | `cyber/fusion.py` | One audited pipeline across all layers | Every stage report preserved; recommendations only from SUPPORTED evidence; authority always NONE |
| Lab | `cyber/lab.py` | Synthetic-target attack simulation (synth-* fixtures only) | No real-world names; effort-scaled reasoning |
| Seed corpus | `cyber/seed_corpus.py` | 48 real ATT&CK techniques across 12 tactics + 6 historical CVEs | PARTIAL provenance (offline reproduction); upgradeable by live-feed ingestion |
| Generalization | `cyber/generalize.py` | Unseen behaviors → ranked TENTATIVE hypotheses | Similarity NEVER produces SUPPORTED; below threshold = UNKNOWN; poison vocabulary neutralized |
| Adaptive analyst | `cyber/adaptive.py` | Runtime observations → hypotheses → evidence-gated promotion → hunts | Unmappable stays UNKNOWN; promotion traceable from the case |
| Actor corpus | `cyber/actor_corpus.py` | APT28/APT29/Lazarus, campaigns, malware families, established TTPs | High-confidence public attributions only; PARTIAL/WEAK; no authority |

## Tactic coverage (seed corpus)

initial-access, execution, persistence, privilege-escalation, defense-evasion,
credential-access, discovery, lateral-movement, collection,
command-and-control, exfiltration, impact — plus cloud-platform techniques
(T1059.009, T1078.004, T1580, T1530, T1496).

## What is explicitly NOT claimed

* No effectiveness claim against real environments (fixtures only).
* No comparative claim against any other model or product (UNVERIFIED).
* No execution authority anywhere in this layer — that lives exclusively in
  `security.authorization` (Expert 2).
* No live feeds ingested yet — corpora are offline PARTIAL-provenance seeds.

## Enforcement

Every gate above is locked by a behavioral test under `tests/`
(test_cyber_*). CI runs compileall + pytest on every push; a removed gate
fails the suite.

## Known infrastructure note (for Expert 2, not modified by Expert 1)

The diagnostics status writer reports `result: SUCCESS` even when the pytest
step was skipped or failed (observed on runs db52b8e8..6e3398b8 and
3cf99597). Trust the Actions API run/job conclusions, not the diag file.
