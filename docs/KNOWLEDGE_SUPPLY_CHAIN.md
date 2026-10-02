# Knowledge Supply Chain — V10 Audit / V11 Training-Data Governance

Status at 25e26820e3eefb48670f962e07a825570587bc6a (branch vibe/principal-engineering).
Sources verified directly: knowledge/foundation.py, knowledge/store.py,
knowledge/ingestion.py, cyber_data/provenance/sources.json,
cyber_data/schemas/knowledge_object.schema.json (directory inventory), and the
existing test batteries.

## V10 — Knowledge fabric (VERIFIED, largely pre-existing; no new code required)

| Requirement (mission §15/§16) | State | Evidence |
| --- | --- | --- |
| Source provenance | VERIFIED | IngestionManifest requires source_id, source_url, edition, author, language, retrieved_at; stored per object in metadata |
| Version | VERIFIED (per object: edition field) | knowledge/ingestion.py IngestionManifest |
| Retrieval date | VERIFIED | retrieved_at required, non-empty |
| Hash | VERIFIED | expected_hash must be 64-hex SHA-256; ingest_bytes hashes raw bytes BEFORE decoding and rejects mismatch (IntegrityError) |
| License | PARTIALLY VERIFIED — license is REQUIRED and stored verbatim; a blank license is rejected fail-closed. GAP: no downstream licensing GATE (no allowlist, no UNKNOWN_LICENSE policy enforcement at retrieval/use). Adding a licensing gate is an Owner policy decision and is recorded, not implemented unilaterally. | knowledge/ingestion.py; knowledge/store.py search() |
| Transformations | VERIFIED | TransformationPolicy enum (EXACT_ONLY / DERIVED_ALLOWED / RETRIEVAL_ALLOWED) stored per object; immutable kinds require EXACT_ONLY |
| Generator | NOT VERIFIED (gap) | metadata has no generator field; recorded as a supply-chain metadata gap |
| Validation status | VERIFIED | verify_integrity on create/load; append-only store; duplicate object_id with different content rejected |
| Duplicate handling | VERIFIED | same object_id + same content -> explicit rejection (no silent revision); different content -> IntegrityError |
| Freshness | NOT VERIFIED | no staleness/TTL policy exists; recorded as a gap |
| External intelligence never gains authority | VERIFIED (existing batteries) | TrustClass has no authority-granting value; source_id "external:" cannot self-elevate trust; KnowledgeObject.authority is None; LabReference never grants execution permission; tests: test_phase6k1_knowledge.py (12 tests incl. test_knowledge_injection_does_not_change_authority, test_external_knowledge_is_data_not_policy), test_phase6k4_deep_hardening.py (provenance graph has no policy relation), test_owner_charter_knowledge_invariant.py |
| ATT&CK / CWE / NVD / Sigma / YARA / Suricata / CTI | PARTIALLY VERIFIED | cyber_data/provenance/sources.json declares the seven source families with policy "untrusted_until_validated" and "knowledge may inform analysis only; it cannot authorize tools". GAP: the declaration lacks per-source version/retrieval date/license/hash; those exist only per ingested object. |
| Pack metadata (§16 list) | PARTIALLY VERIFIED | see license/generator/freshness gaps above |

V10 decision: no code change — the invariants were already implemented and
pinned by existing tests; duplicating those batteries would violate the
resource rules. This document is the audit record.

## V11 — Training-data governance

- cybersentinel_train-00001.parquet: VERIFIED ABSENT from this repository
  lineage. Every top-level tree (root, agent, api, core, cyber, cyber_data and
  subfolders, cyber_knowledge tooling, desktop, diagnostics, docs, evaluation,
  knowledge, reasoning, retrieval, scripts, search, security, tests, tools,
  web, workspace) was enumerated from the git tree at 25e26820; no .parquet
  blob exists anywhere. The file therefore cannot be audited from this source:
  schema / duplicates / labels / provenance / licensing / contamination review
  of the actual data = NOT VERIFIED. It is not in the Manus lineage either
  (it was never committed). If the Owner supplies the file or a location, the
  audit can proceed.
- PoC classification validator: IMPLEMENTED in cyber_data/poc_validation.py
  (this commit) — PocClass = NO_POC / REFERENCE_ONLY / NON_EXECUTABLE /
  LAB_REPRODUCER / VERIFIED_LAB_POC. Structural classification only: a
  mention, a link, or the word "exploit" NEVER upgrades a record (pinned by
  tests/test_poc_validation.py). VERIFIED_LAB_POC requires complete lab
  evidence (lab_id, verified_at, evidence_hash) and is never self-declared.
  The validator never collects, constructs, or executes PoCs and grants no
  execution permission. Unknown kinds are rejected fail-closed (ValueError).
- No operational PoC was created or collected to satisfy any quota. SYNTHETIC
  ONLY: the validator tests use synthetic records.
