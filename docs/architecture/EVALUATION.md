# Agent Evaluation

`evaluation/agent_evaluation.py` extends the existing CyberSentinel benchmark and critic modules with typed per-run records. It keeps task success, evidence quality, hallucination rate, tool correctness, skill usefulness, memory usefulness, latency, cost units, recovery, and safety violations as separate measurements. There is deliberately no aggregate score that could conceal a safety or evidence failure.

`EvaluationPolicy` names required dimensions and configurable bounds. Default checks require task success, evidence quality, hallucination rate, tool correctness, and safety-violation count; safety violations must be zero, and unsupported metrics do not silently become passes. Evidence-quality measurements require evidence references. An evaluator without an independent evidence resolver returns **indeterminate**, not accepted; a resolver error is also indeterminate, while invalid evidence or a failed threshold rejects the run.

`EvaluationStore` persists immutable, schema-versioned SQLite records keyed by Owner and mission. Exact retries use a caller-supplied idempotency key; a different payload under the same key is a conflict. Rows bind the metric payload, generated record identity and idempotency key in integrity digests, and cross-owner reads return no record. The database is created with owner-only file permissions where supported.

## Boundaries

The evaluation API does not itself launch benchmark missions, prove evidence authenticity, or change tool authority. Its evidence validator must resolve the referenced record through the trusted mission/evidence boundary. The store is not yet exposed through an authenticated product API or evaluation UI, and its SQLite database is not transactionally coupled to MissionStore or ArtifactStore. Cost uses abstract `units`; it does not report currency or billing.

## Verification

`tests/test_agent_evaluation.py` covers strict metric typing, policy thresholds, separate dimensions, missing/invalid evidence, fail-closed validator errors, owner isolation, append-only persistence, idempotent writes, and integrity tampering.