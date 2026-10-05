# Agent Evaluation

`evaluation/agent_evaluation.py` extends the existing CyberSentinel benchmark and critic modules with typed per-run records. It keeps the 11 controlling-brief dimensions—task success, evidence quality, hallucination rate, tool correctness, skill usefulness, memory usefulness, agent coordination, recovery, latency, token usage, and safety violations—separate, and retains the pre-existing abstract-cost dimension for backward compatibility. There is deliberately no aggregate score that could conceal a safety or evidence failure.

`EvaluationPolicy` names required dimensions and configurable bounds. Default checks require task success, evidence quality, hallucination rate, tool correctness, and safety-violation count; safety violations must be zero, and unsupported metrics do not silently become passes. Evidence-quality measurements require evidence references. An evaluator without an independent evidence resolver returns **indeterminate**, not accepted; a resolver error is also indeterminate, while invalid evidence or a failed threshold rejects the run.

`EvaluationStore` persists immutable, schema-versioned SQLite records keyed by Owner and mission. Exact retries use a caller-supplied idempotency key; a different payload under the same key is a conflict. Rows bind the metric payload, generated record identity and idempotency key in integrity digests, and cross-owner reads return no record. The database is created with owner-only file permissions where supported. Token counts are bounded integers sourced from provider-reported usage metadata; they are not independently reconstructed or attested tokenizer counts. The structural agent-coordination ratio counts completed assigned specialist tasks and is not a semantic quality score.

## Boundaries

The authenticated read-only Mission evaluation summary and Desktop panel do not themselves launch benchmark missions, prove evidence authenticity, or change tool authority. The MissionWorker's post-terminal outcome hook reloads and verifies the exact Mission, Owner authorization binding, trajectory, and fenced evidence chain before appending an idempotent deterministic outcome record. The evaluation database is separate from MissionStore/evidence-chain transactions, so the callback is best-effort and never changes the durable Mission completion state. Cost uses abstract `units`; it does not report currency or billing.

The production recorder currently measures terminal goal-verifier success, fenced-receipt integrity ratio (not semantic support), integrity-covered Mission latency, complete bounded provider-reported token totals when available, and a structural assigned-specialist completion ratio when the specialist graph is present. Hallucination, semantic tool correctness, memory/Skill usefulness, recovery success, security-violation counts, and cost are not inferred; unavailable dimensions remain absent/unavailable. The fixed adversarial test catalog is control-plane regression evidence, not a quality benchmark or real provider/service acceptance.

## Verification

`tests/test_agent_evaluation.py` covers strict metric typing, policy thresholds, separate dimensions, missing/invalid evidence, fail-closed validator errors, owner isolation, append-only persistence, idempotent writes, and integrity tampering.
