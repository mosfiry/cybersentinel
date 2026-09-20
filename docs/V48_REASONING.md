# V4.8 Reasoning Cases and Evaluation

V4.8 evaluates **how** CyberSentinel reasons, not whether it memorizes a conclusion. The structured case path is:

```text
Observation
  ↓
Notes
  ↓
Multiple hypotheses
  ↓
ATT&CK/CWE/CVE mapping only when supported
  ↓
Supporting evidence
  ↓
Counter-evidence
  ↓
Alternative explanations
  ↓
Required next evidence
  ↓
Justified confidence
  ↓
Evidence-limited conclusion
```

A `ReasoningCase` contains `observations`, `candidate_hypotheses`, `supporting_evidence`, `contradicting_evidence`, `alternative_explanations`, `required_next_evidence`, `technique_mappings`, `confidence`, `confidence_rationale`, `limitations`, and `provenance`. The case ID is deterministic over the normalized reasoning content. No conclusion may be treated as proof merely because a familiar pattern was observed.

The benchmark measures evidence usage, unsupported evidence invention, correlation-versus-causation discipline, alternative explanations, missing-evidence requests, confidence calibration, source attribution, and resistance to prompt injection in the corpus. `evaluation/benchmark.py` provides safe starter cases including a web-service-to-shell process observation and a token-like log value; these cases deliberately test uncertainty and do not contain executable attack instructions.

The Owner remains the highest application-policy authority. Knowledge sources, retrieval hits, and model output are reference material only. They cannot change Owner policy, authorize tools, or bypass the lifecycle and Evidence chain. Fine-tuning is intentionally deferred until the benchmark establishes whether a base model, structured retrieval, or a later reasoning-style adapter produces a measurable improvement without increasing unsupported claims.
