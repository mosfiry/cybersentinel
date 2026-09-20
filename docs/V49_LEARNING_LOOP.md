# V4.9 CyberSentinel Learning Loop

V4.9 does not add exploit, credential-theft, malware, persistence, reverse-shell, or arbitrary shell tools. Owner-only access controls analysis and memory, but it does not turn untrusted model output into an attack executor. The safe learning loop is:

```text
Knowledge / historical incident
  ↓
Revision pin + file inspection + license/secret/PII/poisoning checks
  ↓
Case Generator
  ↓
Observation + known/unknown facts + hypotheses + alternatives
  ↓
CyberSentinel analysis
  ↓
Teacher / Critic
  ↓
Reasoning Memory
  ↓
Benchmark Gate + regression comparison
```

The case generator preserves provenance and deliberately caps confidence when a case comes from reference knowledge. It does not convert a procedure, proof of concept, command, or payload into a tool. The deterministic critic reports `unsupported_claim`, `missing_evidence`, `premature_conclusion`, `ignored_counter_evidence`, `bad_alternative`, `poor_confidence`, `source_error`, and `mapping_error` classes as applicable. The benchmark gate rejects a candidate if unsupported claims or prompt-injection failures increase, or evidence usage decreases.

Owner-only reasoning memory stores the case, evidence considered, hypotheses, limitations, provenance, and critic report. It is retrievable through the authenticated `GET /api/reasoning/<request_id>` endpoint and never exposed to unauthenticated bridge clients. This enables “why did you conclude that?” to be answered from persisted reasoning artifacts rather than an invented explanation.

Knowledge from Hugging Face, GitHub, ATT&CK, CVE/CWE, Sigma, YARA, Suricata, and incident reports remains reference data. Revisions are pinned, files are inspected, licenses are retained, and secrets/PII/poisoning are screened before transformation. Fine-tuning remains deferred until Base, Base+RAG, and Base+RAG+Cases configurations pass the same hidden benchmark without increasing unsupported claims.
