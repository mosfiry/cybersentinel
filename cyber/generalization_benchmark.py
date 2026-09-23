"""Quantitative generalization benchmark: honest, fixture-scoped metrics.

Owner policy (this module):
* Metrics are measured ONLY on the synthetic probe set defined below.
  They say how the generalization engine behaves on THESE probes - they are
  NOT a claim about real-world accuracy and NOT a comparison against any
  other system or model.
* Every probe is an UNSEEN behavior description: it must be answered by
  structural similarity to the seeded corpus, never by verbatim keyword
  recall of the probe text.
* Refusal probes (unrelated prose) MUST map to UNKNOWN: the engine is
  rewarded for refusing to force a match, not punished.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyber.generalize import UnseenTechniqueMatcher
from cyber.seed_corpus import build_seed_graph

# (description, tactic hint, expected technique id) - ground truth is ours,
# asserted only for these fixtures
_PROBES: list[tuple[str, str, str]] = [
    ("powershell one-liner staged the payload", "execution", "T1059.001"),
    ("email lure with an attachment delivered the dropper", "initial-access", "T1566.001"),
    ("mimikatz pulled credentials out of lsass memory", "credential-access", "T1003.001"),
    ("traffic beaconed over https to the c2 endpoint", "command-and-control", "T1071.001"),
    ("files were encrypted and a ransom note demanded payment", "impact", "T1486"),
    ("attacker dumped password hashes from the registry", "credential-access", "T1003"),
    ("files were packed and obfuscated to evade the scanner", "defense-evasion", "T1027"),
    ("a new user account was created for persistence", "persistence", "T1136"),
    ("lateral movement reused a stolen hash over ntlm", "lateral-movement", "T1550.002"),
    ("uac bypass elevated the process token", "privilege-escalation", "T1548.002"),
    ("a port scan enumerated reachable network services", "discovery", "T1046"),
    ("cryptomining hijacked cloud compute in the tenant", "impact", "T1496"),
]

# unrelated prose: the ONLY honest answer is UNKNOWN
_REFUSAL_PROBES: list[str] = [
    "the intern watered the office plants",
    "a pigeon landed on the roof antenna",
    "someone repainted the server room door",
]


@dataclass
class GeneralizationBenchmarkResult:
    probe_count: int = 0
    top1_hits: int = 0
    top5_hits: int = 0
    tentative_probes: int = 0
    unknown_probes: int = 0
    refusal_probes_total: int = 0
    refusal_probes_unknown: int = 0
    per_probe: list[dict[str, Any]] = field(default_factory=list)

    @property
    def top1_accuracy(self) -> float:
        return (self.top1_hits / self.probe_count) if self.probe_count else 0.0

    @property
    def top5_recall(self) -> float:
        return (self.top5_hits / self.probe_count) if self.probe_count else 0.0

    @property
    def refusal_honesty(self) -> float:
        total = self.refusal_probes_total
        return (self.refusal_probes_unknown / total) if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": "synthetic fixtures only; no real-world or comparative claim",
            "probe_count": self.probe_count,
            "top1_accuracy": round(self.top1_accuracy, 3),
            "top5_recall": round(self.top5_recall, 3),
            "tentative_probes": self.tentative_probes,
            "unknown_probes": self.unknown_probes,
            "refusal_honesty": round(self.refusal_honesty, 3),
            "per_probe": list(self.per_probe),
        }


def run_generalization_benchmark() -> GeneralizationBenchmarkResult:
    """Run the fixture probe set; returns honest, scoped metrics."""
    graph, _ = build_seed_graph()
    matcher = UnseenTechniqueMatcher(graph)
    result = GeneralizationBenchmarkResult()
    for description, tactic, expected in _PROBES:
        mapping = matcher.map_behavior(description, tactic=tactic)
        hyps = mapping["hypotheses"]
        ids = [h["technique_id"] for h in hyps]
        result.probe_count += 1
        if mapping["status"] == "UNKNOWN":
            result.unknown_probes += 1
        else:
            result.tentative_probes += 1
        if ids and ids[0] == expected:
            result.top1_hits += 1
        if expected in ids:
            result.top5_hits += 1
        result.per_probe.append({
            "description": description,
            "expected": expected,
            "status": mapping["status"],
            "ranked": ids,
        })
    for description in _REFUSAL_PROBES:
        mapping = matcher.map_behavior(description)
        result.refusal_probes_total += 1
        if mapping["status"] == "UNKNOWN":
            result.refusal_probes_unknown += 1
        result.per_probe.append({
            "description": description,
            "expected": None,
            "status": mapping["status"],
            "ranked": [],
        })
    return result
