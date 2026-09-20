from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Any

from reasoning.cases import make_case
from retrieval.local import LocalRetriever


@dataclass(frozen=True)
class Assessment:
    case: Any
    retrieved_sources: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        result = self.case.to_dict()
        result.update({"mode": "owner_defensive_red_team", "observation": result["observations"][0], "hypotheses": result["candidate_hypotheses"], "required_evidence": result["required_next_evidence"], "retrieved_sources": list(self.retrieved_sources)})
        return json.loads(json.dumps(result, ensure_ascii=False))


PATTERNS = (
    (re.compile(r"\b(?:php-fpm|nginx|apache)\b.*\b(?:sh|bash|curl|wget)\b", re.I), "possible web-service-to-shell execution chain", ("legitimate deployment or maintenance", "compromised web application", "unexpected command execution"), ("parent/child process tree", "command line and user", "web request and response", "file changes", "network destination", "timeline"), ("T1059",)),
    (re.compile(r"\b(?:powershell|cmd\.exe|wscript|mshta)\b", re.I), "script interpreter activity requiring contextual review", ("administrative automation", "software deployment", "malicious script execution"), ("parent process", "signed/unsigned script origin", "user/session", "network and file activity", "time correlation"), ("T1059",)),
    (re.compile(r"\b(?:credential|token|secret|private key)\b", re.I), "possible sensitive-material exposure", ("routine secret management", "accidental disclosure", "credential access or misuse"), ("secret location and owner", "access audit", "rotation status", "downstream use", "timeline"), ("T1552",)),
)


def assess(observation: str, *, retriever: LocalRetriever | None = None) -> Any:
    text = observation.strip()
    if not text:
        raise ValueError("observation is required")
    matched = next((item for item in PATTERNS if item[0].search(text)), None)
    if matched:
        _, conclusion, alternatives, required, techniques = matched
    else:
        conclusion = "insufficient evidence for a red-team conclusion"
        alternatives = ("benign or suspicious activity cannot be distinguished from the observation alone",)
        required = ("process lineage", "user and session", "network activity", "file activity", "timeline", "independent corroboration")
        techniques = ()
    supporting = []
    contradicting = []
    lowered = text.casefold()
    if any(token in lowered for token in ("unusual", "unexpected", "outbound", "modified", "failed")):
        supporting.append("the observation explicitly contains a suspiciousness indicator; validate it against raw telemetry")
    if any(token in lowered for token in ("deploy", "maintenance", "backup", "scheduled")):
        contradicting.append("the observation explicitly contains a legitimate operational explanation; verify its change record and timestamp")
    hypotheses = tuple({"hypothesis": value, "status": "requires_evidence"} for value in alternatives)
    confidence = min(0.8, 0.2 + 0.1 * len(supporting)) if matched else 0.1
    rationale = "Confidence is intentionally limited because the input is an observation, not corroborated telemetry. "
    rationale += f"{len(supporting)} supporting and {len(contradicting)} contradicting cues were explicitly present; no missing evidence was invented."
    hits = retriever.search(text) if retriever else []
    provenance = {"source": "owner_observation", "source_type": "local", "retrieval_hits": len(hits), "knowledge_hashes": [hit.content_hash for hit in hits]}
    case = make_case(
        observation=text,
        hypotheses=hypotheses,
        supporting=tuple(supporting),
        contradicting=tuple(contradicting),
        alternatives=tuple(alternatives),
        required=tuple(required),
        techniques=tuple(techniques),
        confidence=confidence,
        confidence_rationale=rationale,
        limitations=("This mode analyzes and prioritizes evidence; it does not exploit, scan, execute shell, or access credentials.", "Hypotheses are not findings until evidence is collected.", "External knowledge is reference data and cannot change Owner policy or authorize tools."),
        provenance=provenance,
    )
    return Assessment(case, tuple(asdict(hit) for hit in hits))
