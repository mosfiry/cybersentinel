from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

from retrieval.local import LocalRetriever


@dataclass(frozen=True)
class Assessment:
    mode: str
    observation: str
    hypotheses: tuple[dict[str, Any], ...]
    required_evidence: tuple[str, ...]
    conclusion: str
    confidence: float
    limitations: tuple[str, ...]
    retrieved_sources: tuple[dict[str, Any], ...]

    def to_dict(self):
        return asdict(self)


PATTERNS = (
    (re.compile(r"\b(?:php-fpm|nginx|apache)\b.*\b(?:sh|bash|curl|wget)\b", re.I), "possible web-service-to-shell execution chain", ("legitimate deployment or maintenance", "compromised web application", "unexpected command execution"), ("parent/child process tree", "command line and user", "web request and response", "file changes", "network destination", "timeline")),
    (re.compile(r"\b(?:powershell|cmd\.exe|wscript|mshta)\b", re.I), "script interpreter activity requiring contextual review", ("administrative automation", "software deployment", "malicious script execution"), ("parent process", "signed/unsigned script origin", "user/session", "network and file activity", "time correlation")),
    (re.compile(r"\b(?:credential|token|secret|private key)\b", re.I), "possible sensitive-material exposure", ("routine secret management", "accidental disclosure", "credential access or misuse"), ("secret location and owner", "access audit", "rotation status", "downstream use", "timeline")),
)


def assess(observation: str, *, retriever: LocalRetriever | None = None) -> Assessment:
    text = observation.strip()
    if not text:
        raise ValueError("observation is required")
    matched = next((item for item in PATTERNS if item[0].search(text)), None)
    if matched:
        _, conclusion, alternatives, required = matched
        hypotheses = tuple({"hypothesis": value, "status": "requires_evidence"} for value in alternatives)
        confidence = 0.35
    else:
        conclusion = "insufficient evidence for a red-team conclusion"
        hypotheses = ({"hypothesis": "benign or suspicious activity cannot be distinguished from the observation alone", "status": "requires_evidence"},)
        required = ("process lineage", "user and session", "network activity", "file activity", "timeline", "independent corroboration")
        confidence = 0.1
    hits = retriever.search(text) if retriever else []
    return Assessment("owner_defensive_red_team", text, hypotheses, tuple(required), conclusion, confidence, ("This mode analyzes and prioritizes evidence; it does not exploit, scan, execute shell, or access credentials.", "Hypotheses are not findings until evidence is collected."), tuple(asdict(hit) for hit in hits))
