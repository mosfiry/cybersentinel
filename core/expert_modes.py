from __future__ import annotations

from typing import Any


def attacker_reasoning(observation: str) -> dict[str, Any]:
    """Model likely attacker goals and traces without generating attack steps."""
    text = str(observation).strip()
    if not text:
        raise ValueError("observation is required")
    return {
        "mode": "attacker_reasoning",
        "objective": "infer likely attacker intent and observable attack path",
        "observation": text,
        "candidate_hypotheses": [
            "malicious activity consistent with the observed behavior",
            "legitimate administration, deployment, or maintenance",
            "unexpected but non-malicious automation",
        ],
        "attack_path": [
            "initial access or trigger (unknown)",
            "execution or abuse of an existing process",
            "persistence, privilege change, or lateral movement (unknown)",
            "collection or impact (unknown)",
        ],
        "required_evidence": [
            "process lineage and command-line telemetry",
            "identity, session, and authorization context",
            "network destinations and timestamp correlation",
            "file, registry, or configuration changes",
        ],
        "observable_artifacts": [
            "authentication and process events",
            "network and DNS telemetry",
            "file and configuration audit records",
        ],
        "detection_points": [
            "unexpected parent-child process relationships",
            "new external destinations or unusual account activity",
            "changes outside an approved maintenance window",
        ],
        "limitations": [
            "This is analytical threat modeling only.",
            "It does not generate payloads, exploit steps, credentials, persistence, or shell commands.",
            "An observation alone is not proof of compromise.",
        ],
    }


def defender_reasoning(observation: str) -> dict[str, Any]:
    """Turn the same observation into defensive detection and response questions."""
    text = str(observation).strip()
    if not text:
        raise ValueError("observation is required")
    return {
        "mode": "defender_reasoning",
        "observation": text,
        "detection": [
            "preserve raw telemetry and establish a timestamped baseline",
            "correlate process, identity, network, and file activity",
            "test the signal against an approved operational change",
        ],
        "threat_hunting": [
            "search for related parent-child processes",
            "search for the same account, destination, and time window",
            "compare with known-good deployment and maintenance records",
        ],
        "containment": [
            "scope affected hosts and accounts before action",
            "apply the least disruptive approved containment step",
            "preserve evidence and record the decision owner",
        ],
        "hardening": [
            "improve telemetry coverage and alert context",
            "restrict unnecessary service permissions",
            "document an approved operational baseline",
        ],
        "required_next_evidence": [
            "process tree and command line",
            "account and session identity",
            "network and file activity",
            "change record or independent corroboration",
        ],
        "limitations": [
            "Recommendations require Owner-approved scope and operational review.",
            "No containment or remediation action is executed by this reasoning function.",
        ],
    }


def analyze_expert_case(observation: str) -> dict[str, Any]:
    return {
        "observation": str(observation).strip(),
        "attacker_reasoning": attacker_reasoning(observation),
        "defender_reasoning": defender_reasoning(observation),
        "confidence": 0.2,
        "confidence_rationale": "The input is an observation; corroborating telemetry is required.",
    }
