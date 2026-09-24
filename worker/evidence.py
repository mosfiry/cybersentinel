from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .provenance import ProvenanceLayer, WORKER_PROVENANCE_LAYERS


class EvidenceClass(str, Enum):
    """What kind of claim an evidence item is. Deliberately distinct from
    finding status: a body difference is an OBSERVATION, never by itself a
    CONFIRMED vulnerability."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    HYPOTHESIS = "HYPOTHESIS"
    CONFIRMED = "CONFIRMED"
    UNPROVEN = "UNPROVEN"
    BLOCKED = "BLOCKED"


class ObservationKind(str, Enum):
    """Only observation kinds the live worker can actually produce."""

    RESPONSE_BODY = "RESPONSE_BODY"
    RESPONSE_BODY_LENGTH = "RESPONSE_BODY_LENGTH"
    BODY_HASH = "BODY_HASH"
    RESPONSE_DIFFERENCE = "RESPONSE_DIFFERENCE"
    RESPONSE_MATCH = "RESPONSE_MATCH"
    REQUEST_TIMING = "REQUEST_TIMING"


class FindingStatus(str, Enum):
    """Finding maturity. Body difference alone can never yield CONFIRMED."""

    OBSERVATION = "OBSERVATION"
    HYPOTHESIS = "HYPOTHESIS"
    UNPROVEN = "UNPROVEN"
    CONFIRMED = "CONFIRMED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class WorkerObservation:
    """Structured, re-verifiable evidence returned by a live worker.

    All fields describe ONE operation the worker actually performed.
    Nothing here authorizes anything; provenance is always EXTERNAL_DATA
    (or MODEL_OUTPUT for interpretation notes), never an authority layer.
    """

    request_id: str
    worker_id: str
    capability: str
    timestamp: str
    target: str
    operation: ObservationKind
    url: str
    evidence_class: EvidenceClass
    status: str
    body_hash: str = ""
    body_length: int = 0
    duration_ms: int = 0
    raw_body_ref: str = ""
    limitations: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    provenance: ProvenanceLayer = ProvenanceLayer.EXTERNAL_DATA

    def __post_init__(self) -> None:
        # Worker observations must remain in their declared worker layer.
        if self.provenance not in WORKER_PROVENANCE_LAYERS:
            raise ValueError("worker evidence may not claim authority provenance: " + self.provenance.value)
        # MODEL_OUTPUT is an interpretation layer, not raw worker observation.
        if self.provenance is ProvenanceLayer.MODEL_OUTPUT and self.evidence_class not in (EvidenceClass.INFERRED, EvidenceClass.HYPOTHESIS, EvidenceClass.UNPROVEN, EvidenceClass.BLOCKED):
            raise ValueError("MODEL_OUTPUT evidence must be an interpretation claim")


def finding_status_from_observation(observation: WorkerObservation) -> FindingStatus:
    """Deterministic observation -> finding maturity mapping.

    Core honesty rule: response_difference is UNPROVEN. A changed
    representation reaching a clean request is a hypothesis that needs
    cache-header evidence (Age/ETag/Vary/CF-Cache-Status) the worker cannot
    capture — so it stays UNPROVEN, never CONFIRMED.
    """
    if observation.evidence_class in (EvidenceClass.HYPOTHESIS, EvidenceClass.UNPROVEN):
        return FindingStatus.UNPROVEN
    if observation.operation is ObservationKind.RESPONSE_DIFFERENCE:
        return FindingStatus.UNPROVEN
    if observation.evidence_class is EvidenceClass.CONFIRMED:
        # This package has no trusted CyberSentinel validation event. A worker
        # cannot self-confirm by supplying metadata such as
        # corroborated_by_validator=True.
        return FindingStatus.UNPROVEN
    return FindingStatus.OBSERVATION
