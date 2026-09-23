# Live Worker Capability Contract.
#
# ARCHITECTURAL INVARIANT (unchanged by this package):
#   OWNER_INSTRUCTION > SYSTEM_PLATFORM > OWNER_POLICY >
#   DETERMINISTIC_ENFORCEMENT > AUTHORIZATION_SCOPE > TOOL_RUNTIME >
#   MODEL_OUTPUT > EXTERNAL_DATA
#
# This package defines what an external live worker (e.g. the Vibe
# execution environment) is PROVEN able to do.  It grants no authority:
#   Capability != Authorization.
# Having an http_get capability never authorizes the worker against any
# target.  Authorization stays exclusively in the existing CyberSentinel
# path (Owner policy -> MissionAuthorizationSnapshot -> Scope Firewall).
#
# Every capability entry records provenance from the 2026-09-23 live
# capability audit; UNKNOWN items are never promoted to AVAILABLE.
from .capability import CapabilityStatus, WorkerCapability, WorkerCapabilitySet, VIBE_CAPABILITY_SET
from .requirements import CapabilityRequirement, CapabilityCheckResult, RequirementDecision, check_requirements
from .provenance import ProvenanceLayer, PROVENANCE_HIERARCHY, promotion_allowed
from .evidence import EvidenceClass, FindingStatus, ObservationKind, WorkerObservation, finding_status_from_observation
from .adapter import LiveResearchWorkerAdapter, WorkerTaskPlan

__all__ = [
    "CapabilityStatus", "WorkerCapability", "WorkerCapabilitySet", "VIBE_CAPABILITY_SET",
    "CapabilityRequirement", "CapabilityCheckResult", "RequirementDecision", "check_requirements",
    "ProvenanceLayer", "PROVENANCE_HIERARCHY", "promotion_allowed",
    "EvidenceClass", "FindingStatus", "ObservationKind", "WorkerObservation", "finding_status_from_observation",
    "LiveResearchWorkerAdapter", "WorkerTaskPlan",
]
