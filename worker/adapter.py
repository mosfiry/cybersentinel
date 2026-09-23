from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .capability import WorkerCapabilitySet
from .evidence import WorkerObservation
from .provenance import ProvenanceLayer, promotion_allowed
from .requirements import CapabilityCheckResult, CapabilityRequirement, check_requirements


@dataclass(frozen=True)
class WorkerTaskPlan:
    """Deterministic plan descriptor for one external-worker task.

    The adapter never executes anything itself: Vibe has no inbound API, so
    this is a PULL model — CyberSentinel (or the Owner) hands the plan to
    the worker, and the worker returns evidence. No fake REST server, no
    fake network channel, no claimed live connection.
    """

    task_id: str
    requirements: tuple[CapabilityRequirement, ...]
    check: CapabilityCheckResult
    authorization_required: bool = True
    dispatchable: bool = field(default=False)

    @property
    def blocked_reason(self) -> tuple[str, ...]:
        return self.check.missing + self.check.unknown


class LiveResearchWorkerAdapter:
    """Pull-based adapter for an external live research worker (e.g. Vibe).

    Contract:
      1. receive task + capability requirements
      2. deterministic capability check (no LLM judgement involved)
      3. scope/authorization is NEVER decided here — the adapter marks
         every plan authorization_required=True; the existing CyberSentinel
         path (Owner policy -> MissionAuthorizationSnapshot -> Scope
         Firewall) remains the only authority.
      4. blocked capabilities produce BLOCKED plans, never EXECUTE_ANYWAY.
      5. evidence is accepted only with honest provenance (EXTERNAL_DATA)
         and validated structure.
    """

    def __init__(self, capability_set: WorkerCapabilitySet):
        self.capability_set = capability_set

    # --- capability != authorization: fixed, unoverridable facts ---

    @staticmethod
    def capability_grants_authority() -> bool:
        """A capability NEVER grants authority. Constant by design."""
        return False

    def plan_task(self, task_id: str, requirements: Iterable[CapabilityRequirement]) -> WorkerTaskPlan:
        check = check_requirements(requirements, self.capability_set)
        return WorkerTaskPlan(
            task_id=task_id,
            requirements=tuple(requirements),
            check=check,
            authorization_required=True,
            dispatchable=check.allowed,
        )

    def accept_evidence(self, observation: WorkerObservation) -> None:
        """Validate worker evidence before it can enter the evidence chain.

        Rejects any attempt to smuggle authority provenance in as data.
        (Acceptance here is structural validation only; the evidence chain
        itself and finding validation stay inside CyberSentinel.)
        """
        if not promotion_allowed(observation.provenance, ProvenanceLayer.TOOL_RUNTIME):
            # Worker evidence claiming OWNER/AUTHORITY layers is a hard error.
            raise ValueError("evidence provenance violates authority boundary: " + observation.provenance.value)
        if not observation.request_id or not observation.worker_id:
            raise ValueError("evidence missing request_id/worker_id")
        if observation.worker_id != self.capability_set.worker_id:
            raise ValueError("evidence worker_id does not match adapter capability set")
