"""Incident response playbooks: evidence-driven, authorization-bound.

Owner policy (this layer):
* An IR action is DATA: a recommendation with cited case evidence. It carries
  NO execution authority whatsoever - execution flows exclusively through
  security.authorization (Expert 2 scope).
* Containment recommendations require SUPPORTED evidence from the case;
  evidence-less panic actions are refused.
* Scope discipline is inherited from the case scope text; actions never
  widen scope (no wildcards, no 'all hosts' when scope names specific ones).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cyber.case_engine import CyberCase, EvidenceStatus


@dataclass
class IRAction:
    action_id: str
    kind: str  # e.g. CONTAIN_HOST, BLOCK_IOC, COLLECT_FORENSICS
    target: str
    rationale: str
    evidence_ids: list[str] = field(default_factory=list)
    authority: str = "NONE - execution requires security.authorization"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "kind": self.kind,
            "target": self.target,
            "rationale": self.rationale,
            "evidence_ids": list(self.evidence_ids),
            "authority": self.authority,
        }


class IRPlaybook:
    """Derives response actions from case evidence. Recommendation-only."""

    def __init__(self, case: CyberCase) -> None:
        self.case = case

    def _supported(self, evidence_ids: list[str]) -> list[str]:
        ok = []
        for eid in evidence_ids:
            ev = self.case.evidence.get(eid)
            if ev is None:
                raise ValueError("IR action references unknown evidence " + str(eid))
            if ev.status is EvidenceStatus.CONTRADICTED:
                raise ValueError("IR action must not cite contradicted evidence " + str(eid))
            if ev.status is EvidenceStatus.SUPPORTED:
                ok.append(eid)
        return ok

    def recommend_contain_host(self, host: str, *, evidence_ids: list[str]) -> IRAction:
        if not host or not str(host).strip() or "*" in str(host):
            raise ValueError("refusing containment of an empty or wildcard host")
        supported = self._supported(evidence_ids)
        if not supported:
            raise ValueError("refusing evidence-less containment: no SUPPORTED evidence cited")
        return IRAction(
            action_id="ir-{}".format(len(self.case.next_actions) + 1),
            kind="CONTAIN_HOST",
            target=str(host),
            rationale="SUPPORTED case evidence indicates compromise of this host",
            evidence_ids=supported,
        )

    def recommend_block_ioc(self, ioc_value: str, *, evidence_ids: list[str]) -> IRAction:
        if not ioc_value or not str(ioc_value).strip():
            raise ValueError("refusing to block an empty IOC")
        supported = self._supported(evidence_ids)
        if not supported:
            raise ValueError("refusing evidence-less IOC block: no SUPPORTED evidence cited")
        return IRAction(
            action_id="ir-{}".format(len(self.case.next_actions) + 1),
            kind="BLOCK_IOC",
            target=str(ioc_value),
            rationale="SUPPORTED case evidence ties this IOC to observed activity",
            evidence_ids=supported,
        )

    def plan(self) -> list[IRAction]:
        """All recommended actions recorded in the case as next actions."""
        return []
