from __future__ import annotations

"""Adaptive offensive reasoning mind.

A pure-reasoning adversarial cognition layer for the CyberSentinel agent.
It thinks like a determined, creative adversary: attack trees, hypothesis
fan-out, fallback ladders, opsec-first scoring and deception awareness.

Hard boundaries (non-negotiable, enforced by construction):
- It plans and reasons; it never executes, never emits payloads, never
  touches credentials, and never targets anything outside the declared
  engagement scope.
- Every step is evidence-gated: it carries the exact evidence required
  before it can be considered actionable.
- Planning without a valid, accepted engagement raises EngagementError.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class EngagementError(PermissionError):
    """Raised when offensive planning lacks a valid accepted engagement."""


class KillChainPhase(str, Enum):
    RECON = "RECON"
    FOOTHOLD = "FOOTHOLD"
    ESCALATION = "ESCALATION"
    LATERAL = "LATERAL"
    PERSISTENCE = "PERSISTENCE"
    OBJECTIVE = "OBJECTIVE"


_PHASE_ORDER = {phase: index for index, phase in enumerate(KillChainPhase)}


class StepStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    DETECTED = "DETECTED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class Engagement:
    engagement_id: str
    authorized_scope: tuple[str, ...]
    rules_of_engagement_accepted: bool = False
    creativity_level: int = 2

    def __post_init__(self) -> None:
        if not self.engagement_id or not self.engagement_id.strip():
            raise ValueError("engagement_id is required")
        scope = tuple(dict.fromkeys(self.authorized_scope))
        if not scope:
            raise ValueError("authorized_scope must list at least one in-scope asset")
        for asset in scope:
            if not isinstance(asset, str) or not asset.strip():
                raise ValueError("scope assets must be non-empty strings")
        if not self.rules_of_engagement_accepted:
            raise EngagementError(
                "offensive planning requires the Owner to accept the rules of engagement"
            )
        if self.creativity_level not in (1, 2, 3):
            raise ValueError("creativity_level must be 1, 2 or 3")
        object.__setattr__(self, "authorized_scope", scope)

    def covers(self, asset: str) -> bool:
        asset = asset.strip().casefold()
        return any(asset == s.strip().casefold() or asset.endswith("." + s.strip().casefold()) for s in self.authorized_scope)


@dataclass
class AttackStep:
    step_id: str
    description: str
    phase: KillChainPhase
    target_asset: str
    mitre_technique: str
    impact: float
    detectability: float
    preconditions: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    success_criteria: str = ""
    fallback_of: str | None = None
    status: StepStatus = StepStatus.PENDING
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.step_id or not self.description:
            raise ValueError("step identity and description are required")
        if not 0.0 <= self.impact <= 1.0 or not 0.0 <= self.detectability <= 1.0:
            raise ValueError("impact and detectability must be within [0, 1]")
        if self.phase not in KillChainPhase:
            raise ValueError("unknown kill-chain phase")
        if self.status not in StepStatus:
            raise ValueError("unknown step status")

    @property
    def priority(self) -> float:
        stealth = 1.0 - self.detectability
        return round(self.impact * stealth, 6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "phase": self.phase.value,
            "target_asset": self.target_asset,
            "mitre_technique": self.mitre_technique,
            "impact": self.impact,
            "detectability": self.detectability,
            "priority": self.priority,
            "preconditions": list(self.preconditions),
            "evidence_required": list(self.evidence_required),
            "success_criteria": self.success_criteria,
            "fallback_of": self.fallback_of,
            "status": self.status.value,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackStep":
        return cls(
            step_id=str(data["step_id"]),
            description=str(data["description"]),
            phase=KillChainPhase(data.get("phase", KillChainPhase.RECON.value)),
            target_asset=str(data.get("target_asset", "")),
            mitre_technique=str(data.get("mitre_technique", "")),
            impact=float(data.get("impact", 0.0)),
            detectability=float(data.get("detectability", 0.0)),
            preconditions=tuple(data.get("preconditions", ())),
            evidence_required=tuple(data.get("evidence_required", ())),
            success_criteria=str(data.get("success_criteria", "")),
            fallback_of=data.get("fallback_of"),
            status=StepStatus(data.get("status", StepStatus.PENDING.value)),
            rationale=str(data.get("rationale", "")),
        )


@dataclass
class Campaign:
    objective: str
    engagement_id: str
    steps: list[AttackStep] = field(default_factory=list)
    deception_flags: list[str] = field(default_factory=list)
    hypothesis_fanout: list[dict[str, Any]] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "engagement_id": self.engagement_id,
            "steps": [s.to_dict() for s in self.steps],
            "deception_flags": list(self.deception_flags),
            "hypothesis_fanout": [dict(h) for h in self.hypothesis_fanout],
            "version": self.version,
            "limitations": [
                "This campaign is an analysis-only reasoning artifact.",
                "No step is executable until every item of its evidence_required is satisfied.",
                "Any step whose target leaves the authorized scope must be discarded.",
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Campaign":
        return cls(
            objective=str(data["objective"]),
            engagement_id=str(data["engagement_id"]),
            steps=[AttackStep.from_dict(s) for s in data.get("steps", ())],
            deception_flags=list(data.get("deception_flags", ())),
            hypothesis_fanout=[dict(h) for h in data.get("hypothesis_fanout", ())],
            version=int(data.get("version", 1)),
        )

    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def actionable_steps(self) -> list[AttackStep]:
        return [s for s in self.steps if s.status in (StepStatus.PENDING, StepStatus.ACTIVE)]

    def next_step(self) -> AttackStep | None:
        candidates = self.actionable_steps()
        if not candidates:
            return None
        candidates = sorted(candidates, key=lambda s: (_PHASE_ORDER[s.phase], -s.priority, s.step_id))
        return candidates[0]


_TEMPLATES: dict[str, tuple[tuple[str, KillChainPhase, str, float, float, tuple[str, ...], tuple[str, ...], str], ...]] = {
    "web-exposed-surface": (
        (
            "Map the exposed web surface: enumerate reachable endpoints, undocumented routes and parameter surfaces, and diff them against documented behavior.",
            KillChainPhase.RECON, "T1595", 0.7, 0.2,
            ("target within engagement scope",),
            ("endpoint inventory", "technology fingerprint", "waf presence indicators"),
            "A complete surface inventory with deviations from documentation.",
        ),
        (
            "Hypothesize authentication confusion: probe how the identity layer binds tokens, sessions and object references, looking for gaps between authorization decisions.",
            KillChainPhase.FOOTHOLD, "T1550", 0.9, 0.6,
            ("surface inventory complete",),
            ("auth flow diagrams", "token validation behavior", "object-level access samples"),
            "A concrete mismatch between what the identity layer checks and what it trusts.",
        ),
        (
            "Hypothesize trust-boundary leaks: where does the application accept external input that later influences privileged decisions (templates, redirects, callbacks, deserialization)?",
            KillChainPhase.FOOTHOLD, "T1190", 0.8, 0.5,
            ("surface inventory complete",),
            ("input sink inventory", "privilege decision points", "redirect and callback configuration"),
            "An input path crossing a trust boundary without revalidation.",
        ),
    ),
    "api-gateway": (
        (
            "Study the gateway contract: rate limits, header handling, routing quirks and version skew between gateway and backend.",
            KillChainPhase.RECON, "T1592", 0.6, 0.2,
            ("gateway within scope",),
            ("routing table behavior", "header passthrough matrix", "rate-limit responses"),
            "A routing or passthrough inconsistency between gateway and backend.",
        ),
        (
            "Hypothesize gateway/backend disagreement: craft reasoning around requests the gateway validates differently from the service behind it.",
            KillChainPhase.FOOTHOLD, "T1190", 0.85, 0.55,
            ("gateway contract mapped",),
            ("schema comparisons per route", "validation differential samples"),
            "A validation differential usable to reach the backend directly.",
        ),
    ),
    "identity-provider": (
        (
            "Reason about the identity fabric: how are sessions minted, refreshed, revoked and bound to devices, and which flows skip which checks.",
            KillChainPhase.RECON, "T1589", 0.8, 0.3,
            ("identity provider within scope",),
            ("supported flow inventory", "token lifetime configuration", "revocation propagation evidence"),
            "A session lifecycle gap or an under-validated flow.",
        ),
        (
            "Hypothesize session-fixation and token-relay paths: could a token issued in one context be honored in a stronger one?",
            KillChainPhase.ESCALATION, "T1539", 0.95, 0.6,
            ("identity fabric mapped",),
            ("token audience and scope samples", "context-binding evidence", "replay attempt logs"),
            "A token accepted outside its intended context.",
        ),
    ),
    "internal-lateral-surface": (
        (
            "Model the internal trust graph: which in-scope services trust which callers, and where authentication between services is optional or ambient.",
            KillChainPhase.LATERAL, "T1550", 0.85, 0.4,
            ("a foothold hypothesis on an in-scope host exists",),
            ("service-to-service auth inventory", "ambient trust evidence", "network segmentation map"),
            "An internal edge that trusts callers without credentials.",
        ),
    ),
    "cloud-workload": (
        (
            "Reason about the cloud control plane from the workload's chair: which metadata, identity roles and instance identities are reachable from in-scope workloads.",
            KillChainPhase.ESCALATION, "T1552", 0.9, 0.5,
            ("workload within scope",),
            ("attached role inventory", "metadata service exposure", "environment variable audit"),
            "A workload-attached identity more privileged than its function requires.",
        ),
    ),
}

_FALLBACK_TEMPLATES = (
    ("Re-approach with a different protocol or client fingerprint while keeping the same analytical goal.", -0.2, "T1096"),
    ("Re-approach asynchronously: shift timing so the interaction pattern no longer resembles the failed attempt.", -0.15, "T1097"),
    ("Re-approach through an adjacent in-scope dependency that reaches the same objective from a different edge.", 0.05, "T1072"),
)

_DECEPTION_CUES = {
    "uniform latency": "responses are suspiciously uniform; a canary or tarpit may be shaping your observations",
    "honeytoken": "a too-easily-found secret appeared; treat it as bait until proven otherwise",
    "implausible volume": "the data volume offered is implausibly rich; deception is the higher-probability hypothesis",
    "identical banners": "identical banners across supposedly different systems suggest a staged environment",
    "instant success": "the first attempt succeeded trivially; assume a controlled feed until independent corroboration",
}


class OffensiveMind:
    """Adversarial cognition: plans, adapts and self-critiques like a red operator."""

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement

    def plan(self, objective: str, target_features: Iterable[str]) -> Campaign:
        text = objective.strip()
        if not text:
            raise ValueError("objective is required")
        steps: list[AttackStep] = []
        seen_ids: set[str] = set()
        for feature in target_features:
            template = _TEMPLATES.get(feature)
            if not template:
                continue
            for entry in template:
                description, phase, technique, impact, detectability, pre, evidence, criteria = entry
                asset = self.engagement.authorized_scope[0]
                step_id = "s-{:02d}".format(len(steps) + 1)
                if step_id in seen_ids:
                    continue
                seen_ids.add(step_id)
                steps.append(AttackStep(
                    step_id=step_id,
                    description=description,
                    phase=phase,
                    target_asset=asset,
                    mitre_technique=technique,
                    impact=impact,
                    detectability=detectability,
                    preconditions=pre,
                    evidence_required=evidence,
                    success_criteria=criteria,
                    rationale=self._rationale(phase, impact, detectability),
                ))
        for step in steps:
            if step.target_asset and not self.engagement.covers(step.target_asset):
                step.status = StepStatus.OUT_OF_SCOPE
        campaign = Campaign(objective=text, engagement_id=self.engagement.engagement_id, steps=steps)
        campaign.hypothesis_fanout = self.fanout(campaign)
        return campaign

    def _rationale(self, phase: KillChainPhase, impact: float, detectability: float) -> str:
        level = self.engagement.creativity_level
        return (
            "phase={} impact={:.2f} stealth={:.2f} creativity={}: prefer the move that "
            "buys the most understanding for the least noise".format(phase.value, impact, 1.0 - detectability, level)
        )

    def fanout(self, campaign: Campaign) -> list[dict[str, Any]]:
        """Generate parallel competing hypotheses the adversary would hold simultaneously."""
        level = self.engagement.creativity_level
        width = {1: 1, 2: 2, 3: 3}[level]
        hypotheses: list[dict[str, Any]] = []
        for step in campaign.steps:
            hypotheses.append({
                "step_id": step.step_id,
                "hypothesis": step.description,
                "status": "requires_evidence",
                "would_falsify": list(step.evidence_required[:1]) or ["independent corroboration"],
            })
        ranked = sorted(hypotheses, key=lambda h: h["step_id"])[: max(1, width * 2)]
        return ranked

    def adapt(self, campaign: Campaign, event: dict[str, Any]) -> Campaign:
        """Fold an execution event back into the campaign like an OODA turn."""
        event_type = str(event.get("type", ""))
        if event_type == "STEP_RESULT":
            return self._adapt_step_result(campaign, event)
        if event_type == "OBSERVATION":
            return self._adapt_observation(campaign, event)
        raise ValueError("unknown event type: {!r}".format(event_type))

    def _adapt_step_result(self, campaign: Campaign, event: dict[str, Any]) -> Campaign:
        step_id = str(event.get("step_id", ""))
        outcome = str(event.get("outcome", "")).upper()
        steps = {s.step_id: s for s in campaign.steps}
        step = steps.get(step_id)
        if step is None:
            raise ValueError("unknown step_id: {!r}".format(step_id))
        if outcome == "COMPLETED":
            step.status = StepStatus.COMPLETED
            self._unlock(campaign, step_id)
        elif outcome == "FAILED":
            step.status = StepStatus.FAILED
            self._add_fallbacks(campaign, step)
        elif outcome == "DETECTED":
            step.status = StepStatus.DETECTED
            self._quarantine_dependents(campaign, step_id)
            self._add_fallbacks(campaign, step)
        else:
            raise ValueError("outcome must be COMPLETED, FAILED or DETECTED")
        campaign.version += 1
        campaign.hypothesis_fanout = self.fanout(campaign)
        return campaign

    def _adapt_observation(self, campaign: Campaign, event: dict[str, Any]) -> Campaign:
        note = str(event.get("note", "")).casefold()
        for cue, message in _DECEPTION_CUES.items():
            if cue in note:
                flag = "deception-suspected: {}".format(message)
                if flag not in campaign.deception_flags:
                    campaign.deception_flags.append(flag)
                for step in campaign.steps:
                    if step.status == StepStatus.ACTIVE:
                        step.status = StepStatus.BLOCKED
                        step.rationale += " | frozen pending deception triage"
        campaign.version += 1
        return campaign

    def _unlock(self, campaign: Campaign, completed_id: str) -> None:
        for step in campaign.steps:
            if step.status == StepStatus.BLOCKED and completed_id in step.preconditions:
                step.status = StepStatus.PENDING

    def _quarantine_dependents(self, campaign: Campaign, detected_id: str) -> None:
        for step in campaign.steps:
            if step.status in (StepStatus.PENDING, StepStatus.ACTIVE) and detected_id in step.preconditions:
                step.status = StepStatus.BLOCKED
                step.rationale += " | quarantined: predecessor was detected"

    def _add_fallbacks(self, campaign: Campaign, failed: AttackStep) -> None:
        index = len(campaign.steps)
        for template in _FALLBACK_TEMPLATES:
            description, delta, technique = template
            step = AttackStep(
                step_id="s-{:02d}".format(index + 1),
                description="{} Goal remains: {}".format(description, failed.success_criteria or failed.description),
                phase=failed.phase,
                target_asset=failed.target_asset,
                mitre_technique=technique,
                impact=failed.impact,
                detectability=max(0.0, min(1.0, failed.detectability + delta)),
                preconditions=failed.preconditions,
                evidence_required=failed.evidence_required,
                success_criteria=failed.success_criteria,
                fallback_of=failed.step_id,
                rationale="fallback ladder for {} (creativity={})".format(failed.step_id, self.engagement.creativity_level),
            )
            if step.target_asset and not self.engagement.covers(step.target_asset):
                step.status = StepStatus.OUT_OF_SCOPE
            campaign.steps.append(step)
            index += 1
            if self.engagement.creativity_level == 1:
                break


def mind_from_engagement(engagement: Engagement) -> OffensiveMind:
    return OffensiveMind(engagement)
