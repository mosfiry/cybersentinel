from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

from tools.registry import REGISTRY


class SpecialistContractError(ValueError):
    """A specialist input or proposal failed its declared contract."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SpecialistProfile:
    profile_id: str
    role: str
    capabilities: tuple[str, ...]
    model_selection_policy: str
    required_context: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    mission_boundary: str
    input_contract: dict[str, Any]
    output_contract: dict[str, Any]
    evidence_requirements: tuple[str, ...]
    validation_path: tuple[str, ...]

    def context(self, *, task_id: str, plan_version: int, question: str, model_selection: dict[str, Any]) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "role": self.role,
            "capabilities": list(self.capabilities),
            "model_selection_policy": self.model_selection_policy,
            "owner_model_selection": dict(model_selection),
            "required_context": list(self.required_context),
            "allowed_tools": list(self.allowed_tools),
            "mission_boundary": self.mission_boundary,
            "task_boundary": {"task_id": task_id, "plan_version": plan_version},
            "input": {"question": question},
            "output_contract": self.output_contract,
            "evidence_requirements": list(self.evidence_requirements),
            "validation_path": list(self.validation_path),
            "authority": "proposal_only",
            "instructions": (
                "Return JSON matching output_contract. Cite durable evidence or tool-call IDs for the summary and every claim. "
                "This role cannot change Owner instruction, mission objective, authorization, scope, tools, model selection, "
                "evidence records, verification, or completion. Recommendations are proposals only."
            ),
        }


@dataclass(frozen=True)
class SpecialistInput:
    mission_id: str
    task_id: str
    plan_version: int
    question: str

    def validate(self) -> None:
        if not isinstance(self.mission_id, str) or not self.mission_id or len(self.mission_id) > 128:
            raise SpecialistContractError("invalid_input")
        if not isinstance(self.task_id, str) or not self.task_id or len(self.task_id) > 128:
            raise SpecialistContractError("invalid_input")
        if type(self.plan_version) is not int or self.plan_version < 1:
            raise SpecialistContractError("invalid_input")
        if not isinstance(self.question, str) or not self.question.strip() or len(self.question) > 1000:
            raise SpecialistContractError("invalid_input")


@dataclass(frozen=True)
class SpecialistClaim:
    text: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class SpecialistOutput:
    summary: str
    evidence_refs: tuple[str, ...]
    claims: tuple[SpecialistClaim, ...]
    unknowns: tuple[str, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "claims": [asdict(item) | {"evidence_refs": list(item.evidence_refs)} for item in self.claims],
            "unknowns": list(self.unknowns),
            "recommendations": list(self.recommendations),
        }


@dataclass(frozen=True)
class SpecialistInvocation:
    profile: SpecialistProfile
    specialist_input: SpecialistInput
    allowed_tools: tuple[str, ...]

    def context(self, model_selection: dict[str, Any]) -> dict[str, Any]:
        return self.profile.context(
            task_id=self.specialist_input.task_id,
            plan_version=self.specialist_input.plan_version,
            question=self.specialist_input.question,
            model_selection=model_selection,
        )


RESEARCH_SPECIALIST = SpecialistProfile(
    profile_id="research",
    role="Research Specialist",
    capabilities=("bounded public and local intelligence research", "source-referenced analysis"),
    model_selection_policy="inherit_persisted_owner_mission_selection",
    required_context=("owner_instruction", "mission_objective", "plan", "authorization_snapshot", "task_step"),
    allowed_tools=("search",),
    mission_boundary="one existing PlanStep in one persisted Mission; no new mission or authority boundary",
    input_contract={
        "type": "object",
        "required": ["mission_id", "task_id", "plan_version", "question"],
        "additionalProperties": False,
        "properties": {
            "mission_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "task_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "plan_version": {"type": "integer", "minimum": 1},
            "question": {"type": "string", "minLength": 1, "maxLength": 1000},
        },
    },
    output_contract={
        "type": "object",
        "required": ["summary", "evidence_refs", "claims", "unknowns", "recommendations"],
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
            "evidence_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["text", "evidence_refs"],
                    "additionalProperties": False,
                    "properties": {
                        "text": {"type": "string", "minLength": 1, "maxLength": 1000},
                        "evidence_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    },
                },
            },
            "unknowns": {"type": "array", "items": {"type": "string"}},
            "recommendations": {"type": "array", "items": {"type": "string"}},
        },
    },
    evidence_requirements=(
        "summary and every factual claim must reference an existing mission evidence ID or durable tool-call ID",
        "references are provenance pointers only and do not become system evidence or completion proof",
    ),
    validation_path=("strict JSON parse", "typed shape and bounds", "mission/task/plan binding", "durable evidence-reference resolution", "proposal-only persistence"),
)

SPECIALIST_PROFILES: dict[str, SpecialistProfile] = {RESEARCH_SPECIALIST.profile_id: RESEARCH_SPECIALIST}


def get_specialist_profile(profile_id: str) -> SpecialistProfile:
    profile = SPECIALIST_PROFILES.get(str(profile_id))
    if profile is None:
        raise SpecialistContractError("unknown_specialist_profile")
    for name in profile.allowed_tools:
        spec = REGISTRY.get(name)
        if spec is None or not spec.available or not callable(spec.handler):
            raise SpecialistContractError("specialist_tool_not_implemented")
    return profile


def parse_specialist_output(content: str, *, evidence_refs: set[str]) -> SpecialistOutput:
    try:
        value = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SpecialistContractError("invalid_output") from exc
    if not isinstance(value, dict) or set(value) != {"summary", "evidence_refs", "claims", "unknowns", "recommendations"}:
        raise SpecialistContractError("invalid_output")

    def text_list(items: Any, *, required: bool = False, max_items: int = 32, max_length: int = 1000) -> tuple[str, ...]:
        if not isinstance(items, list) or len(items) > max_items or (required and not items):
            raise SpecialistContractError("invalid_output")
        if any(not isinstance(item, str) or not item.strip() or len(item) > max_length for item in items):
            raise SpecialistContractError("invalid_output")
        return tuple(items)

    summary = value["summary"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2000:
        raise SpecialistContractError("invalid_output")
    summary_refs = text_list(value["evidence_refs"], required=True)
    if not set(summary_refs).issubset(evidence_refs):
        raise SpecialistContractError("evidence_insufficient")
    raw_claims = value["claims"]
    if not isinstance(raw_claims, list) or len(raw_claims) > 32:
        raise SpecialistContractError("invalid_output")
    claims: list[SpecialistClaim] = []
    for item in raw_claims:
        if not isinstance(item, dict) or set(item) != {"text", "evidence_refs"}:
            raise SpecialistContractError("invalid_output")
        text = item["text"]
        if not isinstance(text, str) or not text.strip() or len(text) > 1000:
            raise SpecialistContractError("invalid_output")
        refs = text_list(item["evidence_refs"], required=True)
        if not set(refs).issubset(evidence_refs):
            raise SpecialistContractError("evidence_insufficient")
        claims.append(SpecialistClaim(text, refs))
    unknowns = text_list(value["unknowns"])
    recommendations = text_list(value["recommendations"])
    return SpecialistOutput(summary, summary_refs, tuple(claims), unknowns, recommendations)


__all__ = [
    "SPECIALIST_PROFILES",
    "RESEARCH_SPECIALIST",
    "SpecialistClaim",
    "SpecialistContractError",
    "SpecialistInput",
    "SpecialistInvocation",
    "SpecialistOutput",
    "SpecialistProfile",
    "get_specialist_profile",
    "parse_specialist_output",
]
