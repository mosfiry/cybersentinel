"""Owner-scoped, versioned procedural skills with explicit approval gates.

The registry stores procedures, never executable Python or prompt authority. Candidate
and approved skill records remain untrusted data. Every execution step is rechecked
against a live typed MissionAuthorizationSnapshot and a derived DelegationScope, then
handed to an injected dispatcher that must route through MissionRuntime/ToolRegistry
and its evidence/fence boundary. This module does not call tool handlers directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol
import uuid

from security.mission_authorization import MissionAuthorizationSnapshot

from .models import DelegationScope


SKILL_SCHEMA_VERSION = 1
_MAX_SKILL_BYTES = 128_000
_MAX_STEPS = 32
_MAX_TESTS = 64
_MAX_RESULT_BYTES = 64_000
_MAX_TIMEOUT_SECONDS = 120
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_JSON_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}


class SkillError(ValueError):
    """Invalid, unavailable, stale, or non-executable skill data."""


class SkillAuthorizationError(PermissionError):
    """A skill operation lacks a current, owner-issued authorization grant."""


class SkillStatus(str, Enum):
    CANDIDATE = "candidate"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


@dataclass(frozen=True)
class SkillStep:
    step_id: str
    tool_name: str
    action: str
    argument_bindings: Mapping[str, str] = field(default_factory=dict)
    constant_arguments: Mapping[str, Any] = field(default_factory=dict)
    description: str = ""
    expects_evidence: bool = True
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(str(self.step_id)) or not _ID_RE.fullmatch(str(self.tool_name)):
            raise ValueError("skill step and tool identifiers must be bounded identifiers")
        if not str(self.action).strip() or len(self.action) > 96:
            raise ValueError("skill step requires a bounded action identifier")
        if not isinstance(self.expects_evidence, bool):
            raise ValueError("skill evidence requirement must be boolean")
        if not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise ValueError("skill step timeout is outside the bounded policy")
        if len(self.description) > 2000:
            raise ValueError("skill step description is too long")
        bindings = {str(key): str(value) for key, value in dict(self.argument_bindings).items()}
        constants = dict(self.constant_arguments)
        if set(bindings) & set(constants):
            raise ValueError("a skill argument cannot be both bound and constant")
        _json_bytes(constants, max_bytes=16_000)
        object.__setattr__(self, "argument_bindings", bindings)
        object.__setattr__(self, "constant_arguments", constants)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "action": self.action,
            "argument_bindings": dict(self.argument_bindings),
            "constant_arguments": dict(self.constant_arguments),
            "description": self.description,
            "expects_evidence": bool(self.expects_evidence),
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillStep":
        return cls(**dict(value))


@dataclass(frozen=True)
class SkillTestCase:
    test_id: str
    inputs: Mapping[str, Any]
    expected_tool_sequence: tuple[str, ...]
    fixture_outputs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(str(self.test_id)):
            raise ValueError("skill test id must be a bounded identifier")
        _json_bytes(dict(self.inputs), max_bytes=16_000)
        _json_bytes(dict(self.fixture_outputs), max_bytes=32_000)
        object.__setattr__(self, "inputs", dict(self.inputs))
        object.__setattr__(self, "expected_tool_sequence", tuple(str(x) for x in self.expected_tool_sequence))
        object.__setattr__(self, "fixture_outputs", dict(self.fixture_outputs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "inputs": dict(self.inputs),
            "expected_tool_sequence": list(self.expected_tool_sequence),
            "fixture_outputs": dict(self.fixture_outputs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SkillTestCase":
        data = dict(value)
        data["expected_tool_sequence"] = tuple(data.get("expected_tool_sequence", ()))
        return cls(**data)


_DEFAULT_INPUT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
_DEFAULT_OUTPUT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}


@dataclass(frozen=True)
class SkillDefinition:
    skill_id: str
    name: str
    description: str
    version: int
    author_source: str
    capabilities: tuple[str, ...]
    required_tools: tuple[str, ...]
    allowed_scope: tuple[str, ...]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    procedure: tuple[SkillStep, ...]
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    examples: tuple[Mapping[str, Any], ...]
    tests: tuple[SkillTestCase, ...]
    provenance: str
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    output_bindings: Mapping[str, str] = field(default_factory=dict)
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(str(self.skill_id)):
            raise ValueError("skill id must be a bounded identifier")
        if not str(self.name).strip() or len(self.name) > 160 or not str(self.description).strip() or len(self.description) > 8000:
            raise ValueError("skill name or description is missing or too long")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("skill version must be a positive integer")
        if not str(self.author_source).strip() or not str(self.provenance).strip():
            raise ValueError("skill source and provenance are required")
        for field_name in ("capabilities", "required_tools", "allowed_scope", "preconditions", "postconditions"):
            values = tuple(str(value).strip() for value in getattr(self, field_name))
            if any(not value for value in values) or len(values) != len(set(values)):
                raise ValueError(f"{field_name} must contain unique non-empty strings")
            object.__setattr__(self, field_name, values)
        object.__setattr__(self, "procedure", tuple(self.procedure))
        object.__setattr__(self, "examples", tuple(dict(x) for x in self.examples))
        object.__setattr__(self, "tests", tuple(self.tests))
        object.__setattr__(self, "output_bindings", {str(k): str(v) for k, v in dict(self.output_bindings).items()})
        object.__setattr__(self, "input_schema", dict(self.input_schema or _DEFAULT_INPUT_SCHEMA))
        object.__setattr__(self, "output_schema", dict(self.output_schema or _DEFAULT_OUTPUT_SCHEMA))
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("skill confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", float(self.confidence))
        payload = self._payload()
        digest = hashlib.sha256(_json_bytes(payload, max_bytes=_MAX_SKILL_BYTES)).hexdigest()
        if self.content_hash and not hmac.compare_digest(self.content_hash, digest):
            raise ValueError("skill content hash mismatch")
        object.__setattr__(self, "content_hash", digest)

    def _payload(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author_source": self.author_source,
            "capabilities": list(self.capabilities),
            "required_tools": list(self.required_tools),
            "allowed_scope": list(self.allowed_scope),
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "procedure": [step.to_dict() for step in self.procedure],
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "examples": [dict(x) for x in self.examples],
            "tests": [test.to_dict() for test in self.tests],
            "provenance": self.provenance,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "output_bindings": dict(self.output_bindings),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SkillDefinition":
        data = dict(payload)
        data["capabilities"] = tuple(data.get("capabilities", ()))
        data["required_tools"] = tuple(data.get("required_tools", ()))
        data["allowed_scope"] = tuple(data.get("allowed_scope", ()))
        data["preconditions"] = tuple(data.get("preconditions", ()))
        data["postconditions"] = tuple(data.get("postconditions", ()))
        data["procedure"] = tuple(SkillStep.from_dict(item) for item in data.get("procedure", ()))
        data["examples"] = tuple(data.get("examples", ()))
        data["tests"] = tuple(SkillTestCase.from_dict(item) for item in data.get("tests", ()))
        data["output_bindings"] = dict(data.get("output_bindings", {}))
        return cls(**data)


@dataclass(frozen=True)
class SkillApprovalGrant:
    owner_identity_ref: str
    approver_identity_ref: str
    action: str
    decision_id: str

    def __post_init__(self) -> None:
        if not all(str(value).strip() for value in (self.owner_identity_ref, self.approver_identity_ref, self.action, self.decision_id)):
            raise ValueError("skill approval grant is incomplete")


@dataclass(frozen=True)
class SkillRevision:
    owner_identity_ref: str
    definition: SkillDefinition
    status: SkillStatus


@dataclass(frozen=True)
class SkillCritique:
    critic_id: str
    passed: bool
    reason: str

    def __post_init__(self) -> None:
        if not str(self.critic_id).strip() or not str(self.reason).strip() or not isinstance(self.passed, bool):
            raise ValueError("skill critic result must be typed and complete")


@dataclass(frozen=True)
class SkillCandidateEvidence:
    owner_identity_ref: str
    mission_id: str
    trajectory_sha256: str
    critic_id: str
    validator_id: str
    verification_evidence_sha256: str
    evidence_refs: tuple[str, ...]
    candidate_sha256: str

    def __post_init__(self) -> None:
        refs = tuple(str(ref).strip() for ref in self.evidence_refs)
        if not all(str(value).strip() for value in (self.owner_identity_ref, self.mission_id, self.critic_id, self.validator_id)):
            raise ValueError("skill candidate evidence is missing owner, mission, critic, or validator identity")
        if not refs or any(not ref for ref in refs) or len(set(refs)) != len(refs):
            raise ValueError("skill candidate requires unique evidence references")
        for digest in (self.trajectory_sha256, self.verification_evidence_sha256, self.candidate_sha256):
            if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
                raise ValueError("skill candidate evidence requires full SHA-256 digests")
        object.__setattr__(self, "evidence_refs", refs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner_identity_ref": self.owner_identity_ref,
            "mission_id": self.mission_id,
            "trajectory_sha256": self.trajectory_sha256,
            "critic_id": self.critic_id,
            "validator_id": self.validator_id,
            "verification_evidence_sha256": self.verification_evidence_sha256,
            "evidence_refs": list(self.evidence_refs),
            "candidate_sha256": self.candidate_sha256,
        }


@dataclass(frozen=True)
class SkillExecutionContext:
    snapshot: MissionAuthorizationSnapshot
    delegation_scope: DelegationScope
    agent_id: str
    task_id: str
    request_id: str
    skill_id: str = ""
    skill_version: int = 0
    skill_content_hash: str = ""
    is_cancelled: Callable[[], bool] = field(default=lambda: False, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, MissionAuthorizationSnapshot) or not isinstance(self.delegation_scope, DelegationScope):
            raise TypeError("skill execution requires typed mission authorization and delegated scope")
        if not all(str(value).strip() for value in (self.agent_id, self.task_id, self.request_id)):
            raise ValueError("skill execution context is missing agent/task/request identity")
        if self.skill_id or self.skill_version or self.skill_content_hash:
            if not _ID_RE.fullmatch(self.skill_id) or self.skill_version < 1 or not re.fullmatch(r"[0-9a-f]{64}", self.skill_content_hash):
                raise ValueError("skill execution revision binding is incomplete")
        scope = self.delegation_scope
        if (scope.owner_identity_ref, scope.mission_id, scope.target_identity, scope.root_authorization_hash) != (
            self.snapshot.owner_identity, self.snapshot.mission_id, self.snapshot.target_identity, self.snapshot.authorization_hash
        ):
            raise SkillAuthorizationError("delegated skill scope is not bound to the current mission authorization")


@dataclass(frozen=True)
class SkillStepReceipt:
    value: Any
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        refs = tuple(str(ref).strip() for ref in self.evidence_refs)
        if len(refs) > 128 or any(not ref or len(ref) > 1024 for ref in refs) or len(set(refs)) != len(refs):
            raise ValueError("skill evidence references must be non-empty and unique")
        _json_bytes(self.value, max_bytes=_MAX_RESULT_BYTES)
        object.__setattr__(self, "evidence_refs", refs)


@dataclass(frozen=True)
class SkillExecutionReceipt:
    run_id: str
    owner_identity_ref: str
    skill_id: str
    version: int
    mission_id: str
    agent_id: str
    status: str
    result: Mapping[str, Any]
    result_hash: str
    evidence_refs: tuple[str, ...]


class AuthorizedSkillDispatcher(Protocol):
    """Host bridge: must reauthorize and execute through MissionRuntime per call."""

    def __call__(self, context: SkillExecutionContext, step: SkillStep, arguments: Mapping[str, Any], tool_spec: Any) -> SkillStepReceipt: ...


def _json_bytes(value: Any, *, max_bytes: int) -> bytes:
    try:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("value is not bounded JSON data") from exc
    if len(payload) > max_bytes:
        raise ValueError("JSON payload exceeds skill resource limit")
    return payload


def _validate_schema_definition(schema: Mapping[str, Any]) -> None:
    if not isinstance(schema, Mapping) or schema.get("type") != "object":
        raise SkillError("skill input and output schemas must be JSON objects")
    if set(schema) - {"type", "properties", "required", "additionalProperties"}:
        raise SkillError("unsupported JSON schema keyword")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping) or len(properties) > 128:
        raise SkillError("invalid or oversized JSON schema properties")
    required = schema.get("required", ())
    if not isinstance(required, (list, tuple)) or any(not isinstance(name, str) or name not in properties for name in required):
        raise SkillError("JSON schema required property is not declared")
    if not isinstance(schema.get("additionalProperties", False), bool):
        raise SkillError("additionalProperties must be boolean")
    for name, rule in properties.items():
        if not isinstance(name, str) or not _ID_RE.fullmatch(name) or not isinstance(rule, Mapping):
            raise SkillError("invalid JSON schema property")
        if set(rule) - {"type", "enum", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "items"}:
            raise SkillError("unsupported JSON schema property keyword")
        kind = rule.get("type")
        if kind not in _JSON_TYPES - {"object"}:
            raise SkillError("nested or unknown JSON schema types are not supported")
        if kind == "array":
            item_rule = rule.get("items")
            if not isinstance(item_rule, Mapping) or set(item_rule) - {"type", "enum", "minLength", "maxLength", "minimum", "maximum"}:
                raise SkillError("array schema requires a bounded scalar item schema")
            if item_rule.get("type") not in _JSON_TYPES - {"object", "array"}:
                raise SkillError("nested or unknown array item types are not supported")
        enum = rule.get("enum")
        if enum is not None and (not isinstance(enum, (list, tuple)) or len(enum) > 256):
            raise SkillError("invalid schema enum")


def _value_matches(value: Any, rule: Mapping[str, Any]) -> bool:
    kind = rule["type"]
    matches = {
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
        "array": lambda v: isinstance(v, list),
    }[kind](value)
    if not matches:
        return False
    if "enum" in rule and value not in rule["enum"]:
        return False
    if isinstance(value, str):
        if len(value) < int(rule.get("minLength", 0)) or len(value) > int(rule.get("maxLength", 16_000)):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in rule and value < rule["minimum"] or "maximum" in rule and value > rule["maximum"]:
            return False
    if isinstance(value, list):
        if len(value) < int(rule.get("minItems", 0)) or len(value) > int(rule.get("maxItems", 128)):
            return False
        if any(not _value_matches(item, rule["items"]) for item in value):
            return False
    return True


def validate_object(value: Any, schema: Mapping[str, Any]) -> tuple[bool, str]:
    _validate_schema_definition(schema)
    if not isinstance(value, Mapping):
        return False, "expected_object"
    properties = schema.get("properties", {})
    if not schema.get("additionalProperties", False) and set(value) - set(properties):
        return False, "unexpected_property"
    if set(schema.get("required", ())) - set(value):
        return False, "missing_required_property"
    for key, item in value.items():
        rule = properties.get(key)
        if rule is not None and not _value_matches(item, rule):
            return False, f"invalid_property:{key}"
        try:
            _json_bytes(item, max_bytes=16_000)
        except ValueError:
            return False, f"invalid_json_property:{key}"
    return True, "valid"


def _resolve_binding(reference: str, inputs: Mapping[str, Any], outputs: Mapping[str, Any]) -> Any:
    parts = reference.split(".")
    if len(parts) == 2 and parts[0] == "input" and parts[1] in inputs:
        return inputs[parts[1]]
    if len(parts) == 3 and parts[0] == "step" and parts[1] in outputs and isinstance(outputs[parts[1]], Mapping) and parts[2] in outputs[parts[1]]:
        return outputs[parts[1]][parts[2]]
    raise SkillError("skill binding source is missing")


def validate_skill_definition(definition: SkillDefinition, tool_specs: Mapping[str, Any]) -> None:
    """Validate a skill against the current canonical tool catalog; never execute it."""
    if not isinstance(definition, SkillDefinition):
        raise TypeError("typed SkillDefinition required")
    # Frozen dataclasses can still contain mutable nested mappings. Recompute the
    # canonical hash before any write or execution to detect post-construction edits.
    SkillDefinition.from_dict(definition.to_dict())
    if not 1 <= len(definition.procedure) <= _MAX_STEPS:
        raise SkillError("skill procedure must contain 1–32 bounded steps")
    if not 1 <= len(definition.tests) <= _MAX_TESTS:
        raise SkillError("skill requires deterministic test cases")
    if len(definition.examples) > 32 or len(definition.preconditions) > 64 or len(definition.postconditions) > 64:
        raise SkillError("skill metadata exceeds bounds")
    _validate_schema_definition(definition.input_schema)
    _validate_schema_definition(definition.output_schema)
    if not definition.output_bindings:
        raise SkillError("skill requires explicit output bindings")
    if set(definition.output_bindings) != set(definition.output_schema.get("properties", {})):
        raise SkillError("output schema properties must exactly match declared bindings")
    _json_bytes(definition.to_dict(), max_bytes=_MAX_SKILL_BYTES)
    step_ids: set[str] = set()
    prior_steps: set[str] = set()
    actual_tools: list[str] = []
    for step in definition.procedure:
        if step.step_id in step_ids:
            raise SkillError("duplicate skill step id")
        spec = tool_specs.get(step.tool_name)
        if spec is None:
            raise SkillError(f"skill requires unknown tool: {step.tool_name}")
        if getattr(spec, "scope_required", False) and not set(getattr(spec, "scope_requirements", ())).issubset(definition.allowed_scope):
            raise SkillError("skill scope does not include the canonical tool's required scope")
        names = set(step.argument_bindings) | set(step.constant_arguments)
        tool_schema = getattr(spec, "input_schema", {}) or {}
        tool_properties = set(tool_schema.get("properties", {})) if isinstance(tool_schema, Mapping) else set()
        if tool_properties and not names.issubset(tool_properties):
            raise SkillError("skill step defines fields outside the canonical tool schema")
        for reference in step.argument_bindings.values():
            parts = reference.split(".")
            if len(parts) == 2 and parts[0] == "input":
                if parts[1] not in definition.input_schema.get("properties", {}):
                    raise SkillError("skill step references an undeclared input")
            elif len(parts) == 3 and parts[0] == "step":
                if parts[1] not in prior_steps or not _ID_RE.fullmatch(parts[2]):
                    raise SkillError("skill step references a missing or later step output")
            else:
                raise SkillError("skill bindings must use input.<name> or step.<id>.<output>")
        step_ids.add(step.step_id)
        prior_steps.add(step.step_id)
        actual_tools.append(step.tool_name)
    if tuple(sorted(set(actual_tools))) != tuple(sorted(definition.required_tools)):
        raise SkillError("required_tools must exactly match procedure tools")
    for test in definition.tests:
        valid, reason = validate_object(test.inputs, definition.input_schema)
        if not valid:
            raise SkillError(f"invalid test case {test.test_id}: {reason}")
        if test.expected_tool_sequence != tuple(actual_tools):
            raise SkillError(f"test case {test.test_id} does not cover the exact procedure tool sequence")
        step_ids_for_test = {step.step_id for step in definition.procedure}
        if set(test.fixture_outputs) - step_ids_for_test:
            raise SkillError(f"test case {test.test_id} defines an unknown step output")
        simulated_outputs: dict[str, Any] = {}
        for step in definition.procedure:
            arguments = dict(step.constant_arguments)
            arguments.update({name: _resolve_binding(ref, test.inputs, simulated_outputs) for name, ref in step.argument_bindings.items()})
            valid_args, reason, _ = tool_specs[step.tool_name].validate_input(arguments)
            if not valid_args:
                raise SkillError(f"test case {test.test_id} fails tool input validation: {reason}")
            output = dict(test.fixture_outputs.get(step.step_id, {}))
            _json_bytes(output, max_bytes=_MAX_RESULT_BYTES)
            simulated_outputs[step.step_id] = output
        simulated_result = {
            name: _resolve_binding(reference, test.inputs, simulated_outputs)
            for name, reference in definition.output_bindings.items()
        }
        valid_output, reason = validate_object(simulated_result, definition.output_schema)
        if not valid_output:
            raise SkillError(f"test case {test.test_id} fails output schema validation: {reason}")
    for output_name, reference in definition.output_bindings.items():
        if not _ID_RE.fullmatch(output_name) or not isinstance(reference, str):
            raise SkillError("invalid output binding")
        parts = reference.split(".")
        if len(parts) == 2 and parts[0] == "input":
            if parts[1] not in definition.input_schema.get("properties", {}):
                raise SkillError("output binding references an undeclared input")
        elif len(parts) == 3 and parts[0] == "step":
            if parts[1] not in prior_steps or not _ID_RE.fullmatch(parts[2]):
                raise SkillError("output binding references a missing skill step")
        else:
            raise SkillError("outputs must bind to input.<name> or step.<id>.<output>")
        if not definition.output_schema.get("additionalProperties", False) and output_name not in definition.output_schema.get("properties", {}):
            raise SkillError("output binding is outside the declared output schema")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class SkillRegistry:
    """Versioned SQLite skill registry with immutable revisions and owner action events."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        tool_specs: Mapping[str, Any] | None = None,
        approval_authorizer: Callable[[str, str, str, int], SkillApprovalGrant | None] | None = None,
    ) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if tool_specs is None:
            from tools.registry import REGISTRY
            tool_specs = REGISTRY
        self.tool_specs = dict(tool_specs)
        self.approval_authorizer = approval_authorizer
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
            if connection.in_transaction:
                connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("CREATE TABLE IF NOT EXISTS skill_schema_versions(component TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            row = conn.execute("SELECT version FROM skill_schema_versions WHERE component='skills'").fetchone()
            if row is None:
                conn.execute("INSERT INTO skill_schema_versions VALUES('skills', ?)", (SKILL_SCHEMA_VERSION,))
            elif int(row[0]) > SKILL_SCHEMA_VERSION:
                raise RuntimeError("skill schema is newer than this runtime")
            elif int(row[0]) < SKILL_SCHEMA_VERSION:
                raise RuntimeError("no migration registered for skill schema")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_revisions (
                    owner_identity_ref TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(owner_identity_ref, skill_id, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_events (
                    event_id TEXT PRIMARY KEY,
                    owner_identity_ref TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor_identity_ref TEXT NOT NULL,
                    decision_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_heads (
                    owner_identity_ref TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    active_version INTEGER,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(owner_identity_ref, skill_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_run_events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    owner_identity_ref TEXT NOT NULL,
                    skill_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    mission_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_skill_revisions_owner ON skill_revisions(owner_identity_ref, skill_id, version)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_skill_events_owner ON skill_events(owner_identity_ref, skill_id, version, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_skill_run_owner ON skill_run_events(owner_identity_ref, mission_id, agent_id, created_at)")
            conn.commit()

    def _event_status(self, conn: sqlite3.Connection, owner_ref: str, skill_id: str, version: int) -> SkillStatus:
        row = conn.execute(
            "SELECT action FROM skill_events WHERE owner_identity_ref=? AND skill_id=? AND version=? ORDER BY rowid DESC LIMIT 1",
            (owner_ref, skill_id, version),
        ).fetchone()
        if row is None or row[0] == "candidate_registered":
            return SkillStatus.CANDIDATE
        action = str(row[0])
        if action in {"approved", "rollback_activated"}:
            return SkillStatus.APPROVED
        if action == "deprecated":
            return SkillStatus.DEPRECATED
        if action == "revoked":
            return SkillStatus.REVOKED
        return SkillStatus.CANDIDATE

    def _load_revision(self, conn: sqlite3.Connection, owner_ref: str, skill_id: str, version: int) -> SkillRevision | None:
        row = conn.execute(
            "SELECT content_hash,payload_json FROM skill_revisions WHERE owner_identity_ref=? AND skill_id=? AND version=?",
            (owner_ref, skill_id, version),
        ).fetchone()
        if row is None:
            return None
        definition = SkillDefinition.from_dict(json.loads(row[1]))
        if not hmac.compare_digest(str(row[0]), definition.content_hash):
            raise SkillError("stored skill revision content hash mismatch")
        return SkillRevision(owner_ref, definition, self._event_status(conn, owner_ref, skill_id, version))

    def register_candidate(
        self,
        owner_identity_ref: str,
        definition: SkillDefinition,
        candidate_evidence: SkillCandidateEvidence,
    ) -> SkillRevision:
        owner_ref = str(owner_identity_ref).strip()
        if not owner_ref:
            raise SkillError("owner identity reference is required")
        if not isinstance(candidate_evidence, SkillCandidateEvidence):
            raise SkillError("verified mission, critic and evidence provenance is required for a candidate")
        if candidate_evidence.owner_identity_ref != owner_ref or candidate_evidence.candidate_sha256 != definition.content_hash:
            raise SkillError("skill candidate evidence owner or content binding mismatch")
        validate_skill_definition(definition, self.tool_specs)
        payload = _json_bytes(definition.to_dict(), max_bytes=_MAX_SKILL_BYTES).decode("utf-8")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT content_hash FROM skill_revisions WHERE owner_identity_ref=? AND skill_id=? AND version=?",
                (owner_ref, definition.skill_id, definition.version),
            ).fetchone()
            if existing:
                if existing[0] != definition.content_hash:
                    raise SkillError("skill revision is immutable; create a new version")
                return self._load_revision(conn, owner_ref, definition.skill_id, definition.version)
            latest = conn.execute(
                "SELECT MAX(version) FROM skill_revisions WHERE owner_identity_ref=? AND skill_id=?",
                (owner_ref, definition.skill_id),
            ).fetchone()[0]
            if latest is not None and definition.version <= int(latest):
                raise SkillError("skill version must increase monotonically")
            conn.execute(
                "INSERT INTO skill_revisions VALUES(?,?,?,?,?,?)",
                (owner_ref, definition.skill_id, definition.version, definition.content_hash, payload, definition.created_at),
            )
            self._append_event(conn, owner_ref, definition.skill_id, definition.version, "candidate_registered", "candidate_pipeline", "", {
                "content_hash": definition.content_hash,
                "candidate_evidence": candidate_evidence.to_dict(),
            })
            conn.commit()
            return SkillRevision(owner_ref, definition, SkillStatus.CANDIDATE)

    def _append_event(self, conn: sqlite3.Connection, owner_ref: str, skill_id: str, version: int, action: str, actor_ref: str, decision_id: str, details: Mapping[str, Any]) -> None:
        conn.execute(
            "INSERT INTO skill_events VALUES(?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex, owner_ref, skill_id, version, action, actor_ref, decision_id, _utcnow(), _json_bytes(dict(details), max_bytes=16_000).decode("utf-8")),
        )

    def _require_owner_grant(self, action: str, owner_ref: str, skill_id: str, version: int) -> SkillApprovalGrant:
        if self.approval_authorizer is None:
            raise SkillAuthorizationError("owner authorization adapter is not configured; skill remains non-executable")
        grant = self.approval_authorizer(action, owner_ref, skill_id, version)
        if not isinstance(grant, SkillApprovalGrant):
            raise SkillAuthorizationError("a typed owner approval grant is required")
        if (grant.owner_identity_ref, grant.approver_identity_ref, grant.action) != (owner_ref, owner_ref, action):
            raise SkillAuthorizationError("skill approval grant owner or action mismatch")
        return grant

    def approve(self, owner_identity_ref: str, skill_id: str, version: int) -> SkillRevision:
        owner_ref = str(owner_identity_ref).strip()
        candidate = self.get_revision(owner_ref, skill_id, version)
        if candidate is None or candidate.status is not SkillStatus.CANDIDATE:
            raise SkillError("only a registered candidate can be approved")
        validate_skill_definition(candidate.definition, self.tool_specs)
        grant = self._require_owner_grant("approve", owner_ref, skill_id, version)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._load_revision(conn, owner_ref, skill_id, version)
            if current is None or current.status is not SkillStatus.CANDIDATE:
                raise SkillError("only a registered candidate can be approved")
            head = conn.execute("SELECT active_version FROM skill_heads WHERE owner_identity_ref=? AND skill_id=?", (owner_ref, skill_id)).fetchone()
            if head and head[0] is not None and version <= int(head[0]):
                raise SkillError("new skill approval must not silently roll back the active version")
            self._append_event(conn, owner_ref, skill_id, version, "approved", grant.approver_identity_ref, grant.decision_id, {"content_hash": candidate.definition.content_hash})
            conn.execute(
                "INSERT INTO skill_heads VALUES(?,?,?,?) ON CONFLICT(owner_identity_ref,skill_id) DO UPDATE SET active_version=excluded.active_version,updated_at=excluded.updated_at",
                (owner_ref, skill_id, version, _utcnow()),
            )
            conn.commit()
        return SkillRevision(owner_ref, candidate.definition, SkillStatus.APPROVED)

    def revoke(self, owner_identity_ref: str, skill_id: str, version: int) -> None:
        owner_ref = str(owner_identity_ref).strip()
        revision = self.get_revision(owner_ref, skill_id, version)
        if revision is None or revision.status is not SkillStatus.APPROVED:
            raise SkillError("only an approved revision can be revoked")
        grant = self._require_owner_grant("revoke", owner_ref, skill_id, version)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._load_revision(conn, owner_ref, skill_id, version)
            if current is None or current.status is not SkillStatus.APPROVED:
                raise SkillError("only a currently approved revision can be revoked")
            self._append_event(conn, owner_ref, skill_id, version, "revoked", grant.approver_identity_ref, grant.decision_id, {})
            conn.execute("UPDATE skill_heads SET active_version=NULL,updated_at=? WHERE owner_identity_ref=? AND skill_id=? AND active_version=?", (_utcnow(), owner_ref, skill_id, version))
            conn.commit()

    def deprecate(self, owner_identity_ref: str, skill_id: str, version: int) -> None:
        owner_ref = str(owner_identity_ref).strip()
        revision = self.get_revision(owner_ref, skill_id, version)
        if revision is None or revision.status is not SkillStatus.APPROVED:
            raise SkillError("only an approved revision can be deprecated")
        grant = self._require_owner_grant("deprecate", owner_ref, skill_id, version)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._load_revision(conn, owner_ref, skill_id, version)
            if current is None or current.status is not SkillStatus.APPROVED:
                raise SkillError("only a currently approved revision can be deprecated")
            self._append_event(conn, owner_ref, skill_id, version, "deprecated", grant.approver_identity_ref, grant.decision_id, {})
            conn.execute("UPDATE skill_heads SET active_version=NULL,updated_at=? WHERE owner_identity_ref=? AND skill_id=? AND active_version=?", (_utcnow(), owner_ref, skill_id, version))
            conn.commit()

    def rollback(self, owner_identity_ref: str, skill_id: str, target_version: int) -> SkillRevision:
        owner_ref = str(owner_identity_ref).strip()
        target = self.get_revision(owner_ref, skill_id, target_version)
        if target is None or target.status not in {SkillStatus.APPROVED, SkillStatus.DEPRECATED}:
            raise SkillError("rollback target must be a previously approved revision")
        grant = self._require_owner_grant("rollback", owner_ref, skill_id, target_version)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current_target = self._load_revision(conn, owner_ref, skill_id, target_version)
            if current_target is None or current_target.status not in {SkillStatus.APPROVED, SkillStatus.DEPRECATED}:
                raise SkillError("rollback target is no longer eligible")
            head = conn.execute("SELECT active_version FROM skill_heads WHERE owner_identity_ref=? AND skill_id=?", (owner_ref, skill_id)).fetchone()
            previous = int(head[0]) if head and head[0] is not None else None
            self._append_event(conn, owner_ref, skill_id, target_version, "rollback_activated", grant.approver_identity_ref, grant.decision_id, {"previous_version": previous})
            conn.execute(
                "INSERT INTO skill_heads VALUES(?,?,?,?) ON CONFLICT(owner_identity_ref,skill_id) DO UPDATE SET active_version=excluded.active_version,updated_at=excluded.updated_at",
                (owner_ref, skill_id, target_version, _utcnow()),
            )
            conn.commit()
        return SkillRevision(owner_ref, target.definition, SkillStatus.APPROVED)

    def get_revision(self, owner_identity_ref: str, skill_id: str, version: int) -> SkillRevision | None:
        if not str(owner_identity_ref).strip():
            return None
        with self._connect() as conn:
            return self._load_revision(conn, str(owner_identity_ref), skill_id, int(version))

    def get_active(self, owner_identity_ref: str, skill_id: str) -> SkillRevision | None:
        if not str(owner_identity_ref).strip():
            return None
        with self._connect() as conn:
            row = conn.execute("SELECT active_version FROM skill_heads WHERE owner_identity_ref=? AND skill_id=?", (owner_identity_ref, skill_id)).fetchone()
            if row is None or row[0] is None:
                return None
            revision = self._load_revision(conn, owner_identity_ref, skill_id, int(row[0]))
            if revision is None or revision.status is not SkillStatus.APPROVED:
                return None
            return revision

    def list_revisions(self, owner_identity_ref: str, skill_id: str) -> list[SkillRevision]:
        if not str(owner_identity_ref).strip():
            return []
        with self._connect() as conn:
            versions = conn.execute("SELECT version FROM skill_revisions WHERE owner_identity_ref=? AND skill_id=? ORDER BY version", (owner_identity_ref, skill_id)).fetchall()
            return [self._load_revision(conn, owner_identity_ref, skill_id, int(row[0])) for row in versions]

    def events(self, owner_identity_ref: str, skill_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM skill_events WHERE owner_identity_ref=? AND skill_id=? ORDER BY rowid", (owner_identity_ref, skill_id)).fetchall()
            return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def record_run_event(self, *, run_id: str, owner_identity_ref: str, skill_id: str, version: int, mission_id: str, agent_id: str, status: str, details: Mapping[str, Any]) -> None:
        if status not in {"STARTED", "SUCCEEDED", "FAILED", "CANCELLED", "BLOCKED"}:
            raise SkillError("unsupported skill run event")
        if not all(str(value).strip() for value in (run_id, owner_identity_ref, skill_id, mission_id, agent_id)) or version < 1:
            raise SkillError("skill run event identity is incomplete")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute(
                "SELECT owner_identity_ref,skill_id,version,mission_id,agent_id,status FROM skill_run_events WHERE run_id=? ORDER BY rowid DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            identity = (owner_identity_ref, skill_id, version, mission_id, agent_id)
            if status == "STARTED":
                if previous is not None:
                    raise SkillError("skill run ID has already been used")
            elif previous is None or previous[5] != "STARTED" or tuple(previous[:5]) != identity:
                raise SkillError("skill run terminal event lacks a matching STARTED event")
            conn.execute(
                "INSERT INTO skill_run_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, run_id, owner_identity_ref, skill_id, version, mission_id, agent_id, status, _utcnow(), _json_bytes(dict(details), max_bytes=16_000).decode("utf-8")),
            )
            conn.commit()

    def run_events(self, owner_identity_ref: str, *, mission_id: str | None = None, agent_id: str | None = None) -> list[dict[str, Any]]:
        clauses = ["owner_identity_ref=?"]
        values: list[Any] = [owner_identity_ref]
        for column, value in (("mission_id", mission_id), ("agent_id", agent_id)):
            if value is not None:
                clauses.append(column + "=?")
                values.append(value)
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM skill_run_events WHERE " + " AND ".join(clauses) + " ORDER BY rowid", values).fetchall()
            return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]


class SkillLearningPipeline:
    """Promote validated Mission experience only to a non-executable candidate."""

    def __init__(
        self,
        registry: SkillRegistry,
        *,
        critic: Callable[[str, SkillDefinition, list[Mapping[str, Any]], list[Mapping[str, Any]]], SkillCritique],
        verification_plan: Any,
        mission_owner_resolver: Callable[[str], str],
    ):
        from agent.verification import VerificationPlan
        if not isinstance(verification_plan, VerificationPlan) or verification_plan.validator is None:
            raise TypeError("SkillLearningPipeline requires an independent VerificationPlan")
        if not callable(mission_owner_resolver):
            raise TypeError("SkillLearningPipeline requires a canonical mission-owner resolver")
        self.registry = registry
        self.critic = critic
        self.verification_plan = verification_plan
        self.mission_owner_resolver = mission_owner_resolver

    def propose_candidate(
        self,
        owner_identity_ref: str,
        mission_id: str,
        definition: SkillDefinition,
        *,
        trajectory: list[Mapping[str, Any]],
        evidence: list[Mapping[str, Any]],
        evidence_refs: tuple[str, ...],
    ) -> SkillRevision:
        from agent.trajectory import verify_trajectory
        from agent.verification import FindingClaim, VerificationEngine, VerificationResult

        if not str(owner_identity_ref).strip() or not mission_id or not trajectory or len(trajectory) > 10000:
            raise SkillError("skill learning requires a bounded completed mission trajectory")
        if self.mission_owner_resolver(mission_id) != owner_identity_ref:
            raise SkillAuthorizationError("mission owner does not match skill candidate owner")
        trajectory_payload = [dict(event) for event in trajectory]
        _json_bytes(trajectory_payload, max_bytes=4_000_000)
        if not verify_trajectory(trajectory_payload):
            raise SkillError("mission trajectory hash chain is invalid")
        if any(str(event.get("mission_id", "")) != mission_id for event in trajectory_payload):
            raise SkillError("trajectory contains events from another mission")
        event_types = [str(event.get("event", "")) for event in trajectory_payload]
        if "MissionStarted" not in event_types or "GoalVerified" not in event_types or event_types[-1] != "MissionCompleted":
            raise SkillError("skill learning requires a successfully verified and completed mission")
        if event_types.index("GoalVerified") > event_types.index("MissionCompleted"):
            raise SkillError("skill learning requires a successfully verified and completed mission")
        if not evidence or len(evidence) > 256:
            raise SkillError("skill learning requires bounded validator evidence")
        evidence_payload = [dict(item) for item in evidence]
        _json_bytes(evidence_payload, max_bytes=1_000_000)
        critique = self.critic(mission_id, definition, trajectory_payload, evidence_payload)
        if not isinstance(critique, SkillCritique) or not critique.passed:
            raise SkillError("independent skill critic rejected the candidate")
        reference_values = {
            str(item.get("evidence_id") or item.get("id") or item.get("reference") or "")
            for item in evidence_payload
        }
        if not evidence_refs or not set(evidence_refs).issubset(reference_values):
            raise SkillError("candidate evidence references are not present in validator input")
        trajectory_hash = hashlib.sha256(_json_bytes(trajectory_payload, max_bytes=4_000_000)).hexdigest()
        claim = FindingClaim(
            claim=f"Candidate procedure derived from completed mission {mission_id}",
            target=mission_id,
            provenance={"skill_id": definition.skill_id, "skill_version": definition.version, "critic_id": critique.critic_id},
        )
        report = VerificationEngine().verify(claim, self.verification_plan, evidence_payload)
        if report.result is not VerificationResult.PASS:
            raise SkillError("independent evidence verification did not pass")
        if report.validator_id == critique.critic_id:
            raise SkillError("critic and evidence validator must be independent authorities")
        payload = definition.to_dict()
        payload["provenance"] = (
            f"{definition.provenance}; mission={mission_id}; trajectory_sha256={trajectory_hash}; "
            f"critic={critique.critic_id}; validator={report.validator_id}; evidence_sha256={report.evidence_hash}"
        )
        payload["content_hash"] = ""
        candidate = SkillDefinition.from_dict(payload)
        candidate_evidence = SkillCandidateEvidence(
            owner_identity_ref=owner_identity_ref,
            mission_id=mission_id,
            trajectory_sha256=trajectory_hash,
            critic_id=critique.critic_id,
            validator_id=report.validator_id,
            verification_evidence_sha256=report.evidence_hash,
            evidence_refs=tuple(evidence_refs),
            candidate_sha256=candidate.content_hash,
        )
        return self.registry.register_candidate(owner_identity_ref, candidate, candidate_evidence)


class SkillExecutor:
    """Bounded procedure runner. All side effects are delegated to the host's authorized dispatcher."""

    def __init__(self, registry: SkillRegistry, dispatcher: AuthorizedSkillDispatcher):
        self.registry = registry
        self.dispatcher = dispatcher

    @staticmethod
    def _resolve(reference: str, inputs: Mapping[str, Any], outputs: Mapping[str, Any]) -> Any:
        return _resolve_binding(reference, inputs, outputs)

    def execute(self, owner_identity_ref: str, skill_id: str, inputs: Mapping[str, Any], context: SkillExecutionContext) -> SkillExecutionReceipt:
        revision = self.registry.get_active(owner_identity_ref, skill_id)
        if revision is None:
            raise SkillAuthorizationError("skill has no active owner-approved revision")
        definition = revision.definition
        validate_skill_definition(definition, self.registry.tool_specs)
        snapshot = context.snapshot
        delegated = context.delegation_scope
        valid, reason = snapshot.validate_for_mission(
            mission_id=delegated.mission_id,
            owner_identity=owner_identity_ref,
            target_identity=delegated.target_identity,
        )
        if not valid or owner_identity_ref != snapshot.owner_identity:
            raise SkillAuthorizationError(reason if not valid else "skill owner does not match the authenticated mission owner")
        if definition.allowed_scope and (
            not set(definition.allowed_scope).issubset(delegated.scope)
            or not set(definition.allowed_scope).issubset(snapshot.scope)
        ):
            raise SkillAuthorizationError("skill allowed scope exceeds mission or delegated task scope")
        required_tools = set(definition.required_tools)
        # An empty tool set is fail-closed for skill execution even if legacy snapshot semantics use it as a wildcard.
        if not required_tools.issubset(set(snapshot.allowed_tools)) or not required_tools.issubset(set(delegated.allowed_tools)):
            raise SkillAuthorizationError("skill tool set exceeds explicit mission/delegated tool grants")
        valid_inputs, input_reason = validate_object(inputs, definition.input_schema)
        if not valid_inputs:
            raise SkillError("invalid skill inputs: " + input_reason)
        run_id = uuid.uuid4().hex
        input_hash = hashlib.sha256(_json_bytes(dict(inputs), max_bytes=16_000)).hexdigest()
        self.registry.record_run_event(
            run_id=run_id, owner_identity_ref=owner_identity_ref, skill_id=skill_id, version=definition.version,
            mission_id=snapshot.mission_id, agent_id=context.agent_id, status="STARTED",
            details={"task_id": context.task_id, "request_id": context.request_id, "input_hash": input_hash, "content_hash": definition.content_hash},
        )
        outputs: dict[str, Any] = {}
        evidence: list[str] = []
        execution_context = SkillExecutionContext(
            snapshot=snapshot,
            delegation_scope=delegated,
            agent_id=context.agent_id,
            task_id=context.task_id,
            request_id=context.request_id,
            skill_id=skill_id,
            skill_version=definition.version,
            skill_content_hash=definition.content_hash,
            is_cancelled=context.is_cancelled,
        )
        try:
            for step in definition.procedure:
                if context.is_cancelled():
                    raise InterruptedError("skill execution cancelled")
                current = self.registry.get_active(owner_identity_ref, skill_id)
                if current is None or current.definition.version != definition.version or current.definition.content_hash != definition.content_hash:
                    raise SkillAuthorizationError("skill revision was revoked or changed before tool dispatch")
                spec = self.registry.tool_specs[step.tool_name]
                if getattr(spec, "scope_required", False) and not set(getattr(spec, "scope_requirements", ())).issubset(delegated.scope):
                    raise SkillAuthorizationError("tool scope requirement exceeds delegated scope")
                allowed, decision_reason = snapshot.check(action=step.action, tool_id=step.tool_name, target_identity=snapshot.target_identity)
                if not allowed:
                    raise SkillAuthorizationError(decision_reason)
                args = dict(step.constant_arguments)
                args.update({name: self._resolve(reference, inputs, outputs) for name, reference in step.argument_bindings.items()})
                valid_tool_input, tool_reason, _normalized = spec.validate_input(args)
                if not valid_tool_input:
                    raise SkillError("canonical tool schema rejected skill arguments: " + tool_reason)
                _json_bytes(args, max_bytes=16_000)
                receipt = self.dispatcher(execution_context, step, args, spec)
                if not isinstance(receipt, SkillStepReceipt):
                    raise SkillError("authorized tool dispatcher must return a typed SkillStepReceipt")
                if step.expects_evidence and not receipt.evidence_refs:
                    raise SkillError("skill step expected evidence but dispatcher returned none")
                value = json.loads(_json_bytes(receipt.value, max_bytes=_MAX_RESULT_BYTES))
                outputs[step.step_id] = value
                evidence.extend(receipt.evidence_refs)
            # Return only declared output bindings, never arbitrary tool output prose.
            result = {
                name: self._resolve(reference, inputs, outputs)
                for name, reference in definition.output_bindings.items()
            }
            valid_output, output_reason = validate_object(result, definition.output_schema)
            if not valid_output:
                raise SkillError("skill output schema rejected procedure result: " + output_reason)
            result_json = _json_bytes(dict(result), max_bytes=_MAX_RESULT_BYTES)
        except Exception as exc:
            state = "CANCELLED" if isinstance(exc, InterruptedError) else "FAILED"
            self.registry.record_run_event(
                run_id=run_id, owner_identity_ref=owner_identity_ref, skill_id=skill_id, version=definition.version,
                mission_id=snapshot.mission_id, agent_id=context.agent_id, status=state,
                details={"error_type": type(exc).__name__, "completed_step_count": len(outputs), "evidence_refs": evidence[:128]},
            )
            raise
        result_hash = hashlib.sha256(result_json).hexdigest()
        evidence_refs = tuple(dict.fromkeys(evidence))
        self.registry.record_run_event(
            run_id=run_id, owner_identity_ref=owner_identity_ref, skill_id=skill_id, version=definition.version,
            mission_id=snapshot.mission_id, agent_id=context.agent_id, status="SUCCEEDED",
            details={"result_hash": result_hash, "evidence_refs": list(evidence_refs), "completed_step_count": len(outputs)},
        )
        return SkillExecutionReceipt(
            run_id=run_id, owner_identity_ref=owner_identity_ref, skill_id=skill_id, version=definition.version,
            mission_id=snapshot.mission_id, agent_id=context.agent_id, status="SUCCEEDED",
            result=dict(result), result_hash=result_hash, evidence_refs=evidence_refs,
        )


__all__ = [
    "AuthorizedSkillDispatcher", "SkillApprovalGrant", "SkillAuthorizationError", "SkillCandidateEvidence",
    "SkillCritique", "SkillDefinition", "SkillError", "SkillExecutionContext", "SkillExecutionReceipt",
    "SkillExecutor", "SkillLearningPipeline", "SkillRegistry",
    "SkillRevision", "SkillStatus", "SkillStep", "SkillStepReceipt", "SkillTestCase",
    "validate_object", "validate_skill_definition",
]
