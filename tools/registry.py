from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
import sys
import hashlib
import inspect
import json
import math
import mimetypes
import re
import threading
import time
import uuid
from urllib.parse import urlsplit

from workspace.environment import MAX_SANDBOX_PROCESS_SECONDS

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
VALID_NETWORK_ACCESS = frozenset({
    "none", "allowlisted_search_provider", "allowlisted_intel_providers",
    "scope_pinned_browser", "scope_pinned_http", "scope_pinned_web_research", "scope_pinned_mcp",
    "host_process_unscoped",
})
VALID_FILESYSTEM_ACCESS = frozenset({
    "none", "host_fs_via_process", "mission_artifact_write", "workspace_read_only_artifact_write",
})
VALID_PROCESS_ACCESS = frozenset({"none", "workspace_process_unisolated", "workspace_process_sandboxed"})
VALID_CREDENTIAL_ACCESS = frozenset({"none", "provider_managed", "host_user_credentials_possible"})
VALID_RATE_LIMITS = frozenset({"bounded"})
DEFAULT_TOOL_TIMEOUT = 30


def _canonical_json_chunks(value: Any):
    """Yield compact JSON text without materializing a second encoded copy."""
    if value is None:
        yield "null"
    elif value is True:
        yield "true"
    elif value is False:
        yield "false"
    elif isinstance(value, int):
        yield str(value)
    elif isinstance(value, float):
        yield json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    elif isinstance(value, str):
        yield '"'
        for char in value:
            if char == '"':
                yield '\\"'
            elif char == "\\":
                yield "\\\\"
            elif ord(char) < 0x20:
                yield f"\\u{ord(char):04x}"
            else:
                yield char
        yield '"'
    elif isinstance(value, dict):
        yield "{"
        for index, key in enumerate(value):
            if not isinstance(key, str):
                raise TypeError("tool result objects must have string keys")
            if index:
                yield ","
            yield from _canonical_json_chunks(key)
            yield ":"
            yield from _canonical_json_chunks(value[key])
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _canonical_json_chunks(item)
        yield "]"
    else:
        raise TypeError("tool result is not canonical-JSON serializable")


def canonical_json_stats(value: Any, *, max_chars: int | None = None) -> tuple[int, str, bool]:
    """Return canonical JSON character count, SHA-256, and whether the cap truncated it."""
    if max_chars is not None and (isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 0):
        raise ValueError("max_chars must be a non-negative integer")
    digest = hashlib.sha256()
    count = 0
    for chunk in _canonical_json_chunks(value):
        if max_chars is not None and count + len(chunk) > max_chars:
            chunk = chunk[: max_chars - count]
            if chunk:
                digest.update(chunk.encode("utf-8"))
                count += len(chunk)
            return count, digest.hexdigest(), True
        digest.update(chunk.encode("utf-8"))
        count += len(chunk)
    return count, digest.hexdigest(), False


def bounded_result(value: Any, max_result_chars: int) -> tuple[Any, bool]:
    """Preserve small results and replace oversized results with a fixed-size summary."""
    if isinstance(max_result_chars, bool) or not isinstance(max_result_chars, int) or max_result_chars < 128:
        raise ValueError("max_result_chars must be an integer of at least 128")
    _size, prefix_sha256, truncated = canonical_json_stats(value, max_chars=max_result_chars)
    if not truncated:
        return value, False
    if isinstance(value, dict):
        decision_key = next((key for key in ("ok", "success") if isinstance(value.get(key), bool)), "ok")
        decision_value = value.get(decision_key, True)
    else:
        decision_key, decision_value = "ok", True
    summary = {decision_key: decision_value, "truncated": True, "prefix_sha256": prefix_sha256}
    if canonical_json_stats(summary, max_chars=max_result_chars)[2]:
        raise ValueError("max_result_chars is too small for the required result summary")
    return summary, True


class ToolTimeout(TimeoutError):
    pass


def _default_input_schema(argument_type: type | None) -> dict[str, Any]:
    if argument_type is str:
        return {
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": MAX_ARG_LENGTH}},
            "required": ["query"],
            "additionalProperties": False,
        }
    if argument_type is None:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    if argument_type is dict:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    return {}


def _schema_definition_valid(schema: Any, *, depth: int = 0) -> bool:
    """Accept only the small, deterministic JSON Schema subset used by tools."""
    if depth > 8 or not isinstance(schema, dict):
        return False
    allowed = {
        "type", "properties", "required", "additionalProperties", "items", "enum",
        "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "pattern",
    }
    if set(schema) - allowed or schema.get("type") not in {"object", "array", "string", "integer", "number", "boolean", "null"}:
        return False
    if "properties" in schema:
        properties = schema["properties"]
        if not isinstance(properties, dict) or len(properties) > 64 or any(
            not isinstance(name, str) or not name or len(name) > 128
            or not _schema_definition_valid(value, depth=depth + 1)
            for name, value in properties.items()
        ):
            return False
    if "required" in schema:
        if not isinstance(schema["required"], list) or any(not isinstance(item, str) for item in schema["required"]):
            return False
        if len(set(schema["required"])) != len(schema["required"]):
            return False
    if "items" in schema and not _schema_definition_valid(schema["items"], depth=depth + 1):
        return False
    if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
        return False
    if "enum" in schema and (not isinstance(schema["enum"], list) or len(schema["enum"]) > 64):
        return False
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str) or len(schema["pattern"]) > 256:
            return False
        try:
            import re
            re.compile(schema["pattern"])
        except Exception:
            return False
    for name in ("minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems"):
        value = schema.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0):
            return False
    return True


def _validate_json_value(value: Any, schema: dict[str, Any], *, path: str = "arguments", depth: int = 0) -> str | None:
    if depth > 16:
        return f"{path} nesting exceeds the limit"
    kind = schema["type"]
    matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[kind]
    if not matches:
        return f"{path} must be {kind}"
    if "enum" in schema and value not in schema["enum"]:
        return f"{path} is not an allowed value"
    if kind == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 16384):
            return f"{path} length is outside the permitted range"
        if "pattern" in schema:
            import re
            if not re.fullmatch(schema["pattern"], value):
                return f"{path} has an invalid format"
    elif kind == "object":
        if len(value) > 64 or any(not isinstance(key, str) for key in value):
            return f"{path} has too many or invalid properties"
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                return f"{path}.{required} is required"
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return f"{path} contains unknown properties"
        for name, item in value.items():
            if name in properties:
                error = _validate_json_value(item, properties[name], path=f"{path}.{name}", depth=depth + 1)
                if error:
                    return error
    elif kind == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 64):
            return f"{path} item count is outside the permitted range"
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                error = _validate_json_value(item, item_schema, path=f"{path}[{index}]", depth=depth + 1)
                if error:
                    return error
    elif kind in {"integer", "number"}:
        if isinstance(value, float) and not math.isfinite(value):
            return f"{path} must be finite"
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            return f"{path} is outside the permitted range"
    return None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_class: str
    requires_owner: bool
    argument_type: type | None
    handler: Callable[..., Any]
    owner_only: bool = False
    scope_required: bool = False
    version: str = "1.0.0"
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    network_access: str = "none"
    filesystem_access: str = "none"
    process_access: str = "none"
    credential_access: str = "none"
    scope_requirements: tuple[str, ...] = ()
    timeout: int = DEFAULT_TOOL_TIMEOUT
    rate_limit: str = "bounded"
    evidence_requirements: tuple[str, ...] = ("authorization_decision", "observation")
    effect_provider: str = ""
    idempotency_supported: bool = False
    parallel_execution_safe: bool = False  # Explicit review attestation for concurrent, side-effect-free handlers.
    execution_context_required: bool = False
    scope_url_argument: str | None = None
    scope_rate_deferred: bool = False
    allow_custom_input_schema: bool = False
    workspace_scope_required: bool = False
    # Dynamic read tools such as status may be sampled repeatedly; opt in only
    # when identical reads within a plan step cannot add new evidence.
    block_identical_read_repeats: bool = False

    def __post_init__(self) -> None:
        if not self.input_schema:
            object.__setattr__(self, "input_schema", _default_input_schema(self.argument_type))

    @property
    def tool_id(self) -> str:
        return self.name

    @property
    def required_authorization(self) -> str:
        if self.scope_required:
            return "owner_and_scope_snapshot"
        if self.workspace_scope_required:
            return "owner_and_workspace_root"
        return "owner" if self.requires_owner else "none"

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "version": self.version,
            "description": self.description,
            "input_schema": deepcopy(self.input_schema),
            "output_schema": self.output_schema or {"type": "object"},
            "risk_class": self.risk_class,
            "required_authorization": self.required_authorization,
            "network_access": self.network_access,
            "filesystem_access": self.filesystem_access,
            "process_access": self.process_access,
            "credential_access": self.credential_access,
            "scope_requirements": list(self.scope_requirements),
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "evidence_requirements": list(self.evidence_requirements),
            "external_effect_ledger": bool(self.effect_provider),
            "idempotency_supported": self.idempotency_supported,
            "parallel_execution_safe": self.parallel_execution_safe,
            "execution_context_required": self.execution_context_required,
            "workspace_scope_required": self.workspace_scope_required,
            "scope_url_argument": self.scope_url_argument,
            "scope_rate_deferred": self.scope_rate_deferred,
            "allow_custom_input_schema": self.allow_custom_input_schema,
        }

    def validate(self, argument: Any) -> tuple[bool, str]:
        if self.argument_type is None:
            if argument is not None:
                return False, f"{self.name} does not accept an argument"
            return True, "valid"
        if self.argument_type is dict:
            if not isinstance(argument, dict):
                return False, f"{self.name} requires an object argument"
            error = _validate_json_value(argument, self.input_schema)
            return (False, error) if error else (True, "valid")
        if not isinstance(argument, self.argument_type):
            return False, f"{self.name} requires a string argument"
        if len(argument) > MAX_ARG_LENGTH:
            return False, "tool argument exceeds maximum length"
        try:
            argument.encode("utf-8")
        except UnicodeError:
            return False, "tool argument has invalid text encoding"
        if not argument.strip():
            return False, f"{self.name} requires a non-empty string argument"
        return True, "valid"

    def validate_input(self, arguments: Any) -> tuple[bool, str, str | None]:
        """Validate a provider argument object against the exact registered schema.

        Scalar/None inputs remain accepted for existing internal callers; model
        adapters must pass the complete object so extra and missing keys cannot
        be hidden by extracting only ``query``.
        """
        if not isinstance(arguments, dict):
            valid, reason = self.validate(arguments)
            return valid, reason, arguments if valid else None
        try:
            encoded = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode("utf-8")) > 16_384:
                return False, "tool argument object exceeds the configured size limit", None
        except (TypeError, ValueError, UnicodeError):
            return False, "tool arguments must contain bounded JSON values", None
        error = _validate_json_value(arguments, self.input_schema)
        if error:
            return False, error, None
        if self.argument_type is dict:
            return True, "valid", arguments
        if self.argument_type is None:
            return True, "valid", None
        return True, "valid", arguments.get("query")


def _status(_):
    from core.engine import status
    return status()


def _latest_intel(_):
    from core.intel import latest_intel
    records = latest_intel(50)
    untrusted_records = []
    for record in records:
        item = dict(record)
        item["trust_classification"] = "UNTRUSTED_DATA"
        item["authority"] = "none"
        untrusted_records.append(item)
    return untrusted_records


def _refresh_intel(_):
    from core.intel import refresh_all
    return refresh_all()


def _local_security(_):
    from core.local_defense import local_security_check
    return local_security_check()


def _system_info(_):
    from core.local_defense import local_system_info
    return local_system_info()


def _search(argument):
    from search.service import search_service
    from search.providers import SearchScope
    from search.exceptions import SearchError, ProviderUnavailableError

    query = argument or ""
    scope = None  # Auto-select based on query

    # Parse scope from argument if present
    # Format: "scope:github query" or "scope:nvd CVE-2021-1234"
    if ":" in query:
        parts = query.split(":", 1)
        scope_str = parts[0].lower()
        query = parts[1].strip()

        # Map scope string to SearchScope
        scope_map = {
            "local": SearchScope.LOCAL,
            "github": SearchScope.GITHUB,
            "nvd": SearchScope.NVD,
            "cve": SearchScope.CVE,
            "mitre": SearchScope.MITRE,
            "web": SearchScope.WEB,
        }
        scope = scope_map.get(scope_str)

    try:
        response = search_service.search(
            query=query,
            scope=scope,
            max_results=50,
        )

        # Format results for backward compatibility
        results = {
            "query": query,
            "scope": scope.value if scope else None,
            "total_results": response.total_results,
            "results": [
                {
                    "id": r.result_id,
                    "title": r.title,
                    "content": r.content,
                    "source": r.source,
                    "source_type": r.source_type,
                    "url": r.url,
                    "provenance": r.provenance,
                    "metadata": r.metadata,
                }
                for r in response.results
            ],
        }

        if response.error:
            results["error"] = response.error
        if response.error_type:
            results["error_type"] = response.error_type

        return results
    except ProviderUnavailableError as e:
        return {"error": str(e), "error_type": "provider_unavailable", "query": query}
    except SearchError as e:
        return {"error": str(e), "error_type": e.error_type, "query": query}
    except Exception as e:
        return {"error": str(e), "error_type": "unknown", "query": query}


def _watch(argument):
    from core.db import add_watch, watches
    add_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


def _unwatch(argument):
    from core.db import remove_watch, watches
    remove_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


def _run_project_tests(argument, *, workspace=None, execution_context=None):
    if workspace is None or execution_context is None:
        raise PermissionError("run_project_tests requires the canonical Mission Workspace and ExecutionContext")
    execution_context.assert_active()
    authorization = execution_context.mission_authorization
    authorized_root = str(dict(authorization.workspace_boundary).get("root", "")).strip()
    if not authorized_root or Path(workspace.root).resolve() != Path(authorized_root).expanduser().resolve():
        raise PermissionError("run_project_tests workspace differs from the Owner-authorized Mission root")
    if (
        getattr(workspace, "authorization_snapshot", None) is None
        or workspace.authorization_snapshot.authorization_hash != authorization.authorization_hash
        or str(workspace.mission_id) != execution_context.mission_id
        or str(workspace.request_id) != execution_context.request_id
        or str(workspace.tool_id) != execution_context.tool_id
    ):
        raise PermissionError("run_project_tests Workspace binding is not current for this Mission")
    target = argument or "."
    try:
        if not workspace.resolve(target).is_dir():
            raise ValueError("project directory does not exist")
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("project directory is outside the configured test root") from exc
    mission_timeout = getattr(authorization, "max_duration", 60)
    if isinstance(mission_timeout, bool) or not isinstance(mission_timeout, (int, float)) or not math.isfinite(mission_timeout) or mission_timeout <= 0:
        raise PermissionError("Mission process timeout is invalid")
    workspace_timeout = getattr(getattr(workspace, "policy", None), "max_timeout_seconds", MAX_SANDBOX_PROCESS_SECONDS)
    if isinstance(workspace_timeout, bool) or not isinstance(workspace_timeout, (int, float)) or not math.isfinite(workspace_timeout) or workspace_timeout <= 0:
        raise PermissionError("Workspace process timeout is invalid")
    effective_timeout = min(
        MAX_SANDBOX_PROCESS_SECONDS,
        float(mission_timeout),
        float(workspace_timeout),
    )
    result = workspace.develop(
        ("python3", "-m", "pytest", "-q", "--junitxml=/artifacts/pytest.xml"),
        cwd=target,
        timeout=effective_timeout,
        cancellation_event=execution_context.cancellation_event,
    )
    execution_context.assert_active()
    if execution_context.artifact_store is None:
        raise PermissionError("run_project_tests requires the Mission artifact store")

    from agent.intelligence_layer.artifacts import ArtifactKind, ArtifactSensitivity, ArtifactValidation
    artifact_refs: list[dict[str, Any]] = []
    scope_values = tuple(
        value for value in (
            str(execution_context.scope_snapshot.get("scope_snapshot_id", "")),
            str(execution_context.scope_snapshot.get("target_id", "")),
        ) if value
    )
    command_digest = hashlib.sha256(
        json.dumps(result.command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    workspace_digest = hashlib.sha256(str(Path(workspace.root).resolve()).encode("utf-8")).hexdigest()
    for captured in result.artifacts:
        media_type = mimetypes.guess_type(captured.filename)[0] or "application/octet-stream"
        record = execution_context.artifact_store.put(
            owner_identity_ref=execution_context.owner_identity,
            mission_id=execution_context.mission_id,
            task_id=str(execution_context.execution_fence.task_id),
            kind=ArtifactKind.REPORT,
            content=captured.content,
            filename=captured.filename,
            media_type=media_type,
            sensitivity=ArtifactSensitivity.SENSITIVE,
            validation=ArtifactValidation.UNVALIDATED,
            confidence=0.0,
            scope=scope_values,
            provenance={
                "source": "sandboxed-project-test-runner",
                "tool_id": execution_context.tool_id,
                "execution_id": execution_context.execution_id,
                "command_sha256": command_digest,
                "workspace_root_sha256": workspace_digest,
                "relative_path_sha256": hashlib.sha256(captured.relative_path.encode("utf-8", errors="replace")).hexdigest(),
            },
            metadata={"trust": "untrusted_data", "authority": "none", "sandbox_backend": result.sandbox_backend},
        )
        artifact_refs.append({
            "artifact_id": record.artifact_id,
            "sha256": record.content_sha256,
            "size_bytes": record.size_bytes,
            "kind": record.kind.value,
            "validation": record.validation.value,
        })

    from .web_research import redact_specialist_text
    raw_output = (result.stdout + result.stderr)[-16_000:]
    safe_output = redact_specialist_text(raw_output)[-4_000:]
    evidence_payload = {
        "claim": "Bounded project tests ran inside a network-isolated OS sandbox",
        "source": "sandboxed-process:run_project_tests",
        "evidence": {
            "record_type": "UNTRUSTED_SANDBOX_PROCESS_RESULT",
            "trust": "untrusted_data",
            "authority": "none",
            "sandbox_backend": result.sandbox_backend,
            "network": "disabled",
            "workspace_mode": "read_only",
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "output_sha256": hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest(),
            "artifact_refs": artifact_refs,
            "artifact_capture_truncated": result.artifact_capture_truncated,
        },
        "verification": "observed",
        "confidence": 5,
        "request_id": execution_context.request_id,
    }
    evidence = execution_context.evidence_store.append(
        evidence_payload, execution_fence=execution_context.execution_fence,
    )
    return {
        "ok": result.ok,
        "timed_out": result.timed_out,
        "cancelled": result.cancelled,
        "returncode": result.exit_code,
        "output": safe_output,
        "trust": "untrusted_data",
        "authority": "none",
        "sandbox_backend": result.sandbox_backend,
        "network": "disabled",
        "workspace_mode": "read_only",
        "artifact_refs": artifact_refs,
        "artifact_capture_truncated": result.artifact_capture_truncated,
        "evidence_ref": {
            "evidence_id": str(evidence.get("evidence_id", "")),
            "sequence": int(evidence.get("sequence", 0)),
            "current_hash": str(evidence.get("current_hash", "")),
        },
    }


def _red_team_assess(argument):
    from reasoning.red_team import assess
    return assess(argument).to_dict()


def _scoped_http_probe(argument):
    """Metadata-only bounded probe placeholder; network execution comes after Scope Firewall."""
    return {"ok": True, "operation": "scoped_http_probe", "url": argument, "note": "scope-authorized observation placeholder"}


def _accepts_keyword(handler: Callable[..., Any], name: str) -> bool:
    try:
        parameters = inspect.signature(handler).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


_BROWSER_SESSION_ID = {"type": "string", "minLength": 35, "maxLength": 35, "pattern": "^bs_[0-9a-f]{32}$"}
_BROWSER_SELECTOR = {"type": "string", "minLength": 1, "maxLength": 256}
_BROWSER_URL = {"type": "string", "minLength": 8, "maxLength": 2048}
_BROWSER_OPERATIONS = ["open", "navigate", "extract", "links", "inspect", "structured_extract", "screenshot", "download", "close"]
_BROWSER_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string", "enum": _BROWSER_OPERATIONS},
        "session_id": _BROWSER_SESSION_ID,
        "url": _BROWSER_URL,
        "selector": _BROWSER_SELECTOR,
        "max_items": {"type": "integer", "minimum": 1, "maximum": 30},
        "max_chars": {"type": "integer", "minimum": 1, "maximum": 6000},
        "attributes": {"type": "array", "maxItems": 9, "items": {"type": "string", "enum": ["alt", "aria-label", "class", "href", "id", "name", "role", "title", "type"]}},
    },
    "required": ["operation"],
    "additionalProperties": False,
}
_BROWSER_FILL_SCHEMA = {
    "type": "object",
    "properties": {"session_id": _BROWSER_SESSION_ID, "selector": _BROWSER_SELECTOR, "value": {"type": "string", "maxLength": 512}},
    "required": ["session_id", "selector", "value"],
    "additionalProperties": False,
}

_WEB_RESEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "maxLength": 512},
        "max_results": {"type": "integer", "minimum": 1, "maximum": 3},
    },
    "required": ["query"],
    "additionalProperties": False,
}


_MCP_SERVER_ID = {"type": "string", "minLength": 36, "maxLength": 36, "pattern": "^mcp_[0-9a-f]{32}$"}
_MCP_TOOL_NAME = {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"}
_MCP_DISCOVER_SCHEMA = {
    "type": "object",
    "properties": {"server_id": _MCP_SERVER_ID, "tool_name": _MCP_TOOL_NAME},
    "required": ["server_id"],
    "additionalProperties": False,
}
_MCP_INVOKE_SCHEMA = {
    "type": "object",
    "properties": {
        "server_id": _MCP_SERVER_ID,
        "tool_name": _MCP_TOOL_NAME,
        "arguments": {"type": "object", "additionalProperties": True},
    },
    "required": ["server_id", "tool_name", "arguments"],
    "additionalProperties": False,
}

from .browser import browser_fill, browser_read
from .mcp_client import mcp_discover, mcp_invoke
from .web_research import web_research


def _access_metadata_valid(spec: ToolSpec) -> bool:
    label_pattern = r"[a-z][a-z0-9_.-]{0,63}"
    if not isinstance(spec.description, str) or not spec.description or len(spec.description) > 512:
        return False
    if not isinstance(spec.version, str) or not spec.version or len(spec.version) > 32:
        return False
    if not isinstance(spec.effect_provider, str) or len(spec.effect_provider) > 128:
        return False
    if any(not isinstance(value, bool) for value in (
        spec.idempotency_supported, spec.execution_context_required,
        spec.allow_custom_input_schema, spec.scope_rate_deferred, spec.workspace_scope_required,
    )):
        return False
    if not isinstance(spec.risk_class, str) or spec.risk_class not in VALID_RISK_CLASSES:
        return False
    for value, choices in (
        (spec.network_access, VALID_NETWORK_ACCESS),
        (spec.filesystem_access, VALID_FILESYSTEM_ACCESS),
        (spec.process_access, VALID_PROCESS_ACCESS),
        (spec.credential_access, VALID_CREDENTIAL_ACCESS),
        (spec.rate_limit, VALID_RATE_LIMITS),
    ):
        if not isinstance(value, str) or value not in choices:
            return False
    if not isinstance(spec.timeout, int) or isinstance(spec.timeout, bool) or not 1 <= spec.timeout <= 600:
        return False
    if not isinstance(spec.evidence_requirements, tuple) or not 1 <= len(spec.evidence_requirements) <= 16:
        return False
    if any(not isinstance(item, str) or not re.fullmatch(label_pattern, item) for item in spec.evidence_requirements):
        return False
    if len(set(spec.evidence_requirements)) != len(spec.evidence_requirements):
        return False
    if not isinstance(spec.scope_requirements, tuple) or len(spec.scope_requirements) > 16:
        return False
    if any(not isinstance(item, str) or not re.fullmatch(label_pattern, item) for item in spec.scope_requirements):
        return False
    if len(set(spec.scope_requirements)) != len(spec.scope_requirements):
        return False
    if any(not isinstance(value, bool) for value in (spec.requires_owner, spec.owner_only, spec.scope_required)):
        return False
    if any(not isinstance(value, dict) for value in (spec.input_schema, spec.output_schema)):
        return False
    if spec.scope_required and (not spec.requires_owner or not spec.scope_requirements):
        return False
    if not spec.scope_required and not spec.workspace_scope_required and spec.scope_requirements:
        return False
    if spec.workspace_scope_required and (
        not spec.requires_owner
        or not spec.execution_context_required
        or "owner_mission_workspace_root" not in spec.scope_requirements
    ):
        return False
    if spec.network_access.startswith("scope_pinned_") and not spec.scope_required:
        return False
    if spec.process_access != "none" and spec.risk_class != "bounded-exec":
        return False
    if spec.filesystem_access == "host_fs_via_process" and (
        spec.risk_class != "bounded-exec" or spec.process_access != "workspace_process_unisolated"
    ):
        return False
    if spec.filesystem_access == "workspace_read_only_artifact_write" and (
        spec.risk_class != "bounded-exec"
        or spec.process_access != "workspace_process_sandboxed"
        or not spec.workspace_scope_required
        or not spec.execution_context_required
    ):
        return False
    if spec.network_access == "host_process_unscoped" and (
        spec.risk_class != "bounded-exec" or spec.process_access != "workspace_process_unisolated"
    ):
        return False
    if spec.credential_access != "none" and not spec.requires_owner:
        return False
    return True


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not isinstance(spec.name, str) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        scope_namespace = spec.name.split(".", 1)[0]
        scope_namespaces = {"bugbounty", "recon", "research", "evidence", "browser", "mcp", "report"}
        if (
            not spec.description
            or not _access_metadata_valid(spec)
            or not isinstance(spec.parallel_execution_safe, bool)
            or not callable(spec.handler)
            or (spec.owner_only and not spec.requires_owner)
            or (scope_namespace in scope_namespaces and not spec.scope_required)
            or (spec.effect_provider and (not spec.effect_provider.strip() or len(spec.effect_provider) > 128))
            or (spec.risk_class in {"network-read", "state-write", "bounded-exec"} and not spec.effect_provider)
            or (spec.idempotency_supported and (not spec.effect_provider or not _accepts_keyword(spec.handler, "idempotency_key")))
            or (not isinstance(spec.execution_context_required, bool))
            or (not isinstance(spec.allow_custom_input_schema, bool))
            or (spec.allow_custom_input_schema and spec.argument_type is not dict)
            or (spec.execution_context_required and (not spec.requires_owner or not _accepts_keyword(spec.handler, "execution_context")))
            or (not isinstance(spec.scope_rate_deferred, bool))
            or (spec.scope_url_argument is not None and (
                not spec.scope_required
                or spec.argument_type is not dict
                or not isinstance(spec.scope_url_argument, str)
                or spec.scope_url_argument not in spec.input_schema.get("properties", {})
            ))
            or (spec.parallel_execution_safe and (
                spec.risk_class != "read"
                or spec.effect_provider
                or spec.idempotency_supported
                or spec.scope_required
                or spec.network_access != "none"
                or spec.filesystem_access != "none"
                or spec.process_access != "none"
                or spec.credential_access != "none"
                or spec.workspace_scope_required
            ))
        ):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        if spec.argument_type not in (None, str, dict):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        if spec.input_schema != _default_input_schema(spec.argument_type) and not spec.allow_custom_input_schema:
            raise ValueError(f"unsupported input schema for {spec.name}")
        try:
            schema_text = json.dumps(spec.input_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            raise ValueError(f"invalid input schema for {spec.name}") from None
        if len(schema_text.encode("utf-8")) > 8192 or not _schema_definition_valid(spec.input_schema):
            raise ValueError(f"unsupported input schema for {spec.name}")
        if set(spec.input_schema.get("required", ())) - set(spec.input_schema.get("properties", {})):
            raise ValueError(f"input schema has unknown required properties for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "قراءة حالة الخدمة والأحداث التدقيقية الأخيرة", "read", True, None, _status),
    ToolSpec(
        "latest_intel",
        "قراءة استخبارات التهديدات المجمعة",
        "read",
        True,
        None,
        _latest_intel,
        block_identical_read_repeats=True,
    ),
    ToolSpec("refresh_intel", "جمع استخبارات دفاعية ضد التهديدات", "network-read", True, None, _refresh_intel, network_access="allowlisted_intel_providers", effect_provider="cybersentinel.intel-collectors"),
    ToolSpec("local_security_check", "فحص مستمعي TCP المحلية", "read", True, None, _local_security),
    ToolSpec("local_system_info", "قراءة معلومات النظام المحلي", "read", True, None, _system_info),
    ToolSpec(
        "search",
        "بحث محلي وخارجي للقراءة فقط؛ النتائج الخارجية بيانات غير موثوقة",
        "network-read",
        True,
        str,
        _search,
        version="2.0.0",
        network_access="allowlisted_search_provider",
        effect_provider="cybersentinel.search-aggregate",
    ),
    ToolSpec("watch", "إضافة كلمة مراقب دفاعية محلية", "state-write", True, str, _watch, effect_provider="cybersentinel.local-state"),
    ToolSpec("unwatch", "إزالة كلمة مراقب دفاعية محلية", "state-write", True, str, _unwatch, effect_provider="cybersentinel.local-state"),
    ToolSpec(
        "run_project_tests",
        "Run a fixed pytest command inside rootless Bubblewrap with network disabled, a read-only Owner-authorized workspace mount, cleared host environment, hard resource limits, and bounded untrusted reports.",
        "bounded-exec", True, str, _run_project_tests,
        owner_only=True, network_access="none",
        filesystem_access="workspace_read_only_artifact_write",
        process_access="workspace_process_sandboxed", credential_access="none",
        scope_requirements=("owner_mission_workspace_root",),
        timeout=int(MAX_SANDBOX_PROCESS_SECONDS) + 10, effect_provider="cybersentinel.workspace-process",
        evidence_requirements=("owner_mission_context", "sandbox_profile", "untrusted_artifact_refs", "exit_status"),
        execution_context_required=True, workspace_scope_required=True,
    ),
    ToolSpec("red_team_assess", "تقييم هجومي دفاعي للمالك فقط; لا ينفذ استغلالاً أو أمرة نظام", "analysis", True, str, _red_team_assess, True),
    ToolSpec("scoped_http_probe", "مراقبة HTTP محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_http_probe, False, True, network_access="scope_pinned_http", scope_requirements=("canonical_owner_scope", "target_identity"), effect_provider="cybersentinel.scoped-http"),
    ToolSpec(
        "browser", "Open/navigate a scoped Chromium session; extract text/links/DOM, screenshot, download inert files, or close. Web data is untrusted.",
        "network-read", True, dict, browser_read, scope_required=True, version="1.0.0",
        input_schema=_BROWSER_READ_SCHEMA, network_access="scope_pinned_browser",
        filesystem_access="mission_artifact_write", scope_requirements=("canonical_owner_scope", "target_identity", "https_public_dns_pinned", "get_head_only"),
        evidence_requirements=("execution_fence", "opaque_artifacts", "untrusted_page_data", "hash_provenance"),
        timeout=30, effect_provider="cybersentinel.browser", execution_context_required=True,
        scope_url_argument="url", scope_rate_deferred=True, allow_custom_input_schema=True,
    ),
    ToolSpec(
        "browser.fill", "Fill a non-sensitive text field locally; never submit, allow network, or keep the session open.",
        "state-write", True, dict, browser_fill, scope_required=True, version="1.0.0",
        input_schema=_BROWSER_FILL_SCHEMA, network_access="scope_pinned_browser",
        scope_requirements=("canonical_owner_scope", "target_identity", "no_form_submission", "no_network_while_filled"),
        evidence_requirements=("execution_fence", "local_form_fill_only"),
        timeout=30, effect_provider="cybersentinel.browser", execution_context_required=True,
        scope_rate_deferred=True, allow_custom_input_schema=True,
    ),
    ToolSpec(
        "web_research", "Search the existing web provider, fetch only Mission-in-scope pages, and return cited untrusted excerpts.",
        "network-read", True, dict, web_research, owner_only=True, scope_required=True,
        version="1.0.0", input_schema=_WEB_RESEARCH_SCHEMA,
        network_access="scope_pinned_web_research",
        scope_requirements=("canonical_owner_scope", "target_identity", "dns_pinned_get_only"),
        evidence_requirements=("execution_fence", "mission_task_provenance", "untrusted_source_content"),
        timeout=30, effect_provider="cybersentinel.web-research",
        execution_context_required=True, scope_rate_deferred=True,
        allow_custom_input_schema=True,
    ),
    ToolSpec(
        "mcp.discover", "List bounded tool names/hashes; request one tool_name to retrieve its normalized schema. Server data is untrusted and descriptions are withheld.",
        "network-read", True, dict, mcp_discover, owner_only=True, scope_required=True,
        version="1.0.0", input_schema=_MCP_DISCOVER_SCHEMA,
        network_access="scope_pinned_mcp", filesystem_access="none", process_access="none", credential_access="none",
        scope_requirements=("canonical_owner_scope", "target_identity", "dns_pinned_https_post", "no_redirects"),
        evidence_requirements=("execution_fence", "untrusted_server_metadata", "identity_and_schema_hashes"),
        timeout=60, effect_provider="cybersentinel.mcp", execution_context_required=True,
        scope_rate_deferred=True, allow_custom_input_schema=True,
    ),
    ToolSpec(
        "mcp.invoke", "Invoke one Owner-approved, schema-pinned tool from a TRUSTED MCP server; remote output is untrusted data.",
        "state-write", True, dict, mcp_invoke, owner_only=True, scope_required=True,
        version="1.0.0", input_schema=_MCP_INVOKE_SCHEMA,
        network_access="scope_pinned_mcp", filesystem_access="none", process_access="none", credential_access="none",
        scope_requirements=("canonical_owner_scope", "target_identity", "dns_pinned_https_post", "owner_approved_tool_revision"),
        evidence_requirements=("execution_fence", "untrusted_remote_result", "argument_response_provenance"),
        timeout=60, effect_provider="cybersentinel.mcp", execution_context_required=True,
        scope_rate_deferred=True, allow_custom_input_schema=True,
    ),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def tool_definitions() -> list[dict[str, Any]]:
    """Build provider-neutral canonical tool metadata for local context and audit."""
    definitions: list[dict[str, Any]] = []
    for spec in REGISTRY.values():
        parameters = deepcopy(spec.input_schema)
        definitions.append({
            "name": spec.name,
            "description": spec.description[:512],
            "risk_class": spec.risk_class,
            "owner_required": spec.requires_owner,
            "parameters": parameters,
            **spec.metadata(),
        })
    return definitions


def model_tool_definitions(names: list[str] | tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Build detached OpenAI-compatible schemas from canonical ToolSpecs."""
    if names is None:
        specs = tuple(REGISTRY.values())
    else:
        if not isinstance(names, (list, tuple)):
            raise ValueError("tool names must be a list or tuple")
        seen: set[str] = set()
        selected = []
        for name in names:
            if not isinstance(name, str) or not name or name in seen:
                raise ValueError("tool names must be nonempty, unique strings")
            spec = REGISTRY.get(name)
            if spec is None:
                raise ValueError("unknown registered tool")
            seen.add(name)
            selected.append(spec)
        specs = tuple(selected)

    return [
        {
            "type": "function",
            "function": {
                "name": spec.name,
                "description": spec.description[:512],
                "parameters": deepcopy(spec.input_schema),
            },
        }
        for spec in specs
    ]


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def _scope_urls_for_tool(spec: ToolSpec, argument: Any, scope_context: dict[str, Any]) -> list[str]:
    urls = [str(scope_context["url"])]
    if spec.scope_url_argument:
        candidate = argument.get(spec.scope_url_argument) if isinstance(argument, dict) else None
        if candidate is not None:
            if not isinstance(candidate, str) or not candidate:
                raise PermissionError("a canonical in-scope URL argument is required")
            if candidate not in urls:
                urls.append(candidate)
    elif isinstance(argument, str) and "://" in argument and argument not in urls:
        urls.append(argument)
    return urls


def _delegated_network_hosts_for_tool(spec: ToolSpec, argument: Any, scope_context: dict[str, Any]) -> tuple[str, ...]:
    """Return exact canonical hosts touched by a scope-bound delegated tool."""
    if not spec.scope_required or not isinstance(scope_context, dict):
        return ()
    try:
        from security.scope import canonical_host

        urls = _scope_urls_for_tool(spec, argument, scope_context)
        redirects = scope_context.get("redirect_chain", ())
        if not isinstance(redirects, (list, tuple)) or any(not isinstance(item, str) for item in redirects):
            return ()
        urls.extend(item for item in redirects if item not in urls)
        hosts: list[str] = []
        for value in urls:
            parts = urlsplit(value)
            if (
                parts.scheme.lower() not in {"http", "https"}
                or not parts.hostname
                or parts.username is not None
                or parts.password is not None
            ):
                return ()
            hosts.append(canonical_host(parts.hostname))
        return tuple(dict.fromkeys(hosts))
    except (KeyError, TypeError, ValueError, PermissionError):
        return ()


def _delegated_resource_access_allowed(
    spec,
    snapshot,
    delegated_scope,
    workspace=None,
    evidence_store=None,
    *,
    argument: Any = None,
    scope_context: dict[str, Any] | None = None,
) -> bool:
    """Allow canonical Owner-granted resource profiles inside a task scope only."""
    if (
        spec.name not in set(snapshot.allowed_tools)
        or spec.name not in delegated_scope.allowed_tools
        or spec.name not in delegated_scope.allowed_actions
        or spec.credential_access != "none"
    ):
        return False

    safe_network = {"scope_pinned_browser", "scope_pinned_http", "scope_pinned_mcp"}
    network_capable = spec.network_access != "none" or spec.risk_class == "network-read"
    if network_capable:
        if spec.network_access not in safe_network or not spec.scope_required:
            return False
        hosts = _delegated_network_hosts_for_tool(spec, argument, scope_context or {})
        if not hosts:
            return False
        try:
            from security.scope import canonical_host

            granted_hosts = {canonical_host(item) for item in delegated_scope.allowed_networks}
        except (TypeError, ValueError):
            return False
        if any(host not in granted_hosts for host in hosts):
            return False

    workspace_root = str(dict(snapshot.workspace_boundary).get("root", "") or "").strip()
    if spec.filesystem_access == "workspace_read_only_artifact_write":
        if (
            not spec.workspace_scope_required
            or not spec.execution_context_required
            or spec.process_access != "workspace_process_sandboxed"
            or not bool(getattr(evidence_store, "require_execution_fence", False))
            or not workspace_root
            or not delegated_scope.workspace_root
            or Path(delegated_scope.workspace_root).expanduser().resolve() != Path(workspace_root).expanduser().resolve()
            or workspace is None
            or Path(str(getattr(workspace, "root", ""))).expanduser().resolve() != Path(workspace_root).expanduser().resolve()
        ):
            return False
    elif spec.filesystem_access == "mission_artifact_write":
        if (
            not spec.execution_context_required
            or spec.process_access != "none"
            or not bool(getattr(evidence_store, "require_execution_fence", False))
        ):
            return False
    elif spec.filesystem_access != "none":
        return False

    if spec.process_access == "workspace_process_sandboxed":
        if spec.filesystem_access != "workspace_read_only_artifact_write":
            return False
    elif spec.process_access != "none":
        return False

    return True


def execute(name: str, argument: Any = None, *, timeout: float | None = None, max_result_chars: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, mission_authorization_version: int | None = None, owner_authorization: Any = None, owner_authorization_record: dict[str, Any] | None = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_fence: Any = None, execution_id: str | None = None, event_bus: Any = None, hook_registry: Any = None, delegation_scope: Any = None, scope_ref: str | None = None):
    import math

    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be a positive finite number")
    if max_result_chars is not None and (isinstance(max_result_chars, bool) or not isinstance(max_result_chars, int) or max_result_chars < 128):
        raise ValueError("max_result_chars must be an integer of at least 128")
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    spec_timeout = float(spec.timeout)
    if not math.isfinite(spec_timeout) or spec_timeout <= 0:
        raise ValueError("tool timeout must be a positive finite number")
    limit = spec_timeout if timeout is None else min(float(timeout), spec_timeout)
    valid, reason, argument = spec.validate_input(argument)
    if not valid:
        raise ValueError(reason)
    if (mission_id is not None or mission_authorization is not None or spec.effect_provider) and execution_fence is None:
        from agent.execution_fence import ExecutionFenceError
        raise ExecutionFenceError(
            "mission-bound tool dispatch requires an execution fence; effect-capable tool dispatch requires one as well"
        )
    if spec.effect_provider and mission_authorization is None:
        from agent.execution_fence import ExecutionFenceError
        raise ExecutionFenceError("effect-capable tool dispatch requires a mission authorization snapshot")
    decision_valid = False
    if authorization_decision is not None:
        from security.authorization_context import AuthorizationDecision
        decision_valid = bool(request_id) and isinstance(authorization_decision, AuthorizationDecision) and authorization_decision.is_valid_for(name, argument, request_id)
        if not decision_valid:
            raise PermissionError("invalid or argument-mismatched AuthorizationDecision")
    if spec.owner_only and not decision_valid:
        raise PermissionError("AuthorizationDecision required for this tool")
    if spec.scope_required and not decision_valid:
        raise PermissionError("scope-bound AuthorizationDecision required")
    if spec.scope_required:
        if not isinstance(scope_context, dict):
            raise PermissionError("scope context required")
        required = {"program_id", "target_id", "scope_snapshot_id", "url"}
        if not required.issubset(scope_context):
            raise PermissionError("incomplete scope context")
        from security.scope_resolver import resolve
        for checked_url in _scope_urls_for_tool(spec, argument, scope_context):
            decision = resolve(
                scope_context["scope_snapshot_id"],
                scope_context["target_id"],
                checked_url,
                method=scope_context.get("method", "GET"),
                expected_program_id=scope_context["program_id"],
                redirect_chain=scope_context.get("redirect_chain", []),
                consume_rate=not spec.scope_rate_deferred,
            )
            if not decision.allowed:
                raise PermissionError("scope denied: " + decision.reason)
    snapshot = None
    delegated_scope = None
    if delegation_scope is not None and mission_authorization is None:
        raise PermissionError("delegated tool dispatch requires a current mission authorization snapshot")
    if mission_authorization is not None:
        from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
        snapshot = mission_authorization if isinstance(mission_authorization, MissionAuthorizationSnapshot) else MissionAuthorizationSnapshot.from_dict(dict(mission_authorization))
        if spec.execution_context_required and (
            isinstance(mission_authorization_version, bool)
            or not isinstance(mission_authorization_version, int)
            or mission_authorization_version != snapshot.version
        ):
            raise PermissionError("ExecutionContext-bound dispatch requires the current persisted Mission authorization version")
        allowed, reason = snapshot.check(action=name, tool_id=name, target_identity=target_identity or snapshot.target_identity, at=None)
        if not allowed:
            code = "authorization_expired" if reason == "authorization snapshot expired or not active" else "authorization_denied"
            raise MissionAuthorizationError("mission authorization blocked: " + reason, code=code)
        if delegation_scope is not None:
            from agent.intelligence_layer.models import DelegationScope

            if not isinstance(delegation_scope, DelegationScope):
                raise PermissionError("delegated tool dispatch requires a typed DelegationScope")
            delegated_scope = delegation_scope
            delegated_scope.validate_current(snapshot, authorization_version=snapshot.version)
            if not delegated_scope.is_within_owner_authorization(snapshot):
                raise PermissionError("delegated grant exceeds the Owner authorization snapshot")
            delegated_scope_ref = str(scope_ref or (delegated_scope.scope[0] if delegated_scope.scope else ""))
            if not delegated_scope.permits(
                tool=name,
                action=name,
                scope_ref=delegated_scope_ref,
                target_identity=target_identity or snapshot.target_identity,
            ):
                raise PermissionError("tool, action, target, or scope exceeds task delegation")
            if not _delegated_resource_access_allowed(
                spec, snapshot, delegated_scope, workspace, evidence_store,
                argument=argument, scope_context=scope_context,
            ):
                raise PermissionError("delegated scope does not grant the declared tool resource access")
    if spec.workspace_scope_required:
        if snapshot is None or workspace is None:
            raise PermissionError("tool requires the canonical Owner-authorized Mission workspace")
        from workspace import Workspace
        if not isinstance(workspace, Workspace):
            raise PermissionError("tool requires a governed Workspace instance")
        authorized_root = str(dict(snapshot.workspace_boundary).get("root", "")).strip()
        if not authorized_root or Path(workspace.root).resolve() != Path(authorized_root).expanduser().resolve():
            raise PermissionError("Workspace root differs from the Owner-authorized Mission boundary")
        if name == "run_project_tests":
            sandbox_unavailable = workspace.process_sandbox_unavailable_reason()
            if sandbox_unavailable:
                from workspace.environment import ProcessSandboxUnavailable
                raise ProcessSandboxUnavailable(sandbox_unavailable)
    if execution_fence is not None:
        execution_fence.assert_dispatch(
            mission_id=str(mission_id or ""),
            request_id=str(request_id or ""),
            execution_id=str(execution_id or ""),
            authorization_snapshot=mission_authorization,
        )
    cancellation_event = threading.Event()
    tool_execution_context = None
    if spec.execution_context_required:
        from core.context import ExecutionContext
        from security.authorization_context import AuthorizationContext
        if (
            not isinstance(owner_authorization, AuthorizationContext)
            or not isinstance(owner_authorization_record, dict)
            or snapshot is None
            or evidence_store is None
            or execution_fence is None
            or not mission_id
            or not execution_id
            or not request_id
            or not isinstance(target_identity, str)
        ):
            raise PermissionError("tool requires the canonical Owner/Mission ExecutionContext")
        artifact_store = None
        if spec.filesystem_access in {"mission_artifact_write", "workspace_read_only_artifact_write"}:
            if not bool(getattr(evidence_store, "require_execution_fence", False)):
                raise PermissionError("artifact writes require the strict fenced Mission evidence store")
            from agent.intelligence_layer.artifacts import ArtifactStore
            artifact_path = Path(str(evidence_store.mission_store.db_path)).with_name("artifacts.sqlite3")
            artifact_store = ArtifactStore(artifact_path)
        try:
            authentication_method = str(owner_authorization.owner_evidence.to_dict().get("authentication_method", "username_password"))
        except Exception:
            authentication_method = "username_password"
        tool_execution_context = ExecutionContext(
            request_id=str(request_id),
            owner_authenticated=True,
            owner_identity=str(snapshot.owner_identity),
            policy_snapshot=str(owner_authorization.policy_fingerprint),
            owner_session_id=owner_authorization.session_id,
            authentication_method=authentication_method,
            policy_snapshot_details={"policy_fingerprint": str(owner_authorization.policy_fingerprint)},
            scope_snapshot=dict(scope_context or {}),
            authorization_context=dict(owner_authorization_record),
            authorization_decisions=(authorization_decision.to_dict(),),
            mission_id=str(mission_id),
            execution_id=str(execution_id),
            target_identity=target_identity,
            tool_id=name,
            tool_argument=argument,
            owner_authorization=owner_authorization,
            mission_authorization=snapshot,
            mission_authorization_version=mission_authorization_version,
            authorization_decision=authorization_decision,
            execution_fence=execution_fence,
            evidence_store=evidence_store,
            artifact_store=artifact_store,
            cancellation_event=cancellation_event,
            deadline_monotonic=time.monotonic() + limit,
            delegation_scope=delegated_scope,
        )
        tool_execution_context.assert_active()
    event_binding = ""
    if event_bus is not None or hook_registry is not None:
        from agent.intelligence_layer.events import EventBus, HookPhase, HookRegistry, IntelligenceEventType

        if event_bus is not None and not isinstance(event_bus, EventBus):
            raise TypeError("event_bus must be an EventBus")
        if hook_registry is not None and not isinstance(hook_registry, HookRegistry):
            raise TypeError("hook_registry must be a HookRegistry")
        if snapshot is None or not mission_id or not snapshot.owner_identity:
            raise PermissionError("mission-bound hooks and event records require an Owner authorization snapshot")
        event_binding = hashlib.sha256(
            "\0".join((str(snapshot.owner_identity), str(mission_id), str(request_id or ""), str(execution_id or ""), spec.tool_id)).encode("utf-8")
        ).hexdigest()
        argument_sha256 = hashlib.sha256(
            json.dumps(argument, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        ).hexdigest()
        if hook_registry is not None:
            hook_result = hook_registry.run(
                owner_identity_ref=str(snapshot.owner_identity),
                mission_id=str(mission_id),
                phase=HookPhase.BEFORE_TOOL,
                correlation_id=str(execution_id or request_id or event_binding),
                data={"tool_id": spec.tool_id, "tool_version": spec.version, "risk_class": spec.risk_class, "argument_sha256": argument_sha256},
            )
            if not hook_result.allowed:
                raise PermissionError("tool dispatch blocked by current mission policy hook")
        if authorization_decision is not None and not authorization_decision.is_valid_for(name, argument, str(request_id or "")):
            raise PermissionError("AuthorizationDecision expired or changed before tool dispatch")
        if spec.scope_required:
            if not isinstance(scope_context, dict):
                raise PermissionError("scope context required")
            for checked_url in _scope_urls_for_tool(spec, argument, scope_context):
                decision = resolve(
                    scope_context["scope_snapshot_id"],
                    scope_context["target_id"],
                    checked_url,
                    method=scope_context.get("method", "GET"),
                    expected_program_id=scope_context["program_id"],
                    redirect_chain=scope_context.get("redirect_chain", []),
                    consume_rate=not spec.scope_rate_deferred,
                )
                if not decision.allowed:
                    raise PermissionError("scope denied before tool dispatch: " + decision.reason)
        allowed, reason = snapshot.check(
            action=name,
            tool_id=name,
            target_identity=target_identity or snapshot.target_identity,
            at=None,
        )
        if not allowed:
            code = "authorization_expired" if reason == "authorization snapshot expired or not active" else "authorization_denied"
            raise MissionAuthorizationError("mission authorization blocked before tool dispatch: " + reason, code=code)
        if delegated_scope is not None:
            delegated_scope.validate_current(snapshot)
            if not delegated_scope.permits(
                tool=name,
                action=name,
                scope_ref=str(scope_ref or (delegated_scope.scope[0] if delegated_scope.scope else "")),
                target_identity=target_identity or snapshot.target_identity,
            ):
                raise PermissionError("task delegation changed before tool dispatch")
        if event_bus is not None:
            event_bus.publish(
                owner_identity_ref=str(snapshot.owner_identity),
                mission_id=str(mission_id),
                event_type=IntelligenceEventType.TASK_STARTED,
                idempotency_key=f"task-started:{event_binding}",
                request_id=str(request_id or ""),
                task_id=str(execution_id or ""),
                payload={"tool_id": spec.tool_id, "tool_version": spec.version, "phase": "pre-dispatch"},
            )
            event_bus.publish(
                owner_identity_ref=str(snapshot.owner_identity),
                mission_id=str(mission_id),
                event_type=IntelligenceEventType.TOOL_CALLED,
                idempotency_key=f"tool-called:{event_binding}",
                request_id=str(request_id or ""),
                task_id=str(execution_id or ""),
                payload={"tool_id": spec.tool_id, "tool_version": spec.version, "risk_class": spec.risk_class, "argument_sha256": argument_sha256, "phase": "pre-dispatch"},
            )
        if execution_fence is not None:
            execution_fence.assert_dispatch(
                mission_id=str(mission_id or ""),
                request_id=str(request_id or ""),
                execution_id=str(execution_id or ""),
                authorization_snapshot=mission_authorization,
            )
    effect_ledger = None
    effect = None
    dispatch_id = ""
    if execution_fence is not None and spec.effect_provider:
        from agent.external_effects import ExternalEffectLedger

        if argument is None or isinstance(argument, str):
            argument_bytes = (argument or "").encode("utf-8")
        else:
            argument_bytes = json.dumps(argument, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        argument_sha256 = hashlib.sha256(argument_bytes).hexdigest()
        effect_context = {
            "target_identity": str(target_identity or (snapshot.target_identity if snapshot is not None else "")),
            "scope_context": scope_context if isinstance(scope_context, dict) else {},
            "workspace_boundary": dict(snapshot.workspace_boundary) if snapshot is not None else {},
            "network_boundary": dict(snapshot.network_boundary) if snapshot is not None else {},
            "credential_boundary": dict(snapshot.credential_boundary) if snapshot is not None else {},
        }
        effect_context_sha256 = hashlib.sha256(
            json.dumps(
                effect_context,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        fingerprint_value = {
            "tool_id": spec.tool_id,
            "version": spec.version,
            "argument_sha256": argument_sha256,
            "effect_context_sha256": effect_context_sha256,
        }
        operation_fingerprint = hashlib.sha256(
            json.dumps(fingerprint_value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        effect_ledger = ExternalEffectLedger(execution_fence.queue.db_path)
        effect = effect_ledger.reserve(
            execution_fence,
            operation=spec.tool_id,
            operation_fingerprint=operation_fingerprint,
            argument_sha256=argument_sha256,
            provider=spec.effect_provider,
            idempotency_supported=spec.idempotency_supported,
            authorization_snapshot=mission_authorization,
        )
        dispatch_id = uuid.uuid4().hex
    elif spec.idempotency_supported:
        from agent.execution_fence import ExecutionFenceError
        raise ExecutionFenceError("provider idempotency requires a fenced effect reservation")

    def invoke_handler(*, workspace_context=None):
        from agent.execution_fence import ExecutionFenceError
        from agent.external_effects import EffectRecoveryRequired, EffectState

        if execution_fence is not None:
            execution_fence.assert_dispatch(
                mission_id=str(mission_id or ""),
                request_id=str(request_id or ""),
                execution_id=str(execution_id or ""),
                authorization_snapshot=mission_authorization,
            )
        if tool_execution_context is not None:
            tool_execution_context.assert_active()
        if effect is not None:
            effect_ledger.mark_dispatched(
                effect.effect_id,
                execution_fence,
                dispatch_id=dispatch_id,
                authorization_snapshot=mission_authorization,
            )
        handler_kwargs = {}
        if spec.workspace_scope_required:
            handler_kwargs["workspace"] = workspace_context
        if spec.idempotency_supported:
            handler_kwargs["idempotency_key"] = effect.idempotency_key
        if tool_execution_context is not None:
            tool_execution_context.assert_active()
            handler_kwargs["execution_context"] = tool_execution_context
        try:
            result = spec.handler(argument, **handler_kwargs)
            if tool_execution_context is not None:
                tool_execution_context.assert_active()
        except ExecutionFenceError:
            raise
        except Exception as exc:
            if effect is None:
                raise
            handler_code = getattr(exc, "code", None)
            if isinstance(handler_code, str) and re.fullmatch(r"[A-Za-z0-9_]{1,56}", handler_code):
                reason_code = f"HANDLER_{handler_code.upper()}"[:64]
            else:
                exception_type = type(exc).__name__.upper()
                if re.fullmatch(r"[A-Z0-9_]{1,48}", exception_type) is None:
                    exception_type = "UNCLASSIFIED"
                reason_code = f"HANDLER_EXCEPTION_{exception_type}"[:64]
            try:
                effect_ledger.mark_recovery_required(
                    effect.effect_id,
                    execution_fence,
                    dispatch_id=dispatch_id,
                    reason_code=reason_code,
                    authorization_snapshot=mission_authorization,
                )
            except ExecutionFenceError:
                raise
            except Exception as ledger_exc:
                raise EffectRecoveryRequired(
                    effect.effect_id,
                    EffectState.DISPATCHED,
                    "OUTCOME_PERSISTENCE_FAILED",
                ) from ledger_exc
            raise EffectRecoveryRequired(
                effect.effect_id,
                EffectState.RECOVERY_REQUIRED,
                reason_code,
            ) from None
        if max_result_chars is not None:
            try:
                result, _truncated = bounded_result(result, max_result_chars)
            except Exception:
                if effect is None:
                    raise
                try:
                    effect_ledger.mark_recovery_required(
                        effect.effect_id,
                        execution_fence,
                        dispatch_id=dispatch_id,
                        reason_code="RESULT_BOUNDARY_FAILED",
                        authorization_snapshot=mission_authorization,
                    )
                except Exception as ledger_exc:
                    raise EffectRecoveryRequired(
                        effect.effect_id,
                        EffectState.DISPATCHED,
                        "OUTCOME_PERSISTENCE_FAILED",
                    ) from ledger_exc
                raise EffectRecoveryRequired(
                    effect.effect_id,
                    EffectState.RECOVERY_REQUIRED,
                    "RESULT_BOUNDARY_FAILED",
                ) from None
        if effect is not None:
            try:
                if spec.name == "mcp.invoke" and isinstance(result, dict) and result.get("status") == "remote_tool_error":
                    # A remote error envelope does not prove that a stateful tool
                    # made no partial external changes; do not claim success or replay.
                    effect_ledger.mark_recovery_required(
                        effect.effect_id,
                        execution_fence,
                        dispatch_id=dispatch_id,
                        reason_code="REMOTE_TOOL_ERROR",
                        authorization_snapshot=mission_authorization,
                    )
                else:
                    effect_ledger.mark_succeeded(
                        effect.effect_id,
                        execution_fence,
                        dispatch_id=dispatch_id,
                        result=result,
                        authorization_snapshot=mission_authorization,
                    )
            except ExecutionFenceError:
                raise
            except Exception as exc:
                raise EffectRecoveryRequired(
                    effect.effect_id,
                    EffectState.DISPATCHED,
                    "OUTCOME_PERSISTENCE_FAILED",
                ) from exc
        return result

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    if spec.workspace_scope_required:
        workspace_authorization = mission_authorization
        if workspace is None:
            raise PermissionError("Owner-authorized Mission Workspace is required for sandboxed execution")
        workspace.bind(mission_id=str(mission_id or ""), request_id=str(request_id or ""), tool_id=name, authorization_snapshot=snapshot, evidence_store=evidence_store, execution_context=tool_execution_context)
        def dispatch_workspace():
            return invoke_handler(workspace_context=workspace)
        future = executor.submit(dispatch_workspace)
    else:
        def dispatch_tool():
            return invoke_handler()
        future = executor.submit(dispatch_tool)
    try:
        result = future.result(timeout=limit)
        if event_bus is not None:
            try:
                from agent.intelligence_layer.events import IntelligenceEventType

                success = bool(result.get("success", result.get("ok", True))) if isinstance(result, dict) else True
                event_bus.publish(
                    owner_identity_ref=str(snapshot.owner_identity),
                    mission_id=str(mission_id),
                    event_type=IntelligenceEventType.TASK_COMPLETED,
                    idempotency_key=f"tool-completed:{event_binding}:{int(success)}",
                    request_id=str(request_id or ""),
                    task_id=str(execution_id or ""),
                    payload={"tool_id": spec.tool_id, "tool_version": spec.version, "success": success},
                )
            except Exception:
                # A post-effect observer must not turn a known result into an ambiguous retry.
                pass
        return result
    except FutureTimeout as exc:
        cancellation_event.set()
        cancelled = future.cancel()
        if effect is not None:
            from agent.external_effects import EffectRecoveryRequired, EffectState

            if cancelled:
                try:
                    effect_ledger.mark_failed(
                        effect.effect_id,
                        execution_fence,
                        reason_code="CANCELLED_BEFORE_DISPATCH",
                        provider_confirmed_no_effect=True,
                        authorization_snapshot=mission_authorization,
                    )
                except Exception:
                    pass
                state = EffectState.FAILED
                reason_code = "DISPATCH_CANCELLED"
            else:
                try:
                    effect_ledger.mark_recovery_required(
                        effect.effect_id,
                        execution_fence,
                        dispatch_id=dispatch_id,
                        reason_code="TOOL_TIMEOUT",
                        authorization_snapshot=mission_authorization,
                    )
                    state = EffectState.RECOVERY_REQUIRED
                except Exception:
                    state = EffectState.DISPATCHED
                reason_code = "TOOL_TIMEOUT"
            raise EffectRecoveryRequired(effect.effect_id, state, reason_code) from exc
        raise ToolTimeout(f"tool {name} timed out after {limit}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
