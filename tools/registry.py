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
import uuid

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
DEFAULT_TOOL_TIMEOUT = 30
TOOL_TIMEOUTS = {"run_project_tests": 65, "refresh_intel": 30}


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
    return {}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_class: str
    requires_owner: bool
    argument_type: type | None
    handler: Callable[[str | None], Any]
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
        }

    def validate(self, argument: Any) -> tuple[bool, str]:
        if self.argument_type is None:
            if argument is not None:
                return False, f"{self.name} does not accept an argument"
            return True, "valid"
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
        if self.input_schema != _default_input_schema(self.argument_type):
            return False, "tool input schema is unsupported", None
        if self.argument_type is None:
            if arguments:
                return False, f"{self.name} does not accept properties", None
            return True, "valid", None
        if len(arguments) != 1 or "query" not in arguments:
            return False, "tool arguments must contain exactly the required query property", None
        valid, reason = self.validate(arguments["query"])
        return valid, reason, arguments["query"] if valid else None


def _status(_):
    from core.engine import status
    return status()


def _latest_intel(_):
    from core.intel import latest_intel
    return latest_intel(50)


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


def _run_project_tests(argument, *, workspace=None):
    if workspace is None:
        raise PermissionError("run_project_tests requires governed Workspace")
    target = argument or "."
    try:
        if not workspace.resolve(target).is_dir():
            raise ValueError("project directory does not exist")
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("project directory is outside the configured test root") from exc
    result = workspace.develop((sys.executable, "-m", "pytest", "-q"), cwd=target, timeout=60)
    return {"ok": result.ok, "timed_out": result.timed_out, "returncode": result.exit_code, "output": (result.stdout + result.stderr)[-4000:]}


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


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        scope_namespace = spec.name.split(".", 1)[0]
        scope_namespaces = {"bugbounty", "recon", "research", "evidence", "browser", "report"}
        if (
            not spec.description
            or spec.risk_class not in VALID_RISK_CLASSES
            or not callable(spec.handler)
            or (spec.owner_only and not spec.requires_owner)
            or (scope_namespace in scope_namespaces and not spec.scope_required)
            or (spec.effect_provider and (not spec.effect_provider.strip() or len(spec.effect_provider) > 128))
            or (spec.risk_class in {"network-read", "state-write", "bounded-exec"} and not spec.effect_provider)
            or (spec.idempotency_supported and (not spec.effect_provider or not _accepts_keyword(spec.handler, "idempotency_key")))
        ):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        if spec.argument_type not in (None, str):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        if spec.input_schema != _default_input_schema(spec.argument_type):
            raise ValueError(f"unsupported input schema for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "قراءة حالة الخدمة والأحداث التدقيقية الأخيرة", "read", True, None, _status),
    ToolSpec("latest_intel", "قراءة استخبارات التهديدات المجمعة", "read", True, None, _latest_intel),
    ToolSpec("refresh_intel", "جمع استخبارات دفاعية ضد التهديدات", "network-read", True, None, _refresh_intel, effect_provider="cybersentinel.intel-collectors"),
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
    ToolSpec("run_project_tests", "تشغيل pytest -q داخل جذر اختبار المشروع المحدد", "bounded-exec", True, str, _run_project_tests, effect_provider="cybersentinel.workspace-process"),
    ToolSpec("red_team_assess", "تقييم هجومي دفاعي للمالك فقط; لا ينفذ استغلالاً أو أمرة نظام", "analysis", True, str, _red_team_assess, True),
    ToolSpec("scoped_http_probe", "مراقبة HTTP محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_http_probe, False, True, effect_provider="cybersentinel.scoped-http"),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def tool_definitions() -> list[dict[str, Any]]:
    """Build provider-neutral tool metadata from the canonical registry."""
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


def execute(name: str, argument: Any = None, *, timeout: float | None = None, max_result_chars: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_fence: Any = None, execution_id: str | None = None, event_bus: Any = None, hook_registry: Any = None):
    import math

    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("timeout must be a positive finite number")
    if max_result_chars is not None and (isinstance(max_result_chars, bool) or not isinstance(max_result_chars, int) or max_result_chars < 128):
        raise ValueError("max_result_chars must be an integer of at least 128")
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
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
        requested_url = argument if isinstance(argument, str) and "://" in argument else scope_context["url"]
        urls = [scope_context["url"]] if requested_url == scope_context["url"] else [scope_context["url"], requested_url]
        for checked_url in urls:
            decision = resolve(
                scope_context["scope_snapshot_id"],
                scope_context["target_id"],
                checked_url,
                method=scope_context.get("method", "GET"),
                expected_program_id=scope_context["program_id"],
                redirect_chain=scope_context.get("redirect_chain", []),
            )
            if not decision.allowed:
                raise PermissionError("scope denied: " + decision.reason)
    snapshot = None
    if mission_authorization is not None:
        from security.mission_authorization import MissionAuthorizationError, MissionAuthorizationSnapshot
        snapshot = mission_authorization if isinstance(mission_authorization, MissionAuthorizationSnapshot) else MissionAuthorizationSnapshot.from_dict(dict(mission_authorization))
        allowed, reason = snapshot.check(action=name, tool_id=name, target_identity=target_identity or snapshot.target_identity, at=None)
        if not allowed:
            code = "authorization_expired" if reason == "authorization snapshot expired or not active" else "authorization_denied"
            raise MissionAuthorizationError("mission authorization blocked: " + reason, code=code)
    if execution_fence is not None:
        execution_fence.assert_dispatch(
            mission_id=str(mission_id or ""),
            request_id=str(request_id or ""),
            execution_id=str(execution_id or ""),
            authorization_snapshot=mission_authorization,
        )
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
            requested_url = argument if isinstance(argument, str) and "://" in argument else scope_context["url"]
            urls = [scope_context["url"]] if requested_url == scope_context["url"] else [scope_context["url"], requested_url]
            for checked_url in urls:
                decision = resolve(
                    scope_context["scope_snapshot_id"],
                    scope_context["target_id"],
                    checked_url,
                    method=scope_context.get("method", "GET"),
                    expected_program_id=scope_context["program_id"],
                    redirect_chain=scope_context.get("redirect_chain", []),
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

        argument_sha256 = hashlib.sha256((argument or "").encode("utf-8")).hexdigest()
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
        if effect is not None:
            effect_ledger.mark_dispatched(
                effect.effect_id,
                execution_fence,
                dispatch_id=dispatch_id,
                authorization_snapshot=mission_authorization,
            )
        handler_kwargs = {}
        if name == "run_project_tests":
            handler_kwargs["workspace"] = workspace_context
        if spec.idempotency_supported:
            handler_kwargs["idempotency_key"] = effect.idempotency_key
        try:
            result = spec.handler(argument, **handler_kwargs)
        except ExecutionFenceError:
            raise
        except Exception as exc:
            if effect is None:
                raise
            try:
                effect_ledger.mark_recovery_required(
                    effect.effect_id,
                    execution_fence,
                    dispatch_id=dispatch_id,
                    reason_code=type(exc).__name__.upper()[:64],
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
                "HANDLER_EXCEPTION",
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

    limit = timeout if timeout is not None else TOOL_TIMEOUTS.get(name, spec.timeout)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    if name == "run_project_tests":
        workspace_authorization = mission_authorization
        if workspace is None:
            from datetime import datetime, timedelta, timezone
            from security.mission_authorization import MissionAuthorizationSnapshot
            root = Path(os.getenv("CYBERSENTINEL_TEST_ROOT", Path.cwd())).expanduser().resolve()
            legacy_owner = getattr(authorization_decision, "owner_evidence_fingerprint", "legacy-compatibility")
            compatibility_snapshot = MissionAuthorizationSnapshot.create(owner_identity=legacy_owner, mission_id=str(request_id or "legacy-request"), target_identity="legacy-workspace", scope=("workspace",), allowed_actions=(name,), forbidden_actions=(), allowed_tools=(name,), time_window={"timezone": "UTC"}, max_duration=60, rate_limits={name: 1}, network_boundary={"allowed": ()}, data_boundary={"allowed": ("legacy-workspace",)}, credential_boundary={"allowed": ()}, workspace_boundary={"root": str(root)}, policy_version="compatibility", owner_approval=legacy_owner, created_at=datetime.now(timezone.utc).isoformat(), expires_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat())
            from workspace import Workspace
            workspace = Workspace(root, authorization_snapshot=compatibility_snapshot)
            workspace_authorization = compatibility_snapshot
        workspace.bind(mission_id=str(mission_id or ""), request_id=str(request_id or ""), tool_id=name, authorization_snapshot=workspace_authorization, evidence_store=evidence_store)
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
