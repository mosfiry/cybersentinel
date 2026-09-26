from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
import sys

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
DEFAULT_TOOL_TIMEOUT = 30
TOOL_TIMEOUTS = {"run_project_tests": 65, "refresh_intel": 30}


class ToolTimeout(TimeoutError):
    pass


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
            "input_schema": self.input_schema or {"type": "string" if self.argument_type is str else "null"},
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
        }

    def validate(self, argument: Any) -> tuple[bool, str]:
        if self.argument_type is None:
            if argument is not None:
                return False, f"{self.name} does not accept an argument"
            return True, "valid"
        if not isinstance(argument, self.argument_type):
            return False, f"{self.name} requires a string argument"
        if not argument.strip():
            return False, f"{self.name} requires a non-empty string argument"
        if len(argument.strip()) > MAX_ARG_LENGTH:
            return False, "tool argument exceeds maximum length"
        return True, "valid"


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


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        scope_namespace = spec.name.split(".", 1)[0]
        scope_namespaces = {"bugbounty", "recon", "research", "evidence", "browser", "report"}
        if not spec.description or spec.risk_class not in VALID_RISK_CLASSES or not callable(spec.handler) or (spec.owner_only and not spec.requires_owner) or (scope_namespace in scope_namespaces and not spec.scope_required):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        if spec.argument_type not in (None, str):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "ÙØ±Ø§Ø¡Ø© Ø­Ø§ÙØ© Ø§ÙØ®Ø¯ÙØ© ÙØ§ÙØ£Ø­Ø¯Ø§Ø« Ø§ÙØªØ¯ÙÙÙÙØ© Ø§ÙØ£Ø®ÙØ±Ø©", "read", True, None, _status),
    ToolSpec("latest_intel", "ÙØ±Ø§Ø¡Ø© Ø§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø§ÙØªÙØ¯ÙØ¯Ø§Øª Ø§ÙÙØ¬ÙØ¹Ø©", "read", True, None, _latest_intel),
    ToolSpec("refresh_intel", "Ø¬ÙØ¹ Ø§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø¯ÙØ§Ø¹ÙØ© Ø¶Ø¯ Ø§ÙØªÙØ¯ÙØ¯Ø§Øª", "network-read", True, None, _refresh_intel),
    ToolSpec("local_security_check", "ÙØ­Øµ ÙØ³ØªÙØ¹Ù TCP Ø§ÙÙØ­ÙÙØ©", "read", True, None, _local_security),
    ToolSpec("local_system_info", "ÙØ±Ø§Ø¡Ø© ÙØ¹ÙÙÙØ§Øª Ø§ÙÙØ¸Ø§Ù Ø§ÙÙØ­ÙÙ", "read", True, None, _system_info),
    ToolSpec("search", "Ø¨Ø­Ø« ÙÙ Ø§ÙØ£Ø­Ø¯Ø§Ø« ÙØ§ÙØ§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø§ÙÙØ­ÙÙØ©", "read", True, str, _search),
    ToolSpec("watch", "Ø¥Ø¶Ø§ÙØ© ÙÙÙØ© ÙØ±Ø§ÙØ¨ Ø¯ÙØ§Ø¹ÙØ© ÙØ­ÙÙØ©", "state-write", True, str, _watch),
    ToolSpec("unwatch", "Ø¥Ø²Ø§ÙØ© ÙÙÙØ© ÙØ±Ø§ÙØ¨ Ø¯ÙØ§Ø¹ÙØ© ÙØ­ÙÙØ©", "state-write", True, str, _unwatch),
    ToolSpec("run_project_tests", "ØªØ´ØºÙÙ pytest -q Ø¯Ø§Ø®Ù Ø¬Ø°Ø± Ø§Ø®ØªØ¨Ø§Ø± Ø§ÙÙØ´Ø±ÙØ¹ Ø§ÙÙØ­Ø¯Ø¯", "bounded-exec", True, str, _run_project_tests),
    ToolSpec("red_team_assess", "ØªÙÙÙÙ ÙØ¬ÙÙÙ Ø¯ÙØ§Ø¹Ù ÙÙÙØ§ÙÙ ÙÙØ·; ÙØ§ ÙÙÙØ° Ø§Ø³ØªØºÙØ§ÙØ§Ù Ø£Ù Ø£ÙØ±Ø© ÙØ¸Ø§Ù", "analysis", True, str, _red_team_assess, True),
    ToolSpec("scoped_http_probe", "ÙØ±Ø§ÙØ¨Ø© HTTP ÙØ­Ø¯ÙØ¯Ø© ÙØ§ ØªØ¹ÙÙ Ø¥ÙØ§ ÙØ¹ Scope Snapshot ÙTarget ÙØµØ§Ø¯Ù Ø¹ÙÙÙ", "network-read", True, str, _scoped_http_probe, False, True),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def tool_definitions() -> list[dict[str, Any]]:
    """Build provider-neutral tool metadata from the canonical registry."""
    definitions: list[dict[str, Any]] = []
    for spec in REGISTRY.values():
        parameters: dict[str, Any] = {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
        if spec.argument_type is str:
            parameters["properties"]["query"] = {
                "type": "string",
                "maxLength": MAX_ARG_LENGTH,
            }
            parameters["required"] = ["query"]
        definitions.append({
            "name": spec.name,
            "description": spec.description[:512],
            "risk_class": spec.risk_class,
            "owner_required": spec.requires_owner,
            "parameters": parameters,
            **spec.metadata(),
        })
    return definitions


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def execute(name: str, argument: str | None = None, *, timeout: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_proof: Any = None, execution_class: str | None = None, execution_run_id: str | None = None):
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    # The registry is the last line of defense, not a policy creator. There is
    # no implicit "not mission-bound" escape hatch: a caller cannot opt out of
    # the proof boundary by omitting mission_id. Every governed execution is
    # classified (MISSION_BOUND when mission governance kwargs are present,
    # OWNER_DIRECT otherwise) and must carry an ExecutionAuthorizationProof of
    # exactly that class, derived from authorization that already exists.
    from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, RejectionCode
    mission_bound = mission_authorization is not None or workspace is not None or evidence_store is not None or bool(mission_id)
    resolved_class = str(execution_class or (ExecutionClass.MISSION_BOUND.value if mission_bound else ExecutionClass.OWNER_DIRECT.value))
    if execution_proof is None:
        raise PermissionError(f"{RejectionCode.PROOF_REQUIRED.value}: {resolved_class} execution requires an ExecutionAuthorizationProof")
    proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.verify(execution_proof, name=name, argument=argument, mission_id=mission_id, request_id=request_id, run_id=execution_run_id)
    if not proof_ok:
        raise PermissionError(f"{proof_code}: {proof_reason}")
    if str(getattr(execution_proof, "execution_class", ExecutionClass.MISSION_BOUND.value)) != resolved_class:
        raise PermissionError(f"{RejectionCode.EXECUTION_CLASS_MISMATCH.value}: proof execution class {getattr(execution_proof, 'execution_class', '')} does not match {resolved_class} execution")
    decision_valid = False
    if authorization_decision is not None:
        from security.authorization_context import AuthorizationDecision
        decision_valid = bool(request_id) and isinstance(authorization_decision, AuthorizationDecision) and authorization_decision.is_valid_for(name, argument, request_id)
        if not decision_valid:
            raise PermissionError("invalid or argument-mismatched AuthorizationDecision")
        # Decision binding: the proof must be bound to exactly this decision
        # (canonical signature) and its policy fingerprint. A proof derived
        # from a different decision can never authorize this execution.
        if str(getattr(authorization_decision, "decision_signature", "")) != str(getattr(execution_proof, "decision_fingerprint", "")):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: execution proof is not bound to the supplied AuthorizationDecision")
        if str(getattr(authorization_decision, "policy_fingerprint", "")) != str(getattr(execution_proof, "policy_fingerprint", "")):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: execution proof policy binding does not match the authorization decision policy")
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
    if mission_authorization is not None:
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = mission_authorization if isinstance(mission_authorization, MissionAuthorizationSnapshot) else MissionAuthorizationSnapshot.from_dict(dict(mission_authorization))
        if str(snapshot.authorization_hash) != str(getattr(execution_proof, "snapshot_hash", "")):
            raise PermissionError(f"{RejectionCode.SNAPSHOT_MISMATCH.value}: live mission authorization snapshot differs from the proof-bound snapshot")
        allowed, reason = snapshot.check(action=name, tool_id=name, target_identity=target_identity or snapshot.target_identity, at=None)
        if not allowed:
            raise PermissionError("mission authorization blocked: " + reason)
    valid, reason = spec.validate(argument)
    if not valid:
        raise ValueError(reason)
    limit = timeout or TOOL_TIMEOUTS.get(name, spec.timeout)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    if name == "run_project_tests":
        # Legacy compatibility snapshot minting was removed: the registry must
        # never create authorization from a decision field. A governed
        # workspace and a real mission authorization snapshot are required
        # from the caller.
        if workspace is None or mission_authorization is None:
            raise PermissionError("run_project_tests requires a governed workspace and a mission authorization snapshot")
        workspace.bind(mission_id=str(mission_id or ""), request_id=str(request_id or ""), tool_id=name, authorization_snapshot=mission_authorization, evidence_store=evidence_store)
        future = executor.submit(spec.handler, argument, workspace=workspace)
    else:
        future = executor.submit(spec.handler, argument)
    try:
        return future.result(timeout=limit)
    except FutureTimeout as exc:
        future.cancel()
        raise ToolTimeout(f"tool {name} timed out after {limit}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
