from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import fnmatch
import os
import shutil
import sys
import tempfile
import subprocess
import hmac

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
VALID_NETWORK_ACCESS = frozenset({"none", "fixed_cisa_https_get", "fixed_public_search_apis", "scope_authorized_http_get"})
VALID_FILESYSTEM_ACCESS = frozenset({
    "none",
    "application_db_read",
    "application_db_read_write",
    "application_db_read_and_policy_file_read",
    "procfs_read_and_application_db_write",
    "runtime_metadata_and_application_db_write",
    "secret_filtered_read_only_snapshot",
})
VALID_PROCESS_ACCESS = frozenset({"none", "bubblewrap+prlimit"})
VALID_CREDENTIAL_ACCESS = frozenset({"none", "optional_github_token"})
DEFAULT_TOOL_TIMEOUT = 30
TOOL_TIMEOUTS = {"run_project_tests": 65, "refresh_intel": 30}


class ToolTimeout(TimeoutError):
    pass


class ToolUnavailableError(RuntimeError):
    pass


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
    network_access: str = "unspecified"
    filesystem_access: str = "unspecified"
    process_access: str = "unspecified"
    credential_access: str = "unspecified"
    scope_requirements: tuple[str, ...] = ()
    timeout: int = DEFAULT_TOOL_TIMEOUT
    rate_limit: str = "bounded"
    evidence_requirements: tuple[str, ...] = ("authorization_decision", "observation")
    available: bool = True
    availability_reason: str = ""

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
            "available": self.available,
            "availability_reason": self.availability_reason,
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


def _sandbox_python_environment_args(prefix: Path, *, disable_bytecode: bool = False) -> list[str]:
    """Build a cleared environment, allowing only the bound interpreter library path."""
    args = ["--clearenv", "--setenv", "PATH", f"{prefix / 'bin'}:/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "CYBERSENTINEL_MEMORY_DB_PATH", "/tmp/cybersentinel-pytest-memory.sqlite3", "--setenv", "CYBERSENTINEL_TASKS_DB_PATH", "/tmp/cybersentinel-pytest-tasks.sqlite3"]
    runtime_library_dir = prefix / "lib"
    if runtime_library_dir.is_dir():
        args.extend(("--setenv", "LD_LIBRARY_PATH", str(runtime_library_dir)))
    if disable_bytecode:
        args.extend(("--setenv", "PYTHONDONTWRITEBYTECODE", "1"))
    args.extend(("--setenv", "PYTHONNOUSERSITE", "1", "--setenv", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1"))
    return args


def _sandbox_preflight_failure_reason(output: bytes | str) -> str:
    """Map sandbox diagnostics to fixed safe categories; never expose raw output."""
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    normalized = text.casefold()
    if any(marker in normalized for marker in ("operation not permitted", "permission denied", "no permissions to create", "failed to create new namespace")):
        return "Unavailable: host denied required OS namespace isolation"
    if "error while loading shared libraries" in normalized or "cannot open shared object file" in normalized:
        return "Unavailable: isolated Python runtime library path is unavailable"
    if "no such file or directory" in normalized or "execvp" in normalized:
        return "Unavailable: isolated Python executable or dependency path is inaccessible"
    return "Unavailable: OS test sandbox or isolated pytest interpreter failed preflight"


def _probe_project_test_sandbox() -> tuple[bool, str, str, str]:
    """Verify the OS sandbox and isolated interpreter are available at startup."""
    bwrap = shutil.which("bwrap") or ""
    prlimit = shutil.which("prlimit") or ""
    if not bwrap or not prlimit:
        return False, "Unavailable: bubblewrap/prlimit OS sandbox is not installed", bwrap, prlimit
    prefix = Path(sys.prefix).resolve()
    try:
        prefix.relative_to(Path.home().resolve())
    except ValueError:
        pass
    else:
        return False, "Unavailable: the test interpreter is inside the user home and cannot be exposed to project tests", bwrap, prlimit
    command = [prlimit, "--cpu=5", "--as=2147483648", "--fsize=67108864", "--nofile=256", "--nproc=1024", "--", bwrap, "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr"]
    for system_path in ("/bin", "/lib", "/lib64", "/etc"):
        if Path(system_path).exists():
            command.extend(("--ro-bind", system_path, system_path))
    if not prefix.is_relative_to(Path("/usr")):
        command.extend(("--ro-bind", str(prefix), str(prefix)))
    command.extend(("--size", "268435456", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev"))
    command.extend(_sandbox_python_environment_args(prefix))
    command.extend(("--", sys.executable, "-c", "import pytest"))
    try:
        probe = subprocess.run(command, capture_output=True, timeout=4, check=False, env={"PATH": os.environ.get("PATH", "")})
    except Exception as exc:
        return False, f"Unavailable: OS test sandbox preflight failed ({type(exc).__name__})", bwrap, prlimit
    if probe.returncode != 0:
        output = (probe.stderr or b"") + b"\n" + (probe.stdout or b"")
        return False, _sandbox_preflight_failure_reason(output), bwrap, prlimit
    return True, "", bwrap, prlimit


_PROJECT_TEST_SANDBOX_AVAILABLE, _PROJECT_TEST_SANDBOX_REASON, _BWRAP, _PRLIMIT = _probe_project_test_sandbox()


def _project_snapshot_ignore(_directory: str, names: list[str]) -> set[str]:
    blocked_exact = {".git", ".pytest_cache", "__pycache__", ".env", ".envrc", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".vault-token", ".terraformrc", "terraform.rc", "credentials.json", "token.json", "client_secret.json", ".ssh", ".gnupg", ".aws", ".azure", ".gcloud", ".kube", ".docker", ".config", ".terraform", ".pulumi", ".vercel", "secrets", "credentials", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_xmss", "identity", "authorized_keys", "known_hosts"}
    safe_templates = {".env.example", ".env.sample", ".env.template"}
    blocked_globs = ("*.key", "*.pem", "*.p12", "*.pfx", "*.crt", "*.cer", "*.der", "*.ovpn", "*.tfstate", "*.tfstate.*", "*.sqlite", "*.sqlite3", "*.db", "*.db-wal", "*.db-shm", "*service-account*.json")
    ignored = set()
    for name in names:
        folded = name.casefold()
        if folded in blocked_exact or (folded.startswith(".env.") and folded not in safe_templates) or any(fnmatch.fnmatch(folded, pattern) for pattern in blocked_globs):
            ignored.add(name)
    return ignored


def _project_snapshot_size(source: Path, *, max_entries: int = 20_000, max_bytes: int = 256 * 1024 * 1024, max_depth: int = 128) -> None:
    count = 0
    total = 0
    for directory, child_dirs, files in os.walk(source, topdown=True, followlinks=False):
        ignored_dirs = _project_snapshot_ignore(directory, child_dirs)
        child_dirs[:] = [name for name in child_dirs if name not in ignored_dirs]
        ignored_files = _project_snapshot_ignore(directory, files)
        relative_directory = Path(directory).relative_to(source)
        if len(relative_directory.parts) > max_depth:
            raise ValueError("project test input exceeds the 128-level directory depth limit")
        for name in (*child_dirs, *(item for item in files if item not in ignored_files)):
            path = Path(directory) / name
            if path.is_symlink():
                total += len(os.readlink(path).encode("utf-8", errors="replace"))
                count += 1
            elif path.is_dir():
                count += 1
                continue
            else:
                try:
                    info = path.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ValueError("project snapshot contains an unreadable entry") from exc
                if path.is_file():
                    total += info.st_size
                count += 1
            if count > max_entries or total > max_bytes:
                raise ValueError("project test input exceeds the 20,000-entry / 256 MiB snapshot limit")


def _run_project_tests(argument, *, workspace=None):
    if workspace is None:
        raise PermissionError("run_project_tests requires governed Workspace")
    if not _PROJECT_TEST_SANDBOX_AVAILABLE:
        raise ToolUnavailableError(_PROJECT_TEST_SANDBOX_REASON)
    target = argument or "."
    try:
        if not workspace.resolve(target).is_dir():
            raise ValueError("project directory does not exist")
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("project directory is outside the configured test root") from exc
    _project_snapshot_size(workspace.resolve(target))
    try:
        with tempfile.TemporaryDirectory(prefix="cybersentinel-pytest-snapshot-") as temporary:
            snapshot = Path(temporary) / "project"
            shutil.copytree(workspace.resolve(target), snapshot, symlinks=True, ignore=_project_snapshot_ignore)
            prefix = Path(sys.prefix).resolve()
            command = [_PRLIMIT, "--cpu=60", "--as=2147483648", "--fsize=67108864", "--nofile=256", "--nproc=1024", "--", _BWRAP, "--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"]
            for system_path in ("/bin", "/lib", "/lib64", "/etc"):
                if Path(system_path).exists():
                    command.extend(("--ro-bind", system_path, system_path))
            if not prefix.is_relative_to(Path("/usr")):
                command.extend(("--ro-bind", str(prefix), str(prefix)))
            command.extend(("--ro-bind", str(snapshot), "/workspace", "--size", "268435456", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev", "--chdir", "/workspace"))
            command.extend(_sandbox_python_environment_args(prefix, disable_bytecode=True))
            command.extend(("--", sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--basetemp=/tmp/pytest-run", "-q"))
            result = workspace.develop(tuple(command), cwd=".", timeout=60)
    except (OSError, shutil.Error) as exc:
        raise ToolUnavailableError("isolated project test setup failed closed") from exc
    return {"ok": result.ok, "timed_out": result.timed_out, "returncode": result.exit_code, "output": (result.stdout + result.stderr)[-4000:]}


def _red_team_assess(argument):
    from reasoning.red_team import assess
    return assess(argument).to_dict()


def _scoped_http_probe(argument, *, scope_context):
    from tools.scoped_http_probe import scoped_http_probe
    return scoped_http_probe(argument, scope_context=scope_context)


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        scope_namespace = spec.name.split(".", 1)[0]
        scope_namespaces = {"bugbounty", "recon", "research", "evidence", "browser", "report"}
        if not spec.description or spec.risk_class not in VALID_RISK_CLASSES or not callable(spec.handler) or (spec.owner_only and not spec.requires_owner) or (scope_namespace in scope_namespaces and not spec.scope_required) or type(spec.available) is not bool or (not spec.available and not spec.availability_reason):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        access_metadata = (
            (spec.network_access, VALID_NETWORK_ACCESS),
            (spec.filesystem_access, VALID_FILESYSTEM_ACCESS),
            (spec.process_access, VALID_PROCESS_ACCESS),
            (spec.credential_access, VALID_CREDENTIAL_ACCESS),
        )
        if any(not isinstance(value, str) or value not in vocabulary for value, vocabulary in access_metadata):
            raise ValueError(f"invalid or unspecified access metadata for {spec.name}")
        if spec.argument_type not in (None, str):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "قراءة حالة الخدمة والأحداث التدقيقية الأخيرة", "read", True, None, _status, network_access="none", filesystem_access="application_db_read_and_policy_file_read", process_access="none", credential_access="none"),
    ToolSpec("latest_intel", "قراءة استخبارات التهديدات المجمعة", "read", True, None, _latest_intel, network_access="none", filesystem_access="application_db_read", process_access="none", credential_access="none"),
    ToolSpec("refresh_intel", "جمع استخبارات دفاعية ضد التهديدات", "network-read", True, None, _refresh_intel, network_access="fixed_cisa_https_get", filesystem_access="application_db_read_write", process_access="none", credential_access="none"),
    ToolSpec("local_security_check", "فحص مستمعي TCP المحلية", "read", True, None, _local_security, network_access="none", filesystem_access="procfs_read_and_application_db_write", process_access="none", credential_access="none"),
    ToolSpec("local_system_info", "قراءة معلومات النظام المحلي", "read", True, None, _system_info, network_access="none", filesystem_access="runtime_metadata_and_application_db_write", process_access="none", credential_access="none"),
    ToolSpec("search", "بحث في الأحداث والاستخبارات المحلية", "read", True, str, _search, network_access="fixed_public_search_apis", filesystem_access="application_db_read", process_access="none", credential_access="optional_github_token"),
    ToolSpec("watch", "إضافة كلمة مراقب دفاعية محلية", "state-write", True, str, _watch, network_access="none", filesystem_access="application_db_read_write", process_access="none", credential_access="none"),
    ToolSpec("unwatch", "إزالة كلمة مراقب دفاعية محلية", "state-write", True, str, _unwatch, network_access="none", filesystem_access="application_db_read_write", process_access="none", credential_access="none"),
    ToolSpec("run_project_tests", "تشغيل pytest داخل نسخة قراءة فقط معزولة بنظام التشغيل", "bounded-exec", True, str, _run_project_tests, timeout=65, network_access="none", filesystem_access="secret_filtered_read_only_snapshot", process_access="bubblewrap+prlimit", credential_access="none", available=_PROJECT_TEST_SANDBOX_AVAILABLE, availability_reason=_PROJECT_TEST_SANDBOX_REASON),
    ToolSpec("red_team_assess", "تقييم هجومي دفاعي للمالك فقط; لا ينفذ استغلالاً أو أمرة نظام", "analysis", True, str, _red_team_assess, True, network_access="none", filesystem_access="none", process_access="none", credential_access="none"),
    ToolSpec("scoped_http_probe", "One bounded, scope-authorized HTTP GET. GET only; redirects are blocked; no credentials or response body are returned.", "network-read", True, str, _scoped_http_probe, False, True, timeout=10, network_access="scope_authorized_http_get", filesystem_access="none", process_access="none", credential_access="none", scope_requirements=("persisted_scope_snapshot", "program_id", "target_id", "GET"), output_schema={"type": "object", "additionalProperties": False, "properties": {"success": {"type": "boolean"}, "outcome": {"type": "string"}, "observation_only": {"type": "boolean"}, "status": {"type": ["integer", "null"]}, "content_type": {"type": "string", "maxLength": 128}, "byte_count": {"type": "integer", "maximum": 65536}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "truncated": {"type": "boolean"}, "error_code": {"type": "string"}}}),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def tool_definitions(*, include_unavailable: bool = False) -> list[dict[str, Any]]:
    """Build provider-neutral tool metadata from the canonical registry."""
    definitions: list[dict[str, Any]] = []
    for spec in REGISTRY.values():
        if not spec.available and not include_unavailable:
            continue
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


def execute(name: str, argument: str | None = None, *, timeout: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, tool_call_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_proof: Any = None, execution_class: str | None = None):
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    if not spec.available:
        raise ToolUnavailableError(spec.availability_reason or "tool is unavailable")
    from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, RejectionCode
    mission_bound = mission_authorization is not None or workspace is not None or evidence_store is not None or bool(mission_id)
    resolved_class = str(execution_class or (ExecutionClass.MISSION_BOUND.value if mission_bound else ExecutionClass.OWNER_DIRECT.value))
    if not str(tool_call_id or ""):
        raise PermissionError("execution requires a unique tool-call identity")
    if execution_proof is None:
        raise PermissionError(f"{RejectionCode.PROOF_REQUIRED.value}: {resolved_class} execution requires an ExecutionAuthorizationProof")
    proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.verify(
        execution_proof, name=name, argument=argument, mission_id=mission_id, request_id=request_id, tool_call_id=tool_call_id,
    )
    if not proof_ok:
        raise PermissionError(f"{proof_code}: {proof_reason}")
    if str(getattr(execution_proof, "execution_class", "")) != resolved_class:
        raise PermissionError(f"{RejectionCode.EXECUTION_CLASS_MISMATCH.value}: proof execution class does not match governed execution")
    decision_valid = False
    if authorization_decision is not None:
        from security.authorization_context import AuthorizationDecision
        decision_valid = bool(request_id) and isinstance(authorization_decision, AuthorizationDecision) and authorization_decision.is_valid_for(name, argument, request_id)
        if not decision_valid:
            raise PermissionError("invalid or argument-mismatched AuthorizationDecision")
        if str(authorization_decision.decision_signature) != str(execution_proof.decision_fingerprint):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: proof is not bound to the supplied authorization decision")
        if str(authorization_decision.policy_fingerprint) != str(execution_proof.policy_fingerprint):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: proof policy binding does not match the authorization decision")
    if spec.requires_owner and not decision_valid:
        raise PermissionError("Owner AuthorizationDecision required for this tool")
    if spec.scope_required and not decision_valid:
        raise PermissionError("scope-bound AuthorizationDecision required")
    valid, reason = spec.validate(argument)
    if not valid:
        raise ValueError(reason)
    strict_scope_context = None
    if spec.scope_required:
        from security.authorization_context import _fingerprint
        from security.scope_store import get_snapshot
        from tools.scoped_http_probe import _scope_authorized_url, validate_scope_context_fields
        strict_scope_context = validate_scope_context_fields(scope_context)
        live_scope = get_snapshot(strict_scope_context["scope_snapshot_id"])
        if live_scope is None:
            raise PermissionError("scope snapshot is not persisted")
        if not hmac.compare_digest(_fingerprint(live_scope.to_dict()), str(authorization_decision.scope_fingerprint)):
            raise PermissionError("scope snapshot differs from the Owner AuthorizationDecision")
        if not hmac.compare_digest(_fingerprint(strict_scope_context), str(execution_proof.scope_hash)):
            raise PermissionError("scope context differs from the execution proof")
    if mission_authorization is not None:
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = mission_authorization if isinstance(mission_authorization, MissionAuthorizationSnapshot) else MissionAuthorizationSnapshot.from_dict(dict(mission_authorization))
        if str(snapshot.authorization_hash) != str(getattr(execution_proof, "snapshot_hash", "")):
            raise PermissionError(f"{RejectionCode.SNAPSHOT_MISMATCH.value}: live mission snapshot differs from proof-bound snapshot")
        allowed, reason = snapshot.check(action=name, tool_id=name, target_identity=target_identity or snapshot.target_identity, at=None)
        if not allowed:
            raise PermissionError("mission authorization blocked: " + reason)
    elif mission_bound:
        raise PermissionError(f"{RejectionCode.SNAPSHOT_MISSING.value}: mission-bound execution requires the Owner authorization snapshot")
    if spec.scope_required:
        _scope_authorized_url(argument, strict_scope_context, consume_rate=True)
    from security.execution_proof import consume_execution_proof_once
    consume_execution_proof_once(execution_proof)
    limit = timeout or TOOL_TIMEOUTS.get(name, spec.timeout)
    if spec.scope_required:
        limit = min(limit, spec.timeout)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    if name == "run_project_tests":
        if workspace is None or mission_authorization is None or not mission_id:
            raise PermissionError("run_project_tests requires a mission-bound Workspace and Owner authorization snapshot")
        workspace.bind(mission_id=str(mission_id), request_id=str(request_id or ""), tool_id=name, action_id=str(tool_call_id or ""), authorization_snapshot=mission_authorization, evidence_store=evidence_store)
        future = executor.submit(spec.handler, argument, workspace=workspace)
    elif spec.scope_required:
        future = executor.submit(spec.handler, argument, scope_context=strict_scope_context)
    else:
        future = executor.submit(spec.handler, argument)
    try:
        return future.result(timeout=limit)
    except FutureTimeout as exc:
        future.cancel()
        raise ToolTimeout(f"tool {name} timed out after {limit}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
