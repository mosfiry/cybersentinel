from __future__ import annotations

import json
import hmac
import os
import signal
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import SimpleCookie
import threading
from urllib.parse import parse_qs, unquote, urlparse
from core.config import (
    BRIDGE_HOST,
    BRIDGE_PORT,
    BRIDGE_TOKEN,
    PUBLIC_SESSION_COOKIE,
    PUBLIC_OWNER_SESSION_COOKIE,
    PUBLIC_SESSION_TTL_SECONDS,
    PUBLIC_WEB_ENABLED,
    PUBLIC_WEB_ORIGIN,
    DB_PATH,
)
from core.engine import RUNTIME, status
from core.lifecycle import get as get_lifecycle, request_cancel
from core.db import events_for_request, reasoning_for_request
import security.owner_password as owner_password
from security.owner_password import login as owner_password_login, logout as owner_password_logout
from api.chat import chat, get_session, sse, stream, task_stream, create_task, resume_task, pause_task, cancel_task
from agent.task_manager import TaskManager
from tools.registry import tool_definitions
from core.version import PRODUCT_NAME, SERVER_VERSION, VERSION
from core.health import readiness_snapshot
from api.missions import MissionService
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker
from agent.mission_runtime import MissionRuntime
from agent.mission import MissionStore
from agent.agent_core import AgentCore
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot
from security.public_session import PublicSessionManager
from agent.runtime_supervisor import RuntimeSupervisor
from workspace.environment import Workspace, WorkspaceBoundaryError, WorkspacePolicyError
from workspace.projects import WorkspaceProjectStore
from agent.local_runtime.manager import LocalModelManager
from agent.local_runtime.runtime import LlamaCppRuntime

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
PUBLIC_SESSIONS = PublicSessionManager(ttl_seconds=PUBLIC_SESSION_TTL_SECONDS)
PUBLIC_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PUBLIC_MISSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MAX_PUBLIC_WORKSPACE_FILE_BYTES = 262_144
PUBLIC_WORKSPACE_BLOCKED_DIRS = {".git", ".ssh", ".gnupg", "secrets", "credentials"}
PUBLIC_WORKSPACE_BLOCKED_NAMES = {".env", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts"}
PUBLIC_WORKSPACE_SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template"}
DESKTOP_MODE = os.environ.get("CYBERSENTINEL_DESKTOP_MODE", "").casefold() == "true"
DESKTOP_SETUP_TOKEN = os.environ.get("CYBERSENTINEL_DESKTOP_SETUP_TOKEN", "")
_DESKTOP_MODEL_MANAGER: LocalModelManager | None = None
_DESKTOP_MANAGER_LOCK = threading.Lock()


def _project_store() -> WorkspaceProjectStore:
    return WorkspaceProjectStore(root_base=DB_PATH.parent / "workspaces")


def _desktop_model_manager() -> LocalModelManager:
    global _DESKTOP_MODEL_MANAGER
    with _DESKTOP_MANAGER_LOCK:
        if _DESKTOP_MODEL_MANAGER is None:
            storage_root = Path(
                os.environ.get("CYBERSENTINEL_MODEL_ROOT", str(DB_PATH.parent / "local-models"))
            ).expanduser().resolve()
            runtime_dir = Path(
                os.environ.get("CYBERSENTINEL_LLM_RUNTIME_DIR", str(ROOT / "runtime" / "llama"))
            ).expanduser().resolve()
            manager = LocalModelManager(
                storage_root,
                runtime=LlamaCppRuntime(runtime_dir),
                router=RUNTIME.router,
            )
            _DESKTOP_MODEL_MANAGER = manager
            manager.restore_active()
        return _DESKTOP_MODEL_MANAGER


def _shutdown_desktop_services() -> None:
    manager = _DESKTOP_MODEL_MANAGER
    if manager is not None:
        manager.shutdown()


def _redact_git_remote(value: str) -> str:
    value = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1[REDACTED]@", str(value))
    sensitive_key = r"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|oauth[_-]?token|api[_-]?key|private[_-]?key|client[_-]?secret|consumer[_-]?secret|token|key|password|passwd|pwd|secret|credential|auth(?:orization)?|signature|sig)"
    return re.sub(rf"(?i)([?&]{sensitive_key}=)[^&\s]+", r"\1[REDACTED]", value)


class BridgeHTTPServer(ThreadingHTTPServer):
    """Threaded bridge server that drains active requests during shutdown."""

    daemon_threads = False
    block_on_close = True


def build_mission_worker(*, worker_id: str = "worker") -> MissionWorker:
    """Construct a worker over the bridge's stores with a stable logical identity.

    Keep the historical default for one-worker deployments. Independent worker
    processes should be assigned distinct IDs; a restarted process should reuse
    its logical ID so the queue advances and enforces its durable generation.
    """
    core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
    queue = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3"), require_execution_fence=True, mission_store=core.store)
    scheduler = MissionScheduler(DB_PATH.with_name("mission_scheduler.sqlite3"), queue)

    def runtime_factory() -> MissionRuntime:
        return MissionRuntime(core.store, executor=core._executor, require_authorization_snapshot=True, require_execution_fence=True)

    return MissionWorker(queue, runtime_factory, worker_id=worker_id, scheduler=scheduler)


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION

    def _send(self, code, payload, ctype="application/json; charset=utf-8", headers=None):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for name, value in (headers or {}).items():
            values = value if isinstance(value, (list, tuple)) else (value,)
            for item in values:
                self.send_header(name, item)
        self.end_headers()
        self.wfile.write(raw)

    def _bridge_auth(self):
        supplied = self.headers.get("X-CyberSentinel-Token", "")
        return bool(BRIDGE_TOKEN) and hmac.compare_digest(supplied, BRIDGE_TOKEN)

    def _static(self, name):
        p = (WEB / name).resolve()
        if WEB.resolve() not in p.parents or not p.is_file() or p.suffix not in MIME:
            return self._send(404, {"ok": False, "error": "not_found"})
        return self._send(200, p.read_bytes(), MIME[p.suffix])

    def _read_json(self):
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:
            raise ValueError("invalid_content_length")
        raw_length = lengths[0] if lengths else "0"
        if not raw_length.isdecimal():
            raise ValueError("invalid_content_length")
        n = int(raw_length)
        if n > 32768:
            raise ValueError("request_too_large")
        if n and "application/json" not in self.headers.get("Content-Type", "").lower():
            raise ValueError("application_json_required")
        body = self.rfile.read(n)
        if len(body) != n:
            raise ValueError("truncated_request_body")
        return json.loads(body or b"{}")

    def _chat_auth(self):
        return self.headers.get("X-CyberSentinel-Owner-Session", "")

    def _owner_session(self):
        token = self._chat_auth()
        session = owner_password.resolve_session(token)
        if session is None or session.get("auth_method") != "username_password":
            return None
        return {**session, "session_token": token}

    def _mission_service(self) -> MissionService:
        core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
        runtime = MissionRuntime(core.store, executor=core._executor, require_authorization_snapshot=True, require_execution_fence=True)
        queue = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3"), require_execution_fence=True, mission_store=core.store)
        scheduler = MissionScheduler(DB_PATH.with_name("mission_scheduler.sqlite3"), queue)
        return MissionService(runtime, queue, scheduler, owner_revalidator=core.prepare_mission_for_queue)

    def _mission_owner(self):
        if not self._bridge_auth():
            self._send(401, {"ok": False, "error": "bridge authentication required"})
            return None
        owner_session = self._owner_session()
        if owner_session is None:
            self._send(403, {"ok": False, "error": "owner authentication required"})
            return None
        return owner_session

    def _mission_snapshot_factory(self, owner_identity: str, scope_context: dict | None = None):
        scope_context = scope_context or {}
        target = str(scope_context.get("target_id") or "api-target")
        root = str(scope_context.get("workspace_root") or Path.cwd().resolve())
        def factory(mission):
            actions = tuple(step.action for step in mission.plan.steps if step.action != "__planning_failure__")
            return MissionAuthorizationSnapshot.create(owner_identity=owner_identity, mission_id=mission.mission_id, target_identity=target, scope=("workspace",), allowed_actions=actions, forbidden_actions=tuple(scope_context.get("forbidden_actions", ())), allowed_tools=actions, time_window={"timezone": "UTC"}, max_duration=max(300, mission.max_iterations * 60), rate_limits={action: 10 for action in actions}, network_boundary={"allowed": tuple(scope_context.get("allowed_networks", ()))}, data_boundary={"allowed": (target,)}, credential_boundary={"allowed": tuple(scope_context.get("allowed_credentials", ()))}, workspace_boundary={"root": root}, policy_version="api-owner-policy", owner_approval=owner_identity)
        return factory

    def _public_enabled(self):
        local_bind = BRIDGE_HOST.casefold() in {"127.0.0.1", "localhost", "::1", "[::1]"}
        return bool(PUBLIC_WEB_ENABLED and (local_bind or PUBLIC_WEB_ORIGIN))

    def _public_origin_allowed(self):
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            return True
        if PUBLIC_WEB_ORIGIN:
            return origin.rstrip("/") == PUBLIC_WEB_ORIGIN.rstrip("/")
        host = self.headers.get("Host", "").strip()
        return bool(host and origin == f"http://{host}")

    def _public_cookie(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        morsel = cookie.get(PUBLIC_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _public_owner_cookie(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        morsel = cookie.get(PUBLIC_OWNER_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _public_guard(self, *, csrf=True):
        if not self._public_enabled():
            self._send(404, {"ok": False, "error": "public_boundary_disabled"})
            return None
        if not self._public_origin_allowed():
            self._send(403, {"ok": False, "error": "origin_not_allowed"})
            return None
        try:
            if csrf:
                return PUBLIC_SESSIONS.validate(self._public_cookie(), self.headers.get("X-CSRF-Token"))
            session = PUBLIC_SESSIONS.get(self._public_cookie())
            if session is None:
                raise PermissionError("public session required")
            return session
        except PermissionError as exc:
            self._send(401, {"ok": False, "error": str(exc)})
            return None

    def _public_cookie_header(self, session_id, max_age):
        if not PUBLIC_COOKIE_NAME_RE.fullmatch(PUBLIC_SESSION_COOKIE):
            raise RuntimeError("invalid public session cookie name")
        return f"{PUBLIC_SESSION_COOKIE}={session_id}; Max-Age={max_age}; Path=/api/public; HttpOnly; Secure; SameSite=Lax"

    def _public_owner_cookie_header(self, session_token: str, max_age: int) -> str:
        if not PUBLIC_COOKIE_NAME_RE.fullmatch(PUBLIC_OWNER_SESSION_COOKIE):
            raise RuntimeError("invalid Owner session cookie name")
        return f"{PUBLIC_OWNER_SESSION_COOKIE}={session_token}; Max-Age={max_age}; Path=/api/public; HttpOnly; Secure; SameSite=Lax"

    def _public_owner_session(self):
        token = self._public_owner_cookie()
        session = owner_password.resolve_session(token) if token else None
        if session is None or session.get("auth_method") != "username_password":
            return None
        return {**session, "session_token": token}

    def _public_mission_owner(self, *, csrf: bool = False):
        if self._public_guard(csrf=csrf) is None:
            return None
        owner = self._public_owner_session()
        if owner is None:
            self._send(403, {"ok": False, "error": "owner_authorization_required"})
            return None
        return owner

    def _public_scope_context(self, project) -> dict[str, object]:
        return {
            "target_id": f"local-project:{project.project_id}",
            "workspace_root": str(project.root_path.resolve()),
            "scope": ["workspace"],
            "allowed_networks": [],
            "allowed_credentials": [],
        }

    def _workspace_for_mission(self, mission_id: str, owner: dict, capability: str):
        service = self._mission_service()
        mission, owner_ref = service._authorized_mission(
            mission_id, owner["session_token"], allow_unbound_read=False
        )
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        if capability not in snapshot.allowed_actions or capability not in snapshot.allowed_tools:
            raise PermissionError("read-only workspace capability is not in this mission snapshot")
        valid, reason = snapshot.validate_for_mission(
            mission_id=mission.mission_id,
            owner_identity=owner_ref,
            target_identity=snapshot.target_identity,
            version=int(mission.provenance.get("authorization_snapshot_version", 1)),
        )
        if not valid:
            raise PermissionError(reason)
        root = str(snapshot.workspace_boundary.get("root", ""))
        if not root:
            raise PermissionError("mission has no authorized workspace root")
        root_path = Path(root).expanduser().resolve(strict=True)
        if not root_path.is_dir():
            raise PermissionError("mission workspace is unavailable")
        workspace = Workspace(
            root_path,
            mission_id=mission.mission_id,
            request_id=mission.request_id,
            tool_id=capability,
            authorization_snapshot=snapshot,
        )
        return mission, snapshot, workspace

    @staticmethod
    def _sensitive_workspace_path(path: Path, root: Path) -> bool:
        try:
            parts = tuple(part.casefold() for part in path.relative_to(root).parts)
        except ValueError:
            return True
        for part in parts:
            if part in PUBLIC_WORKSPACE_BLOCKED_DIRS or part in PUBLIC_WORKSPACE_BLOCKED_NAMES:
                return True
            if part.startswith(".env.") and part not in PUBLIC_WORKSPACE_SAFE_ENV_TEMPLATES:
                return True
        return False

    @staticmethod
    def _public_mission_summary(mission: dict, project_id: str = "") -> dict:
        fields = (
            "mission_id", "objective", "owner_request", "status", "request_id",
            "retry_count", "verification_state", "completion_proof", "queue",
        )
        result = {key: mission[key] for key in fields if key in mission}
        result["project_id"] = str(project_id or "")
        return result

    def _send_sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for event in events:
            self.wfile.write(sse(event))
            self.wfile.flush()

    def _public_get(self, parsed):
        if not self._public_enabled():
            return self._send(404, {"ok": False, "error": "public_boundary_disabled"})
        if not self._public_origin_allowed():
            return self._send(403, {"ok": False, "error": "origin_not_allowed"})
        if parsed.path == "/api/public/health":
            worker_health = None
            supervisor = getattr(self.server, "mission_worker_supervisor", None)
            if supervisor is not None:
                worker_health = supervisor.health()
            ready = worker_health is None or worker_health.get("state") == "RUNNING"
            return self._send(200 if ready else 503, {
                "ok": ready,
                "service": PRODUCT_NAME,
                "version": VERSION,
                **({"mission_worker": worker_health} if worker_health is not None else {}),
            })
        if parsed.path == "/api/public/auth/session":
            if self._public_guard(csrf=False) is None:
                return
            owner = self._public_owner_session()
            return self._send(200, {
                "ok": True,
                "authenticated": owner is not None,
                "username": str(owner.get("username", "")) if owner else "",
                "expires_at": str(owner.get("expires_at", "")) if owner else "",
            })
        if parsed.path == "/api/public/desktop/setup":
            if self._public_guard(csrf=False) is None:
                return
            model_state = _desktop_model_manager().public_state()
            return self._send(200, {
                "ok": True,
                "desktop_mode": DESKTOP_MODE,
                "owner_configured": owner_password.owner_account_exists(),
                "model_manager": model_state,
            })
        if parsed.path == "/api/public/desktop/models":
            if self._public_guard(csrf=False) is None:
                return
            return self._send(200, _desktop_model_manager().public_state())
        if parsed.path == "/api/public/projects":
            owner = self._public_mission_owner()
            if owner is None:
                return
            try:
                store = _project_store()
                store.ensure_default(int(owner["owner_id"]))
                return self._send(200, {
                    "ok": True,
                    "projects": store.list(int(owner["owner_id"])),
                })
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if parsed.path == "/api/public/providers":
            if self._public_mission_owner() is None:
                return
            router = getattr(RUNTIME, "router", None)
            providers = getattr(router, "providers", ()) or ()
            capability_names = (
                "generate", "stream", "tool_calling", "structured_output",
                "chat", "native_chat", "parallel_tool_calls", "reasoning",
                "reasoning_budget", "long_context", "vision",
            )
            safe_providers = []
            known_names = {"local", "colab", "hf", "default"}
            for provider in providers[:32]:
                name = str(getattr(provider, "name", ""))
                capabilities = getattr(provider, "capabilities", None)
                try:
                    failure_count = min(
                        max(int(getattr(provider, "failure_count", 0)), 0),
                        1_000_000,
                    )
                except (TypeError, ValueError):
                    failure_count = 0
                safe_providers.append({
                    "name": name if name in known_names else "configured_provider",
                    "configured": bool(
                        getattr(provider, "base_url", "")
                        and getattr(provider, "model", "")
                    ),
                    "failure_count": failure_count,
                    "capabilities": {
                        key: bool(getattr(capabilities, key, False))
                        for key in capability_names
                    },
                })
            return self._send(200, {"ok": True, "providers": safe_providers})
        if parsed.path == "/api/public/missions":
            owner = self._public_mission_owner()
            if owner is None:
                return
            try:
                raw_limit = parse_qs(parsed.query).get("limit", ["100"])[0]
                limit = int(raw_limit)
                if not 1 <= limit <= 100:
                    raise ValueError("mission listing limit must be between 1 and 100")
                missions = self._mission_service().list_missions(
                    owner_session_token=owner["session_token"], limit=limit
                )
                store = _project_store()
                default_project = store.ensure_default(int(owner["owner_id"]))
                mission_ids = [str(item.get("mission_id", "")) for item in missions]
                project_map = store.map_missions(int(owner["owner_id"]), mission_ids)
                for mission_id in mission_ids:
                    if mission_id and mission_id not in project_map:
                        store.assign_mission(int(owner["owner_id"]), mission_id, default_project.project_id)
                        project_map[mission_id] = default_project.project_id
                return self._send(200, {
                    "ok": True,
                    "missions": [
                        self._public_mission_summary(item, project_map.get(str(item.get("mission_id", "")), ""))
                        for item in missions
                    ],
                })
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, TypeError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if parsed.path.startswith("/api/public/missions/"):
            owner = self._public_mission_owner()
            if owner is None:
                return
            parts = [unquote(item) for item in parsed.path[len("/api/public/missions/"):].split("/")]
            mission_id = parts[0] if parts else ""
            if not PUBLIC_MISSION_ID_RE.fullmatch(mission_id):
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            action = parts[1] if len(parts) > 1 else "status"
            try:
                service = self._mission_service()
                service._authorized_mission(
                    mission_id,
                    owner["session_token"],
                    allow_unbound_read=False,
                )
                if action == "effects" and len(parts) == 2:
                    effects = service.effects(mission_id, owner_session_token=owner["session_token"])
                    return self._send(200, {"ok": True, "mission_id": mission_id, "effects": effects})
                if action == "effects" and len(parts) == 3:
                    effect = service.inspect_effect(
                        mission_id, parts[2], owner_session_token=owner["session_token"]
                    )
                    return self._send(200, {"ok": True, "mission_id": mission_id, "effect": effect})
                values = {
                    "status": service.status,
                    "timeline": service.timeline,
                    "evidence": service.evidence,
                    "artifacts": service.artifacts,
                    "logs": service.logs,
                    "report": service.report,
                }
                if len(parts) != 2 or action not in values:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                value = values[action](mission_id, owner_session_token=owner["session_token"])
                return self._send(200, {"ok": True, "mission_id": mission_id, action: value})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if parsed.path.startswith("/api/public/workspace/"):
            owner = self._public_mission_owner()
            if owner is None:
                return
            parts = [unquote(item) for item in parsed.path[len("/api/public/workspace/"):].split("/")]
            if len(parts) != 2 or not PUBLIC_MISSION_ID_RE.fullmatch(parts[0]):
                return self._send(404, {"ok": False, "error": "not_found"})
            mission_id, action = parts
            query = parse_qs(parsed.query)
            relative = query.get("path", [""])[0] if action == "file" else query.get("path", ["."])[0]
            if len(relative) > 1024:
                return self._send(400, {"ok": False, "error": "path_too_long"})
            capability = "git_read" if action == "git" else "workspace_read"
            try:
                mission, _snapshot, workspace = self._workspace_for_mission(mission_id, owner, capability)
                secure_access = (
                    workspace.supports_secure_public_git_access
                    if action == "git"
                    else workspace.supports_secure_public_workspace_access
                )
                if action in {"files", "file", "git"} and not secure_access:
                    return self._send(501, {
                        "ok": False,
                        "error": "secure_workspace_access_unavailable",
                    })
                root = workspace.root
                if action == "files":
                    directory = workspace.resolve(relative)
                    if self._sensitive_workspace_path(directory, root):
                        return self._send(404, {"ok": False, "error": "not_found"})
                    entries = workspace.list_entries(relative, limit=500)
                    files = []
                    for item in entries:
                        try:
                            candidate = workspace.resolve(str(Path(relative) / item["name"]))
                        except WorkspaceBoundaryError:
                            continue
                        if not self._sensitive_workspace_path(candidate, root):
                            files.append(item)
                    return self._send(200, {
                        "ok": True,
                        "mission_id": mission_id,
                        "path": relative,
                        "files": files,
                        "truncated": len(entries) >= 500,
                    })
                if action == "file":
                    if not relative:
                        return self._send(400, {"ok": False, "error": "path_required"})
                    resolved = workspace.resolve(relative)
                    if self._sensitive_workspace_path(resolved, root):
                        return self._send(404, {"ok": False, "error": "not_found"})
                    content = workspace.read_bounded(relative, max_bytes=MAX_PUBLIC_WORKSPACE_FILE_BYTES)
                    return self._send(200, {
                        "ok": True,
                        "mission_id": mission_id,
                        "path": relative,
                        "content": content,
                    })
                if action == "git":
                    operation = query.get("operation", ["status"])[0]
                    result = workspace.git_readonly(operation, timeout=15.0)
                    output = result.stdout
                    error_output = result.stderr
                    if operation == "remote":
                        output = _redact_git_remote(output)
                        error_output = _redact_git_remote(error_output)
                    return self._send(200, {
                        "ok": result.ok,
                        "mission_id": mission_id,
                        "operation": operation,
                        "output": output,
                        "error_output": error_output,
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                    })
                return self._send(404, {"ok": False, "error": "unknown_workspace_action"})
            except (WorkspaceBoundaryError, FileNotFoundError, NotADirectoryError):
                return self._send(404, {"ok": False, "error": "not_found"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, UnicodeDecodeError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
            except OSError:
                return self._send(404, {"ok": False, "error": "not_found"})
            finally:
                if "workspace" in locals():
                    workspace.close()
        return self._send(404, {"ok": False, "error": "not_found"})

    def _public_post(self, parsed):
        path = parsed.path
        if not self._public_enabled():
            return self._send(404, {"ok": False, "error": "public_boundary_disabled"})
        if not self._public_origin_allowed():
            return self._send(403, {"ok": False, "error": "origin_not_allowed"})
        if path == "/api/public/session":
            session = PUBLIC_SESSIONS.create()
            return self._send(
                201,
                {"ok": True, "session": session.public()},
                headers={"Set-Cookie": self._public_cookie_header(session.session_id, PUBLIC_SESSION_TTL_SECONDS)},
            )
        if path == "/api/public/logout":
            session = self._public_guard(csrf=True)
            if session is None:
                return
            PUBLIC_SESSIONS.revoke(session.session_id)
            owner_token = self._public_owner_cookie()
            if owner_token:
                owner_password_logout(owner_token)
            return self._send(200, {"ok": True}, headers={
                "Set-Cookie": [
                    self._public_cookie_header("", 0),
                    self._public_owner_cookie_header("", 0),
                ]
            })
        if path == "/api/public/auth/login":
            if self._public_guard(csrf=True) is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                session = owner_password_login(
                    str(payload.get("username", "")),
                    str(payload.get("password", "")),
                )
                token = str(session.get("session_id", ""))
                if not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
                    raise PermissionError("invalid_credentials")
            except Exception:
                return self._send(403, {"ok": False, "error": "invalid_credentials"})
            return self._send(200, {
                "ok": True,
                "authenticated": True,
                "username": str(session.get("username", "")),
                "expires_at": str(session.get("expires_at", "")),
            }, headers={
                "Set-Cookie": self._public_owner_cookie_header(token, owner_password.SESSION_TTL_SECONDS)
            })
        if path == "/api/public/projects":
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                project = _project_store().create(
                    int(owner["owner_id"]), payload.get("name"), payload.get("description", "")
                )
                return self._send(201, {"ok": True, "project": project.public(mission_count=0)})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if path == "/api/public/projects/import":
            if not DESKTOP_MODE or not DESKTOP_SETUP_TOKEN:
                return self._send(404, {"ok": False, "error": "not_found"})
            origin = self.headers.get("Origin", "").strip()
            selection_key = self.headers.get("X-CyberSentinel-Desktop-Capability", "")
            if not origin or not hmac.compare_digest(selection_key, DESKTOP_SETUP_TOKEN):
                return self._send(403, {"ok": False, "error": "native_folder_selection_required"})
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                project = _project_store().create(
                    int(owner["owner_id"]),
                    payload.get("name"),
                    payload.get("description", ""),
                    selected_root=payload.get("selected_root"),
                )
                return self._send(201, {"ok": True, "project": project.public(mission_count=0)})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if path.startswith("/api/public/projects/"):
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            project_id = unquote(path[len("/api/public/projects/"):])
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                action = str(payload.get("action", "update"))
                if action == "archive":
                    project = _project_store().update(int(owner["owner_id"]), project_id, archived=True)
                elif action == "unarchive":
                    project = _project_store().update(int(owner["owner_id"]), project_id, archived=False)
                elif action == "update":
                    project = _project_store().update(
                        int(owner["owner_id"]), project_id,
                        name=payload.get("name") if "name" in payload else None,
                        description=payload.get("description") if "description" in payload else None,
                    )
                else:
                    return self._send(400, {"ok": False, "error": "unknown_project_action"})
                return self._send(200, {"ok": True, "project": project.public()})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_project"})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if path.startswith("/api/public/desktop/models/"):
            session = self._public_guard(csrf=True)
            if session is None:
                return
            parts = [unquote(item) for item in path[len("/api/public/desktop/models/"):].split("/")]
            if len(parts) != 2 or parts[1] not in {"install", "activate"}:
                return self._send(404, {"ok": False, "error": "not_found"})
            owner = self._public_owner_session()
            if owner_password.owner_account_exists() and owner is None:
                return self._send(403, {"ok": False, "error": "owner_authorization_required"})
            try:
                if parts[1] == "install":
                    result = _desktop_model_manager().install(parts[0])
                else:
                    if owner is not None:
                        missions = self._mission_service().list_missions(
                            owner_session_token=owner["session_token"], limit=100
                        )
                        terminal = {
                            "GOAL_COMPLETED", "COMPLETED", "CANCELLED", "FAILED",
                            "FAILED_RETRY_EXHAUSTED", "OWNER_INPUT_REQUIRED",
                            "OWNER_REAUTH_REQUIRED", "RECOVERY_REQUIRED", "PAUSED",
                            "SCOPE_BLOCKED", "SAFETY_BLOCKED", "TERMINAL_FAILURE",
                        }
                        busy = any(
                            str(item.get("status", "")).upper() not in terminal
                            or str((item.get("queue") or {}).get("state", "")).lower()
                            in {"ready", "queued", "leased", "running", "retry", "waiting"}
                            for item in missions
                        )
                        if busy:
                            return self._send(409, {"ok": False, "error": "model_switch_blocked_by_active_mission"})
                    result = _desktop_model_manager().activate(parts[0])
                return self._send(202, result)
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_model"})
            except FileNotFoundError as exc:
                return self._send(409, {"ok": False, "error": str(exc)})
            except RuntimeError as exc:
                return self._send(409, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                return self._send(409 if str(exc).startswith("model_not_compatible") else 400, {"ok": False, "error": str(exc)})
        if path == "/api/public/auth/logout":
            if self._public_guard(csrf=True) is None:
                return
            token = self._public_owner_cookie()
            if token:
                owner_password_logout(token)
            return self._send(200, {"ok": True, "authenticated": False}, headers={
                "Set-Cookie": self._public_owner_cookie_header("", 0)
            })
        if path == "/api/public/chat":
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                safe_payload = dict(payload)
                safe_payload.pop("scope_context", None)
                safe_payload.pop("completion_criteria", None)
                requested_project_id = str(safe_payload.pop("project_id", "") or "")
                store = _project_store()
                project = (
                    store.get(int(owner["owner_id"]), requested_project_id, include_archived=False)
                    if requested_project_id
                    else store.ensure_default(int(owner["owner_id"]))
                )
                safe_payload["scope_context"] = self._public_scope_context(project)
                result = chat(safe_payload, owner_session_token=owner["session_token"])
                mission_id = str(result.get("mission_id", ""))
                if not mission_id and isinstance(result.get("mission"), dict):
                    mission_id = str(result["mission"].get("mission_id", ""))
                if mission_id:
                    store.assign_mission(int(owner["owner_id"]), mission_id, project.project_id)
                return self._send(200, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_project"})
            except ValueError as exc:
                status = 413 if str(exc) == "request_too_large" else 400
                return self._send(status, {"ok": False, "error": str(exc)})
            except Exception:
                return self._send(502, {"ok": False, "error": "mission_request_failed"})
        if path == "/api/public/missions":
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                objective = str(payload.get("objective", "")).strip()
                if not objective:
                    raise ValueError("objective_required")
                if len(objective) > 12_000:
                    raise ValueError("objective_too_long")
                store = _project_store()
                requested_project_id = str(payload.get("project_id", "") or "")
                project = (
                    store.get(int(owner["owner_id"]), requested_project_id, include_archived=False)
                    if requested_project_id
                    else store.ensure_default(int(owner["owner_id"]))
                )
                scope_context = self._public_scope_context(project)
                core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
                mission = core.run_owner_mission(
                    objective,
                    owner_session_token=owner["session_token"],
                    request_id=uuid.uuid4().hex,
                    scope_context=scope_context,
                    run=False,
                )
                store.assign_mission(int(owner["owner_id"]), mission.mission_id, project.project_id)
                service = self._mission_service()
                service.start_mission(mission.mission_id, owner_session_token=owner["session_token"])
                current = service.status(mission.mission_id, owner_session_token=owner["session_token"])
                return self._send(201, {
                    "ok": True,
                    "mission_id": mission.mission_id,
                    "mission": self._public_mission_summary(current, project.project_id),
                    "project_id": project.project_id,
                    "queue": current.get("queue", {}),
                })
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError as exc:
                error = "unknown_project" if "unknown_project" in str(exc) else "unknown_mission"
                return self._send(404, {"ok": False, "error": error})
            except ValueError as exc:
                status = 413 if str(exc) == "request_too_large" else 400
                return self._send(status, {"ok": False, "error": str(exc)})
            except RuntimeError as exc:
                return self._send(409, {"ok": False, "error": str(exc)})
            except Exception:
                return self._send(502, {"ok": False, "error": "mission_creation_failed"})
        if path.startswith("/api/public/missions/"):
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            parts = [unquote(item) for item in path[len("/api/public/missions/"):].split("/")]
            mission_id = parts[0] if parts else ""
            if not PUBLIC_MISSION_ID_RE.fullmatch(mission_id):
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            try:
                service = self._mission_service()
                if len(parts) == 4 and parts[1] == "effects" and parts[3] == "reconcile":
                    payload = self._read_json()
                    if not isinstance(payload, dict):
                        raise ValueError("invalid_request")
                    outcome = str(payload.get("outcome", ""))
                    evidence_reference = str(payload.get("evidence_reference", "")).strip()
                    if len(evidence_reference) > 512:
                        raise ValueError("evidence_reference_too_long")
                    result = service.reconcile_effect(
                        mission_id,
                        parts[2],
                        owner_session_token=owner["session_token"],
                        outcome=outcome,
                        evidence_reference=evidence_reference,
                    )
                    return self._send(200, {"ok": True, "mission_id": mission_id, "reconciliation": result})
                if len(parts) == 2 and parts[1] == "reconcile":
                    return self._send(400, {"ok": False, "error": "effect_id_and_evidence_reference_required"})
                action = parts[1] if len(parts) > 1 else "start"
                if len(parts) != 2:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                if action == "start":
                    result = service.start_mission(mission_id, owner_session_token=owner["session_token"])
                elif action == "resume":
                    result = service.resume_mission(mission_id, owner_session_token=owner["session_token"])
                elif action == "pause":
                    result = service.pause_mission(mission_id, owner_session_token=owner["session_token"])
                elif action == "cancel":
                    result = service.cancel_mission(mission_id, owner_session_token=owner["session_token"])
                else:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                return self._send(200, {"ok": True, "mission": result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            except ValueError as exc:
                status = 413 if str(exc) == "request_too_large" else 400
                return self._send(status, {"ok": False, "error": str(exc)})
            except RuntimeError as exc:
                return self._send(409, {"ok": False, "error": str(exc)})
        return self._send(404, {"ok": False, "error": "not_found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/public/"):
            return self._public_get(parsed)
        if self.path == "/api/health":
            if DESKTOP_MODE and not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            return self._send(200, {"ok": True, "service": PRODUCT_NAME, "version": VERSION})
        if self.path == "/api/health/live":
            return self._send(
                200,
                {
                    "ok": True,
                    "service": PRODUCT_NAME,
                    "version": VERSION,
                    "state": "PROCESS_ALIVE",
                },
            )
        if self.path == "/api/health/ready":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            providers = getattr(getattr(RUNTIME, "router", None), "providers", ())
            snapshot = readiness_snapshot(DB_PATH, provider_configured=bool(providers))
            return self._send(
                200 if snapshot["ready"] else 503,
                {"ok": snapshot["ready"], **snapshot},
            )
        if self.path == "/api/public/health":
            if not self._public_enabled() or not self._public_origin_allowed():
                return self._send(404, {"ok": False, "error": "not_found"})
            return self._send(200, {"ok": True, "service": PRODUCT_NAME, "version": VERSION})
        if self.path == "/":
            return self._static("index.html")
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/missions/"):
            auth = self._mission_owner()
            if auth is None:
                return
            parts = parsed.path[len("/api/missions/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else "status"
            try:
                service = self._mission_service()
                if action == "effects" and len(parts) == 3:
                    value = service.inspect_effect(
                        mission_id,
                        parts[2],
                        owner_session_token=auth["session_token"],
                    )
                    return self._send(200, {"ok": True, "mission_id": mission_id, "effect": value})
                if action == "effects" and len(parts) == 2:
                    value = service.effects(mission_id, owner_session_token=auth["session_token"])
                    return self._send(200, {"ok": True, "mission_id": mission_id, "effects": value})
                values = {"status": service.status, "timeline": service.timeline, "evidence": service.evidence, "artifacts": service.artifacts, "logs": service.logs, "report": service.report}
                if len(parts) > 2 or action not in values:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                return self._send(200, {"ok": True, "mission_id": mission_id, action: values[action](mission_id, owner_session_token=auth["session_token"])})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
        if parsed.path == "/api/tools":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            return self._send(200, {"ok": True, "tools": tool_definitions()})
        if parsed.path.startswith("/api/session/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            session_id = parsed.path[len("/api/session/"):]
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            value = get_session(session_id, owner_session_id=owner_session["session_id"])
            return self._send(200 if value else 404, {"ok": bool(value), "session": value} if value else {"ok": False, "error": "unknown_session"})
        if parsed.path == "/api/chat/stream":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            query = parse_qs(parsed.query)
            payload = {"text": query.get("text", [""])[0], "conversation_id": query.get("conversation_id", [""])[0]}
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            return self._send_sse(stream(payload, owner_session_token=owner_session["session_token"]))
        if parsed.path.startswith("/api/tasks/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            task_id = parsed.path[len("/api/tasks/"):]
            if task_id.endswith("/stream"):
                task_id = task_id[:-len("/stream")].rstrip("/")
                task = TaskManager.get_task(task_id)
                if task is None:
                    return self._send(404, {"ok": False, "error": "unknown_task"})
                if not task.owner_session_id or task.owner_session_id != owner_session["session_id"]:
                    return self._send(404, {"ok": False, "error": "unknown_task"})
                return self._send_sse(task_stream(task_id, owner_session_token=self._chat_auth()))
            task = TaskManager.get_task(task_id)
            if task is None:
                return self._send(404, {"ok": False, "error": "unknown_task"})
            if not task.owner_session_id or task.owner_session_id != owner_session["session_id"]:
                return self._send(404, {"ok": False, "error": "unknown_task"})
            return self._send(200, {"ok": True, "task": task.to_dict()})
        if self.path in {"/app.js", "/style.css"}:
            return self._static(self.path[1:])
        if self.path.startswith("/static/"):
            return self._static(self.path[8:])
        if self.path == "/api/status":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            return self._send(200, status())
        if self.path.startswith("/api/execution/"):
            owner_session = self._mission_owner()
            if owner_session is None:
                return
            request_id = self.path[len("/api/execution/"):]
            record = get_lifecycle(request_id)
            if record is None or not record.owner_session_id or record.owner_session_id != owner_session["session_id"]:
                return self._send(404, {"ok": False, "error": "unknown_request_id"})
            return self._send(200, {"ok": True, "request_id": request_id, "lifecycle": record.__dict__, "events": events_for_request(request_id)})
        if self.path.startswith("/api/reasoning/"):
            owner_session = self._mission_owner()
            if owner_session is None:
                return
            request_id = self.path[len("/api/reasoning/"):]
            record = get_lifecycle(request_id)
            if record is None or not record.owner_session_id or record.owner_session_id != owner_session["session_id"]:
                return self._send(404, {"ok": False, "error": "unknown_reasoning_request"})
            memory = reasoning_for_request(request_id)
            if memory is None:
                return self._send(404, {"ok": False, "error": "unknown_reasoning_request"})
            return self._send(200, {"ok": True, "request_id": request_id, "memory": memory})
        return self._send(404, {"ok": False, "error": "not_found"})

    def _desktop_bootstrap_owner(self):
        if not DESKTOP_MODE or not DESKTOP_SETUP_TOKEN or not self._public_enabled():
            return self._send(404, {"ok": False, "error": "not_found"})
        origin = self.headers.get("Origin", "").strip()
        supplied = self.headers.get("X-CyberSentinel-Setup-Key", "")
        if not origin or not self._public_origin_allowed():
            return self._send(403, {"ok": False, "error": "origin_not_allowed"})
        if not hmac.compare_digest(supplied, DESKTOP_SETUP_TOKEN):
            return self._send(403, {"ok": False, "error": "desktop_setup_authorization_required"})
        if owner_password.owner_account_exists():
            return self._send(409, {"ok": False, "error": "owner_account_already_exists"})
        try:
            payload = self._read_json()
            if not isinstance(payload, dict):
                raise ValueError("invalid_request")
            password = payload.get("password")
            if not isinstance(password, str) or not 12 <= len(password) <= 256:
                raise ValueError("password_must_be_12_to_256_characters")
            owner_id = owner_password.create_owner_account(owner_password.OWNER_USERNAME, password)
            _project_store().ensure_default(owner_id)
            return self._send(201, {"ok": True, "owner_created": True})
        except PermissionError as exc:
            return self._send(409, {"ok": False, "error": str(exc)})
        except ValueError as exc:
            return self._send(400, {"ok": False, "error": str(exc)})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/desktop/bootstrap-owner":
            return self._desktop_bootstrap_owner()
        if parsed.path.startswith("/api/public/"):
            return self._public_post(parsed)
        if self.path == "/api/missions":
            auth = self._mission_owner()
            if auth is None:
                return
            try:
                payload = self._read_json()
                if isinstance(payload.get("plan"), dict):
                    objective = str(payload.get("objective") or payload.get("text") or "").strip()
                    if not objective:
                        raise ValueError("objective_required")
                    raw_plan = payload["plan"]
                    raw_steps = raw_plan.get("steps", [])
                    steps = tuple(PlanStep(step_id=str(item["step_id"]), objective=str(item.get("objective", item["step_id"])), prerequisites=tuple(item.get("prerequisites", ())), action=str(item.get("action", "")), expected_observation=str(item.get("expected_observation", "")), authorization_requirement=str(item.get("authorization_requirement", "owner")), scope_requirement=str(item.get("scope_requirement", "")), retry_policy=dict(item.get("retry_policy", {})), verification=tuple(item.get("verification", ()))) for item in raw_steps)
                    plan = Plan(version=int(raw_plan.get("version", 1)), objective=objective, assumptions=tuple(raw_plan.get("assumptions", ())), steps=steps, dependencies=tuple(raw_plan.get("dependencies", ())), completion_criteria=tuple(raw_plan.get("completion_criteria", ())), risk=str(raw_plan.get("risk", "unknown")), created_from=str(raw_plan.get("created_from", "api")))
                    owner_identity = f"owner:{int(auth['owner_id'])}"
                    mission = self._mission_service().create_mission(objective, objective, plan, owner_identity_ref=owner_identity, scope_snapshot=payload.get("scope_context"), completion_criteria=payload.get("completion_criteria") or [], authorization_snapshot_factory=self._mission_snapshot_factory(owner_identity, payload.get("scope_context")))
                    return self._send(201, {"ok": True, "mission": mission, "mission_id": mission["mission_id"], "status": mission["status"]})
                result = chat(payload, owner_session_token=auth["session_token"])
                return self._send(201, {"ok": True, "mission": result.get("mission"), "mission_id": result.get("mission_id"), "status": result.get("status")})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path.startswith("/api/missions/"):
            auth = self._mission_owner()
            if auth is None:
                return
            parts = self.path[len("/api/missions/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else "start"
            try:
                service = self._mission_service()
                if len(parts) == 4 and parts[1] == "effects" and parts[3] == "reconcile":
                    payload = self._read_json()
                    result = service.reconcile_effect(
                        mission_id,
                        parts[2],
                        owner_session_token=auth["session_token"],
                        outcome=str(payload.get("outcome", "")),
                        evidence_reference=str(payload.get("evidence_reference", "")),
                    )
                    return self._send(200, {"ok": True, "mission_id": mission_id, "reconciliation": result})
                if action == "start" or action == "resume":
                    if action == "start":
                        result = service.start_mission(
                            mission_id, owner_session_token=auth["session_token"]
                        )
                    else:
                        result = service.resume_mission(
                            mission_id, owner_session_token=auth["session_token"]
                        )
                    return self._send(200, {"ok": True, "mission": result})
                if action == "pause":
                    return self._send(200, {"ok": True, "mission": service.pause_mission(mission_id, owner_session_token=auth["session_token"])})
                if action == "cancel":
                    return self._send(200, {"ok": True, "mission": service.cancel_mission(mission_id, owner_session_token=auth["session_token"])})
                if action == "schedule":
                    payload = self._read_json()
                    return self._send(201, {"ok": True, "schedule": service.schedule_mission(mission_id, owner_session_token=auth["session_token"], run_at=str(payload["run_at"]), interval_seconds=payload.get("interval_seconds"), retry_limit=int(payload.get("retry_limit", 0)))})
                return self._send(404, {"ok": False, "error": "unknown_mission_action"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if not self._bridge_auth():
            return self._send(401, {"ok": False, "error": "bridge authentication required"})
        if self.path == "/api/auth/login":
            # Canonical human Owner authentication: username + password only.
            # Generic 403 on ANY failure: never reveal whether the username exists.
            try:
                payload = self._read_json()
                session = owner_password_login(
                    str(payload.get("username", "")), str(payload.get("password", ""))
                )
            except Exception:
                return self._send(403, {"ok": False, "error": "invalid_credentials"})
            return self._send(200, {"ok": True, "session": session})
        if self.path == "/api/auth/logout":
            # Revoke the server-side session; idempotent and unauthenticated by design.
            try:
                payload = self._read_json()
            except Exception:
                payload = {}
            session_id = str(payload.get("session_id", "")) if isinstance(payload, dict) else ""
            owner_password_logout(session_id)
            return self._send(200, {"ok": True})
        if self.path == "/api/chat":
            try:
                payload = self._read_json()
                owner_session = self._owner_session()
                if owner_session is None:
                    raise PermissionError("owner authentication required")
                result = chat(payload, owner_session_token=owner_session["session_token"])
                return self._send(200, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
            except Exception:
                return self._send(500, {"ok": False, "error": "chat_failed"})
        if self.path == "/api/tasks":
            try:
                payload = self._read_json()
                owner_session = self._owner_session()
                if owner_session is None:
                    raise PermissionError("owner authentication required")
                result = create_task(payload, owner_session_token=owner_session["session_token"], run=bool(payload.get("run", True)))
                return self._send(201, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path.startswith("/api/tasks/"):
            try:
                task_id, action = self.path[len("/api/tasks/"):].split("/", 1)
                owner_session = self._owner_session()
                if owner_session is None:
                    raise PermissionError("owner authentication required")
                if action == "resume":
                    result = resume_task(task_id, owner_session_token=owner_session["session_token"], run=True)
                elif action == "pause":
                    result = pause_task(task_id, owner_session_token=owner_session["session_token"])
                elif action == "cancel":
                    result = cancel_task(task_id, owner_session_token=owner_session["session_token"])
                else:
                    return self._send(404, {"ok": False, "error": "unknown_task_action"})
                return self._send(200, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path == "/api/cancel":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            try:
                data = self._read_json()
                if not isinstance(data, dict):
                    return self._send(400, {"ok": False, "error": "invalid_request"})
                request_id = str(data.get("request_id", "")).strip()
                if not request_id:
                    return self._send(400, {"ok": False, "error": "request_id_required"})
                record = request_cancel(request_id, owner_session_id=owner_session["session_id"])
                return self._send(200, {"ok": True, "request_id": request_id, "lifecycle": record.status, "cancel_requested": record.cancel_requested})
            except PermissionError:
                return self._send(404, {"ok": False, "error": "unknown_request_id"})
            except ValueError as exc:
                if str(exc) == "request_too_large":
                    return self._send(413, {"ok": False, "error": "request_too_large"})
                if str(exc) == "unknown request_id":
                    return self._send(404, {"ok": False, "error": "unknown_request_id"})
                return self._send(400, {"ok": False, "error": "invalid_request"})
            except Exception:
                return self._send(400, {"ok": False, "error": "invalid_request"})
        if self.path != "/api/command":
            return self._send(404, {"ok": False, "error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 32768:
                return self._send(413, {"ok": False, "error": "request_too_large"})
            data = json.loads(self.rfile.read(n) or b"{}")
            text = str(data.get("text", "")).strip()
            if not text:
                return self._send(400, {"ok": False, "error": "text_required"})
            request_id = str(data.get("request_id", self.headers.get("X-CyberSentinel-Request-ID", ""))).strip()
            if request_id and (len(request_id) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in request_id)):
                return self._send(400, {"ok": False, "error": "invalid_request_id"})
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            result = chat(
                {**data, "text": text, "request_id": request_id or None},
                owner_session_token=owner_session["session_token"],
            )
            return self._send(200, {"ok": True, **result})
        except Exception:
            return self._send(400, {"ok": False, "error": "invalid_request"})

    def log_message(self, fmt, *args):
        print("[bridge]", fmt % args)


def main():
    if "--desktop-self-test" in sys.argv[1:]:
        required = (WEB / "index.html", WEB / "app.js", WEB / "style.css")
        missing = [path.name for path in required if not path.is_file()]
        if missing:
            raise SystemExit("desktop_bundle_missing:" + ",".join(missing))
        print(json.dumps({"ok": True, "version": VERSION, "web_assets": len(required)}), flush=True)
        return
    if not BRIDGE_TOKEN:
        raise SystemExit("BRIDGE_TOKEN is required in .env")
    if DESKTOP_MODE:
        _desktop_model_manager()
    server = BridgeHTTPServer((BRIDGE_HOST, BRIDGE_PORT), Handler)
    worker_stop = threading.Event()
    worker_thread: threading.Thread | None = None
    loopback_host = BRIDGE_HOST.casefold() in {"127.0.0.1", "localhost", "::1", "[::1]"}
    if PUBLIC_WEB_ENABLED and loopback_host:
        supervisor = RuntimeSupervisor(
            build_mission_worker(worker_id="desktop-bridge"),
            poll_interval_seconds=0.5,
        )
        server.mission_worker_supervisor = supervisor
        worker_thread = threading.Thread(
            target=supervisor.serve_forever,
            kwargs={"stop_event": worker_stop},
            name="desktop-mission-worker",
            daemon=False,
        )
        worker_thread.start()
    print(f"{PRODUCT_NAME} {VERSION}: http://{BRIDGE_HOST}:{server.server_address[1]}", flush=True)
    print("Local-only defensive engine, threat intelligence, planner and audit enabled.", flush=True)
    shutdown_started = threading.Event()
    shutdown_thread: threading.Thread | None = None
    stop_signals = (signal.SIGINT, signal.SIGTERM)
    previous_handlers = {signum: signal.getsignal(signum) for signum in stop_signals}

    def request_shutdown(_signum, _frame):
        nonlocal shutdown_thread
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        worker_stop.set()
        shutdown_thread = threading.Thread(
            target=server.shutdown,
            name="bridge-http-shutdown",
            daemon=True,
        )
        shutdown_thread.start()

    control_thread: threading.Thread | None = None
    if sys.argv[1:] == ["--desktop-stdio-control"]:
        def read_desktop_control() -> None:
            for line in sys.stdin:
                if line.rstrip("\r\n") == "CYBERSENTINEL_DESKTOP_SHUTDOWN":
                    request_shutdown(None, None)
                    return

        control_thread = threading.Thread(
            target=read_desktop_control,
            name="desktop-shutdown-control",
            daemon=True,
        )
        control_thread.start()

    try:
        for signum in stop_signals:
            signal.signal(signum, request_shutdown)
        server.serve_forever()
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        worker_stop.set()
        if worker_thread is not None:
            worker_thread.join()
        server.server_close()
        if shutdown_thread is not None:
            shutdown_thread.join()
        _shutdown_desktop_services()


if __name__ == "__main__":
    main()
