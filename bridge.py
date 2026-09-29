from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit
import re
import uuid
import signal
from datetime import datetime, timezone
from threading import Event, Thread
from core.config import (
    BRIDGE_HOST,
    BRIDGE_PORT,
    BRIDGE_TOKEN,
    PUBLIC_SESSION_COOKIE,
    PUBLIC_SESSION_TTL_SECONDS,
    PUBLIC_OWNER_SESSION_COOKIE,
    PUBLIC_WEB_ENABLED,
    PUBLIC_WEB_ORIGIN,
    DB_PATH,
)
from core.engine import RUNTIME, status
from core.lifecycle import get as get_lifecycle, request_cancel
from core.db import events_for_request, reasoning_for_request
import security.owner_password as owner_password
from security.owner_password import login as owner_password_login, logout as owner_password_logout
from api.chat import chat, get_session, sse, stream, task_stream, create_task, get_task, resume_task, pause_task, cancel_task, _task_public
from agent.task_manager import TaskManager
from tools.registry import tool_definitions
from core.version import PRODUCT_NAME, SERVER_VERSION, VERSION
from security.public_session import DEFAULT_PUBLIC_SESSIONS
from api.missions import MissionService
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker, QueueCapacityError, WorkerMissionState
from agent.mission_runtime import MissionRuntime
from agent.mission import MissionStore, MissionStatus
from agent.agent_core import AgentCore
from agent.mission_task_adapter import task_owner_matches
from agent.planning import Plan, PlanStep
from security.mission_authorization import MissionAuthorizationSnapshot
from workspace import Workspace, WorkspaceBoundaryError, WorkspacePolicy, WorkspacePolicyError

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
WORKSPACE_GIT_DIFF_EXCLUSIONS = tuple(
    f":(exclude,icase,glob){pattern}"
    for pattern in (
        ".env*", "**/.env*", ".netrc", "**/.netrc", ".npmrc", "**/.npmrc", ".pypirc", "**/.pypirc", ".git-credentials", "**/.git-credentials",
        ".aws/**", "**/.aws/**", ".azure/**", "**/.azure/**", ".gcloud/**", "**/.gcloud/**", ".kube/**", "**/.kube/**", ".docker/**", "**/.docker/**", ".config/**", "**/.config/**", ".ssh/**", "**/.ssh/**", ".gnupg/**", "**/.gnupg/**", ".terraform/**", "**/.terraform/**", ".pulumi/**", "**/.pulumi/**", ".vercel/**", "**/.vercel/**",
        "id_rsa", "**/id_rsa", "id_dsa", "**/id_dsa", "id_ecdsa", "**/id_ecdsa", "id_ed25519", "**/id_ed25519", "id_ed25519_sk", "**/id_ed25519_sk", "id_xmss", "**/id_xmss", "identity", "**/identity", "authorized_keys", "**/authorized_keys", "known_hosts", "**/known_hosts",
        ".vault-token", "**/.vault-token", ".terraformrc", "**/.terraformrc", "terraform.rc", "**/terraform.rc", "terraform.tfstate*", "**/terraform.tfstate*", "credentials.json", "**/credentials.json", "token.json", "**/token.json", "client_secret.json", "**/client_secret.json",
        "*.key", "**/*.key", "*.pem", "**/*.pem", "*.p12", "**/*.p12", "*.pfx", "**/*.pfx", "*.crt", "**/*.crt", "*.cer", "**/*.cer", "*.der", "**/*.der", "*.ovpn", "**/*.ovpn", "*.sqlite*", "**/*.sqlite*", "*.db*", "**/*.db*", "secrets/**", "**/secrets/**", "credentials/**", "**/credentials/**",
    )
)


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
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _bridge_auth(self):
        return bool(BRIDGE_TOKEN) and self.headers.get("X-CyberSentinel-Token", "") == BRIDGE_TOKEN

    def _static(self, name):
        p = (WEB / name).resolve()
        if WEB.resolve() not in p.parents or not p.is_file() or p.suffix not in MIME:
            return self._send(404, {"ok": False, "error": "not_found"})
        return self._send(200, p.read_bytes(), MIME[p.suffix])

    def _read_json(self):
        n = int(self.headers.get("Content-Length", "0"))
        if n > 32768:
            raise ValueError("request_too_large")
        return json.loads(self.rfile.read(n) or b"{}")

    def _chat_auth(self):
        return self.headers.get("X-CyberSentinel-Owner-Session", "")

    def _owner_session(self):
        session = owner_password.resolve_session(self._chat_auth())
        if session is None or session.get("auth_method") != "username_password":
            return None
        return session

    def _mission_service(self) -> MissionService:
        core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
        runtime = MissionRuntime(core.store, executor=core._executor, require_authorization_snapshot=True)
        queue = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3"))
        scheduler = MissionScheduler(DB_PATH.with_name("mission_scheduler.sqlite3"), queue)
        return MissionService(runtime, queue, scheduler)

    def _mission_owner(self):
        if not self._bridge_auth():
            self._send(401, {"ok": False, "error": "bridge authentication required"})
            return None
        owner_session = self._owner_session()
        if owner_session is None:
            self._send(403, {"ok": False, "error": "owner authentication required"})
            return None
        return owner_session

    def _reauthorize_and_enqueue(self, mission_id: str, owner_session: dict, service: MissionService) -> dict:
        mission = service.mission(mission_id, owner_identity=str(owner_session["owner_id"]))
        try:
            queue_item = service.queue.get(mission_id)
        except KeyError:
            queue_item = None
        if queue_item is not None and queue_item.state is WorkerMissionState.EXECUTING:
            return {"mission": mission.to_public_dict(), "queue": {"state": queue_item.state.value, "attempts": queue_item.attempts, "available_at": queue_item.available_at}}
        if mission.status is MissionStatus.RECOVERY_REQUIRED or (mission.checkpoint or {}).get("status") in {"in_flight", "in_flight_parallel"}:
            raise ValueError("in-flight mission must be reconciled before resume")
        if mission.is_terminal and mission.status not in {MissionStatus.OWNER_INPUT_REQUIRED, MissionStatus.AUTHORIZATION_BLOCKED}:
            raise ValueError("terminal mission cannot be restarted")
        core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
        renewed = core.resume_mission(mission_id, owner_session_token=str(owner_session["session_id"]), run=False)
        queued = service.queue.enqueue(mission_id)
        return {"mission": renewed.to_public_dict(), "queue": {"state": queued.state.value, "attempts": queued.attempts, "available_at": queued.available_at}}

    def _reconcile_mission(self, mission_id: str, owner_session: dict, service: MissionService, executed: bool) -> dict:
        mission = service.mission(mission_id, owner_identity=str(owner_session["owner_id"]))
        if mission.status is not MissionStatus.RECOVERY_REQUIRED:
            raise ValueError("mission has no in-flight action requiring reconciliation")
        # The Owner resolves only whether the ambiguous side effect happened.
        # A browser-supplied observation is never accepted as completion proof.
        service.runtime.reconcile_in_flight(mission_id, executed=executed)
        return self._reauthorize_and_enqueue(mission_id, owner_session, service)

    def _public_mission_owner(self, *, csrf=False):
        if self._public_guard(csrf=csrf) is None:
            return None
        owner_session = self._public_owner_session()
        if owner_session is None:
            self._send(403, {"ok": False, "error": "owner_authorization_required"})
            return None
        return owner_session

    def _workspace_for_mission(self, mission_id: str, owner_id: str, capability: str):
        service = self._mission_service()
        mission = service.mission(mission_id, owner_identity=owner_id)
        snapshot = MissionAuthorizationSnapshot.from_dict(dict(mission.authorization_snapshot or {}))
        if capability not in snapshot.allowed_actions or capability not in snapshot.allowed_tools:
            raise PermissionError("read-only workspace capability is not in this mission snapshot")
        valid, reason = snapshot.validate_for_mission(
            mission_id=mission.mission_id,
            owner_identity=owner_id,
            target_identity=snapshot.target_identity,
        )
        if not valid:
            raise PermissionError(reason)
        root_value = str(snapshot.workspace_boundary.get("root", "")).strip()
        if not root_value:
            raise PermissionError("mission workspace boundary required")
        root = Path(root_value).expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError("mission workspace is unavailable")
        workspace = Workspace(
            root,
            policy=WorkspacePolicy(allow_network=False, allow_credentials=False),
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
        blocked_dirs = {".git", ".ssh", ".gnupg", ".aws", ".azure", ".gcloud", ".kube", ".docker", ".config", ".terraform", ".pulumi", ".vercel", "secrets", "credentials"}
        blocked_names = {".env", ".envrc", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".vault-token", ".terraformrc", "terraform.rc", "terraform.tfstate", "terraform.tfstate.backup", "credentials.json", "token.json", "client_secret.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk", "id_xmss", "identity", "authorized_keys", "known_hosts"}
        safe_env_templates = {".env.example", ".env.sample", ".env.template"}
        if any(part in blocked_dirs or part in blocked_names or (part.startswith(".env.") and part not in safe_env_templates) for part in parts):
            return True
        return any(part.endswith((".key", ".pem", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm", ".sqlite-wal", ".sqlite-shm", ".sqlite3-wal", ".sqlite3-shm")) for part in parts)

    @staticmethod
    def _redact_remote_url(value: str) -> str:
        line = str(value).strip()
        if "://" in line:
            parsed = urlsplit(line)
            host = parsed.hostname or ""
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
        return re.sub(r"^[^@\s]+@", "[redacted]@", line) if "@" in line and ":" in line.split("@", 1)[0] else line

    def _mission_snapshot_factory(self, owner_identity: str, scope_context: dict | None = None, owner_approval: str = ""):
        scope_context = scope_context or {}
        target = str(scope_context.get("target_id") or "api-target")
        root = str(scope_context.get("workspace_root") or Path.cwd().resolve())
        def factory(mission):
            actions = tuple(step.action for step in mission.plan.steps if step.action != "__planning_failure__")
            read_capabilities = ("workspace_read", "git_read")
            return MissionAuthorizationSnapshot.create(owner_identity=owner_identity, mission_id=mission.mission_id, target_identity=target, scope=("workspace",), allowed_actions=tuple(dict.fromkeys((*actions, *read_capabilities))), forbidden_actions=tuple(scope_context.get("forbidden_actions", ())), allowed_tools=tuple(dict.fromkeys((*actions, *read_capabilities))), time_window={"timezone": "UTC"}, max_duration=max(300, mission.max_iterations * 60), rate_limits={action: max(1, mission.max_iterations) for action in actions}, network_boundary={"allowed": tuple(scope_context.get("allowed_networks", ()))}, data_boundary={"allowed": (target,)}, credential_boundary={"allowed": tuple(scope_context.get("allowed_credentials", ()))}, workspace_boundary={"root": root}, policy_version="api-owner-policy", owner_approval=owner_approval or owner_identity)
        return factory

    def _public_enabled(self):
        return PUBLIC_WEB_ENABLED

    def _public_origin_allowed(self):
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            return True
        if PUBLIC_WEB_ORIGIN:
            return origin == PUBLIC_WEB_ORIGIN
        parsed = urlparse(origin)
        host = self.headers.get("Host", "").strip()
        return (
            parsed.scheme in {"http", "https"}
            and parsed.netloc.casefold() == host.casefold()
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )

    def _public_cookie(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(PUBLIC_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _public_owner_cookie(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(PUBLIC_OWNER_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _public_owner_session(self):
        session = owner_password.resolve_session(self._public_owner_cookie())
        if session is None or session.get("auth_method") != "username_password":
            return None
        return session

    def _public_guard(self, *, csrf=True):
        if not self._public_enabled():
            self._send(404, {"ok": False, "error": "public_boundary_disabled"})
            return None
        if not self._public_origin_allowed():
            self._send(403, {"ok": False, "error": "origin_not_allowed"})
            return None
        try:
            if csrf:
                return DEFAULT_PUBLIC_SESSIONS.validate(self._public_cookie(), self.headers.get("X-CSRF-Token"))
            session = DEFAULT_PUBLIC_SESSIONS.get(self._public_cookie())
            if session is None:
                raise PermissionError("public session required")
            return session
        except PermissionError as exc:
            self._send(401, {"ok": False, "error": str(exc)})
            return None

    def _public_cookie_header(self, session_id, max_age):
        return f"{PUBLIC_SESSION_COOKIE}={session_id}; Max-Age={max_age}; Path=/api/public; HttpOnly; Secure; SameSite=Lax"

    def _public_owner_cookie_header(self, session_id, max_age):
        return f"{PUBLIC_OWNER_SESSION_COOKIE}={session_id}; Max-Age={max_age}; Path=/api/public; HttpOnly; Secure; SameSite=Lax"

    def _send_sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for event in events:
            self.wfile.write(sse(event))
            self.wfile.flush()

    def do_GET(self):
        if self.path == "/api/health":
            return self._send(200, {"ok": True, "service": PRODUCT_NAME, "version": VERSION})
        if self.path == "/api/public/health":
            if not self._public_enabled() or not self._public_origin_allowed():
                return self._send(404, {"ok": False, "error": "not_found"})
            return self._send(200, {"ok": True, "service": PRODUCT_NAME, "version": VERSION})
        if self.path == "/":
            return self._static("index.html")
        parsed = urlparse(self.path)
        if parsed.path == "/api/public/auth/session":
            public_session = self._public_guard(csrf=False)
            if public_session is None:
                return
            owner_session = self._public_owner_session()
            response = {"ok": True, "authenticated": owner_session is not None}
            if owner_session is not None:
                response["username"] = owner_session["username"]
                response["expires_at"] = owner_session["expires_at"]
            headers = None
            if self._public_owner_cookie() and owner_session is None:
                headers = {"Set-Cookie": self._public_owner_cookie_header("", 0)}
            return self._send(200, response, headers=headers)
        if parsed.path.startswith("/api/public/conversations/"):
            owner = self._public_mission_owner()
            if owner is None:
                return
            conversation_id = parsed.path[len("/api/public/conversations/"):]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", conversation_id):
                return self._send(400, {"ok": False, "error": "invalid_conversation_id"})
            try:
                from api.chat import get_session
                conversation = get_session(conversation_id, owner_id=str(owner["owner_id"]))
                if conversation is None:
                    return self._send(404, {"ok": False, "error": "unknown_conversation"})
                return self._send(200, {"ok": True, "conversation": conversation})
            except PermissionError:
                return self._send(404, {"ok": False, "error": "unknown_conversation"})
        if parsed.path == "/api/public/missions":
            owner = self._public_mission_owner()
            if owner is None:
                return
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
                missions = self._mission_service().list_missions(str(owner["owner_id"]), limit=limit)
                return self._send(200, {"ok": True, "missions": missions})
            except (TypeError, ValueError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if parsed.path.startswith("/api/public/missions/"):
            owner = self._public_mission_owner()
            if owner is None:
                return
            parts = parsed.path[len("/api/public/missions/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else "status"
            try:
                service = self._mission_service()
                values = {"status": service.status, "timeline": service.timeline, "evidence": service.evidence, "artifacts": service.artifacts, "logs": service.logs}
                if action not in values:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                value = values[action](mission_id, owner_identity=str(owner["owner_id"]))
                return self._send(200, {"ok": True, "mission_id": mission_id, action: value})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
        if parsed.path.startswith("/api/public/workspace/"):
            owner = self._public_mission_owner()
            if owner is None:
                return
            parts = parsed.path[len("/api/public/workspace/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else ""
            query = parse_qs(parsed.query)
            try:
                capability = "git_read" if action == "git" else "workspace_read"
                mission, snapshot, workspace = self._workspace_for_mission(mission_id, str(owner["owner_id"]), capability)
                root = workspace.root
                if action == "files":
                    relative = query.get("path", ["."])[0]
                    directory = workspace.resolve(relative)
                    if self._sensitive_workspace_path(directory, root):
                        return self._send(404, {"ok": False, "error": "not_found"})
                    names = workspace.list(relative)
                    entries = []
                    for name in names:
                        try:
                            candidate = workspace.resolve(str(Path(relative) / name))
                        except WorkspaceBoundaryError:
                            continue
                        if self._sensitive_workspace_path(candidate, root):
                            continue
                        try:
                            item_stat = candidate.stat()
                            entries.append({"name": name, "directory": candidate.is_dir(), "size": item_stat.st_size if candidate.is_file() else None})
                        except OSError:
                            continue
                    return self._send(200, {"ok": True, "mission_id": mission_id, "path": relative, "files": entries})
                if action == "file":
                    relative = query.get("path", [""])[0]
                    if not relative:
                        return self._send(400, {"ok": False, "error": "path_required"})
                    resolved = workspace.resolve(relative)
                    if self._sensitive_workspace_path(resolved, root):
                        return self._send(404, {"ok": False, "error": "not_found"})
                    content = workspace.read(relative)
                    return self._send(200, {"ok": True, "mission_id": mission_id, "path": relative, "content": content})
                if action == "git":
                    operation = query.get("operation", ["status"])[0]
                    fixed = {
                        "status": ("status", "--short", "--branch"),
                        "branch": ("branch", "--show-current"),
                        "log": ("log", "-8", "--oneline", "--decorate"),
                        "diff": ("diff", "--no-ext-diff", "--no-color", "--", ".", *WORKSPACE_GIT_DIFF_EXCLUSIONS),
                        "head": ("rev-parse", "HEAD"),
                        "repository": ("rev-parse", "--show-toplevel"),
                        "remote": ("remote", "get-url", "origin"),
                    }
                    if operation not in fixed:
                        return self._send(400, {"ok": False, "error": "unsupported_git_operation"})
                    result = workspace.git(fixed[operation][0], *fixed[operation][1:])
                    output = self._redact_remote_url(result.stdout) if operation == "remote" and result.exit_code == 0 else result.stdout
                    return self._send(200, {"ok": True, "mission_id": mission_id, "operation": operation, "exit_code": result.exit_code, "output": output, "error_output": result.stderr})
                return self._send(404, {"ok": False, "error": "unknown_workspace_action"})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            except (WorkspaceBoundaryError, WorkspacePolicyError, PermissionError) as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except FileNotFoundError:
                return self._send(404, {"ok": False, "error": "not_found"})
            except (NotADirectoryError, IsADirectoryError, ValueError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if parsed.path.startswith("/api/missions/"):
            auth = self._mission_owner()
            if auth is None:
                return
            parts = parsed.path[len("/api/missions/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else "status"
            try:
                service = self._mission_service()
                values = {"status": service.status, "timeline": service.timeline, "evidence": service.evidence, "artifacts": service.artifacts, "logs": service.logs}
                if action not in values:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                return self._send(200, {"ok": True, "mission_id": mission_id, action: values[action](mission_id, owner_identity=str(auth["owner_id"]))})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
        if parsed.path == "/api/tools":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            return self._send(200, {"ok": True, "tools": tool_definitions(include_unavailable=True)})
        if parsed.path.startswith("/api/session/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            session_id = parsed.path[len("/api/session/"):]
            owner = self._owner_session()
            if owner is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            try:
                value = get_session(session_id, owner_id=str(owner["owner_id"]))
            except PermissionError:
                return self._send(403, {"ok": False, "error": "conversation access denied"})
            return self._send(200 if value else 404, {"ok": bool(value), "session": value} if value else {"ok": False, "error": "unknown_session"})
        if parsed.path == "/api/chat/stream":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            query = parse_qs(parsed.query)
            payload = {"text": query.get("text", [""])[0], "conversation_id": query.get("conversation_id", [""])[0]}
            owner_session = self._owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            return self._send_sse(stream(payload, owner_session_token=owner_session["session_id"]))
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
                if not task_owner_matches(task, owner_session):
                    return self._send(403, {"ok": False, "error": "task access denied"})
                return self._send_sse(task_stream(task_id, owner_session_token=self._chat_auth()))
            task = TaskManager.get_task(task_id)
            if task is None:
                return self._send(404, {"ok": False, "error": "unknown_task"})
            if not task_owner_matches(task, owner_session):
                return self._send(403, {"ok": False, "error": "task access denied"})
            return self._send(200, {"ok": True, **get_task(task_id, owner_session_token=self._chat_auth())})
        if self.path in {"/app.js", "/style.css"}:
            return self._static(self.path[1:])
        if self.path.startswith("/static/"):
            return self._static(self.path[8:])
        if self.path == "/api/status":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            return self._send(200, status())
        if self.path.startswith("/api/execution/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            request_id = self.path[len("/api/execution/"):]
            record = get_lifecycle(request_id)
            if record is None:
                return self._send(404, {"ok": False, "error": "unknown_request_id"})
            return self._send(200, {"ok": True, "request_id": request_id, "lifecycle": record.__dict__, "events": events_for_request(request_id)})
        if self.path.startswith("/api/reasoning/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            if self._owner_session() is None:
                return self._send(403, {"ok": False, "error": "owner authentication required"})
            request_id = self.path[len("/api/reasoning/"):]
            memory = reasoning_for_request(request_id)
            if memory is None:
                return self._send(404, {"ok": False, "error": "unknown_reasoning_request"})
            return self._send(200, {"ok": True, "request_id": request_id, "memory": memory})
        return self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
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
                    owner_identity = str(auth["owner_id"])
                    request_id = str(payload.get("request_id") or uuid.uuid4().hex)
                    scope_context = dict(payload.get("scope_context") or {})
                    scope_context["workspace_root"] = str(Path(scope_context.get("workspace_root") or ROOT).expanduser().resolve())
                    core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
                    authorization_context, _ = core._auth(objective, auth["session_id"], request_id)
                    from security.owner_budget import OwnerAuthorizedToolBudget
                    budget = OwnerAuthorizedToolBudget.from_owner_declaration(scope_context, policy_version=authorization_context.policy_snapshot.policy_version, owner_approval=authorization_context.owner_evidence.proof_fingerprint)
                    requested = tuple(step.action for step in plan.steps if step.action != "__planning_failure__")
                    effective = budget.intersect(requested)
                    if set(requested) - set(effective):
                        raise PermissionError("plan includes tools outside the Owner-authorized tool budget")
                    runtime = MissionRuntime(core.store, executor=core._executor, require_authorization_snapshot=True)
                    mission_obj = runtime.create_from_owner_instruction(objective, plan, authorization_context=authorization_context, scope_snapshot=scope_context, completion_criteria=payload.get("completion_criteria") or [], owner_identity_ref=owner_identity, provenance={"component": "authenticated_bridge_api", "owner_budget": budget.to_dict(), "effective_tools": list(effective)}, authorization_snapshot_factory=self._mission_snapshot_factory(owner_identity, scope_context, authorization_context.owner_evidence.proof_fingerprint))
                    mission = mission_obj.to_public_dict()
                    return self._send(201, {"ok": True, "mission": mission, "mission_id": mission["mission_id"], "status": mission["status"]})
                result = chat(payload, owner_session_token=auth["session_id"])
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
                if action == "start" or action == "resume":
                    result = self._reauthorize_and_enqueue(mission_id, auth, service)
                    return self._send(200, {"ok": True, **result})
                if action == "reconcile":
                    payload = self._read_json()
                    if not isinstance(payload, dict) or type(payload.get("executed")) is not bool:
                        raise ValueError("executed_boolean_required")
                    result = self._reconcile_mission(mission_id, auth, service, payload["executed"])
                    return self._send(200, {"ok": True, **result})
                if action == "pause":
                    return self._send(200, {"ok": True, "mission": service.pause_mission(mission_id, owner_identity=str(auth["owner_id"]))})
                if action == "cancel":
                    return self._send(200, {"ok": True, "mission": service.cancel_mission(mission_id, owner_identity=str(auth["owner_id"]))})
                if action == "schedule":
                    service.mission(mission_id, owner_identity=str(auth["owner_id"]))
                    payload = self._read_json()
                    return self._send(201, {"ok": True, "schedule": service.schedule_mission(mission_id, run_at=str(payload["run_at"]), interval_seconds=payload.get("interval_seconds"), retry_limit=int(payload.get("retry_limit", 0)))})
                return self._send(404, {"ok": False, "error": "unknown_mission_action"})
            except QueueCapacityError:
                return self._send(429, {"ok": False, "error": "mission_queue_full"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path == "/api/public/missions":
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                objective = str(payload.get("objective") or payload.get("text") or "").strip()
                if not objective:
                    raise ValueError("objective_required")
                criteria = payload.get("completion_criteria")
                if criteria is not None and (not isinstance(criteria, list) or len(criteria) > 100):
                    raise ValueError("invalid_completion_criteria")
                core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
                mission = core.run_owner_mission(objective, owner_session_token=owner["session_id"], request_id=uuid.uuid4().hex, scope_context={"workspace_root": str(ROOT), "target_id": "cybersentinel-repository"}, completion_criteria=criteria, run=False)
                queued = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3")).enqueue(mission.mission_id)
                return self._send(201, {"ok": True, "mission": mission.to_public_dict(), "mission_id": mission.mission_id, "queue": queued.__dict__})
            except QueueCapacityError:
                return self._send(429, {"ok": False, "error": "mission_queue_full"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError, TypeError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
            except Exception:
                return self._send(500, {"ok": False, "error": "mission_creation_failed"})
        if self.path.startswith("/api/public/missions/"):
            owner = self._public_mission_owner(csrf=True)
            if owner is None:
                return
            parts = self.path[len("/api/public/missions/"):].split("/")
            mission_id, action = parts[0], parts[1] if len(parts) > 1 else "start"
            owner_id = str(owner["owner_id"])
            try:
                service = self._mission_service()
                if action == "start":
                    result = self._reauthorize_and_enqueue(mission_id, owner, service)
                elif action == "resume":
                    result = self._reauthorize_and_enqueue(mission_id, owner, service)
                elif action == "reconcile":
                    payload = self._read_json()
                    if not isinstance(payload, dict) or type(payload.get("executed")) is not bool:
                        raise ValueError("executed_boolean_required")
                    result = self._reconcile_mission(mission_id, owner, service, payload["executed"])
                elif action == "pause":
                    result = service.pause_mission(mission_id, owner_identity=owner_id)
                elif action == "cancel":
                    result = service.cancel_mission(mission_id, owner_identity=owner_id)
                elif action == "schedule":
                    service.mission(mission_id, owner_identity=owner_id)
                    payload = self._read_json()
                    result = service.schedule_mission(mission_id, run_at=str(payload["run_at"]), interval_seconds=payload.get("interval_seconds"), retry_limit=int(payload.get("retry_limit", 0)))
                else:
                    return self._send(404, {"ok": False, "error": "unknown_mission_action"})
                return self._send(200, {"ok": True, "result": result})
            except KeyError:
                return self._send(404, {"ok": False, "error": "unknown_mission"})
            except QueueCapacityError:
                return self._send(429, {"ok": False, "error": "mission_queue_full"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, TypeError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path == "/api/public/session":
            if not self._public_enabled() or not self._public_origin_allowed():
                return self._send(404, {"ok": False, "error": "public_boundary_disabled"})
            session = DEFAULT_PUBLIC_SESSIONS.create()
            return self._send(201, {"ok": True, "session": session.public()}, headers={"Set-Cookie": self._public_cookie_header(session.session_id, PUBLIC_SESSION_TTL_SECONDS)})
        if self.path == "/api/public/auth/login":
            if self._public_guard(csrf=True) is None:
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_credentials")
                username = payload.get("username")
                password = payload.get("password")
                if (
                    not isinstance(username, str)
                    or not isinstance(password, str)
                    or not username
                    or not password
                    or len(username) > 128
                    or len(password) > 4096
                ):
                    raise ValueError("invalid_credentials")
                session = owner_password_login(username, password)
            except PermissionError:
                return self._send(403, {"ok": False, "error": "invalid_credentials"})
            except ValueError:
                return self._send(400, {"ok": False, "error": "invalid_credentials"})
            except Exception:
                return self._send(500, {"ok": False, "error": "owner_login_failed"})
            previous = self._public_owner_cookie()
            if previous and previous != session["session_id"]:
                owner_password_logout(previous)
            owner = owner_password.resolve_session(session["session_id"])
            if owner is None:
                return self._send(500, {"ok": False, "error": "owner_login_failed"})
            return self._send(
                200,
                {"ok": True, "authenticated": True, "username": owner["username"], "expires_at": owner["expires_at"]},
                headers={"Set-Cookie": self._public_owner_cookie_header(session["session_id"], owner_password.SESSION_TTL_SECONDS)},
            )
        if self.path == "/api/public/auth/logout":
            if self._public_guard(csrf=True) is None:
                return
            owner_password_logout(self._public_owner_cookie())
            return self._send(200, {"ok": True, "authenticated": False}, headers={"Set-Cookie": self._public_owner_cookie_header("", 0)})
        if self.path == "/api/public/logout":
            session = self._public_guard(csrf=False)
            if session is None:
                return
            DEFAULT_PUBLIC_SESSIONS.revoke(session.session_id)
            return self._send(200, {"ok": True}, headers={"Set-Cookie": self._public_cookie_header("", 0)})
        if self.path == "/api/public/chat":
            if self._public_guard(csrf=True) is None:
                return
            owner_session = self._public_owner_session()
            if owner_session is None:
                return self._send(403, {"ok": False, "error": "owner_authorization_required"})
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    raise ValueError("invalid_request")
                # Browser callers cannot choose an arbitrary filesystem root or
                # widen target/network/credential scope through JSON fields.
                payload["scope_context"] = {"workspace_root": str(ROOT), "target_id": "cybersentinel-repository"}
                result = chat(payload, owner_session_token=owner_session["session_id"])
                return self._send(200, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except ValueError as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
            except Exception:
                return self._send(500, {"ok": False, "error": "chat_failed"})
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
                result = chat(payload, owner_session_token=owner_session["session_id"])
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
                result = create_task(payload, owner_session_token=owner_session["session_id"], run=bool(payload.get("run", True)))
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
                    result = resume_task(task_id, owner_session_token=owner_session["session_id"], run=True)
                elif action == "pause":
                    result = pause_task(task_id, owner_session_token=owner_session["session_id"])
                elif action == "cancel":
                    result = cancel_task(task_id, owner_session_token=owner_session["session_id"])
                else:
                    return self._send(404, {"ok": False, "error": "unknown_task_action"})
                return self._send(200, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path == "/api/cancel":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                data = json.loads(self.rfile.read(n) or b"{}")
                request_id = str(data.get("request_id", "")).strip()
                if not request_id:
                    return self._send(400, {"ok": False, "error": "request_id_required"})
                record = request_cancel(request_id)
                return self._send(200, {"ok": True, "request_id": request_id, "lifecycle": record.status, "cancel_requested": record.cancel_requested})
            except ValueError:
                return self._send(404, {"ok": False, "error": "unknown_request_id"})
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
                owner_session_token=owner_session["session_id"],
            )
            return self._send(200, {"ok": True, **result})
        except Exception:
            return self._send(400, {"ok": False, "error": "invalid_request"})

    def log_message(self, fmt, *args):
        print("[bridge]", fmt % args)


def main():
    if not BRIDGE_TOKEN:
        raise SystemExit("BRIDGE_TOKEN is required in .env")
    server = ThreadingHTTPServer((BRIDGE_HOST, BRIDGE_PORT), Handler)
    core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
    queue = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3"))
    scheduler = MissionScheduler(DB_PATH.with_name("mission_scheduler.sqlite3"), queue)

    def resume_queued_mission(mission_id: str, max_slices: int | None, heartbeat):
        mission = core.store.load(mission_id)
        if mission is None:
            raise KeyError("unknown_mission")
        auth_context = mission.authorization_context or {}
        session_id = str(auth_context.get("session_id", ""))
        if not session_id:
            if not mission.is_terminal:
                mission.transition(MissionStatus.OWNER_INPUT_REQUIRED, "live Owner session is unavailable")
                core.store.save(mission)
            return mission
        try:
            return core.resume_mission(mission_id, owner_session_token=session_id, max_slices=max_slices, heartbeat=heartbeat)
        except PermissionError:
            # AgentCore persists a truthful OWNER_INPUT_REQUIRED/blocked state;
            # return that source of truth so the queue does not mislabel it as a crash.
            return core.store.load(mission_id) or mission

    worker = MissionWorker(queue, runtime_factory=lambda: core, worker_id=f"bridge-{uuid.uuid4().hex}", resume_callback=resume_queued_mission)
    recovered = worker.recover_after_restart()
    stop = Event()

    def supervise_missions():
        while not stop.is_set():
            now = datetime.now(timezone.utc).isoformat()
            try:
                queue.recover_expired(now=now)
                scheduler.dispatch_due(now=now)
                item = worker.run_once(now=now, max_slices=1)
            except Exception as exc:
                print(f"[mission-worker] {type(exc).__name__}")
                item = None
            if item is None:
                stop.wait(0.5)

    worker_thread = Thread(target=supervise_missions, name="cybersentinel-mission-worker", daemon=True)
    worker_thread.start()
    print(f"{PRODUCT_NAME} {VERSION}: http://{BRIDGE_HOST}:{BRIDGE_PORT}")
    print("Local-only defensive engine, threat intelligence, planner and audit enabled.")
    print(f"Mission worker ready; recovered {len(recovered)} queued/recoverable item(s).")
    def request_shutdown(_signum, _frame):
        stop.set()
        Thread(target=server.shutdown, name="cybersentinel-http-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        server.serve_forever()
    finally:
        stop.set()
        worker_thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
