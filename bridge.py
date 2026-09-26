from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse
from core.config import (
    BRIDGE_HOST,
    BRIDGE_PORT,
    BRIDGE_TOKEN,
    PUBLIC_SESSION_COOKIE,
    PUBLIC_SESSION_TTL_SECONDS,
    PUBLIC_WEB_ENABLED,
    PUBLIC_WEB_ORIGIN,
    DB_PATH,
)
from core.engine import RUNTIME, status
from core.lifecycle import get as get_lifecycle, request_cancel
from core.db import events_for_request, reasoning_for_request
from security.owner_policy import verify_owner
from security.owner_session import create_owner_session
from api.chat import chat, get_session, sse, stream, task_stream, create_task, resume_task, pause_task, cancel_task
from agent.task_manager import TaskManager
from tools.registry import tool_definitions
from core.version import PRODUCT_NAME, SERVER_VERSION, VERSION
from security.public_session import DEFAULT_PUBLIC_SESSIONS
from api.missions import MissionService
from agent.mission_worker import MissionQueue, MissionScheduler, MissionWorker
from agent.mission_runtime import MissionRuntime
from agent.mission import MissionStore
from agent.agent_core import AgentCore
from agent.planning import Plan, PlanStep

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}


def mission_worker_supervisor(stop: threading.Event, *, poll_seconds: float = 0.5) -> None:
    """Run durable queued/scheduled missions while the bridge server is alive."""
    db_path = DB_PATH.with_name("missions.sqlite3")
    queue = MissionQueue(DB_PATH.with_name("mission_queue.sqlite3"))
    scheduler = MissionScheduler(DB_PATH.with_name("mission_scheduler.sqlite3"), queue)

    def runtime_factory() -> MissionRuntime:
        core = AgentCore(RUNTIME.router, db_path=db_path)
        return MissionRuntime(core.store, executor=core._executor, require_authorization_snapshot=True)

    worker = MissionWorker(queue, runtime_factory, worker_id=f"bridge-{os.getpid()}")
    while not stop.is_set():
        try:
            now = datetime.now(timezone.utc).isoformat()
            queue.recover_expired(now=now)
            scheduler.dispatch_due(now=now)
            if worker.run_once() is None:
                stop.wait(poll_seconds)
        except Exception as exc:
            print(f"[mission-worker] {type(exc).__name__}: {exc}")
            stop.wait(poll_seconds)


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
        return self.headers.get("X-CyberSentinel-Owner-Token", ""), self.headers.get("X-CyberSentinel-Owner-Session"), self.headers.get("X-CyberSentinel-Owner-Challenge")

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
        owner_token, owner_session, owner_challenge = self._chat_auth()
        if owner_session and owner_challenge:
            return owner_token, owner_session, owner_challenge
        owner_ok, reason = verify_owner("Owner mission API", owner_token)
        if not owner_ok:
            self._send(403, {"ok": False, "error": reason})
            return None
        return owner_token, owner_session, owner_challenge

    def _public_enabled(self):
        return PUBLIC_WEB_ENABLED

    def _public_origin_allowed(self):
        origin = self.headers.get("Origin", "").strip()
        return not origin or (PUBLIC_WEB_ORIGIN and origin == PUBLIC_WEB_ORIGIN)

    def _public_cookie(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(PUBLIC_SESSION_COOKIE)
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
                return DEFAULT_PUBLIC_SESSIONS.validate(self._public_cookie(), self.headers.get("X-CSRF-Token"))
            session = DEFAULT_PUBLIC_SESSIONS.get(self._public_cookie())
            if session is None:
                raise PermissionError("public session required")
            return session
        except PermissionError as exc:
            self._send(401, {"ok": False, "error": str(exc)})
            return None

    def _public_cookie_header(self, session_id, max_age):
        return f"{PUBLIC_SESSION_COOKIE}={session_id}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax"

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
                return self._send(200, {"ok": True, "mission_id": mission_id, action: values[action](mission_id)})
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
            owner_ok, reason = verify_owner("Owner conversation session", self.headers.get("X-CyberSentinel-Owner-Token", ""))
            if not owner_ok:
                return self._send(403, {"ok": False, "error": reason})
            value = get_session(session_id)
            return self._send(200 if value else 404, {"ok": bool(value), "session": value} if value else {"ok": False, "error": "unknown_session"})
        if parsed.path == "/api/chat/stream":
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            query = parse_qs(parsed.query)
            payload = {"text": query.get("text", [""])[0], "conversation_id": query.get("conversation_id", [""])[0]}
            owner_token, owner_session, owner_challenge = self._chat_auth()
            return self._send_sse(stream(payload, owner_token=owner_token, owner_session_id=owner_session, owner_challenge=owner_challenge))
        if parsed.path.startswith("/api/tasks/"):
            if not self._bridge_auth():
                return self._send(401, {"ok": False, "error": "bridge authentication required"})
            owner_token, owner_session, _ = self._chat_auth()
            owner_ok, reason = verify_owner("Owner task access", owner_token)
            if not owner_ok:
                return self._send(403, {"ok": False, "error": reason})
            task_id = parsed.path[len("/api/tasks/"):]
            if task_id.endswith("/stream"):
                task_id = task_id[:-len("/stream")].rstrip("/")
                task = TaskManager.get_task(task_id)
                if task is None:
                    return self._send(404, {"ok": False, "error": "unknown_task"})
                return self._send_sse(task_stream(task_id, owner_token=owner_token, owner_session_id=owner_session))
            task = TaskManager.get_task(task_id)
            if task is None:
                return self._send(404, {"ok": False, "error": "unknown_task"})
            if owner_session and task.owner_session_id != owner_session:
                return self._send(403, {"ok": False, "error": "task access denied"})
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
            owner_ok, reason = verify_owner("Owner reasoning memory", self.headers.get("X-CyberSentinel-Owner-Token", ""))
            if not owner_ok:
                return self._send(403, {"ok": False, "error": reason})
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
                owner_token, owner_session, owner_challenge = auth
                if isinstance(payload.get("plan"), dict):
                    instruction = str(payload.get("text") or payload.get("objective") or "").strip()
                    if not instruction:
                        raise ValueError("objective_required")
                    raw_plan = payload["plan"]
                    raw_steps = raw_plan.get("steps", [])
                    steps = tuple(PlanStep(step_id=str(item["step_id"]), objective=str(item.get("objective", item["step_id"])), prerequisites=tuple(item.get("prerequisites", ())), action=str(item.get("action", "")), expected_observation=str(item.get("expected_observation", "")), authorization_requirement=str(item.get("authorization_requirement", "owner")), scope_requirement=str(item.get("scope_requirement", "")), retry_policy=dict(item.get("retry_policy", {})), verification=tuple(item.get("verification", ()))) for item in raw_steps)
                    plan = Plan(version=int(raw_plan.get("version", 1)), objective=instruction, assumptions=tuple(raw_plan.get("assumptions", ())), steps=steps, dependencies=tuple(raw_plan.get("dependencies", ())), completion_criteria=tuple(raw_plan.get("completion_criteria", ())), risk=str(raw_plan.get("risk", "unknown")), created_from=str(raw_plan.get("created_from", "owner-api")))
                    request_id = str(payload.get("request_id") or uuid.uuid4().hex)
                    core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
                    authorization_context, _ = core._auth(instruction, owner_token, request_id, owner_session, owner_challenge)
                    scope_context = core._normalize_scope_context(payload.get("scope_context"))
                    if scope_context and scope_context.get("scope_snapshot_id"):
                        from security.scope_store import get_snapshot
                        scope = get_snapshot(scope_context["scope_snapshot_id"])
                        if scope is None:
                            raise PermissionError("Owner-approved scope snapshot not found")
                        authorization_context = type(authorization_context)(authorization_context.request_id, authorization_context.owner_evidence, authorization_context.policy_snapshot, scope_snapshot=scope, session_id=authorization_context.session_id)
                    allowed_tools = set(core._owner_allowed_tools(instruction))
                    requested_tools = {step.action for step in steps}
                    if not requested_tools or requested_tools - allowed_tools:
                        raise PermissionError("plan actions exceed the deterministic Owner-instruction tool allowlist")
                    if any(not core._owner_proposal_allowed(instruction, step)[0] for step in steps):
                        raise PermissionError("plan tool arguments exceed the deterministic Owner-instruction boundary")
                    service = self._mission_service()
                    snapshot_factory = core._authorization_snapshot_factory(authorization_context, tuple(sorted(allowed_tools)), scope_context)
                    criteria = [{"criterion_id": step.step_id, "description": f"Owner-requested step {step.step_id} completed", "check": "tool observation", "required": True} for step in steps]
                    mission = service.runtime.create_owner_graph(instruction, plan, authorization_context=authorization_context, scope_snapshot=scope_context, completion_criteria=criteria, owner_identity_ref=authorization_context.owner_evidence.proof_fingerprint, provenance={"source": "authenticated_mission_api"}, authorization_snapshot_factory=snapshot_factory, max_parallel=1)
                    mission.progress["mission_api_created"] = True
                    service.runtime.store.save(mission)
                    mission = mission.to_dict()
                    return self._send(201, {"ok": True, "mission": mission, "mission_id": mission["mission_id"], "status": mission["status"]})
                result = chat(payload, owner_token=owner_token, owner_session_id=owner_session, owner_challenge=owner_challenge)
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
                owner_token, owner_session, owner_challenge = auth
                core = AgentCore(RUNTIME.router, db_path=DB_PATH.with_name("missions.sqlite3"))
                mission = service.runtime.store.load(mission_id)
                if mission is None:
                    raise KeyError("unknown_mission")
                owner_context = core.owner_context_for_mission(mission, owner_token=owner_token)
                if action == "start":
                    result = service.start_mission(mission_id, authorization_context=owner_context)
                    return self._send(200, {"ok": True, "mission": result})
                if action in {"pause", "cancel", "resume"}:
                    return self._send(200, {"ok": True, "mission": service.control_mission(mission_id, action, authorization_context=owner_context)})
                if action == "schedule":
                    payload = self._read_json()
                    return self._send(201, {"ok": True, "schedule": service.schedule_mission(mission_id, run_at=str(payload["run_at"]), interval_seconds=payload.get("interval_seconds"), retry_limit=int(payload.get("retry_limit", 0)), authorization_context=owner_context)})
                return self._send(404, {"ok": False, "error": "unknown_mission_action"})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path == "/api/public/session":
            if not self._public_enabled() or not self._public_origin_allowed():
                return self._send(404, {"ok": False, "error": "public_boundary_disabled"})
            session = DEFAULT_PUBLIC_SESSIONS.create()
            return self._send(201, {"ok": True, "session": session.public()}, headers={"Set-Cookie": self._public_cookie_header(session.session_id, PUBLIC_SESSION_TTL_SECONDS)})
        if self.path == "/api/public/logout":
            session = self._public_guard(csrf=False)
            if session is None:
                return
            DEFAULT_PUBLIC_SESSIONS.revoke(session.session_id)
            return self._send(200, {"ok": True}, headers={"Set-Cookie": self._public_cookie_header("", 0)})
        if self.path == "/api/public/chat":
            session = self._public_guard(csrf=True)
            if session is None:
                return
            # Public session identity is deliberately not Owner authority.
            # Do not call the internal chat path until an Owner-approved
            # identity-to-Owner mapping exists.
            return self._send(403, {"ok": False, "error": "owner_authorization_required"})
        if not self._bridge_auth():
            return self._send(401, {"ok": False, "error": "bridge authentication required"})
        if self.path == "/api/owner/session":
            try:
                session = create_owner_session(self.headers.get("X-CyberSentinel-Owner-Token", ""))
                return self._send(201, {"ok": True, "session": session})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
        if self.path == "/api/chat":
            try:
                payload = self._read_json()
                owner_token, owner_session, owner_challenge = self._chat_auth()
                result = chat(payload, owner_token=owner_token, owner_session_id=owner_session, owner_challenge=owner_challenge)
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
                owner_token, owner_session, _ = self._chat_auth()
                owner_challenge = self.headers.get("X-CyberSentinel-Owner-Challenge")
                result = create_task(payload, owner_token=owner_token, owner_session_id=owner_session, owner_challenge=owner_challenge, authentication_method="owner_session_challenge" if owner_session else "owner_token", run=bool(payload.get("run", True)))
                return self._send(201, {"ok": True, **result})
            except PermissionError as exc:
                return self._send(403, {"ok": False, "error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"ok": False, "error": str(exc)})
        if self.path.startswith("/api/tasks/"):
            try:
                task_id, action = self.path[len("/api/tasks/"):].split("/", 1)
                owner_token, owner_session, _ = self._chat_auth()
                if action == "resume":
                    result = resume_task(task_id, owner_token=owner_token, owner_session_id=owner_session, run=True)
                elif action == "pause":
                    result = pause_task(task_id, owner_token=owner_token, owner_session_id=owner_session)
                elif action == "cancel":
                    result = cancel_task(task_id, owner_token=owner_token, owner_session_id=owner_session)
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
            owner_token, owner_session, owner_challenge = self._chat_auth()
            result = chat(
                {**data, "text": text, "request_id": request_id or None},
                owner_token=owner_token,
                owner_session_id=owner_session,
                owner_challenge=owner_challenge,
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
    stop = threading.Event()
    worker_thread = threading.Thread(target=mission_worker_supervisor, args=(stop,), name="cybersentinel-mission-worker", daemon=True)
    worker_thread.start()
    print(f"{PRODUCT_NAME} {VERSION}: http://{BRIDGE_HOST}:{BRIDGE_PORT}")
    print("Local-only defensive engine, governed mission scheduler, threat intelligence, planner and audit enabled.")
    try:
        server.serve_forever()
    finally:
        stop.set()
        worker_thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
