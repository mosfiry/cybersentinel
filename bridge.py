from __future__ import annotations

import json
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
)
from core.engine import status
from core.lifecycle import get as get_lifecycle, request_cancel
from core.db import events_for_request, reasoning_for_request
from security.owner_policy import verify_owner
from security.owner_session import create_owner_session
from api.chat import chat, get_session, sse, stream, task_stream, create_task, resume_task, pause_task, cancel_task
from agent.task_manager import TaskManager
from tools.registry import tool_definitions
from core.version import PRODUCT_NAME, SERVER_VERSION, VERSION
from security.public_session import DEFAULT_PUBLIC_SESSIONS

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}


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
    print(f"{PRODUCT_NAME} {VERSION}: http://{BRIDGE_HOST}:{BRIDGE_PORT}")
    print("Local-only defensive engine, threat intelligence, planner and audit enabled.")
    server.serve_forever()


if __name__ == "__main__":
    main()
