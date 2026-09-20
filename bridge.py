from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from core.config import BRIDGE_HOST, BRIDGE_PORT, BRIDGE_TOKEN
from core.engine import handle, status
from core.lifecycle import get as get_lifecycle, request_cancel
from core.db import events_for_request
from core.version import PRODUCT_NAME, SERVER_VERSION, VERSION

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION

    def _send(self, code, payload, ctype="application/json; charset=utf-8"):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _bridge_auth(self):
        return bool(BRIDGE_TOKEN) and self.headers.get("X-CyberSentinel-Token", "") == BRIDGE_TOKEN

    def _static(self, name):
        p = (WEB / name).resolve()
        if WEB.resolve() not in p.parents or not p.is_file() or p.suffix not in MIME:
            return self._send(404, {"ok": False, "error": "not_found"})
        return self._send(200, p.read_bytes(), MIME[p.suffix])

    def do_GET(self):
        if self.path == "/api/health":
            return self._send(200, {"ok": True, "service": PRODUCT_NAME, "version": VERSION})
        if self.path == "/":
            return self._static("index.html")
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
        return self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        if not self._bridge_auth():
            return self._send(401, {"ok": False, "error": "bridge authentication required"})
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
            owner_token = self.headers.get("X-CyberSentinel-Owner-Token", "")
            return self._send(200, handle(text, source="web", presented_token=self.headers.get("X-CyberSentinel-Token"), owner_token=owner_token, request_id=request_id or None))
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
