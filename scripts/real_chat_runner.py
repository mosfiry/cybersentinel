from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import time
import uuid
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = Path(os.environ.get("REAL_RUN_ARTIFACT_DIR", "/tmp/cybersentinel-real-runs"))
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
RUNNER_TOKEN = os.environ.get("RUNNER_AUTH_TOKEN", "")
OWNER_TOKEN = os.environ.get("OWNER_TOKEN", "")
HOST = os.environ.get("REAL_RUNNER_HOST", "0.0.0.0")
PORT = int(os.environ.get("REAL_RUNNER_PORT", "8788"))

if not RUNNER_TOKEN or not OWNER_TOKEN:
    raise RuntimeError("RUNNER_AUTH_TOKEN and OWNER_TOKEN must be supplied by the launcher, never committed")

# Import only after OWNER_TOKEN is present: owner_policy snapshots it at import time.
from api.chat import chat  # noqa: E402
from core.engine import RUNTIME  # noqa: E402


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


def _authorized(handler: BaseHTTPRequestHandler) -> bool:
    value = handler.headers.get("Authorization", "")
    return value == f"Bearer {RUNNER_TOKEN}"


def _proof(result: dict, *, request_id: str, conversation_id: str, received_at: str) -> dict:
    mission = result.get("mission") or {}
    progress = mission.get("progress") or {}
    model_loop = progress.get("model_loop") or {}
    turns = model_loop.get("turns") or []
    trajectory = result.get("activity") or []
    model_final = ""
    for event in reversed(trajectory):
        data = event.get("data") if isinstance(event, dict) else None
        if isinstance(data, dict) and data.get("model_final"):
            model_final = str(data["model_final"])
            break
    answer = model_final or str(result.get("answer") or "")
    return {
        "proof_version": "real-cybersentinel-v1",
        "claim": "HTTP request entered api.chat -> AgentCore -> MissionRuntime -> ModelRouter -> configured provider",
        "synthetic": False,
        "request_id": request_id,
        "conversation_id": conversation_id,
        "received_at": received_at,
        "mission_id": result.get("mission_id"),
        "status": result.get("status"),
        "answer": answer,
        "api_answer_before_proof_projection": result.get("answer"),
        "provider": (turns[-1].get("provider") if turns else (progress.get("initial_model_response") or {}).get("provider")),
        "model": (turns[-1].get("model") if turns else (progress.get("initial_model_response") or {}).get("model")),
        "provider_trace": progress.get("provider_trace") or ((progress.get("initial_model_response") or {}).get("provider_trace")),
        "execution_state": {
            "model_turn_count": len(turns),
            "tool_result_count": len(model_loop.get("tool_results") or []),
            "last_context_hash": progress.get("last_context_hash"),
            "context_compaction": progress.get("context_compaction"),
        },
        "trajectory": trajectory,
        "evidence": mission.get("evidence") or [],
        "verification_state": mission.get("verification_state") or {},
        "provenance": {
            "entrypoint": "api.chat.chat",
            "agent_core": "agent.agent_core.AgentCore.run_owner_mission",
            "runtime": "agent.mission_runtime.MissionRuntime",
            "provider": "agent.model_router.ModelRouter",
            "artifact_dir": str(ARTIFACT_DIR),
        },
    }


def _write_artifact(request_id: str, request_payload: dict, response_payload: dict) -> str:
    path = ARTIFACT_DIR / f"{request_id}.json"
    path.write_text(json.dumps({"request": request_payload, "response": response_payload}, ensure_ascii=False, default=str, indent=2) + "\n", encoding="utf-8")
    return str(path)


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberSentinel-RealRunner/1.0"

    def _send(self, code: int, payload: dict) -> None:
        raw = _json_bytes(payload)
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if not _authorized(self):
            return self._send(401, {"ok": False, "error": "runner_authentication_required"})
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send(200, {"ok": True, "service": "CyberSentinel real runner", "provider_status": RUNTIME.router.status()})
        if parsed.path.startswith("/v1/runs/"):
            request_id = unquote(parsed.path[len("/v1/runs/"):])
            path = ARTIFACT_DIR / f"{request_id}.json"
            if not path.is_file():
                return self._send(404, {"ok": False, "error": "unknown_request_id"})
            return self._send(200, json.loads(path.read_text(encoding="utf-8")))
        return self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        if not _authorized(self):
            return self._send(401, {"ok": False, "error": "runner_authentication_required"})
        if self.path != "/v1/chat":
            return self._send(404, {"ok": False, "error": "not_found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 32768:
                return self._send(413, {"ok": False, "error": "invalid_body_size"})
            payload = json.loads(self.rfile.read(size).decode("utf-8"))
            message = str(payload.get("message", "")).strip()
            if not message:
                return self._send(400, {"ok": False, "error": "message_required"})
            request_id = str(payload.get("request_id") or uuid.uuid4().hex)
            conversation_id = str(payload.get("conversation_id") or f"real-{request_id}")
            request = {"message": message, "request_id": request_id, "conversation_id": conversation_id}
            received_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # This is the actual CyberSentinel API path. No provider response is
            # fabricated or returned directly by this runner.
            result = chat({"text": message, "request_id": request_id, "conversation_id": conversation_id}, owner_token=OWNER_TOKEN)
            proof = _proof(result, request_id=request_id, conversation_id=conversation_id, received_at=received_at)
            proof["artifact_path"] = _write_artifact(request_id, request, proof)
            return self._send(200, proof)
        except PermissionError as exc:
            return self._send(403, {"ok": False, "error": str(exc)})
        except Exception as exc:
            return self._send(500, {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:500]})

    def log_message(self, fmt: str, *args) -> None:
        print(f"[real-runner] {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"CyberSentinel real runner listening on {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
