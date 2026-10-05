from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for entry in (ROOT, TESTS):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from agent.agent_core import AgentCore
from agent.knowledge_context import TypedKnowledgeRetriever
from agent.model_router import ModelRouter
from agent.providers import OpenAICompatibleProvider
from v13_scenario_runner import (
    WATCH_KEYWORD,
    _LiveBridge,
    _local_workspace_scope_context,
    _persist_local_workspace_scope,
    _emit,
    _run_scenario,
)


class _EmptyKnowledge:
    def retrieve_relevant(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return []

    def retrieve_adaptive(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"results": []}


class _ProviderFixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.request_count = 0
        self.request_error = ""
        self.request_models: list[str] = []


class _ProviderFixtureHandler(BaseHTTPRequestHandler):
    server: _ProviderFixtureServer

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.server.request_error = "unexpected_provider_path"
            self._respond(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_048_576:
                raise ValueError("invalid_provider_request_size")
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict):
                raise ValueError("invalid_provider_request")
            names = {
                item.get("function", {}).get("name")
                for item in request.get("tools", [])
                if isinstance(item, dict) and isinstance(item.get("function"), dict)
            }
            if not {"run_project_tests", "watch"}.issubset(names):
                raise ValueError("required_tools_missing_from_provider_request")
            if request.get("model") != "v9-local-fixture":
                raise ValueError("unexpected_model_identifier")
            self.server.request_count += 1
            self.server.request_models.append(str(request["model"]))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.server.request_error = type(exc).__name__ + ":" + str(exc)
            self._respond(400, {"error": "invalid_fixture_request"})
            return

        calls = [
            {
                "id": "v9-run-tests",
                "type": "function",
                "function": {
                    "name": "run_project_tests",
                    "arguments": json.dumps({"query": "."}, separators=(",", ":")),
                },
            },
            {
                "id": "v9-register-watch",
                "type": "function",
                "function": {
                    "name": "watch",
                    "arguments": json.dumps({"query": WATCH_KEYWORD}, separators=(",", ":")),
                },
            },
        ]
        self._respond(
            200,
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "", "tool_calls": calls},
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )


class _V9LiveBridge(_LiveBridge):
    provider_call_count = 0
    provider_models: list[str] = []

    def _provider_plan(self, objective: str) -> dict[str, Any]:
        server = _ProviderFixtureServer(("127.0.0.1", 0), _ProviderFixtureHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            name="v9-loopback-provider",
            daemon=True,
        )
        thread.start()
        try:
            provider = OpenAICompatibleProvider(
                "v9-loopback-fixture",
                f"http://127.0.0.1:{server.server_address[1]}/v1",
                "v9-local-fixture",
                tool_calling=True,
            )
            planner = AgentCore(
                ModelRouter([provider]),
                store=self.store,
                max_iterations=5,
                knowledge_retriever=_EmptyKnowledge(),
            )
            proposed = planner._plan(
                objective,
                request_id="v9-provider-plan-request",
                conversation_id="v9-provider-plan",
            )
            type(self).provider_call_count += server.request_count
            type(self).provider_models.extend(server.request_models)
            if server.request_error or server.request_count != 1:
                raise RuntimeError("loopback_provider_request_invariant_failed")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("loopback_provider_thread_did_not_stop")

        if [step.action for step in proposed.steps] != ["run_project_tests", "watch"]:
            raise RuntimeError("provider_proposed_unexpected_tool_plan")
        source_test, source_watch = proposed.steps
        test_retry = dict(source_test.retry_policy)
        watch_retry = dict(source_watch.retry_policy)
        if (
            test_retry.get("arguments") != {"query": "."}
            or watch_retry.get("arguments") != {"query": WATCH_KEYWORD}
            or set(test_retry.get("arguments", {})) != {"query"}
            or set(watch_retry.get("arguments", {})) != {"query"}
        ):
            raise RuntimeError("provider_proposed_unexpected_tool_arguments")

        return {
            "version": proposed.version,
            "objective": objective,
            "created_from": "v9-openai-compatible-loopback-provider",
            "risk": "bounded-local",
            "steps": [
                {
                    "step_id": "fixture-tests",
                    "objective": "Run the controlled local fixture tests",
                    "prerequisites": [],
                    "action": source_test.action,
                    "expected_observation": "The single fixture test passes",
                    "authorization_requirement": "owner",
                    "scope_requirement": "workspace",
                    "retry_policy": test_retry,
                    "verification": ["tests-pass"],
                },
                {
                    "step_id": "local-watch",
                    "objective": "Register the fixture's local defensive watch keyword",
                    "prerequisites": ["fixture-tests"],
                    "action": source_watch.action,
                    "expected_observation": "The local watch keyword is present exactly once",
                    "authorization_requirement": "owner",
                    "scope_requirement": "workspace",
                    "retry_policy": watch_retry,
                    "verification": ["watch-registered"],
                },
            ],
        }

    def create_mission(self, session: str) -> tuple[str, dict[str, Any]]:
        objective = "Owner instruction: run deterministic local tests and register a local defensive watch keyword"
        scope_snapshot = _persist_local_workspace_scope(
            session, "v9-temporary-workspace", namespace="v9",
        )
        payload = {
            "objective": objective,
            "plan": self._provider_plan(objective),
            "scope_context": _local_workspace_scope_context(scope_snapshot, self.workspace),
            "completion_criteria": [
                {
                    "criterion_id": "tests-pass",
                    "description": "project pytest process exits successfully",
                    "check": "pytest_success",
                    "required": True,
                },
                {
                    "criterion_id": "watch-registered",
                    "description": "requested local defensive watch is persisted",
                    "check": "watch_registered",
                    "required": True,
                },
            ],
        }
        status, response = self.request("POST", "/api/missions", payload, session)
        if status != 201 or not response.get("mission_id"):
            raise RuntimeError(f"mission_create_failed_{status}")
        mission_id = str(response["mission_id"])
        mission = response.get("mission")
        if not isinstance(mission, dict) or mission.get("owner_instruction") != objective:
            raise RuntimeError("owner_instruction_not_bound_to_mission")
        snapshot = mission.get("authorization_snapshot")
        if not isinstance(snapshot, dict):
            raise RuntimeError("authorization_snapshot_missing")
        if (
            len(str(snapshot.get("authorization_hash", ""))) != 64
            or snapshot.get("mission_id") != mission_id
            or snapshot.get("owner_identity") != mission.get("owner_identity_ref")
            or not snapshot.get("owner_approval")
        ):
            raise RuntimeError("authorization_snapshot_binding_missing")
        return mission_id, mission


def run_scenario(scenario: str) -> dict[str, Any]:
    if scenario not in {"happy", "crash"}:
        raise ValueError("V9 supports only happy and crash scenarios")
    result = _run_scenario(scenario, harness_factory=_V9LiveBridge)
    if _V9LiveBridge.provider_call_count != 1 or _V9LiveBridge.provider_models != ["v9-local-fixture"]:
        raise RuntimeError("V9 provider call was not observed exactly once")
    result["provider"] = {
        "name": "v9-loopback-fixture",
        "model": "v9-local-fixture",
        "transport": "OpenAI-compatible HTTP on 127.0.0.1",
        "request_count": _V9LiveBridge.provider_call_count,
    }
    return result


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2:
            raise RuntimeError("scenario_argument_required")
        result = run_scenario(argv[1])
        return _emit(result)
    except Exception as exc:
        return _emit(
            {"ok": False, "error_type": type(exc).__name__, "error": str(exc)[:300]},
            2,
        )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
