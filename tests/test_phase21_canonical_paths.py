from __future__ import annotations

import inspect

import api.chat as chat_api
import bridge
from agent.mission_task_adapter import MissionTaskAdapter


def test_chat_uses_agentcore_mission_runtime():
    source = inspect.getsource(chat_api.chat)
    assert "run_owner_mission" in source
    assert "AgentTaskRuntime" not in source


def test_tasks_use_mission_task_adapter():
    assert chat_api.MissionTaskAdapter is MissionTaskAdapter
    assert "MissionTaskAdapter" in inspect.getsource(chat_api._runtime)
    assert "AgentTaskRuntime" not in inspect.getsource(chat_api)


def test_command_routes_to_same_chat_entrypoint():
    source = inspect.getsource(bridge.Handler.do_POST)
    command_block = source[source.index('if self.path != "/api/command"'):]
    assert "result = chat(" in command_block
    assert "handle(" not in command_block


def test_agentloop_has_no_production_importers():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    production = [root / "api", root / "bridge.py", root / "agent", root / "core", root / "tools", root / "security"]
    matches = []
    for path in production:
        files = path.rglob("*.py") if path.is_dir() else [path]
        for file in files:
            if file.name == "loop.py":
                continue
            text = file.read_text(encoding="utf-8")
            if "from agent.loop import" in text or "import agent.loop" in text:
                matches.append(str(file))
    assert matches == []
