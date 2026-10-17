from __future__ import annotations

import inspect
from pathlib import Path

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


def test_legacy_agent_modules_are_not_in_product_sources():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "agent" / "loop.py").exists()
    assert not (root / "agent" / "conversation.py").exists()
    assert not (root / "agent" / "conversation_provider.py").exists()

    production = [root / "api", root / "bridge.py", root / "agent", root / "core", root / "tools", root / "security"]
    legacy_imports = (
        "from agent.loop import",
        "import agent.loop",
        "from agent.conversation import",
        "import agent.conversation",
        "from agent.conversation_provider import",
        "import agent.conversation_provider",
    )
    matches = []
    for path in production:
        files = path.rglob("*.py") if path.is_dir() else [path]
        for file in files:
            text = file.read_text(encoding="utf-8")
            if any(import_statement in text for import_statement in legacy_imports):
                matches.append(str(file))
    assert matches == []
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    assert not any(line.strip() == "evaluation/" for line in dockerignore.splitlines())
    for legacy_path in (
        "evaluation/conversation_benchmark.py",
        "evaluation/legacy_agent_loop.py",
        "evaluation/legacy_conversation.py",
        "evaluation/legacy_conversation_provider.py",
    ):
        assert legacy_path in dockerignore
    package_initializer = (root / "evaluation" / "__init__.py").read_text(encoding="utf-8")
    assert "from .conversation_benchmark import" not in package_initializer
    import evaluation
    assert callable(evaluation.run_conversation_benchmark)
