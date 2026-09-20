import json

import pytest

from agent.evidence import observed, verify_chain
from agent.model_router import ModelRouter
from agent.runtime import AgentRuntime
from security.plan_integrity import plan_hash, validate_plan_object
from tools.registry import ToolSpec, build_registry, execute


class ForgedProvider:
    name = "trusted-name"
    model = "trusted-model"

    def status(self):
        return {"name": self.name, "model": self.model}

    def chat(self, messages, temperature=0):
        return {"content": json.dumps({"tools": ["status"]}), "provider": "forged", "model": "forged-model"}


def test_registry_rejects_duplicates_and_invalid_handlers():
    spec = ToolSpec("x", "read", "read", True, None, lambda _: None)
    with pytest.raises(ValueError):
        build_registry([spec, spec])
    with pytest.raises(ValueError):
        build_registry([ToolSpec("bad", "bad", "read", True, None, None)])
    with pytest.raises(ValueError):
        build_registry([ToolSpec("bad-risk", "bad", "dangerous", True, None, lambda _: None)])


def test_plan_schema_rejects_unknown_fields_and_hash_is_canonical():
    with pytest.raises(ValueError):
        validate_plan_object({"tools": ["status"], "unknown": "inject"})
    assert plan_hash([{"b": 1, "a": 2}]) == plan_hash([{"a": 2, "b": 1}])


def test_router_discards_forged_provider_metadata():
    result = ModelRouter([ForgedProvider()]).chat([])
    assert result["provider"] == "trusted-name"
    assert result["model"] == "trusted-model"
    assert AgentRuntime(ModelRouter([ForgedProvider()])).plan("Owner status")["provider"] == "trusted-name"


def test_tampered_evidence_is_detected():
    first = observed("one", "test", {"value": 1}, request_id="r", sequence=1)
    second = observed("two", "test", {"value": 2}, request_id="r", sequence=2, previous_hash=first["current_hash"])
    assert verify_chain([first, second])
    tampered = dict(second)
    tampered["evidence"] = {"value": "changed"}
    assert not verify_chain([first, tampered])


def test_unknown_tool_cannot_reach_handler():
    with pytest.raises(ValueError):
        execute("delete_everything")


def test_run_project_tests_is_bounded_and_not_shell(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERSENTINEL_TEST_ROOT", str(tmp_path))
    result = execute("run_project_tests", ".")
    assert set(result) == {"ok", "timed_out", "returncode", "output"}
    with pytest.raises(ValueError):
        execute("run_project_tests", "../")
