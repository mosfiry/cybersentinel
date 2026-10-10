import pytest

from core.llm import model_status, plan_with_llm


def test_retired_llm_shim_reports_disabled_status():
    assert model_status() == {"configured": False, "retired": True}


def test_retired_llm_shim_fails_explicitly_without_fallback():
    with pytest.raises(RuntimeError, match=r"core\.llm is retired; use agent\.runtime\.AgentRuntime\.plan"):
        plan_with_llm("status")
