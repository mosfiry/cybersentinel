from __future__ import annotations

import pytest

from tools.registry import (
    REGISTRY,
    ToolSpec,
    build_registry,
    get_tool,
    model_tool_definitions,
    tool_definitions,
)


def _handler(_argument):
    return {"ok": True}


def _spec(name: str = "test.tool", **overrides) -> ToolSpec:
    values = {
        "name": name,
        "description": "Bounded contract-test handler.",
        "risk_class": "read",
        "requires_owner": True,
        "argument_type": None,
        "handler": _handler,
    }
    values.update(overrides)
    return ToolSpec(**values)


def test_canonical_registry_is_single_source_with_complete_access_contracts():
    expected_fields = {
        "risk_class",
        "required_authorization",
        "scope_requirements",
        "input_schema",
        "output_schema",
        "network_access",
        "filesystem_access",
        "process_access",
        "credential_access",
        "evidence_requirements",
        "timeout",
    }
    definitions = {item["tool_id"]: item for item in tool_definitions()}
    assert set(definitions) == set(REGISTRY)
    assert {item["function"]["name"] for item in model_tool_definitions()} == set(REGISTRY)
    for name, spec in REGISTRY.items():
        metadata = spec.metadata()
        assert expected_fields <= metadata.keys()
        assert metadata["risk_class"]
        assert metadata["required_authorization"] in {"none", "owner", "owner_and_scope_snapshot"}
        assert isinstance(metadata["scope_requirements"], list)
        assert isinstance(metadata["input_schema"], dict)
        assert isinstance(metadata["output_schema"], dict)
        assert metadata["network_access"]
        assert metadata["filesystem_access"]
        assert metadata["process_access"]
        assert metadata["credential_access"]
        assert metadata["evidence_requirements"]
        assert metadata["timeout"] > 0
        assert get_tool(name) is spec
    pytest_tool = REGISTRY["run_project_tests"]
    assert pytest_tool.risk_class == "bounded-exec"
    assert pytest_tool.network_access == "host_process_unscoped"
    assert pytest_tool.filesystem_access == "host_fs_via_process"
    assert pytest_tool.process_access == "workspace_process_unisolated"
    assert pytest_tool.credential_access == "host_user_credentials_possible"
    assert pytest_tool.timeout == 65
    assert "git.status" not in REGISTRY and "archive.inspect" not in REGISTRY


@pytest.mark.parametrize(
    "overrides",
    [
        {"risk_class": []},
        {"network_access": "unrestricted"},
        {"filesystem_access": []},
        {"process_access": "host_shell"},
        {"credential_access": "caller_supplied"},
        {"evidence_requirements": ()},
        {"evidence_requirements": ([],)},
        {"scope_requirements": ("network",)},
        {"scope_required": True, "scope_requirements": ()},
        {"timeout": True},
    ],
)
def test_registry_rejects_malformed_or_incomplete_tool_metadata(overrides):
    with pytest.raises(ValueError):
        build_registry([_spec(**overrides)])


def test_scope_bound_tool_must_require_owner_and_name_its_scope_constraints():
    with pytest.raises(ValueError):
        build_registry([_spec(scope_required=True, scope_requirements=("target_identity",), requires_owner=False)])


def test_tool_timeout_is_the_effective_canonical_dispatch_limit():
    from tools.registry import execute

    assert callable(execute)
    assert REGISTRY["refresh_intel"].timeout == 30
    assert REGISTRY["run_project_tests"].timeout == 65
