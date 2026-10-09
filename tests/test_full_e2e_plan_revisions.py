from dataclasses import replace
from types import SimpleNamespace

from agent.planning import Plan, PlanStep
from scripts.run_full_e2e_gate_acceptance import (
    MAX_QWEN_PLAN_REVISIONS,
    PLACEHOLDER_SERVER_ID,
    REQUIRED_QWEN_ACTION_NAMES,
    TOOL_NAME,
    _fixture_binding_preserves_model_arguments,
    _plan_with_validator_feedback,
    _qwen_acceptance_planning_schemas,
    _qwen_preflight_diagnostics,
    _redact_diagnostic_text,
    _safe_mission_execution_diagnostics,
    _validate_full_e2e_plan,
)
from scripts.windows_desktop_acceptance import _redact_diagnostic_text as _redact_windows_diagnostic_text


BROWSER_URL = "http://127.0.0.1:443/research-fixture"


def test_intent_selection_exposes_canonical_project_test_tool_only_within_owner_scope():
    from agent.agent_core import AgentCore

    class AcceptancePlanningCore(AgentCore):
        def _schemas(self):
            return _qwen_acceptance_planning_schemas(super()._schemas())

    core = AcceptancePlanningCore.__new__(AcceptancePlanningCore)
    objective = "Propose exactly one run_project_tests call with query bounded-test-project."

    assert AgentCore._eligible_planning_tools(core, objective, {"run_project_tests"}) == {"run_project_tests"}
    assert AgentCore._eligible_planning_tools(core, objective, {"status"}) == set()


def test_acceptance_browser_schema_hides_runtime_identity_and_limits_fixture_operations():
    from tools.registry import model_tool_definitions

    source_schemas = model_tool_definitions()
    original = next(item for item in source_schemas if item["function"]["name"] == "browser")
    planned_schemas = _qwen_acceptance_planning_schemas(source_schemas)
    planned = next(item for item in planned_schemas if item["function"]["name"] == "browser")
    original_parameters = original["function"]["parameters"]
    planned_parameters = planned["function"]["parameters"]

    assert "session_id" in original_parameters["properties"]
    assert set(planned_parameters["properties"]) == {"operation", "url"}
    assert planned_parameters["properties"]["operation"]["enum"] == ["open", "links"]
    assert planned_parameters["required"] == ["operation"]
    assert planned_parameters["additionalProperties"] is False
    assert "session_id" in original_parameters["properties"]
    assert "navigate" in original_parameters["properties"]["operation"]["enum"]


def _plan(entries):
    steps = tuple(
        PlanStep(
            step_id=f"model-step-{index}-{action}",
            objective=f"Model-proposed action {action}",
            action=action,
            expected_observation="observed result",
            retry_policy={"arguments": dict(arguments)},
        )
        for index, (action, arguments) in enumerate(entries, start=1)
    )
    return Plan.initial("Owner-scoped full E2E acceptance", created_from="qwen-test").replan(
        steps=steps,
        reason="model-proposed plan",
    )


def _complete_entries():
    return [
        ("status", {}),
        ("latest_intel", {}),
        ("browser", {"operation": "open", "url": BROWSER_URL}),
        ("browser", {"operation": "links"}),
        ("mcp.discover", {"server_id": PLACEHOLDER_SERVER_ID, "tool_name": TOOL_NAME}),
        ("mcp.invoke", {"server_id": PLACEHOLDER_SERVER_ID, "tool_name": TOOL_NAME, "arguments": {"query": "full-e2e"}}),
        ("run_project_tests", {"query": "bounded-test-project"}),
    ]


def test_qwen_preflight_diagnostics_distinguish_state_and_exclude_raw_model_content():
    marker = "UNTRUSTED-PLAN-CONTENT"
    mission = SimpleNamespace(
        mission_id="mission-fixture",
        status=SimpleNamespace(value="FAILED_RETRY_EXHAUSTED"),
        plan=_plan([("status", {"note": marker}), (marker, {})]),
        failures=[{"reason": marker}],
        authorization_snapshot={},
        verify_integrity=lambda: True,
    )
    model_attempts = [{
        "visible_tool_names": list(REQUIRED_QWEN_ACTION_NAMES),
        "model_tool_names": ["status", marker],
        "planned_action_names": ["status", marker],
    }]
    validation_attempts = [{
        "attempt": 1,
        "valid": False,
        "planned_action_names": ["status", marker],
        "missing_required_action_names": ["latest_intel"],
        "unexpected_action_names": [marker],
        "validation_issues": ["missing_required_actions"],
        "action_counts": {"status": 1, marker: 1},
    }]

    summary = _qwen_preflight_diagnostics(mission, model_attempts, validation_attempts)

    assert summary["mission"]["status_before_fixture_binding"] == "FAILED_RETRY_EXHAUSTED"
    assert summary["mission"]["integrity_valid_before_fixture_binding"] is True
    assert summary["mission"]["planning_failure_count"] == 1
    assert summary["qwen_planning"]["final_validation_valid"] is False
    assert summary["qwen_planning"]["required_tool_schemas_visible"] is True
    assert set(summary["qwen_planning"]["visible_required_tool_names"]) == set(REQUIRED_QWEN_ACTION_NAMES)
    assert summary["qwen_planning"]["missing_final_model_tool_names"]
    assert "<invalid_action_name>" in summary["qwen_planning"]["final_model_tool_names"]
    assert marker not in repr(summary)


def test_mission_execution_diagnostics_locate_inflight_failure_without_raw_tool_data():
    marker = "RAW-OWNER-OR-TOOL-CONTENT"
    plan = _plan([
        ("status", {}),
        ("run_project_tests", {"query": marker}),
    ])
    mission = SimpleNamespace(
        status=SimpleNamespace(value="RUNNING"),
        current_step=1,
        plan=plan,
        checkpoint={"status": "in_flight", "step_id": "model-step-2-run_project_tests", "action_id": marker},
        action_history=[{
            "action_id": marker,
            "step_id": "model-step-1-status",
            "status": "completed",
            "observation": {"success": True, "private": marker},
        }],
        observations=[{"type": "execution_exception", "success": False, "error": marker}],
        failures=[{"class": "RESOURCE", "step_id": "model-step-2-run_project_tests", "reason": marker}],
        error="TimeoutError",
        evidence=[{"result": marker}],
        verification_state={},
        verify_integrity=lambda: True,
    )

    summary = _safe_mission_execution_diagnostics(mission)

    assert summary["mission_status"] == "RUNNING"
    assert summary["mission_integrity_valid"] is True
    assert summary["current_step_action_name"] == "run_project_tests"
    assert summary["checkpoint_status"] == "in_flight"
    assert summary["checkpoint_action_name"] == "run_project_tests"
    assert summary["checkpoint_outcome_ambiguous"] is True
    assert summary["action_results"] == [{"action_name": "status", "result_status": "completed"}]
    assert summary["failure_classes"] == ["RESOURCE"]
    assert summary["last_failure_action_name"] == "run_project_tests"
    assert summary["last_observation_type"] == "execution_exception"
    assert summary["execution_exception_type"] == "TimeoutError"
    assert marker not in repr(summary)

    malformed = SimpleNamespace(
        status=SimpleNamespace(value="RUNNING"),
        current_step=1,
        plan=plan,
        checkpoint={"status": [marker], "step_id": "model-step-2-run_project_tests"},
        action_history=[{"step_id": "model-step-2-run_project_tests", "status": [marker]}],
        observations=[{"type": [marker], "success": False}],
        failures=[{"class": [marker], "step_id": "model-step-2-run_project_tests"}],
        error=[marker],
        evidence=[],
        verification_state={},
        verify_integrity=lambda: True,
    )
    malformed_summary = _safe_mission_execution_diagnostics(malformed)

    assert malformed_summary["checkpoint_status"] == "unknown"
    assert malformed_summary["last_observation_type"] == "other"
    assert malformed_summary["failure_classes"] == []
    assert malformed_summary["execution_exception_type"] is None
    assert marker not in repr(malformed_summary)


def test_effect_recovery_diagnostics_include_only_safe_state_and_reason_code():
    marker = "RAW-EFFECT-IDENTIFIER-OR-DETAIL"
    mission = SimpleNamespace(
        status=SimpleNamespace(value="RECOVERY_REQUIRED"),
        current_step=0,
        plan=_plan([("browser", {"operation": "links"})]),
        checkpoint={"status": "in_flight", "step_id": "model-step-1-browser", "effect_id": marker},
        action_history=[],
        observations=[{
            "type": "external_effect_recovery_required",
            "success": False,
            "effect_id": marker,
            "effect_state": "RECOVERY_REQUIRED",
            "reason_code": "HANDLER_MISSION_ARTIFACT_STORE_UNAVAILABLE",
            "error": marker,
        }],
        failures=[{"class": "UNKNOWN", "effect_id": marker, "reason": marker}],
        error=marker,
        evidence=[],
        verification_state={},
        verify_integrity=lambda: True,
    )

    summary = _safe_mission_execution_diagnostics(mission)

    assert summary["mission_status"] == "RECOVERY_REQUIRED"
    assert summary["last_effect_state"] == "RECOVERY_REQUIRED"
    assert summary["last_effect_reason_code"] == "HANDLER_MISSION_ARTIFACT_STORE_UNAVAILABLE"
    assert marker not in repr(summary)

    mission.observations = [{
        "type": "external_effect_recovery_required",
        "effect_state": marker,
        "reason_code": marker,
    }]
    malformed_summary = _safe_mission_execution_diagnostics(mission)
    assert malformed_summary["last_effect_state"] is None
    assert malformed_summary["last_effect_reason_code"] is None
    assert marker not in repr(malformed_summary)


def test_plan_validator_feedback_reaches_model_and_only_model_revision_supplies_steps():
    incomplete = _plan(_complete_entries()[:-3])
    revised = _plan(_complete_entries())
    calls = []

    def planner(objective, feedback):
        calls.append((objective, feedback))
        return incomplete if len(calls) == 1 else revised

    returned, attempts = _plan_with_validator_feedback(
        planner,
        "Owner-scoped full E2E acceptance",
        available_tool_names=REQUIRED_QWEN_ACTION_NAMES,
        expected_browser_url=BROWSER_URL,
    )

    assert returned is revised
    assert len(calls) == 2
    assert calls[0][1] is None
    assert calls[1][1]["record_type"] == "QWEN_PLAN_VALIDATION_FEEDBACK"
    assert calls[1][1]["valid"] is False
    assert "mcp.invoke" in calls[1][1]["missing_required_action_names"]
    assert "run_project_tests" in calls[1][1]["missing_required_action_names"]
    assert attempts[0]["valid"] is False
    assert attempts[1]["valid"] is True
    assert attempts[1]["planned_action_names"] == [action for action, _ in _complete_entries()]
    assert len(returned.steps) == len(_complete_entries())


def test_plan_revision_is_bounded_and_never_fills_missing_steps():
    incomplete = _plan(_complete_entries()[:-1])
    feedbacks = []

    def planner(_objective, feedback):
        feedbacks.append(feedback)
        return incomplete

    returned, attempts = _plan_with_validator_feedback(
        planner,
        "Owner-scoped full E2E acceptance",
        available_tool_names=REQUIRED_QWEN_ACTION_NAMES,
        expected_browser_url=BROWSER_URL,
    )

    assert len(feedbacks) == MAX_QWEN_PLAN_REVISIONS + 1
    assert returned is incomplete
    assert all(feedbacks[index] is None for index in [0])
    assert all(feedback["record_type"] == "QWEN_PLAN_VALIDATION_FEEDBACK" for feedback in feedbacks[1:])
    assert len(attempts) == MAX_QWEN_PLAN_REVISIONS + 1
    assert attempts[-1]["valid"] is False
    assert "run_project_tests" in attempts[-1]["missing_required_action_names"]
    assert len(returned.steps) == len(_complete_entries()) - 1


def test_plan_revision_stops_when_owner_tool_allowlist_does_not_include_missing_action():
    incomplete = _plan(_complete_entries()[:-1])
    calls = []

    def planner(_objective, feedback):
        calls.append(feedback)
        return incomplete

    authorized_tools = set(REQUIRED_QWEN_ACTION_NAMES) - {"run_project_tests"}
    returned, attempts = _plan_with_validator_feedback(
        planner,
        "Owner-scoped full E2E acceptance",
        available_tool_names=authorized_tools,
        expected_browser_url=BROWSER_URL,
    )

    assert returned is incomplete
    assert len(calls) == 1
    assert attempts[0]["valid"] is False
    assert attempts[0]["authorization_ceiling_blocked_action_names"] == ["run_project_tests"]
    assert "required_actions_not_authorized" in attempts[0]["validation_issues"]


def test_plan_revision_rejects_required_action_present_but_outside_allowlist():
    complete = _plan(_complete_entries())
    calls = []

    def planner(_objective, feedback):
        calls.append(feedback)
        return complete

    authorized_tools = set(REQUIRED_QWEN_ACTION_NAMES) - {"run_project_tests"}
    returned, attempts = _plan_with_validator_feedback(
        planner,
        "Owner-scoped full E2E acceptance",
        available_tool_names=authorized_tools,
        expected_browser_url=BROWSER_URL,
    )

    assert returned is complete
    assert calls == [None]
    assert attempts[0]["valid"] is False
    assert attempts[0]["authorization_ceiling_blocked_action_names"] == ["run_project_tests"]
    assert "required_actions_not_authorized" in attempts[0]["validation_issues"]


def test_plan_revision_rejects_extra_browser_links_arguments_before_execution():
    invalid_entries = _complete_entries()
    invalid_entries[3] = ("browser", {"operation": "links", "url": BROWSER_URL})
    invalid_plan = _plan(invalid_entries)
    valid_plan = _plan(_complete_entries())
    calls = []

    def planner(_objective, feedback):
        calls.append(feedback)
        return invalid_plan if len(calls) == 1 else valid_plan

    returned, attempts = _plan_with_validator_feedback(
        planner,
        "Owner-scoped full E2E acceptance",
        available_tool_names=REQUIRED_QWEN_ACTION_NAMES,
        expected_browser_url=BROWSER_URL,
    )

    assert returned is valid_plan
    assert len(calls) == 2
    assert attempts[0]["valid"] is False
    assert "browser_links_arguments_mismatch" in attempts[0]["validation_issues"]
    assert attempts[0]["browser_open_arguments_match"] is True
    assert attempts[0]["browser_links_arguments_match"] is False
    assert calls[1]["requirements"]["browser_open_arguments_exact"] == {
        "operation": "open",
        "url": BROWSER_URL,
    }
    assert calls[1]["requirements"]["browser_links_arguments_exact"] == {"operation": "links"}
    assert attempts[1]["valid"] is True
    assert attempts[1]["browser_links_arguments_match"] is True


def test_plan_validator_rejects_extra_mcp_invocation_arguments():
    entries = _complete_entries()
    entries[-2] = (
        "mcp.invoke",
        {"server_id": PLACEHOLDER_SERVER_ID, "tool_name": TOOL_NAME, "arguments": {"query": "full-e2e", "extra": "not-approved"}},
    )

    validation = _validate_full_e2e_plan(_plan(entries), expected_browser_url=BROWSER_URL)

    assert validation["valid"] is False
    assert validation["mcp_invoke_arguments_match"] is False
    assert "mcp_invoke_arguments_mismatch" in validation["validation_issues"]


def test_plan_validator_rejects_guessed_mcp_identity_and_browser_session_id():
    entries = _complete_entries()
    entries[2] = (
        "browser",
        {"operation": "open", "url": BROWSER_URL, "session_id": "bs_" + "1" * 32},
    )
    entries[4] = (
        "mcp.discover",
        {"server_id": "mcp_" + "1" * 32, "tool_name": TOOL_NAME},
    )

    validation = _validate_full_e2e_plan(_plan(entries), expected_browser_url=BROWSER_URL)

    assert validation["valid"] is False
    assert validation["browser_session_id_is_harness_bound"] is False
    assert validation["mcp_discover_arguments_match"] is False
    assert "browser_session_id_must_be_harness_bound" in validation["validation_issues"]
    assert "mcp_discover_arguments_mismatch" in validation["validation_issues"]


def test_plan_validator_rejects_unrequested_tool_actions():
    entries = [*_complete_entries(), ("browser.close", {})]

    validation = _validate_full_e2e_plan(_plan(entries), expected_browser_url=BROWSER_URL)

    assert validation["valid"] is False
    assert validation["unexpected_action_names"] == ["browser.close"]
    assert "unexpected_actions" in validation["validation_issues"]


def test_fixture_binding_changes_only_dynamic_identity_arguments():
    model_plan = _plan(_complete_entries())
    browser_session_id = "bs_" + "a" * 32
    mcp_server_id = "mcp_" + "b" * 32
    bound_steps = []
    for step in model_plan.steps:
        arguments = dict(step.retry_policy["arguments"])
        if step.action == "browser":
            arguments["session_id"] = browser_session_id
        elif step.action in {"mcp.discover", "mcp.invoke"}:
            arguments["server_id"] = mcp_server_id
        bound_steps.append(replace(step, retry_policy={"arguments": arguments}))

    assert _fixture_binding_preserves_model_arguments(
        model_plan.steps,
        tuple(bound_steps),
        browser_session_id=browser_session_id,
        mcp_server_id=mcp_server_id,
    )

    altered_steps = list(bound_steps)
    test_step = altered_steps[-1]
    altered_steps[-1] = replace(
        test_step,
        retry_policy={"arguments": {"query": "different-project"}},
    )
    assert not _fixture_binding_preserves_model_arguments(
        model_plan.steps,
        tuple(altered_steps),
        browser_session_id=browser_session_id,
        mcp_server_id=mcp_server_id,
    )


def test_diagnostic_redactors_remove_owner_and_bearer_secrets():
    owner_secret = "owner-session-secret-123456"
    bearer_label = "Bear" + "er"
    message = (
        f"owner_password={owner_secret}; Authorization: {bearer_label} bearer-session-secret-123456"
    )

    for redact in (_redact_diagnostic_text, _redact_windows_diagnostic_text):
        sanitized = redact(message, (owner_secret,))
        assert owner_secret not in sanitized
        assert "bearer-session-secret-123456" not in sanitized
        assert sanitized.count("[REDACTED]") >= 2
