from scripts.acceptance_result import apply_cleanup_gate


def test_cleanup_failure_downgrades_acceptance_pass():
    result = {"status": "PASS", "checks": {"mission_verified": True}}

    assert not apply_cleanup_gate(
        result,
        {"runtime_stopped": True, "temporary_state_removed": False},
    )

    assert result["status"] == "FAIL"
    assert result["checks"]["cleanup_runtime_stopped"] is True
    assert result["checks"]["cleanup_temporary_state_removed"] is False
    assert result["cleanup_failures"] == ["temporary_state_removed"]


def test_successful_cleanup_preserves_but_does_not_upgrade_feature_status():
    passing = {"status": "PASS", "checks": {"mission_verified": True}}
    assert apply_cleanup_gate(passing, {"runtime_stopped": True})
    assert passing["status"] == "PASS"
    assert passing["cleanup_verified"] is True

    failing = {"status": "FAIL", "checks": {"mission_verified": False}}
    assert apply_cleanup_gate(failing, {"runtime_stopped": True})
    assert failing["status"] == "FAIL"
