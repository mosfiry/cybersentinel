"""Fixed deterministic adversarial regression catalog (control-plane evidence only)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdversarialCase:
    case_id: str
    description: str
    test_nodeid: str


ADVERSARIAL_BENCHMARK_VERSION = "cybersentinel-adversarial-control-plane-v1"
ADVERSARIAL_CASES = (
    AdversarialCase(
        "prompt-injection",
        "Hostile stored instruction text remains inert user data, never Owner policy.",
        "tests/test_mission_memory_engine.py::test_hostile_legacy_memory_is_never_a_system_or_owner_policy_message",
    ),
    AdversarialCase(
        "web-injection",
        "External webpage/document instructions cannot enter the trusted memory candidate channel.",
        "tests/test_mission_memory_engine.py::test_external_instruction_material_cannot_enter_memory_candidate_writer",
    ),
    AdversarialCase(
        "memory-poisoning",
        "Fabricated agent output remains pending, untrusted, bounded, and unretrievable.",
        "tests/test_mission_memory_engine.py::test_fabricated_agent_output_stays_pending_untrusted_and_not_retrievable",
    ),
    AdversarialCase(
        "skill-poisoning",
        "Nested declarative Skill content tampering invalidates its canonical digest.",
        "tests/agent_intelligence/test_skills.py::test_mutated_nested_condition_expectation_fails_skill_content_hash",
    ),
    AdversarialCase(
        "malicious-mcp",
        "MCP descriptions and schemas cannot inject executable tool authority.",
        "tests/test_mcp_client.py::test_mcp_description_and_schema_injection_are_rejected_or_discarded",
    ),
    AdversarialCase(
        "cross-mission-leakage",
        "Foreign and absent Mission observability reads are isolated with the same result.",
        "tests/test_mission_observability.py::test_foreign_mission_and_missing_mission_are_the_same_service_result",
    ),
    AdversarialCase(
        "scope-escalation",
        "Tampered child scope is rejected before any provider call.",
        "tests/test_provider_bound_specialists.py::test_scope_tampering_is_rejected_before_any_provider_call",
    ),
    AdversarialCase(
        "tool-privilege-escalation",
        "Schema-invalid task tool batches are rejected before executor dispatch.",
        "tests/test_v11_provider_tool_hardening.py::test_task_runtime_rejects_schema_invalid_batches_before_dispatch",
    ),
    AdversarialCase(
        "fake-evidence",
        "Tampering with persisted evidence invalidates the hash chain.",
        "tests/test_evidence_chain_store.py::test_chain_verification_detects_payload_tampering",
    ),
    AdversarialCase(
        "provider-failure",
        "Non-retryable provider request rejection preserves the Mission boundary and evidence.",
        "tests/test_mission_provider_failure_state.py::test_nonretryable_http_request_rejection_preserves_status_and_mission_evidence",
    ),
    AdversarialCase(
        "browser-failure",
        "Browser timeout is bounded and propagates Mission cancellation.",
        "tests/test_browser_tools.py::test_browser_timeout_sets_mission_cancellation_event",
    ),
    AdversarialCase(
        "runtime-crash",
        "Crash-boundary recovery quarantines uncertain effects and prevents replay.",
        "tests/test_v9_crash_injection.py::test_worker_restart_quarantines_writeahead_crashes_without_replay",
    ),
    AdversarialCase(
        "mission-interruption",
        "Owner cancellation of an ambiguous effect requests stop without claiming it stopped.",
        "tests/test_mission_graph_runtime.py::test_owner_cancel_of_recovery_requests_stop_without_claiming_effect_stopped",
    ),
    AdversarialCase(
        "restart-resume",
        "Restart does not resume an in-flight effect without reconciliation.",
        "tests/test_crash_restart_resume.py::test_restart_never_continues_in_flight_without_reconciliation",
    ),
)

__all__ = ["ADVERSARIAL_BENCHMARK_VERSION", "ADVERSARIAL_CASES", "AdversarialCase"]
