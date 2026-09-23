from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Capability tests — the audited Vibe facts, exactly as proven.
# ---------------------------------------------------------------------------

@pytest.fixture()
def vibe():
    from worker import VIBE_CAPABILITY_SET
    return VIBE_CAPABILITY_SET


def test_http_get_available(vibe):
    assert vibe.status_of("https_get").value == "AVAILABLE"


def test_http_post_not_available(vibe):
    assert vibe.status_of("http_post").value == "NOT_AVAILABLE"


def test_custom_headers_not_available(vibe):
    assert vibe.status_of("custom_request_headers").value == "NOT_AVAILABLE"


def test_response_headers_not_available(vibe):
    assert vibe.status_of("response_headers").value == "NOT_AVAILABLE"


def test_browser_not_available(vibe):
    assert vibe.status_of("browser").value == "NOT_AVAILABLE"


def test_javascript_execution_not_available(vibe):
    assert vibe.status_of("javascript_browser_execution").value == "NOT_AVAILABLE"


def test_long_running_worker_not_available(vibe):
    assert vibe.status_of("long_running_worker").value == "NOT_AVAILABLE"


def test_unknown_never_becomes_available(vibe):
    from worker.capability import CapabilityStatus
    for name in ("scheduled_tasks_execution", "sha256_sandbox", "max_session_duration"):
        assert vibe.status_of(name) is CapabilityStatus.UNKNOWN
    # and a fabricated unverified AVAILABLE capability is rejected by guard
    from worker.capability import WorkerCapability
    with pytest.raises(ValueError):
        WorkerCapability("fabricated", CapabilityStatus.AVAILABLE, verified=False).require_verified()


# ---------------------------------------------------------------------------
# Requirement tests — deterministic, no LLM in the loop.
# ---------------------------------------------------------------------------

def _check(vibe, *names):
    from worker import CapabilityRequirement, check_requirements
    return check_requirements([CapabilityRequirement(n) for n in names], vibe)


def test_requirement_http_get_allowed(vibe):
    result = _check(vibe, "https_get")
    assert result.decision.value == "ALLOWED_BY_CAPABILITY"
    assert result.allowed is True
    assert result.missing == ()


def test_requirement_http_get_plus_custom_headers_blocked(vibe):
    result = _check(vibe, "https_get", "custom_request_headers")
    assert result.decision.value == "BLOCKED_CAPABILITY"
    assert result.allowed is False
    assert result.missing == ("custom_request_headers",)


def test_requirement_browser_blocked(vibe):
    result = _check(vibe, "browser")
    assert result.decision.value == "BLOCKED_CAPABILITY"
    assert result.missing == ("browser",)


def test_requirement_http_post_blocked(vibe):
    result = _check(vibe, "http_post")
    assert result.decision.value == "BLOCKED_CAPABILITY"


def test_requirement_long_running_worker_blocked(vibe):
    result = _check(vibe, "long_running_worker")
    assert result.decision.value == "BLOCKED_CAPABILITY"


def test_unknown_requirement_blocks_and_is_not_available(vibe):
    result = _check(vibe, "https_get", "sha256_sandbox")
    assert result.decision.value == "BLOCKED_UNKNOWN_CAPABILITY"
    assert result.allowed is False
    assert result.unknown == ("sha256_sandbox",)


def test_cache_poisoning_hypothesis_blocked_with_provable_reason(vibe):
    # Hypothesis: Web Cache Poisoning needs (verified audit facts):
    result = _check(vibe, "https_get", "custom_request_headers", "response_headers", "cache_control_observation")
    assert result.decision.value == "BLOCKED_CAPABILITY"
    assert result.missing == ("custom_request_headers", "response_headers", "cache_control_observation")
    # BLOCKED_CAPABILITY — never EXECUTE_ANYWAY; the reason is enumerable.


def test_limited_capability_flags_limitations(vibe):
    result = _check(vibe, "internet")
    assert result.decision.value == "ALLOWED_WITH_LIMITATIONS"
    assert result.limited == ("internet",)
    assert result.allowed is True


# ---------------------------------------------------------------------------
# Security tests — capability != authorization; existing paths untouched.
# ---------------------------------------------------------------------------

def test_capability_never_grants_authority():
    from worker import LiveResearchWorkerAdapter
    assert LiveResearchWorkerAdapter.capability_grants_authority() is False


def test_worker_cannot_authenticate_as_owner(monkeypatch):
    # The strongest possible worker capability evidence still fails
    # security.owner_policy.verify_owner — the only owner auth path.
    monkeypatch.setenv("OWNER_TOKEN", "owner-secret")
    import importlib
    import security.owner_policy as owner_policy
    importlib.reload(owner_policy)
    from worker import VIBE_CAPABILITY_SET, CapabilityStatus
    # even a full AVAILABLE capability set is not a credential
    ok, _reason = owner_policy.verify_owner("Worker task", "capability:https_get:AVAILABLE")
    assert ok is False
    ok, _reason = owner_policy.verify_owner("Worker task", "")
    assert ok is False


def test_plan_always_requires_authorization(vibe):
    from worker import LiveResearchWorkerAdapter, CapabilityRequirement
    adapter = LiveResearchWorkerAdapter(vibe)
    plan = adapter.plan_task("t1", [CapabilityRequirement("https_get")])
    assert plan.authorization_required is True  # capability allowed != authorized
    assert plan.dispatchable is True  # dispatchable refers ONLY to capability


def test_blocked_plan_is_not_dispatchable(vibe):
    from worker import LiveResearchWorkerAdapter, CapabilityRequirement
    adapter = LiveResearchWorkerAdapter(vibe)
    plan = adapter.plan_task("t2", [CapabilityRequirement("browser")])
    assert plan.dispatchable is False
    assert plan.blocked_reason == ("browser",)


def test_provenance_no_promotion_of_worker_data_to_authority():
    from worker import ProvenanceLayer, promotion_allowed
    for worker_layer in (ProvenanceLayer.EXTERNAL_DATA, ProvenanceLayer.MODEL_OUTPUT, ProvenanceLayer.TOOL_RUNTIME):
        for authority in (ProvenanceLayer.OWNER_INSTRUCTION, ProvenanceLayer.OWNER_POLICY, ProvenanceLayer.AUTHORIZATION_SCOPE):
            assert promotion_allowed(worker_layer, authority) is False


def test_evidence_cannot_claim_authority_provenance(vibe):
    from worker import LiveResearchWorkerAdapter, WorkerObservation, ObservationKind, EvidenceClass
    adapter = LiveResearchWorkerAdapter(vibe)
    with pytest.raises(ValueError):
        WorkerObservation(
            request_id="r1", worker_id=vibe.worker_id, capability="https_get",
            timestamp="2026-09-23T00:00:00Z", target="example.com",
            operation=ObservationKind.RESPONSE_BODY, url="https://example.com",
            evidence_class=EvidenceClass.OBSERVED, status="200",
            provenance=ProvenanceLayer.AUTHORIZATION_SCOPE,
        )


def test_adapter_rejects_foreign_worker_evidence(vibe):
    from worker import LiveResearchWorkerAdapter, WorkerObservation, ObservationKind, EvidenceClass
    adapter = LiveResearchWorkerAdapter(vibe)
    with pytest.raises(ValueError):
        adapter.accept_evidence(WorkerObservation(
            request_id="r2", worker_id="someone-else", capability="https_get",
            timestamp="2026-09-23T00:00:00Z", target="example.com",
            operation=ObservationKind.RESPONSE_BODY, url="https://example.com",
            evidence_class=EvidenceClass.OBSERVED, status="200",
        ))


def test_hierarchy_order_unchanged():
    from worker import PROVENANCE_HIERARCHY, ProvenanceLayer
    assert [l.value for l in PROVENANCE_HIERARCHY] == [
        "OWNER_INSTRUCTION", "SYSTEM_PLATFORM", "OWNER_POLICY",
        "DETERMINISTIC_ENFORCEMENT", "AUTHORIZATION_SCOPE",
        "TOOL_RUNTIME", "MODEL_OUTPUT", "EXTERNAL_DATA",
    ]


# ---------------------------------------------------------------------------
# Evidence tests — body difference is not a vulnerability.
# ---------------------------------------------------------------------------

def _obs(operation, evidence_class, metadata=None):
    from worker import WorkerObservation, EvidenceClass, ObservationKind
    assert isinstance(operation, ObservationKind)
    assert isinstance(evidence_class, EvidenceClass)
    return WorkerObservation(
        request_id="r", worker_id="vibe-live-worker", capability="https_get",
        timestamp="2026-09-23T00:00:00Z", target="example.com",
        operation=operation, url="https://example.com",
        evidence_class=evidence_class, status="200",
        body_hash="deadbeef", body_length=42, duration_ms=120,
        metadata=metadata or {},
    )


def test_body_difference_is_not_confirmed_finding():
    from worker import finding_status_from_observation, ObservationKind, EvidenceClass, FindingStatus
    obs = _obs(ObservationKind.RESPONSE_DIFFERENCE, EvidenceClass.OBSERVED)
    assert finding_status_from_observation(obs) is FindingStatus.UNPROVEN


def test_worker_cannot_self_confirm_finding():
    from worker import finding_status_from_observation, ObservationKind, EvidenceClass, FindingStatus
    obs = _obs(ObservationKind.RESPONSE_DIFFERENCE, EvidenceClass.CONFIRMED, metadata={})
    # no validator corroboration -> stays UNPROVEN
    assert finding_status_from_observation(obs) is FindingStatus.UNPROVEN


def test_validator_corroboration_is_explicit_metadata():
    from worker import finding_status_from_observation, ObservationKind, EvidenceClass, FindingStatus
    obs = _obs(ObservationKind.RESPONSE_MATCH, EvidenceClass.CONFIRMED, metadata={"corroborated_by_validator": True})
    assert finding_status_from_observation(obs) is FindingStatus.CONFIRMED


def test_hypothesis_stays_unproven():
    from worker import finding_status_from_observation, ObservationKind, EvidenceClass, FindingStatus
    obs = _obs(ObservationKind.RESPONSE_BODY, EvidenceClass.HYPOTHESIS)
    assert finding_status_from_observation(obs) is FindingStatus.UNPROVEN


def test_plain_observation_is_observation():
    from worker import finding_status_from_observation, ObservationKind, EvidenceClass, FindingStatus
    obs = _obs(ObservationKind.BODY_HASH, EvidenceClass.OBSERVED)
    assert finding_status_from_observation(obs) is FindingStatus.OBSERVATION


# ---------------------------------------------------------------------------
# Unknown handling — UNKNOWN is never AVAILABLE.
# ---------------------------------------------------------------------------

def test_unknown_status_is_first_class():
    from worker.capability import CapabilityStatus
    assert CapabilityStatus.UNKNOWN.value == "UNKNOWN"
    assert CapabilityStatus.AVAILABLE.value == "AVAILABLE"


def test_unlisted_capability_is_unknown_not_available(vibe):
    from worker.capability import CapabilityStatus
    assert vibe.status_of("nonexistent_capability") is CapabilityStatus.UNKNOWN
