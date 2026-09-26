"""Real bounded scoped_dns_lookup handler + live-bridge battery.

P1 of the Offensive Capability Activation mission. The DNS observation is a
REAL bounded capability behind the full authorization chain: typed proposal →
ScopeGuard canonical url → existing proof chain → tools.registry.execute →
single DNS seam. No test performs a real network call: the single DNS seam
(_dns_resolve) is faked at the module boundary.

Coverage:
- success observation (host extracted from the canonical url, structured records)
- duplicate records are deduplicated; ordering is deterministic
- record sets beyond the hard cap are truncated
- resolver failure classifies fail-closed (ok False, DNS_FAILED, no exception)
- non-url / non-string / hostless arguments are rejected BEFORE the seam
- the observation carries no authority-shaped keys
- catalog/runtime disjointness (registered in the registry, never in the catalog)
- LIVE bridge reachability: a real owner-authenticated mission flows through
  MissionRuntime → OffensiveActionBridge → registry scope re-resolution with
  a REAL typed Owner AuthorizationDecision and a persisted scope snapshot
- observed DNS addresses can never widen scope (second action against a
  resolved address is rejected before any execution)
- a decision issued for another tool is rejected
- dry-run executes nothing
"""

from __future__ import annotations

import socket
from dataclasses import replace as dataclass_replace
from pathlib import Path

import pytest

import tools.registry
from runtime_authorization import make_test_authorization_context, make_test_snapshot

import security.owner_policy as owner_policy
import security.scope_store as scope_store
from security.scope_store import init_scope_store, save_snapshot

from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.offensive_bridge import (
    OffensiveActionBridge,
    OffensiveActionProposal,
    OffensiveActionRejected,
    ScopedDnsLookupAdapter,
)
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationDecision
from security.scope import ProgramAuthorization, TargetIdentity, canonical_url, make_snapshot
from tools.registry import SCOPED_DNS_MAX_RECORDS, _scoped_dns_lookup


# ---------------------------------------------------------------------------
# Handler battery (deterministic bounds at the single DNS seam)
# ---------------------------------------------------------------------------

_RESOLVE_OK = [
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),  # duplicate
    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
]


@pytest.fixture
def resolve_log(monkeypatch):
    log: list = []

    def fake_resolve(host):
        log.append(host)
        return _RESOLVE_OK

    monkeypatch.setattr(tools.registry, "_dns_resolve", fake_resolve)
    return log


def test_success_observation_is_structured(resolve_log):
    result = _scoped_dns_lookup("https://target.example/")
    assert result["ok"] is True
    assert result["operation"] == "scoped_dns_lookup"
    assert result["url"] == "https://target.example/"
    assert result["host"] == "target.example"
    assert result["truncated"] is False
    assert isinstance(result["elapsed_ms"], int)
    # Exactly ONE resolve of exactly the canonical url's host.
    assert resolve_log == ["target.example"]
    # Duplicates are deduplicated; ordering is deterministic (family, address).
    assert result["records"] == [
        {"family": "AF_INET", "address": "203.0.113.10"},
        {"family": "AF_INET6", "address": "2001:db8::10"},
    ]
    assert result["record_count"] == 2


def test_record_sets_beyond_hard_cap_are_truncated(monkeypatch):
    many = [(socket.AF_INET, 1, 6, "", (f"203.0.113.{index}", 0)) for index in range(SCOPED_DNS_MAX_RECORDS + 5)]
    monkeypatch.setattr(tools.registry, "_dns_resolve", lambda host: many)
    result = _scoped_dns_lookup("https://target.example/")
    assert result["ok"] is True
    assert result["truncated"] is True
    assert result["record_count"] == SCOPED_DNS_MAX_RECORDS
    assert len(result["records"]) == SCOPED_DNS_MAX_RECORDS


def test_resolver_failure_fails_closed(monkeypatch):
    def failing(host):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(tools.registry, "_dns_resolve", failing)
    result = _scoped_dns_lookup("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "DNS_FAILED"
    assert "Name or service not known" in result["reason"]
    assert isinstance(result["elapsed_ms"], int)


def test_non_url_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_dns_resolve", lambda host: called.append(host) or _RESOLVE_OK)
    result = _scoped_dns_lookup("target.example")
    assert result["ok"] is False
    assert result["error"] == "DNS_ARGUMENT_INVALID"
    assert called == []


def test_non_string_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_dns_resolve", lambda host: called.append(host) or _RESOLVE_OK)
    result = _scoped_dns_lookup(None)
    assert result["ok"] is False
    assert result["error"] == "DNS_ARGUMENT_INVALID"
    assert called == []


def test_hostless_url_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_dns_resolve", lambda host: called.append(host) or _RESOLVE_OK)
    result = _scoped_dns_lookup("https:///")
    assert result["ok"] is False
    assert result["error"] == "DNS_ARGUMENT_INVALID"
    assert called == []


def test_observation_carries_no_authority_keys(resolve_log):
    result = _scoped_dns_lookup("https://target.example/")
    forbidden = {"authorization", "decision", "proof", "token", "allowed", "permission", "scope_snapshot"}
    assert not (forbidden & set(result))
    for record in result["records"]:
        assert not (forbidden & set(record))
        assert set(record) == {"family", "address"}


def test_registered_in_runtime_never_in_catalog():
    spec = tools.registry.get_tool("scoped_dns_lookup")
    assert spec is not None
    assert spec.scope_required is True
    assert spec.risk_class == "network-read"
    assert spec.argument_type is str
    # Catalog/runtime disjointness (Path A): a runtime-registered tool is
    # never a catalog definition; the catalog never confers executability.
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "scoped_dns_lookup" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# Live-bridge fixtures (real owner-side typed state, faked DNS seam only)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="scoped_dns_lookup"),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id="scoped_dns_lookup",
        plan_hash=mission.plan.fingerprint,
        target_kind="network",
        target_url="https://target.example/",
        target_id="t1",
        risk_class="network_read",
        hypothesis_id="h-1",
        required_evidence=("dns records",),
        source_step_id="s-01",
        rationale="observe the in-scope target's dns surface",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


def _scope_snapshot():
    auth = ProgramAuthorization(
        program_id="prog-1",
        platform="test-platform",
        scope_version="v1",
        retrieved_at="2026-09-26T00:00:00+00:00",
        in_scope_assets=({"host": "target.example", "schemes": ["http", "https"]},),
        out_of_scope_assets=(),
        allowed_methods=("GET", "HEAD"),
    )
    return make_snapshot("snap-1", auth, [TargetIdentity(target_id="t1", program_id="prog-1", host="target.example")])


@pytest.fixture
def saved_scope_snapshot(tmp_path, monkeypatch):
    """Persist the typed ScopeSnapshot through the REAL owner scope store."""
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "bridge-owner")
    init_scope_store()
    return save_snapshot(_scope_snapshot(), owner_token="bridge-owner")


@pytest.fixture
def owner_decision(tmp_path):
    """A REAL typed Owner AuthorizationDecision for the scoped dns observation."""
    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    return AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the scoped dns observation against the in-scope target",
        tool="scoped_dns_lookup",
        risk_class="network-read",
        argument=canonical_url("https://target.example/"),
    )


@pytest.fixture
def execute_spy(monkeypatch):
    real_execute = tools.registry.execute
    calls: list[str] = []

    def spy(name, argument=None, **kwargs):
        calls.append(name)
        return real_execute(name, argument, **kwargs)

    monkeypatch.setattr(tools.registry, "execute", spy)
    return calls


@pytest.fixture
def dns_seam(monkeypatch):
    """Fake the single DNS seam: the live chain is real, the network is not."""
    log: list = []

    def fake_resolve(host):
        log.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))]

    monkeypatch.setattr(tools.registry, "_dns_resolve", fake_resolve)
    return log


@pytest.fixture
def counting_handler(monkeypatch):
    class Counter:
        def __init__(self):
            self.calls = 0

        def __call__(self, argument=None, **kwargs):
            self.calls += 1
            return {"ok": True, "operation": "scoped_dns_lookup", "url": argument, "records": [], "note": "observation"}

    counter = Counter()
    spec = tools.registry.get_tool("scoped_dns_lookup")
    assert spec is not None
    monkeypatch.setitem(tools.registry.REGISTRY, "scoped_dns_lookup", dataclass_replace(spec, handler=counter))
    return counter


# ---------------------------------------------------------------------------
# LIVE REACHABILITY (positive): the full chain must actually be wired
# ---------------------------------------------------------------------------


def test_live_bridge_reachability_scope_authorized(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, dns_seam):
    """Owner-authenticated mission → bridge → scope firewall → proof chain →
    registry scope re-resolution → REAL handler (faked seam) → evidence."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedDnsLookupAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["scoped_dns_lookup"]
    # The GUARD's canonical url is the executed argument; only its host resolved.
    assert dns_seam == ["target.example"]
    assert record.guard_decision["allowed"] is True
    normalized = record.result.normalized_output
    assert normalized["operation"] == "scoped_dns_lookup"
    assert normalized["host"] == "target.example"
    assert normalized["records"] == [{"family": "AF_INET", "address": "203.0.113.10"}]
    # Evidence flows through the existing chain (no second evidence system).
    assert record.result.evidence["tool"] == "scoped_dns_lookup"
    assert record.result.evidence["mission_id"] == mission.mission_id


def test_live_dry_run_never_executes(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, dns_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedDnsLookupAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
        dry_run=True,
    )
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []
    assert dns_seam == []


# ---------------------------------------------------------------------------
# NEGATIVE REACHABILITY: every rejection happens BEFORE execution
# ---------------------------------------------------------------------------


def test_dns_action_without_scope_snapshot_is_rejected(tmp_path, execute_spy):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedDnsLookupAdapter())
    assert execute_spy == []


def test_dns_execution_without_owner_decision_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, counting_handler, dns_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(
            _proposal(mission),
            mission=mission,
            adapter=ScopedDnsLookupAdapter(),
            scope_snapshot=saved_scope_snapshot,
        )
    assert execute_spy == []
    assert counting_handler.calls == 0
    assert dns_seam == []


def test_out_of_scope_host_is_rejected_before_execution(tmp_path, execute_spy, counting_handler, saved_scope_snapshot):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://outside.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedDnsLookupAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert counting_handler.calls == 0


def test_observed_dns_address_never_widens_scope(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, dns_seam):
    """A resolved address is OBSERVED data: it can never become a target."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    bridge = OffensiveActionBridge()
    record = bridge.run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedDnsLookupAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    observed_address = record.result.normalized_output["records"][0]["address"]
    assert observed_address == "203.0.113.10"
    assert execute_spy == ["scoped_dns_lookup"]

    # A second action pointing at the OBSERVED address is refused: observation
    # is never authorization (INV-OFF-2 / INV-OFF-5).
    smuggled = _proposal(mission, proposal_id="prop-2", target_url="https://" + observed_address + "/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        bridge.run(smuggled, mission=mission, adapter=ScopedDnsLookupAdapter(), scope_snapshot=saved_scope_snapshot)
    # No second execution, no second resolution: the rejection is pre-execution.
    assert execute_spy == ["scoped_dns_lookup"]
    assert dns_seam == ["target.example"]


def test_decision_issued_for_another_tool_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, counting_handler, dns_seam):
    """A valid Owner decision for scoped_http_probe cannot authorize dns.

    The rejection happens even BEFORE the adapter contract: the existing
    proof chain refuses to derive an ExecutionAuthorizationProof from a
    decision that does not match the tool (fail closed at derivation).
    """
    from security.execution_proof import ExecutionProofError

    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    wrong_tool_decision = AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the http probe only",
        tool="scoped_http_probe",
        risk_class="network-read",
        argument=canonical_url("https://target.example/"),
    )
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    with pytest.raises(ExecutionProofError, match="PROOF_BINDING_MISMATCH"):
        OffensiveActionBridge().run(
            _proposal(mission),
            mission=mission,
            adapter=ScopedDnsLookupAdapter(),
            scope_snapshot=saved_scope_snapshot,
            authorization_decision=wrong_tool_decision,
        )
    assert counting_handler.calls == 0
    assert execute_spy == []
    assert dns_seam == []
