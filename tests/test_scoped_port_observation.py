"""Real bounded scoped_port_observation handler + live-bridge battery.

P1-D of the Offensive Capability Activation mission. The port & service
observation is a REAL bounded capability behind the full authorization chain:
typed proposal -> ScopeGuard canonical url -> existing proof chain ->
tools.registry.execute -> single TCP seam. No test performs a real network
call: the single seam (_port_observe) is faked at the module boundary.

Adversarial/boundary coverage (mission P1-D items):
- success observation: connect success, sha256 over the observed banner,
  printable-filtered banner, cap/truncation semantics, sends_payload=False
- a silent service (empty banner) is data, not failure
- deterministic port derivation (scheme defaults; explicit ports kept);
  the seam always receives the canonical host and canonical port
- timeout / refused / dns / generic failures classify fail-closed
- non-url / non-string / hostless arguments rejected BEFORE the seam
- no authority keys and no secret/session material in observations
- catalog/runtime disjointness
- LIVE bridge reachability with a real typed Owner AuthorizationDecision and
  a persisted scope snapshot (real registry scope re-resolution)
- wrong port (outside the scope asset's ports) rejected pre-network
- observed banner content can never widen scope
- wrong-tool decision rejected at proof derivation, pre-network
- dry-run executes nothing
"""

from __future__ import annotations

import hashlib
import socket
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
    ScopedPortObservationAdapter,
)
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationDecision
from security.scope import ProgramAuthorization, TargetIdentity, canonical_url, make_snapshot
from tools.registry import SCOPED_PORT_BANNER_MAX_BYTES, _scoped_port_observation


# ---------------------------------------------------------------------------
# Handler battery (deterministic bounds at the single TCP seam)
# ---------------------------------------------------------------------------


@pytest.fixture
def port_seam(monkeypatch):
    log: list = []

    def fake_observe(host, port, timeout):
        log.append({"host": host, "port": port, "timeout": timeout})
        return b"HTTP/1.1 200 OK\r\nServer: fake\r\n\r\n"

    monkeypatch.setattr(tools.registry, "_port_observe", fake_observe)
    return log


def test_success_observation_is_structured(port_seam):
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is True
    assert result["operation"] == "scoped_port_observation"
    assert result["url"] == "https://target.example/"
    assert result["host"] == "target.example"
    # the scheme-default port is derived deterministically from the canonical url
    assert result["port"] == 443
    assert result["connect_success"] is True
    assert result["sends_payload"] is False
    assert result["banner_truncated"] is False
    assert isinstance(result["observed_at"], str)
    assert isinstance(result["elapsed_ms"], int)
    # Exactly ONE connect against the canonical host at the derived port.
    assert port_seam == [{"host": "target.example", "port": 443, "timeout": 10}]


def test_banner_is_returned_as_observed_data_with_sha256(port_seam):
    result = _scoped_port_observation("https://target.example/")
    banner = b"HTTP/1.1 200 OK\r\nServer: fake\r\n\r\n"
    assert result["banner_sha256"] == hashlib.sha256(banner).hexdigest()
    # the observed payload is reported in printable form without control bytes
    assert result["banner_printable"] == "HTTP/1.1 200 OKServer: fake"


def test_banner_sha256_is_over_raw_bytes_not_printable(monkeypatch):
    seam_banner = b"prompt\x00\x01> "

    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a, **k: seam_banner)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is True
    assert result["banner_sha256"] == hashlib.sha256(seam_banner).hexdigest()
    # non-printable bytes are dropped from the printable rendering only
    assert "\x00" not in (result["banner_printable"] or "")


def test_silent_service_is_observed_not_failed(monkeypatch):
    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a, **k: b"")
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is True
    assert result["connect_success"] is True
    assert result["banner_sha256"] is None
    assert result["banner_printable"] is None


def test_banner_beyond_hard_cap_is_truncated(monkeypatch):
    big = b"x" * (SCOPED_PORT_BANNER_MAX_BYTES + 5)
    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a, **k: big)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is True
    assert result["banner_truncated"] is True
    # the printable rendering covers exactly the capped banner
    assert result["banner_printable"] == "x" * SCOPED_PORT_BANNER_MAX_BYTES
    assert len(result["banner_sha256"]) == 64  # sha256 over the capped banner


def test_explicit_port_is_kept(port_seam):
    result = _scoped_port_observation("https://target.example:8443/")
    assert result["ok"] is True
    assert result["port"] == 8443
    assert port_seam[0]["port"] == 8443


def test_http_scheme_defaults_to_80(port_seam):
    result = _scoped_port_observation("http://target.example/")
    assert result["ok"] is True
    assert result["port"] == 80
    assert port_seam[0]["port"] == 80


def test_timeout_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tools.registry, "_port_observe", failing)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "PORT_TIMEOUT"
    assert result["connect_success"] is False


def test_connection_refusal_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(tools.registry, "_port_observe", failing)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "PORT_CONNECT_FAILED"


def test_dns_failure_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(tools.registry, "_port_observe", failing)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "PORT_CONNECT_FAILED"


def test_generic_runtime_failure_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(tools.registry, "_port_observe", failing)
    result = _scoped_port_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "PORT_RUNTIME_ERROR"


def test_non_url_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a: called.append(a) or b"")
    result = _scoped_port_observation("target.example")
    assert result["ok"] is False
    assert result["error"] == "PORT_ARGUMENT_INVALID"
    assert called == []


def test_non_string_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a: called.append(a) or b"")
    result = _scoped_port_observation(None)
    assert result["ok"] is False
    assert result["error"] == "PORT_ARGUMENT_INVALID"
    assert called == []


def test_hostless_url_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_port_observe", lambda *a: called.append(a) or b"")
    result = _scoped_port_observation("https:///")
    assert result["ok"] is False
    assert result["error"] == "PORT_ARGUMENT_INVALID"
    assert called == []


def test_observation_carries_no_authority_or_secret_keys(port_seam):
    result = _scoped_port_observation("https://target.example/")
    forbidden = {"authorization", "decision", "proof", "token", "allowed", "permission", "scope_snapshot", "owner_token", "private_key", "session_key", "session_secret", "master_secret", "credentials"}
    assert not (forbidden & set(result))


def test_registered_in_runtime_never_in_catalog():
    spec = tools.registry.get_tool("scoped_port_observation")
    assert spec is not None
    assert spec.scope_required is True
    assert spec.risk_class == "network-read"
    assert spec.argument_type is str
    # Catalog/runtime disjointness (Path A): registration is deterministic,
    # code-defined; the catalog never confers executability.
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "scoped_port_observation" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# Live-bridge fixtures (real owner-side typed state, faked TCP seam only)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="scoped_port_observation"),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id="scoped_port_observation",
        plan_hash=mission.plan.fingerprint,
        target_kind="network",
        target_url="https://target.example/",
        target_id="t1",
        risk_class="network_read",
        hypothesis_id="h-1",
        required_evidence=("port & service observation",),
        source_step_id="s-01",
        rationale="observe the in-scope target's open port surface",
    )
    values.update(overrides)
    return OffensiveActionProposal(**values)


def _scope_snapshot(asset_ports=None):
    asset = {"host": "target.example", "schemes": ["http", "https"]}
    if asset_ports is not None:
        asset["ports"] = list(asset_ports)
    auth = ProgramAuthorization(
        program_id="prog-1",
        platform="test-platform",
        scope_version="v1",
        retrieved_at="2026-09-26T00:00:00+00:00",
        in_scope_assets=(asset,),
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
def saved_port_scoped_snapshot(tmp_path, monkeypatch):
    """A snapshot whose in-scope asset authorizes ONLY port 443."""
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "bridge-owner")
    init_scope_store()
    return save_snapshot(_scope_snapshot(asset_ports=(443,)), owner_token="bridge-owner")


@pytest.fixture
def owner_decision(tmp_path):
    """A REAL typed Owner AuthorizationDecision for the scoped port observation."""
    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    return AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the scoped port observation against the in-scope target",
        tool="scoped_port_observation",
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


# ---------------------------------------------------------------------------
# LIVE REACHABILITY (positive): the full chain must actually be wired
# ---------------------------------------------------------------------------


def test_live_bridge_reachability_scope_authorized(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, port_seam):
    """Owner-derived authorization -> scope snapshot -> execution proof ->
    bridge -> registry resolution -> adapter -> real handler seam -> evidence."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedPortObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["scoped_port_observation"]
    # The GUARD's canonical url drives the observation; host/port come from it alone.
    assert port_seam == [{"host": "target.example", "port": 443, "timeout": 10}]
    assert record.guard_decision["allowed"] is True
    normalized = record.result.normalized_output
    assert normalized["operation"] == "scoped_port_observation"
    assert normalized["sends_payload"] is False
    assert normalized["connect_success"] is True
    # Evidence flows through the EXISTING chain (provenance, no second system).
    evidence = record.result.evidence
    assert evidence["tool"] == "scoped_port_observation"
    assert evidence["mission_id"] == mission.mission_id
    assert evidence["proof_fingerprint"] == record.proof_fingerprint
    assert evidence["request_id"] == mission.request_id


def test_live_dry_run_never_executes(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, port_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedPortObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
        dry_run=True,
    )
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []
    assert port_seam == []


# ---------------------------------------------------------------------------
# NEGATIVE REACHABILITY: every rejection happens BEFORE any network
# ---------------------------------------------------------------------------


def test_port_action_without_scope_snapshot_is_rejected(tmp_path, execute_spy, port_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedPortObservationAdapter())
    assert execute_spy == []
    assert port_seam == []


def test_port_execution_without_owner_decision_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, port_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert port_seam == []


def test_model_supplied_arbitrary_hostname_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, port_seam):
    """MODEL_OUTPUT proposing a target outside the owner scope never executes."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://attacker.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert port_seam == []


def test_dns_derived_ip_target_is_not_authorized(tmp_path, execute_spy, saved_scope_snapshot, port_seam):
    """A resolved address (e.g. from a prior observation) is OBSERVED data: it
    is not in the scope snapshot's authorized assets, so it never executes."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://203.0.113.10/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert port_seam == []


def test_wrong_port_outside_scope_asset_is_rejected(tmp_path, execute_spy, saved_port_scoped_snapshot, port_seam):
    """The scope asset authorizes only port 443: a :8443 observation is
    rejected before any network execution (bridge guard or registry scope
    re-resolution — both are pre-network)."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://target.example:8443/", target_id="t1")
    bridge = OffensiveActionBridge()
    record = None
    try:
        record = bridge.run(proposal, mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_port_scoped_snapshot)
    except OffensiveActionRejected:
        record = None  # rejected by the bridge guard — equally valid pre-network rejection
    if record is not None:
        assert record.status == "REJECTED", record.result.error_state
        assert record.executed is False
    # The invariant: no network execution happened in either case.
    assert execute_spy == []
    assert port_seam == []


def test_observed_banner_never_widens_scope(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, port_seam):
    """Banner content is UNTRUSTED observational data: a second action pointed
    at a banner-observed host is refused pre-execution."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    bridge = OffensiveActionBridge()
    record = bridge.run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedPortObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert execute_spy == ["scoped_port_observation"]

    banner_text = record.result.normalized_output["banner_printable"] or ""
    assert "fake" in banner_text
    smuggled = _proposal(mission, proposal_id="prop-2", target_url="https://fake/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        bridge.run(smuggled, mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == ["scoped_port_observation"]
    assert port_seam == [{"host": "target.example", "port": 443, "timeout": 10}]


def test_decision_issued_for_another_tool_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, port_seam):
    """A valid Owner decision for scoped_dns_lookup cannot authorize the port
    observation (fail closed at proof derivation, pre-network)."""
    from security.execution_proof import ExecutionProofError

    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    wrong_tool_decision = AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the dns observation only",
        tool="scoped_dns_lookup",
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
            adapter=ScopedPortObservationAdapter(),
            scope_snapshot=saved_scope_snapshot,
            authorization_decision=wrong_tool_decision,
        )
    assert execute_spy == []
    assert port_seam == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, port_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="deadbeef" + "0" * 56)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedPortObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert port_seam == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, port_seam):
    """MODEL_OUTPUT cannot mint a tool: an unregistered tool id fails closed
    at the bridge's registry check, before any network."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool_id="port_scan_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedPortObservationAdapter())
    assert execute_spy == []
    assert port_seam == []
