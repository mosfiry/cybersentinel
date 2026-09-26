"""Real bounded scoped_tls_observation handler + live-bridge battery.

P1-B of the Offensive Capability Activation mission. The TLS observation is
a REAL bounded capability behind the full authorization chain: typed proposal
→ ScopeGuard canonical url → existing proof chain → tools.registry.execute →
single TLS seam. No test performs a real network call: the single seam
(_tls_connect) is faked at the module boundary.

Adversarial/boundary coverage (mission P1-B items):
- success observation: actually-derived version/cipher/cert fields, SHA-256
  fingerprint over the DER bytes, sorted+deduped SANs, verification semantics
- handshake success vs certificate validity are classified SEPARATELY
- deterministic port derivation (443 default); SNI is never an input — the
  seam always receives the canonical host
- connection refused / timeout / handshake failure / verification failure
  classify fail-closed with distinct error codes
- non-url / non-string / hostless arguments rejected BEFORE the seam
- no authority keys and no secret/session material in observations
- catalog/runtime disjointness
- LIVE bridge reachability with a real typed Owner AuthorizationDecision and
  a persisted scope snapshot (real registry scope re-resolution)
- wrong port (outside the scope asset's ports) rejected pre-network
- SAN/resolved-endpoint observations can never widen scope
- wrong-tool decision rejected at proof derivation, pre-network
- dry-run executes nothing
"""

from __future__ import annotations

import hashlib
import ssl
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
    ScopedTlsObservationAdapter,
)
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationDecision
from security.scope import ProgramAuthorization, TargetIdentity, canonical_url, make_snapshot
from tools.registry import SCOPED_TLS_MAX_SANS, _scoped_tls_observation


# ---------------------------------------------------------------------------
# Handler battery (deterministic bounds at the single TLS seam)
# ---------------------------------------------------------------------------

_CERT = {
    "subject": ((("commonName", "target.example"),),),
    "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test CA Root"),)),
    "serialNumber": "0ABC123",
    "notBefore": "Sep  1 00:00:00 2026 GMT",
    "notAfter": "Sep  1 00:00:00 2027 GMT",
    "subjectAltName": (("DNS", "alt2.example"), ("DNS", "alt1.example"), ("DNS", "alt1.example")),
}

_DER = b"\x30\x82\x02\xfffake-der-bytes"


class _FakeTlsSocket:
    def __init__(self, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 32), cert=None, der=_DER, peer=("203.0.113.10", 443)):
        self._version = version
        self._cipher = cipher
        self._cert = _CERT if cert is None else cert
        self._der = der
        self._peer = peer
        self.closed = False

    def version(self):
        return self._version

    def cipher(self):
        return self._cipher

    def getpeername(self):
        return self._peer

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else dict(self._cert)

    def close(self):
        self.closed = True


@pytest.fixture
def tls_seam(monkeypatch):
    log: list = []

    def fake_connect(host, port, timeout):
        log.append({"host": host, "port": port, "timeout": timeout})
        return _FakeTlsSocket()

    monkeypatch.setattr(tools.registry, "_tls_connect", fake_connect)
    return log


def test_success_observation_is_structured(tls_seam):
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is True
    assert result["operation"] == "scoped_tls_observation"
    assert result["url"] == "https://target.example/"
    assert result["host"] == "target.example"
    assert result["port"] == 443
    assert result["connection_success"] is True
    # Negotiated values come from the actual handshake result, never inferred.
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["verification_result"] == "TLS_CERTIFICATE_VALID"
    assert result["verification_error"] is None
    assert isinstance(result["observed_at"], str)
    assert result["resolved_endpoint"] == "('203.0.113.10', 443)"
    assert isinstance(result["elapsed_ms"], int)
    # Exactly ONE connect, against the canonical host, default port, SNI-safe.
    assert tls_seam == [{"host": "target.example", "port": 443, "timeout": 10}]


def test_fingerprint_is_sha256_over_der_bytes(tls_seam):
    result = _scoped_tls_observation("https://target.example/")
    assert result["fingerprint_algorithm"] == "SHA-256"
    assert result["certificate_fingerprint"] == hashlib.sha256(_DER).hexdigest()


def test_certificate_fields_are_deterministic(tls_seam):
    result = _scoped_tls_observation("https://target.example/")
    assert result["certificate_subject"] == "target.example"
    assert result["certificate_issuer"] == "Test CA Root"
    assert result["certificate_serial"] == "0ABC123"
    assert result["certificate_not_before"] == "Sep  1 00:00:00 2026 GMT"
    assert result["certificate_not_after"] == "Sep  1 00:00:00 2027 GMT"
    # SANs are deduplicated and sorted deterministically; raw crypto values untouched.
    assert result["subject_alt_names"] == ["DNS:alt1.example", "DNS:alt2.example"]
    assert result["sans_truncated"] is False


def test_san_sets_beyond_hard_cap_are_truncated(monkeypatch):
    big = {"subjectAltName": tuple(("DNS", "a{}.example".format(index)) for index in range(SCOPED_TLS_MAX_SANS + 3))}
    monkeypatch.setattr(tools.registry, "_tls_connect", lambda host, port, timeout: _FakeTlsSocket(cert=big))
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is True
    assert result["sans_truncated"] is True
    assert len(result["subject_alt_names"]) == SCOPED_TLS_MAX_SANS


def test_explicit_port_is_kept_and_sni_is_always_the_canonical_host(tls_seam):
    result = _scoped_tls_observation("https://target.example:8443/")
    assert result["port"] == 8443
    # SNI is not an input: the seam always receives the canonical host.
    assert tls_seam[0]["host"] == "target.example"


def test_certificate_verification_failure_is_not_success(monkeypatch):
    def failing(host, port, timeout):
        raise ssl.SSLCertVerificationError("certificate is not valid")

    monkeypatch.setattr(tools.registry, "_tls_connect", failing)
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "TLS_CERTIFICATE_INVALID"
    assert result["verification_result"] == "TLS_CERTIFICATE_INVALID"
    assert "certificate is not valid" in result["verification_error"]
    assert result["connection_success"] is False


def test_handshake_failure_classifies_distinctly(monkeypatch):
    def failing(host, port, timeout):
        raise ssl.SSLError("handshake failure")

    monkeypatch.setattr(tools.registry, "_tls_connect", failing)
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "TLS_HANDSHAKE_FAILED"
    assert result["verification_result"] == "TLS_CERTIFICATE_UNAVAILABLE"


def test_timeout_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tools.registry, "_tls_connect", failing)
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "TLS_TIMEOUT"


def test_connection_failure_classifies_deterministically(monkeypatch):
    def failing(host, port, timeout):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(tools.registry, "_tls_connect", failing)
    result = _scoped_tls_observation("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "TLS_CONNECTION_FAILED"


def test_non_url_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_tls_connect", lambda *a: called.append(a) or _FakeTlsSocket())
    result = _scoped_tls_observation("target.example")
    assert result["ok"] is False
    assert result["error"] == "TLS_ARGUMENT_INVALID"
    assert called == []


def test_non_string_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_tls_connect", lambda *a: called.append(a) or _FakeTlsSocket())
    result = _scoped_tls_observation(None)
    assert result["ok"] is False
    assert result["error"] == "TLS_ARGUMENT_INVALID"
    assert called == []


def test_hostless_url_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_tls_connect", lambda *a: called.append(a) or _FakeTlsSocket())
    result = _scoped_tls_observation("https:///")
    assert result["ok"] is False
    assert result["error"] == "TLS_ARGUMENT_INVALID"
    assert called == []


def test_observation_carries_no_authority_or_secret_keys(tls_seam):
    result = _scoped_tls_observation("https://target.example/")
    forbidden = {"authorization", "decision", "proof", "token", "allowed", "permission", "scope_snapshot", "owner_token", "private_key", "session_key", "session_secret", "master_secret", "credentials"}
    assert not (forbidden & set(result))


def test_registered_in_runtime_never_in_catalog():
    spec = tools.registry.get_tool("scoped_tls_observation")
    assert spec is not None
    assert spec.scope_required is True
    assert spec.risk_class == "network-read"
    assert spec.argument_type is str
    # Catalog/runtime disjointness (Path A): registration is deterministic,
    # code-defined; the catalog never confers executability.
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "scoped_tls_observation" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# Live-bridge fixtures (real owner-side typed state, faked TLS seam only)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="scoped_tls_observation"),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id="scoped_tls_observation",
        plan_hash=mission.plan.fingerprint,
        target_kind="network",
        target_url="https://target.example/",
        target_id="t1",
        risk_class="network_read",
        hypothesis_id="h-1",
        required_evidence=("tls handshake metadata",),
        source_step_id="s-01",
        rationale="observe the in-scope target's tls surface",
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
    """A REAL typed Owner AuthorizationDecision for the scoped tls observation."""
    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    return AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the scoped tls observation against the in-scope target",
        tool="scoped_tls_observation",
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


def test_live_bridge_reachability_scope_authorized(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, tls_seam):
    """Owner-derived authorization → scope snapshot → execution proof →
    bridge → registry resolution → adapter → real handler seam → evidence."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTlsObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["scoped_tls_observation"]
    # The GUARD's canonical url drives the observation; SNI is the canonical host.
    assert tls_seam == [{"host": "target.example", "port": 443, "timeout": 10}]
    assert record.guard_decision["allowed"] is True
    normalized = record.result.normalized_output
    assert normalized["operation"] == "scoped_tls_observation"
    assert normalized["tls_version"] == "TLSv1.3"
    assert normalized["verification_result"] == "TLS_CERTIFICATE_VALID"
    # Evidence flows through the EXISTING chain (provenance, no second system).
    evidence = record.result.evidence
    assert evidence["tool"] == "scoped_tls_observation"
    assert evidence["mission_id"] == mission.mission_id
    assert evidence["proof_fingerprint"] == record.proof_fingerprint
    assert evidence["request_id"] == mission.request_id


def test_live_dry_run_never_executes(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, tls_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTlsObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
        dry_run=True,
    )
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []
    assert tls_seam == []


# ---------------------------------------------------------------------------
# NEGATIVE REACHABILITY: every rejection happens BEFORE any network
# ---------------------------------------------------------------------------


def test_tls_action_without_scope_snapshot_is_rejected(tmp_path, execute_spy, tls_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedTlsObservationAdapter())
    assert execute_spy == []
    assert tls_seam == []


def test_tls_execution_without_owner_decision_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, tls_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert tls_seam == []


def test_model_supplied_arbitrary_hostname_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, tls_seam):
    """MODEL_OUTPUT proposing a target outside the owner scope never executes."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://attacker.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert tls_seam == []


def test_dns_derived_ip_target_is_not_authorized(tmp_path, execute_spy, saved_scope_snapshot, tls_seam):
    """A resolved address (e.g. from a prior DNS observation) is OBSERVED data:
    it is not in the scope snapshot's authorized assets, so it never executes."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://203.0.113.10/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert tls_seam == []


def test_wrong_port_outside_scope_asset_is_rejected(tmp_path, execute_spy, saved_port_scoped_snapshot, tls_seam):
    """The scope asset authorizes only port 443: a :8443 observation is
    rejected before any network execution (bridge guard or registry scope
    re-resolution — both are pre-network)."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://target.example:8443/", target_id="t1")
    bridge = OffensiveActionBridge()
    record = None
    try:
        record = bridge.run(proposal, mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_port_scoped_snapshot)
    except OffensiveActionRejected:
        record = None  # rejected by the bridge guard — equally valid pre-network rejection
    if record is not None:
        assert record.status == "REJECTED", record.result.error_state
        assert record.executed is False
    # The invariant: no network execution happened in either case.
    assert execute_spy == []
    assert tls_seam == []


def test_observed_certificate_san_never_widens_scope(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, tls_seam):
    """Certificate SAN entries are UNTRUSTED observational data: a second
    action against a SAN-observed host is refused pre-execution."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    bridge = OffensiveActionBridge()
    record = bridge.run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTlsObservationAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    observed_san = record.result.normalized_output["subject_alt_names"][0]
    assert observed_san == "DNS:alt1.example"
    assert execute_spy == ["scoped_tls_observation"]

    smuggled = _proposal(mission, proposal_id="prop-2", target_url="https://alt1.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        bridge.run(smuggled, mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == ["scoped_tls_observation"]
    assert tls_seam == [{"host": "target.example", "port": 443, "timeout": 10}]


def test_decision_issued_for_another_tool_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, tls_seam):
    """A valid Owner decision for scoped_dns_lookup cannot authorize tls.

    The rejection happens even BEFORE the adapter contract: the existing
    proof chain refuses to derive an ExecutionAuthorizationProof from a
    decision that does not match the tool (fail closed at derivation).
    """
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
            adapter=ScopedTlsObservationAdapter(),
            scope_snapshot=saved_scope_snapshot,
            authorization_decision=wrong_tool_decision,
        )
    assert execute_spy == []
    assert tls_seam == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, tls_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="deadbeef" + "0" * 56)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTlsObservationAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert tls_seam == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, tls_seam):
    """MODEL_OUTPUT cannot mint a tool: an unregistered tool id fails closed
    at the bridge's registry check, before any network."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool_id="tls_observe_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTlsObservationAdapter())
    assert execute_spy == []
    assert tls_seam == []
