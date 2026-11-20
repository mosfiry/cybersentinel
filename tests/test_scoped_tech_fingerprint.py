"""Real bounded scoped_tech_fingerprint handler + live-bridge battery.

P1-E of the Offensive Capability Activation mission. The technology
fingerprint is a REAL bounded CLASSIFICATION OF ALREADY-OBSERVED DATA behind
the full authorization chain: typed proposal -> ScopeGuard canonical url ->
existing proof chain -> tools.registry.execute -> single HTTP seam. No test
performs a real network call: the single seam (_fingerprint_fetch) is faked
at the module boundary.

Adversarial/boundary coverage (mission P1-E items):
- success structure: status_code, signals (sorted, family/source/detail),
  header_evidence, sha256 over the SIZE-CAPPED body, truncation semantics,
  sends_payload=False (the GET itself is the only wire traffic)
- a body with no markers is DATA, not failure (unknown is never guessed)
- header signals derive ONLY from the fixed header table; body signals ONLY
  from the fixed lowercase needle table; detail values are OBSERVED and
  truncated at the field cap (classification, never authority)
- timeout / read failure / generic runtime failures classify fail-closed
- non-url / non-string arguments rejected BEFORE the seam
- no authority keys and no secret/session material in observations
- catalog/runtime disjointness
- LIVE bridge reachability with a real typed Owner AuthorizationDecision and
  a persisted scope snapshot (real registry scope re-resolution)
- model-supplied out-of-scope target rejected pre-network
- observed body content can never widen scope
- wrong-tool decision rejected at proof derivation, pre-network
- tampered plan hash / unregistered tool / dry-run never execute
"""

from __future__ import annotations

import hashlib
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
    ScopedTechFingerprintAdapter,
)
from agent.planning import Plan, PlanStep
from security.authorization_context import AuthorizationDecision
from security.scope import ProgramAuthorization, TargetIdentity, canonical_url, make_snapshot
from tools.registry import (
    SCOPED_FP_MAX_BYTES,
    SCOPED_FP_MAX_SIGNALS,
    _scoped_tech_fingerprint,
    _tech_fingerprint,
)


# ---------------------------------------------------------------------------
# Handler battery (deterministic bounds at the single HTTP seam)
# ---------------------------------------------------------------------------


class _CIHeaders(dict):
    """Case-insensitive header map, matching http.client.HTTPMessage semantics."""

    def get(self, key, default=None):
        try:
            return super().__getitem__(key.lower())
        except KeyError:
            return default


class _FakeResponse:
    """Minimal urllib-like response consumed through the real seam contract."""

    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = _CIHeaders({str(k).lower(): v for k, v in (headers or {}).items()})
        self._body = body

    def geturl(self):
        return "https://target.example/"

    def read(self, n=-1):
        return self._body if n in (-1, None) else self._body[:n]


HEADERS = {"User-Agent": "CyberSentinel-X-ScopedFingerprint/1.0", "Accept": "*/*"}


@pytest.fixture
def fp_seam(monkeypatch):
    log: list = []

    def fake_fetch(request, timeout):
        log.append({"url": request.full_url, "timeout": timeout, "headers": dict(request.headers)})
        return _FakeResponse(headers={"Server": "nginx", "Content-Type": "text/html"}, body=b"<html>djangocsrfmiddlewaretoken</html>")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    return log


def test_fingerprint_success_is_structured(fp_seam):
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is True
    assert result["operation"] == "scoped_tech_fingerprint"
    assert result["url"] == "https://target.example/"
    assert result["status_code"] == 200
    assert result["sends_payload"] is False
    assert result["signals_truncated"] is False
    assert result["body_truncated"] is False
    assert isinstance(result["observed_at"], str)
    assert isinstance(result["elapsed_ms"], int)
    # Exactly ONE GET against the canonical url through the single seam.
    assert len(fp_seam) == 1
    call = fp_seam[0]
    assert call["url"].startswith("https://target.example")
    assert call["timeout"] == 10


def test_fingerprint_signals_come_only_from_observed_data(fp_seam):
    result = _scoped_tech_fingerprint("https://target.example/")
    families = {s["family"] for s in result["signals"]}
    assert "web_server" in families       # Server: nginx (observed header)
    assert "django" in families           # djangocsrfmiddlewaretoken (observed body)
    for signal in result["signals"]:
        assert signal["source"] in ("header", "body_marker")
        assert isinstance(signal["detail"], str)
    # signals are deterministically ordered (family, source, detail)
    keys = [(s["family"], s["source"], s["detail"]) for s in result["signals"]]
    assert keys == sorted(keys)
    # header evidence records the OBSERVED value, verbatim (truncated)
    assert result["header_evidence"]["server"] == "nginx"


def test_header_signal_detail_is_truncated_at_field_cap(monkeypatch):
    long_value = "v" * 400

    def fake_fetch(request, timeout):
        return _FakeResponse(headers={"X-Powered-By": long_value}, body=b"")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    result = _scoped_tech_fingerprint("https://target.example/")
    powered = [s for s in result["signals"] if s["family"] == "powered_by"]
    assert len(powered) == 1
    assert len(powered[0]["detail"]) == 256
    assert result["header_evidence"]["x-powered-by"] == "v" * 256


def test_body_marker_signal_uses_code_defined_needle_only(monkeypatch):
    def fake_fetch(request, timeout):
        # noise words that are NOT in the marker table must yield nothing
        return _FakeResponse(body=b"framework42 superduper stack mystery")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["signals"] == []
    assert result["signal_count"] == 0


def test_wordpress_marker_classified_from_observed_body(monkeypatch):
    def fake_fetch(request, timeout):
        return _FakeResponse(body=b"<link href='/wp-content/themes/x'/>")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    result = _scoped_tech_fingerprint("https://target.example/")
    families = {s["family"] for s in result["signals"]}
    assert "wordpress" in families
    assert [s["source"] for s in result["signals"]] == ["body_marker"]


def test_body_sha256_is_over_the_capped_body(monkeypatch):
    big = b"wp-content/" + b"y" * (SCOPED_FP_MAX_BYTES + 8)
    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda *a, **k: _FakeResponse(body=big))
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is True
    assert result["body_truncated"] is True
    assert result["body_size"] == SCOPED_FP_MAX_BYTES
    assert result["body_sha256"] == hashlib.sha256(big[:SCOPED_FP_MAX_BYTES]).hexdigest()
    # classification ran on the capped slice: the marker survived it
    assert any(s["family"] == "wordpress" for s in result["signals"])


def test_marker_never_returns_the_body_verbatim(monkeypatch):
    def fake_fetch(request, timeout):
        return _FakeResponse(body=b"<html>wp-content/</html>" + b"Z" * 64)

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    result = _scoped_tech_fingerprint("https://target.example/")
    raw = repr(result)
    # the observed body bytes are never echoed back (only hashed + classified)
    assert "ZZZZZZZZZZ" not in raw


def test_signal_cap_is_enforced(monkeypatch):
    """The handler hard-caps the emitted signals at SCOPED_FP_MAX_SIGNALS
    (fail loud, deterministic slice): even if future marker growth exceeds the
    bound, never more than the cap survive, with signals_truncated=True."""
    def fake_fetch(request, timeout):
        return _FakeResponse(
            headers={"Server": "nginx", "X-Powered-By": "php", "X-Generator": "gen", "X-ASPNET-Version": "4", "Via": "proxy"},
            body=b"drupal joomla jquery wp-content/ django laravel_session _next/static __nuxt data-reactroot svelte- data-v-app",
        )

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", fake_fetch)
    result = _tech_fingerprint("https://target.example/", max_signals=2)
    assert result["ok"] is True
    assert result["signal_count"] == 2
    assert result["signals_truncated"] is True


def test_silent_body_is_data_not_failure(monkeypatch):
    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda *a, **k: _FakeResponse(body=b""))
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is True
    assert result["status_code"] == 200
    assert result["signal_count"] == 0
    assert result["signals"] == []
    assert result["signals_truncated"] is False


def test_timeout_classifies_deterministically(monkeypatch):
    def failing(request, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", failing)
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "FP_FAILED"
    assert "reason" in result


def test_read_failure_classifies_deterministically(monkeypatch):
    class _RaisingRead:
        status = 200
        headers = {}

        def read(self, n=-1):
            raise OSError("connection reset during read")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda request, timeout: _RaisingRead())
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "FP_READ_FAILED"


def test_generic_runtime_failure_classifies_deterministically(monkeypatch):
    def failing(request, timeout):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", failing)
    result = _scoped_tech_fingerprint("https://target.example/")
    assert result["ok"] is False
    assert result["error"] == "FP_FAILED"


def test_non_url_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda *a: called.append(a))
    result = _scoped_tech_fingerprint("target.example")
    assert result["ok"] is False
    assert result["error"] == "FP_ARGUMENT_INVALID"
    assert called == []


def test_non_string_argument_rejected_before_seam(monkeypatch):
    called: list = []
    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda *a: called.append(a))
    result = _scoped_tech_fingerprint(None)
    assert result["ok"] is False
    assert result["error"] == "FP_ARGUMENT_INVALID"
    assert called == []


def test_observation_carries_no_authority_or_secret_keys(monkeypatch):
    monkeypatch.setattr(tools.registry, "_fingerprint_fetch", lambda *a, **k: _FakeResponse(headers={"Server": "nginx"}, body=b"wp-content/"))
    result = _scoped_tech_fingerprint("https://target.example/")
    forbidden = {"authorization", "decision", "proof", "token", "allowed", "permission", "scope_snapshot", "owner_token", "private_key", "session_key", "session_secret", "master_secret", "credentials"}
    assert not (forbidden & set(result))
    # a signal is classification ONLY: no family field doubles as authority
    for signal in result["signals"]:
        assert not ({"authority", "scope", "plan"} & set(signal))


def test_registered_in_runtime_never_in_catalog():
    spec = tools.registry.get_tool("scoped_tech_fingerprint")
    assert spec is not None
    assert spec.scope_required is True
    assert spec.risk_class == "network-read"
    assert spec.argument_type is str
    # Catalog/runtime disjointness (Path A): registration is deterministic,
    # code-defined; the catalog never confers executability.
    from security.tool_inventory import DEFAULT_SECURITY_TOOL_INVENTORY

    assert "scoped_tech_fingerprint" not in DEFAULT_SECURITY_TOOL_INVENTORY.tool_ids()


# ---------------------------------------------------------------------------
# Live-bridge fixtures (real owner-side typed state, faked HTTP seam only)
# ---------------------------------------------------------------------------


def _runtime(tmp_path):
    return MissionRuntime(MissionStore(Path(tmp_path) / "missions.sqlite3"), executor=lambda *_: {}, authorization_snapshot_factory=make_test_snapshot)


def _mission(runtime):
    plan = Plan.initial("objective").replan(steps=(PlanStep("s1", "objective", action="scoped_tech_fingerprint"),), reason="test")
    return runtime.create("request", "objective", plan, request_id="req-1", completion_criteria=[{"criterion_id": "goal"}])


def _proposal(mission, **overrides):
    values = dict(
        proposal_id="prop-1",
        mission_id=mission.mission_id,
        request_id=mission.request_id,
        tool_id="scoped_tech_fingerprint",
        plan_hash=mission.plan.fingerprint,
        target_kind="network",
        target_url="https://target.example/",
        target_id="t1",
        risk_class="network_read",
        hypothesis_id="h-1",
        required_evidence=("technology fingerprint",),
        source_step_id="s-01",
        rationale="classify observed stack signals for the in-scope target",
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
def owner_decision(tmp_path):
    """A REAL typed Owner AuthorizationDecision for the scoped fingerprint."""
    context = make_test_authorization_context(request_id="req-1", state_dir=tmp_path)
    return AuthorizationDecision.issue(
        context,
        allowed=True,
        reason="owner authorized the technology fingerprint against the in-scope target",
        tool="scoped_tech_fingerprint",
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


def test_live_bridge_reachability_scope_authorized(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, fp_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTechFingerprintAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert record.executed is True
    assert execute_spy == ["scoped_tech_fingerprint"]
    assert len(fp_seam) == 1
    assert record.guard_decision["allowed"] is True
    normalized = record.result.normalized_output
    assert normalized["operation"] == "scoped_tech_fingerprint"
    assert normalized["sends_payload"] is False
    evidence = record.result.evidence
    assert evidence["tool"] == "scoped_tech_fingerprint"
    assert evidence["mission_id"] == mission.mission_id
    assert evidence["proof_fingerprint"] == record.proof_fingerprint
    assert evidence["request_id"] == mission.request_id


def test_live_dry_run_never_executes(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, fp_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    record = OffensiveActionBridge().run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTechFingerprintAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
        dry_run=True,
    )
    assert record.status == "DRY_RUN"
    assert record.executed is False
    assert execute_spy == []
    assert fp_seam == []


# ---------------------------------------------------------------------------
# NEGATIVE REACHABILITY: every rejection happens BEFORE any network
# ---------------------------------------------------------------------------


def test_fingerprint_without_scope_snapshot_is_rejected(tmp_path, execute_spy, fp_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedTechFingerprintAdapter())
    assert execute_spy == []
    assert fp_seam == []


def test_fingerprint_without_owner_decision_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, fp_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(_proposal(mission), mission=mission, adapter=ScopedTechFingerprintAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert fp_seam == []


def test_model_supplied_arbitrary_hostname_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, fp_seam):
    """MODEL_OUTPUT proposing a target outside the owner scope never executes."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, target_url="https://attacker.example/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTechFingerprintAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert fp_seam == []


def test_observed_body_never_widens_scope(tmp_path, execute_spy, saved_scope_snapshot, owner_decision, fp_seam):
    """Body content is UNTRUSTED observational data: a second action pointed
    at a body-observed host is refused pre-execution."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    mission.progress["model_run_id"] = "run-1"
    bridge = OffensiveActionBridge()
    record = bridge.run(
        _proposal(mission),
        mission=mission,
        adapter=ScopedTechFingerprintAdapter(),
        scope_snapshot=saved_scope_snapshot,
        authorization_decision=owner_decision,
    )
    assert record.status == "EXECUTED", record.result.error_state
    assert execute_spy == ["scoped_tech_fingerprint"]

    # a marker string smuggled INTO the fingerprint of a NEW proposal cannot
    # authorize anything: scope stays owner-controlled
    smuggled = _proposal(mission, proposal_id="prop-2", target_url="https://wp-content/", target_id="t1")
    with pytest.raises(OffensiveActionRejected, match="scope"):
        bridge.run(smuggled, mission=mission, adapter=ScopedTechFingerprintAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == ["scoped_tech_fingerprint"]
    assert len(fp_seam) == 1


def test_decision_issued_for_another_tool_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, fp_seam):
    """A valid Owner decision for scoped_dns_lookup cannot authorize the
    fingerprint (fail closed at proof derivation, pre-network)."""
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
            adapter=ScopedTechFingerprintAdapter(),
            scope_snapshot=saved_scope_snapshot,
            authorization_decision=wrong_tool_decision,
        )
    assert execute_spy == []
    assert fp_seam == []


def test_tampered_plan_hash_is_rejected(tmp_path, execute_spy, saved_scope_snapshot, fp_seam):
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, plan_hash="deadbeef" + "0" * 56)
    with pytest.raises(OffensiveActionRejected):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTechFingerprintAdapter(), scope_snapshot=saved_scope_snapshot)
    assert execute_spy == []
    assert fp_seam == []


def test_unregistered_tool_is_rejected(tmp_path, execute_spy, fp_seam):
    """MODEL_OUTPUT cannot mint a tool: an unregistered tool id fails closed
    at the bridge's registry check, before any network."""
    runtime = _runtime(tmp_path)
    mission = _mission(runtime)
    proposal = _proposal(mission, tool_id="tech_scan_v2")
    with pytest.raises(OffensiveActionRejected, match="not registered"):
        OffensiveActionBridge().run(proposal, mission=mission, adapter=ScopedTechFingerprintAdapter())
    assert execute_spy == []
    assert fp_seam == []