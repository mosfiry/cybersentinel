"""Stage C hardening battery: PREPARE resolved-binary disclosure.

The adapter PREPARE phase now resolves the required binary ONCE via
shutil.which and discloses the ABSOLUTE resolved path in PreparedExecution
and in the dry-run plan. This is DISCLOSURE ONLY:

- the handler independently resolves and pins its own binary path (defense
  in depth; see tests/test_local_process_info_hardening.py);
- resolved_binary is sourced EXCLUSIVELY from shutil.which inside prepare();
  it can never be injected through the request, the arguments, the tool
  output, or any model/external data;
- dry-run disclosure never spawns a process, never calls the registry, and
  never reaches a handler;
- a missing binary still fails closed at PREPARE before any resolution
  result can be used.

INV-ADP-1..8 are unchanged; the authority hierarchy is untouched.
"""

import dataclasses

import pytest

import tools.registry
from security.tool_adapter import (
    AdapterAuthorization,
    AdapterPhase,
    LocalSystemInfoAdapter,
    PreparedExecution,
    ToolAdapter,
    ToolAdapterError,
    ToolAdapterRequest,
)


class PsAdapter(LocalSystemInfoAdapter):
    required_binary = "ps"


def _request(**overrides):
    base = dict(tool="local_system_info", argument=None)
    base.update(overrides)
    return ToolAdapterRequest(**base)


def _authorization():
    return AdapterAuthorization(
        tool="local_system_info",
        execution_class="MISSION_BOUND",
        proof_fingerprint="f" * 64,
        snapshot_hash="s" * 64,
        snapshot_version=1,
        decision_fingerprint="d" * 64,
    )


@pytest.fixture
def execute_spy(monkeypatch):
    calls = []
    def _spy(*args, **kwargs):
        calls.append((args, kwargs))
        return {"ok": True}
    monkeypatch.setattr(tools.registry, "execute", _spy)
    return calls


def test_prepare_discloses_resolved_absolute_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    prepared = PsAdapter().prepare(_request(), _authorization())
    assert prepared.required_binary == "ps"
    assert prepared.resolved_binary == "/resolved/ps"


def test_prepare_without_required_binary_has_no_resolved_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    prepared = LocalSystemInfoAdapter().prepare(_request(), _authorization())
    assert prepared.resolved_binary is None


def test_dry_run_discloses_resolved_path_and_never_executes(monkeypatch, execute_spy):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    adapter = PsAdapter()
    prepared = adapter.prepare(_request(), _authorization())
    plan = adapter.dry_run(_request(), _authorization(), prepared)
    assert plan["resolved_binary"] == "/resolved/ps"
    assert plan["required_binary"] == "ps"
    assert plan["would_execute"] is True
    assert execute_spy == []


def test_missing_binary_fails_closed_at_prepare(monkeypatch, execute_spy):
    class MissingBinary(LocalSystemInfoAdapter):
        required_binary = "cybersentinel-no-such-binary-xyz"
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolAdapterError) as exc:
        MissingBinary().prepare(_request(), _authorization())
    assert exc.value.phase == AdapterPhase.PREPARE
    assert "unavailable" in exc.value.reason
    assert execute_spy == []


def test_resolved_path_follows_which_not_request_fields(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    adapter = PsAdapter()
    request = _request()
    # A forged request field can never influence the resolved path: the
    # request is a frozen dataclass without any binary/path field, and
    # prepare() reads only shutil.which.
    assert not any("binary" in f.name or "path" in f.name for f in dataclasses.fields(ToolAdapterRequest))
    prepared = adapter.prepare(request, _authorization())
    assert prepared.resolved_binary == "/resolved/ps"


def test_resolved_path_immune_to_forged_tool_output(monkeypatch, execute_spy):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    adapter = PsAdapter()
    prepared = adapter.prepare(_request(), _authorization())
    plan = adapter.dry_run(_request(), _authorization(), prepared)
    # Tool output can never appear in or alter the dry-run disclosure: the
    # plan is derived from the request, authorization, and prepared record
    # only (dry-run happens before any execution exists).
    assert plan["resolved_binary"] == "/resolved/ps"
    assert "raw_output" not in plan
    assert execute_spy == []


def test_authorization_failure_never_reaches_prepare_or_handler(monkeypatch, execute_spy):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    adapter = PsAdapter()
    request = ToolAdapterRequest(tool="local_system_info", argument=None, execution_proof=None)
    with pytest.raises(ToolAdapterError) as exc:
        adapter.authorize(request)
    assert exc.value.phase == AdapterPhase.AUTHORIZE
    assert exc.value.rejection_code == "PROOF_REQUIRED"
    assert execute_spy == []


def test_existing_contracts_preserved(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/resolved/ps")
    adapter = PsAdapter()
    prepared = adapter.prepare(_request(), _authorization())
    plan = adapter.dry_run(_request(), _authorization(), prepared)
    # Dry-run plan retains every pre-existing Stage B/C key.
    for key in ("tool", "argument_fingerprint", "execution_class",
                "proof_fingerprint", "timeout", "required_binary",
                "handler_source", "would_execute"):
        assert key in plan
    assert plan["handler_source"] == "tools.registry"
    # PreparedExecution retains its positional construction compatibility.
    legacy = PreparedExecution(tool="t", timeout=5, required_binary="ps")
    assert legacy.resolved_binary is None
    assert legacy.handler_source == "tools.registry"
