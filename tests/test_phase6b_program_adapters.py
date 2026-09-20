from __future__ import annotations

from pathlib import Path

import pytest

from security.program_adapters import BugcrowdAdapter, HackerOneAdapter
from security.program_adapters.base import AdapterError
from security.scope import TargetIdentity, make_snapshot
from security.scope_resolver import resolve
from security.scope_store import init_scope_store, save_snapshot
import security.owner_policy as owner_policy
import security.scope_store as scope_store


@pytest.fixture
def scope_db(tmp_path, monkeypatch):
    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    monkeypatch.setattr(owner_policy, "OWNER_TOKEN", "owner-6b")
    init_scope_store()


def bugcrowd_payload(host="target.example.com"):
    return {
        "program": {"id": "program-6b", "name": "Example Program", "current_brief": {"version": "brief-1", "in_scope": [{"host": host, "schemes": ["https"], "ports": [443], "paths": ["/api"]}], "out_of_scope": [{"host": "admin.example.com"}], "allowed_methods": ["GET", "HEAD"], "prohibited_methods": ["POST", "PUT", "DELETE"], "rate_limits": {"requests_per_minute": 5}}},
        "target_groups": [],
    }


def hackerone_payload(host="target.example.com"):
    return {"attributes": {"handle": "program-6b", "name": "Example Program", "scope_version": "brief-1", "structured_scope": [{"asset": host, "schemes": ["https"], "ports": [443], "paths": ["/api"]}], "excluded_assets": [{"host": "admin.example.com"}], "allowed_methods": ["GET", "HEAD"], "prohibited_methods": ["POST", "PUT", "DELETE"], "rate_limits": {"requests_per_minute": 5}}}


def test_platform_adapters_normalize_to_same_authorization_shape():
    bug = BugcrowdAdapter(transport=lambda _id: bugcrowd_payload()).get_program("program-6b").normalized
    h1 = HackerOneAdapter(transport=lambda _id: hackerone_payload()).get_program("program-6b").normalized
    assert bug.program_id == h1.program_id == "program-6b"
    assert bug.in_scope_assets[0]["host"] == h1.in_scope_assets[0]["host"]
    assert bug.allowed_methods == h1.allowed_methods == ("GET", "HEAD")
    assert bug.provenance["raw_hash"]
    assert bug.source_data.trust_classification == "untrusted_data"


def test_adapter_cannot_save_approve_or_execute(scope_db):
    adapter = BugcrowdAdapter(transport=lambda _id: bugcrowd_payload())
    with pytest.raises(AdapterError):
        adapter.save_scope()
    with pytest.raises(AdapterError):
        adapter.approve_scope()
    with pytest.raises(AdapterError):
        adapter.execute_target()


def test_external_malicious_scope_never_becomes_authorized_without_owner_snapshot(scope_db):
    adapter = BugcrowdAdapter(transport=lambda _id: bugcrowd_payload("evil.example.com"))
    candidate = adapter.get_program("program-6b")
    assert candidate.approved is False
    assert candidate.approval_required is True
    authorization = candidate.normalized.to_authorization_candidate()
    target = TargetIdentity("target-evil", "program-6b", "evil.example.com", allowed_ports=(443,), allowed_paths=("/api",))
    # Adapter output alone is not persisted and therefore cannot authorize a request.
    assert resolve("missing", "target-evil", "https://evil.example.com/api").allowed is False
    # Only explicit Owner approval can create the executable snapshot.
    snapshot = save_snapshot(make_snapshot("snapshot-6b", authorization, [target]), owner_token="owner-6b")
    assert resolve(snapshot.snapshot_id, target.target_id, "https://evil.example.com/api", consume_rate=False).allowed


def test_owner_approval_is_required_before_scope_store(scope_db):
    candidate = BugcrowdAdapter(transport=lambda _id: bugcrowd_payload()).get_program("program-6b")
    auth = candidate.normalized.to_authorization_candidate()
    target = TargetIdentity("target-6b", "program-6b", "target.example.com", allowed_ports=(443,), allowed_paths=("/api",))
    with pytest.raises(PermissionError):
        save_snapshot(make_snapshot("snapshot-denied", auth, [target]))
