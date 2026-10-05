from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid

import security.owner_password as owner_password
from security.session_reference import session_reference


def allow_owner_sessions(monkeypatch, *valid_tokens):
    valid = set(valid_tokens)
    valid_references = {session_reference(token) for token in valid_tokens}

    def _resolve(token):
        if token in valid or token in valid_references or session_reference(token) in valid_references:
            return {
                "session_id": session_reference(token),
                "owner_id": 1,
                "username": "mosfiry",
                "auth_method": "username_password",
                "expires_at": "2999-01-01T00:00:00+00:00",
            }
        return None

    monkeypatch.setattr(owner_password, "resolve_session", _resolve)
    monkeypatch.setattr(owner_password, "_resolve_session_reference", _resolve)


def persist_canonical_scope(monkeypatch, tmp_path, *, owner_session_token, target_id, bind_session=True):
    """Persist a narrow localhost-only scope through the real authenticated ScopeStore API."""
    import security.scope_store as scope_store
    from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot

    monkeypatch.setattr(scope_store, "SCOPE_DB_PATH", Path(tmp_path) / "scope.sqlite3")
    scope_store.init_scope_store()
    now = datetime.now(timezone.utc)
    created = now.isoformat()
    expires = (now + timedelta(minutes=30)).isoformat()
    suffix = uuid.uuid4().hex
    program_id = f"test-owner-scope-{suffix}"
    authorization = ProgramAuthorization(
        program_id=program_id,
        platform="owner-approved-local-workspace-test",
        scope_version="1",
        retrieved_at=created,
        in_scope_assets=({"host": "127.0.0.1", "schemes": ["http"], "ports": [80], "paths": ["/"]},),
        owner_session_id=session_reference(owner_session_token) if bind_session else "",
        source="owner",
    )
    target = TargetIdentity(
        target_id=target_id,
        program_id=program_id,
        host="127.0.0.1",
        asset_type="local_workspace",
        environment="test",
        allowed_ports=(80,),
        allowed_paths=("/",),
    )
    snapshot = make_snapshot(
        f"scope-{suffix}", authorization, [target],
        created_at=created, expires_at=expires,
    )
    scope_store.save_snapshot(snapshot, owner_session_token=owner_session_token)
    return snapshot


def workspace_scope_context(snapshot, workspace_root):
    """Build the complete Mission scope projection bound to a persisted local-test target."""
    target = snapshot.targets[0]
    return {
        "program_id": snapshot.authorization.program_id,
        "target_id": target.target_id,
        "scope_snapshot_id": snapshot.snapshot_id,
        "url": f"http://{target.host}/",
        "method": "GET",
        "workspace_root": str(Path(workspace_root).resolve()),
        "scope": ["workspace"],
        "allowed_networks": [],
        "allowed_credentials": [],
    }
