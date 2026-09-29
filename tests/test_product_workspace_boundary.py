from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from http.cookies import SimpleCookie
import json
from pathlib import Path
import subprocess
import threading

import pytest

import bridge
import core.db as core_db
from agent.mission import MissionStore
from agent.mission_runtime import MissionRuntime
from agent.planning import Plan, PlanStep
from agent.mission_worker import MissionQueue
from api.missions import MissionService
from security import owner_password
from security.mission_authorization import MissionAuthorizationSnapshot
from security.public_session import PublicSessionManager

TEST_PASSWORD = "workspace-owner-test-password-2026"


def request(server, method, path, payload=None, *, cookies="", csrf=""):
    connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if cookies:
        headers["Cookie"] = cookies
    if csrf:
        headers["X-CSRF-Token"] = csrf
    connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
    response = connection.getresponse()
    body = response.read()
    result = json.loads(body) if body else {}
    status = response.status
    response_headers = dict(response.getheaders())
    connection.close()
    return status, response_headers, result


def cookie_value(header, name):
    parsed = SimpleCookie()
    parsed.load(header)
    return parsed[name].value if name in parsed else ""


@pytest.fixture
def web_server(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ENABLED", True)
    monkeypatch.setattr(bridge, "PUBLIC_WEB_ORIGIN", "")
    monkeypatch.setattr(bridge, "DEFAULT_PUBLIC_SESSIONS", PublicSessionManager(ttl_seconds=60))
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "owner-auth.sqlite3")
    core_db.connect().close()
    owner_password.create_owner_account(owner_password.OWNER_USERNAME, TEST_PASSWORD)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def login(server):
    status, headers, session = request(server, "POST", "/api/public/session")
    assert status == 201
    public_cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = session["session"]["csrf_token"]
    status, headers, result = request(
        server,
        "POST",
        "/api/public/auth/login",
        {"username": owner_password.OWNER_USERNAME, "password": TEST_PASSWORD},
        cookies=public_cookie,
        csrf=csrf,
    )
    assert status == 200
    owner_cookie = cookie_value(headers["Set-Cookie"], bridge.PUBLIC_OWNER_SESSION_COOKIE)
    assert owner_cookie
    return f"{public_cookie}; {bridge.PUBLIC_OWNER_SESSION_COOKIE}={owner_cookie}", csrf


def make_service(tmp_path, root):
    root.mkdir(parents=True, exist_ok=True)
    store = MissionStore(tmp_path / "missions.sqlite3")

    def snapshot_factory(mission):
        actions = ("status", "workspace_read", "git_read")
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        return MissionAuthorizationSnapshot.create(
            owner_identity="1",
            mission_id=mission.mission_id,
            target_identity="workspace-test",
            scope=("workspace",),
            allowed_actions=actions,
            forbidden_actions=(),
            allowed_tools=actions,
            time_window={"timezone": "UTC"},
            max_duration=3600,
            rate_limits={action: 10 for action in actions},
            network_boundary={"allowed": ()},
            data_boundary={"allowed": ("workspace-test",)},
            credential_boundary={"allowed": ()},
            workspace_boundary={"root": str(root.resolve())},
            policy_version="workspace-http-test",
            owner_approval="test-owner",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )

    runtime = MissionRuntime(store, executor=lambda *_: {"success": False}, authorization_snapshot_factory=snapshot_factory)
    queue = MissionQueue(tmp_path / "mission-queue.sqlite3")
    service = MissionService(runtime, queue)
    mission = runtime.create(
        "Read the repository workspace",
        "Read the repository workspace",
        Plan.initial("Read the repository workspace").replan(
            steps=(PlanStep("status", "read actual system status", action="status"),),
            reason="workspace test fixture",
        ),
        request_id="workspace-test-request",
        owner_identity_ref="1",
        scope_snapshot={"workspace_root": str(root.resolve()), "target_id": "workspace-test", "allowed_networks": [], "allowed_credentials": []},
        completion_criteria=[{"criterion_id": "status", "check": "system_online"}],
    )
    return service, mission


def test_public_workspace_is_owner_filtered_and_redacts_sessions(web_server, tmp_path, monkeypatch):
    server = web_server
    public_cookies, csrf = login(server)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("workspace fixture", encoding="utf-8")
    other_root = tmp_path / "other-repo"
    other_root.mkdir()
    (other_root / "only-other.txt").write_text("other mission file", encoding="utf-8")
    service, mission = make_service(tmp_path, root)
    other_store = MissionStore(tmp_path / "missions.sqlite3")
    def other_snapshot_factory(other_mission):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        actions = ("status", "workspace_read", "git_read")
        return MissionAuthorizationSnapshot.create(
            owner_identity="1", mission_id=other_mission.mission_id, target_identity="other-workspace-test",
            scope=("workspace",), allowed_actions=actions, forbidden_actions=(), allowed_tools=actions,
            time_window={"timezone": "UTC"}, max_duration=3600, rate_limits={action: 10 for action in actions},
            network_boundary={"allowed": ()}, data_boundary={"allowed": ("other-workspace-test",)},
            credential_boundary={"allowed": ()}, workspace_boundary={"root": str(other_root.resolve())},
            policy_version="workspace-http-test", owner_approval="test-owner", created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
        )
    other_runtime = MissionRuntime(other_store, executor=lambda *_: {"success": False}, authorization_snapshot_factory=other_snapshot_factory)
    other_mission = other_runtime.create(
        "Other mission", "Other mission",
        Plan.initial("Other mission").replan(steps=(PlanStep("status", "status", action="status"),), reason="fixture"),
        request_id="other-workspace-request", owner_identity_ref="1",
        scope_snapshot={"workspace_root": str(other_root.resolve()), "target_id": "other-workspace-test", "allowed_networks": [], "allowed_credentials": []},
    )
    foreign = service.runtime.create(
        "private foreign mission",
        "private foreign mission",
        Plan.initial("foreign").replan(steps=(PlanStep("status", "status", action="status"),), reason="fixture"),
        request_id="foreign-request",
        owner_identity_ref="999",
        scope_snapshot={"workspace_root": str(root), "target_id": "workspace-test", "allowed_networks": [], "allowed_credentials": []},
    )
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: service)

    status, _, listed = request(server, "GET", "/api/public/missions", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert {item["mission_id"] for item in listed["missions"]} == {mission.mission_id, other_mission.mission_id}
    assert foreign.mission_id not in json.dumps(listed)
    status, _, reloaded = request(server, "GET", "/api/public/missions", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert {item["mission_id"] for item in reloaded["missions"]} == {mission.mission_id, other_mission.mission_id}

    status, _, mission_response = request(server, "GET", f"/api/public/missions/{mission.mission_id}/status", cookies=public_cookies, csrf=csrf)
    assert status == 200
    serialized = json.dumps(mission_response)
    assert "workspace-test-request" in serialized
    assert "owner_session_id" not in serialized and '"session_id"' not in serialized
    status, _, denied = request(server, "GET", f"/api/public/missions/{foreign.mission_id}/status", cookies=public_cookies, csrf=csrf)
    assert status == 404
    assert denied["error"] == "unknown_mission"

    status, _, file_response = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/file?path=README.md", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert file_response["content"] == "workspace fixture"
    status, _, cross_mission = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/file?path=only-other.txt", cookies=public_cookies, csrf=csrf)
    assert status == 404
    status, _, other_file = request(server, "GET", f"/api/public/workspace/{other_mission.mission_id}/file?path=only-other.txt", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert other_file["content"] == "other mission file"


def test_workspace_http_rejects_traversal_sensitive_symlink_and_bad_files(web_server, tmp_path, monkeypatch):
    server = web_server
    public_cookies, csrf = login(server)
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "README.md").write_text("ok", encoding="utf-8")
    (root / ".env").write_text("DO_NOT_EXPOSE=fixture-secret", encoding="utf-8")
    (root / ".env.example").write_text("SAFE_TEMPLATE=example", encoding="utf-8")
    (root / "oversized.txt").write_text("x" * 1_000_001, encoding="utf-8")
    (root / "binary.bin").write_bytes(b"\xff\xfe")
    (outside / "secret.txt").write_text("outside-secret", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "nested").mkdir()
    (root / "nested" / "escape").symlink_to(outside, target_is_directory=True)
    service, mission = make_service(tmp_path, root)
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: service)
    base = f"/api/public/workspace/{mission.mission_id}/file?path="

    for path in ("../outside/secret.txt", "../../etc/passwd", "%2e%2e%2foutside%2fsecret.txt", "/etc/passwd", "escape/secret.txt", "nested/escape/secret.txt"):
        status, _, _ = request(server, "GET", base + path, cookies=public_cookies, csrf=csrf)
        assert status in {400, 403, 404}, (path, status)
    status, _, _ = request(server, "GET", base + ".env", cookies=public_cookies, csrf=csrf)
    assert status == 404
    status, _, _ = request(server, "GET", base + "missing.txt", cookies=public_cookies, csrf=csrf)
    assert status == 404
    status, _, _ = request(server, "GET", base + "nested", cookies=public_cookies, csrf=csrf)
    assert status == 400
    status, _, _ = request(server, "GET", base + "oversized.txt", cookies=public_cookies, csrf=csrf)
    assert status == 403
    status, _, _ = request(server, "GET", base + "binary.bin", cookies=public_cookies, csrf=csrf)
    assert status == 400
    status, _, safe = request(server, "GET", base + ".env.example", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert safe["content"] == "SAFE_TEMPLATE=example"

    status, _, listing = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/files?path=.", cookies=public_cookies, csrf=csrf)
    assert status == 200
    names = {item["name"] for item in listing["files"]}
    assert ".env" not in names and "escape" not in names
    assert ".env.example" in names


def test_workspace_git_ui_is_real_read_only_and_redacts_remote_credentials(web_server, tmp_path, monkeypatch):
    server = web_server
    public_cookies, csrf = login(server)
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "workspace-test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Workspace Test"], check=True)
    (root / "README.md").write_text("baseline", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "workspace baseline"], check=True)
    subprocess.run(["git", "-C", str(root), "remote", "add", "origin", "https://user:fixture-secret@example.invalid/org/repo.git"], check=True)
    (root / "README.md").write_text("working change", encoding="utf-8")
    service, mission = make_service(tmp_path, root)
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: service)
    base = f"/api/public/workspace/{mission.mission_id}/git?operation="

    for operation in ("status", "branch", "log", "diff", "head", "repository", "remote"):
        status, _, payload = request(server, "GET", base + operation, cookies=public_cookies, csrf=csrf)
        assert status == 200
        assert payload["operation"] == operation
        assert payload["exit_code"] == 0
        assert "fixture-secret" not in json.dumps(payload)
    status, _, payload = request(server, "GET", base + "commit", cookies=public_cookies, csrf=csrf)
    assert status == 400
    assert payload["error"] == "unsupported_git_operation"
    assert "لا تنفّذ commit أو push" in Path("web/app.js").read_text(encoding="utf-8")


def test_workspace_blocks_environment_and_credential_paths_from_file_listing_and_git_diff(web_server, tmp_path, monkeypatch):
    server = web_server
    public_cookies, csrf = login(server)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config").mkdir()
    secret_files = {
        ".envrc": "fixture-secret-envrc",
        ".ENV": "fixture-secret-uppercase-env",
        "config/.env": "fixture-secret-nested-env",
        "config/.env.local": "fixture-secret-nested-env-local",
        ".aws/credentials": "fixture-secret-aws",
        ".AWS/Credentials": "fixture-secret-uppercase-aws",
        ".ssh/id_ed25519": "fixture-secret-ssh",
        ".docker/config.json": "fixture-secret-docker",
        ".config/gcloud": "fixture-secret-config",
        "id_rsa": "fixture-secret-root-key",
    }
    for secret_path, marker in secret_files.items():
        destination = root / secret_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(f"{marker}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "workspace-test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Workspace Test"], check=True)
    (root / "README.md").write_text("baseline", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", *secret_files, "README.md"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "workspace baseline"], check=True)
    for secret_path, marker in secret_files.items():
        (root / secret_path).write_text(f"{marker}-modified\n", encoding="utf-8")
    service, mission = make_service(tmp_path, root)
    monkeypatch.setattr(bridge.Handler, "_mission_service", lambda self: service)

    for secret_path, marker in secret_files.items():
        status, _, file_response = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/file?path={secret_path}", cookies=public_cookies, csrf=csrf)
        assert status == 404
        assert marker not in json.dumps(file_response)

    status, _, listing = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/files?path=.", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert {".envrc", ".ENV", ".aws", ".AWS", ".ssh", ".docker", ".config", "id_rsa"}.isdisjoint({item["name"] for item in listing["files"]})
    status, _, nested_listing = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/files?path=config", cookies=public_cookies, csrf=csrf)
    assert status == 200
    assert {item["name"] for item in nested_listing["files"]}.isdisjoint({".env", ".env.local"})

    status, _, diff = request(server, "GET", f"/api/public/workspace/{mission.mission_id}/git?operation=diff", cookies=public_cookies, csrf=csrf)
    assert status == 200
    for marker in secret_files.values():
        assert marker not in json.dumps(diff)
    for secret_path in secret_files:
        assert secret_path not in diff["output"]


def test_conversation_ids_are_permanent_owner_scoped_and_private_db_is_restricted(tmp_path, monkeypatch):
    monkeypatch.setattr(core_db, "DB_PATH", tmp_path / "private" / "app.sqlite3")
    core_db.connect().close()
    from core.db import add_conversation_message, conversation_info, ensure_conversation
    ensure_conversation("shared-id", "account-a")
    add_conversation_message("shared-id", "user", "private message", owner_id="account-a")
    with pytest.raises(PermissionError, match="conversation access denied"):
        ensure_conversation("shared-id", "account-b")
    with pytest.raises(PermissionError, match="conversation access denied"):
        add_conversation_message("shared-id", "user", "intrusion", owner_id="account-b")
    assert conversation_info("shared-id", owner_id="account-a")["owner_id"] == "account-a"
    with pytest.raises(PermissionError, match="conversation access denied"):
        conversation_info("shared-id", owner_id="account-b")
    assert (tmp_path / "private").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "private" / "app.sqlite3").stat().st_mode & 0o777 == 0o600
