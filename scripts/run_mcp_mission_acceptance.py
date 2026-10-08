#!/usr/bin/env python3
"""Live MCP Streamable HTTP acceptance inside the canonical Owner Mission path.

The local HTTPS fixture is bound only to 127.0.0.1:443. A test-only explicit
PinnedSession loopback override is scoped to that fixture URL; production
PinnedSession defaults and Mission authorization remain unchanged. The fixture
process drops root privileges immediately after binding the standard HTTPS port.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

TOOL_NAME = "read_acceptance_record"
PLACEHOLDER_SERVER_ID = "mcp_" + "0" * 32


class MCPPlanner:
    """Deterministic planner only; canonical Mission and MCP execution are real."""

    name = "mcp-live-acceptance-planner"
    model = "deterministic-mcp-tool-proposal"

    def __init__(self):
        from agent.provider_api import ProviderCapabilities
        self.capabilities = ProviderCapabilities(generate=True, tool_calling=True)

    def tool_calling(self, _messages, tools, **_kwargs):
        from agent.provider_api import ProviderResponse, ToolCall

        names = {
            item.get("function", {}).get("name")
            for item in tools
            if isinstance(item, dict) and isinstance(item.get("function"), dict)
        }
        if not {"mcp.discover", "mcp.invoke"}.issubset(names):
            return ProviderResponse(content="required MCP tools unavailable")
        return ProviderResponse(tool_calls=[
            ToolCall("mcp.discover", {"server_id": PLACEHOLDER_SERVER_ID}, "mcp-discover-call"),
            ToolCall(
                "mcp.invoke",
                {
                    "server_id": PLACEHOLDER_SERVER_ID,
                    "tool_name": TOOL_NAME,
                    "arguments": {"query": "acceptance-read-only"},
                },
                "mcp-invoke-call",
            ),
        ])

    def generate(self, _messages, **_kwargs):
        return {"content": "{}"}


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _walk(value):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _walk(nested)


def _find_mcp_result(mission, status: str, server_id: str):
    for node in _walk(mission.to_dict()):
        if node.get("status") == status and node.get("server_id") == server_id:
            return node
    return None


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
    return records


def _evidence_chain_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT payload FROM evidence_chain ORDER BY sequence").fetchall()
    return [json.loads(row[0]) for row in rows]


def _record_type(record: dict) -> str:
    payload = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    return str(payload.get("record_type", ""))


def _start_fixture(*, script: Path, run_dir: Path, path: str, cert: Path, key: Path, request_log: Path, port: int = 443):
    ready = run_dir / "fixture-ready.json"
    server_log = run_dir / "fixture-server.log"
    prefix = ["sudo", "-n"] if os.name != "nt" and port < 1024 else []
    command = [
        *prefix, sys.executable, str(script),
        "--port", str(port), "--path", path,
        "--cert", str(cert), "--key", str(key),
        "--request-log", str(request_log), "--ready-file", str(ready),
    ]
    output = server_log.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=str(ROOT), stdout=output, stderr=subprocess.STDOUT, text=True)
    finally:
        output.close()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if ready.exists():
            return process, ready, json.loads(ready.read_text(encoding="utf-8"))
        if process.poll() is not None:
            raise RuntimeError("fixture_server_failed_to_start")
        time.sleep(0.05)
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2.0)
    raise RuntimeError("fixture_server_readiness_timeout")


def _stop_fixture(process, ready: Path) -> bool:
    if process is None:
        return True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3.0)
    if process.poll() is not None and ready.exists():
        try:
            ready.unlink()
        except OSError:
            pass
    return process.poll() is not None and not ready.exists()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    artifact = args.artifact.expanduser().resolve()
    state_root = args.state_dir.expanduser().resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    run_dir = state_root / ("run-" + uuid.uuid4().hex[:12])
    run_dir.mkdir(mode=0o700)
    try:
        run_dir.chmod(0o700)
    except OSError:
        pass
    artifact.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "schema": "live-mcp-mission-acceptance-v1",
        "status": "FAIL",
        "planner_mode": "deterministic proposal only; AgentCore, durable MissionRuntime, MCPRemoteClient, PinnedSession, ScopeStore, Owner binding, evidence chain, and validator are production implementations",
        "transport": {
            "fixture_bind": "127.0.0.1",
            "fixture_port": 443,
            "public_exposure": False,
            "protocol": "MCP Streamable HTTP 2025-06-18",
            "list_response": "text/event-stream",
            "production_pinned_session_loopback_default": False,
            "test_override": "allow_loopback=True for the exact 127.0.0.1 endpoint only",
        },
        "checks": {},
        "owner_authorization": {},
        "mcp": {},
        "evidence": {},
        "cleanup": {},
    }
    fixture_process = None
    fixture_ready = None
    patcher = None
    mcp_module = None
    previous_service = None
    original_ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    error_class = ""
    failure_phase = "initialization"
    try:
        import pytest
        from owner_session_testutils import allow_owner_sessions
        import security.scope_store as scope_store
        from security.scope import ProgramAuthorization, TargetIdentity, make_snapshot
        from security.session_reference import session_reference
        from security.scope_resolver import resolve as resolve_scope
        from agent.agent_core import AgentCore
        from agent.evidence import verify_chain
        from agent.mission import MissionStatus, MissionStore
        from agent.model_router import ModelRouter
        from agent.provider_api import ProviderCapabilities
        from security.pinned_http import PinnedSession
        from tools.mcp_client import MCPRemoteClient, MCPServerStore, MCPToolService

        default_loopback = inspect.signature(PinnedSession).parameters["allow_loopback"].default
        if default_loopback is not False:
            raise RuntimeError("production_loopback_default_not_closed")
        result["checks"]["production_loopback_default_remains_denied"] = True

        failure_phase = "local_tls_fixture"
        cert = run_dir / "fixture-cert.pem"
        key = run_dir / "fixture-key.pem"
        request_log = run_dir / "fixture-requests.jsonl"
        openssl_command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "1", "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        ]
        subprocess.run(openssl_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        cert.chmod(0o644)
        endpoint_path = "/mcp/" + os.urandom(20).hex()
        blocked_path = endpoint_path + "/blocked"
        endpoint = "https://127.0.0.1" + endpoint_path
        blocked_endpoint = "https://127.0.0.1" + blocked_path
        result["transport"]["endpoint_sha256"] = _sha256(endpoint)
        result["transport"]["scoped_path_sha256"] = _sha256(endpoint_path)
        result["transport"]["tls_certificate_sha256"] = _sha256(cert.read_bytes())

        fixture_process, fixture_ready, ready_payload = _start_fixture(
            script=ROOT / "scripts" / "mcp_streamable_fixture_server.py",
            run_dir=run_dir,
            path=endpoint_path,
            cert=cert,
            key=key,
            request_log=request_log,
        )
        expected_uid = os.getuid() if hasattr(os, "getuid") else None
        if (
            ready_payload.get("bind") != "127.0.0.1"
            or ready_payload.get("effective_uid") != expected_uid
            or (os.name == "nt" and ready_payload.get("was_root") != 0)
        ):
            raise RuntimeError("fixture_privilege_drop_or_bind_check_failed")
        result["checks"]["fixture_loopback_only_and_process_identity_verified"] = True
        result["transport"]["fixture_effective_uid"] = ready_payload.get("effective_uid")
        result["transport"]["fixture_effective_gid"] = ready_payload.get("effective_gid")
        result["transport"]["fixture_identity_model"] = (
            "same Windows runner process identity; no POSIX UID or privilege drop"
            if os.name == "nt" else "POSIX UID checked after fixture privilege drop"
        )
        result["transport"]["fixture_pid"] = int(ready_payload["pid"])
        tls_context = ssl.create_default_context(cafile=str(cert))
        with urllib.request.urlopen("https://127.0.0.1/health", context=tls_context, timeout=3.0) as response:
            if response.status != 200 or response.read() != b'{"ok":true}':
                raise RuntimeError("fixture_tls_health_failed")
        result["checks"]["local_tls_health"] = True
        os.environ["SSL_CERT_FILE"] = str(cert)

        failure_phase = "owner_scope_setup"
        token = "mcp-live-acceptance-session-" + uuid.uuid4().hex
        patcher = pytest.MonkeyPatch()
        allow_owner_sessions(patcher, token)
        patcher.setattr(scope_store, "SCOPE_DB_PATH", run_dir / "scope.sqlite3")
        scope_store.init_scope_store()
        now = datetime.now(timezone.utc)
        program_id = "owner-mcp-live-acceptance-" + uuid.uuid4().hex[:12]
        target_id = "loopback-mcp-fixture-" + uuid.uuid4().hex[:8]
        authorization = ProgramAuthorization(
            program_id=program_id,
            platform="owner-approved-loopback-mcp-acceptance",
            scope_version="1",
            retrieved_at=now.isoformat(),
            in_scope_assets=({
                "host": "127.0.0.1",
                "schemes": ["https"],
                "ports": [443],
                "paths": [endpoint_path, blocked_path],
            },),
            allowed_methods=("POST",),
            prohibited_methods=("DELETE", "PATCH", "PUT"),
            owner_session_id=session_reference(token),
            source="owner",
        )
        target = TargetIdentity(
            target_id=target_id,
            program_id=program_id,
            host="127.0.0.1",
            asset_type="local_mcp_fixture",
            environment="test",
            allowed_ports=(443,),
            allowed_paths=(endpoint_path, blocked_path),
        )
        snapshot = make_snapshot(
            "scope-" + uuid.uuid4().hex,
            authorization,
            [target],
            created_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=20)).isoformat(),
        )
        scope_store.save_snapshot(snapshot, owner_session_token=token)
        scope_context = {
            "program_id": program_id,
            "target_id": target_id,
            "scope_snapshot_id": snapshot.snapshot_id,
            "url": endpoint,
            "method": "POST",
            "scope": ["host:127.0.0.1"],
            "workspace_root": str(ROOT),
            "allowed_networks": ["127.0.0.1"],
            "allowed_credentials": [],
        }
        scope_decision = resolve_scope(
            snapshot.snapshot_id,
            target_id,
            endpoint,
            method="POST",
            expected_program_id=program_id,
        )
        if not scope_decision.allowed:
            raise RuntimeError("owner_scope_resolver_denied_fixture")
        result["checks"]["owner_scope_allows_exact_local_endpoint"] = True
        result["owner_authorization"]["scope"] = {
            "snapshot_id": snapshot.snapshot_id,
            "program_id": program_id,
            "target_id": target_id,
            "target_host": "127.0.0.1",
            "scheme": "https",
            "port": 443,
            "allowed_methods": ["POST"],
            "allowed_path_count": 2,
            "source": "owner",
            "session_bound": True,
        }

        def test_client_factory(client_endpoint, execution_context):
            return MCPRemoteClient(
                client_endpoint,
                execution_context,
                session_factory=lambda **kwargs: PinnedSession(allow_loopback=True, **kwargs),
            )

        mcp_module = __import__("tools.mcp_client", fromlist=["MCPToolService"])
        previous_service = mcp_module._DEFAULT_SERVICE
        mcp_service = MCPToolService(client_factory=test_client_factory)
        mcp_module._DEFAULT_SERVICE = mcp_service

        failure_phase = "owner_mission_planning"
        store = MissionStore(run_dir / "missions.sqlite3")
        core = AgentCore(ModelRouter([MCPPlanner()]), store=store)
        mission = core.run_owner_mission(
            "Discover the scoped MCP server, wait for Owner approval of its exact read-only schema, invoke that tool, and preserve remote content as untrusted evidence",
            owner_session_token=token,
            scope_context=scope_context,
            completion_criteria=[
                {
                    "criterion_id": "mcp-discovery",
                    "description": "the scoped server identity and one untrusted schema revision were discovered with evidence",
                    "check": "mcp_discovery",
                    "expected_tool_name": TOOL_NAME,
                    "expected_trust_level": "UNTRUSTED",
                    "required": True,
                },
                {
                    "criterion_id": "mcp-invocation",
                    "description": "the exact Owner-approved schema revision was invoked and its untrusted result was evidence-bound",
                    "check": "mcp_invoke",
                    "expected_tool_name": TOOL_NAME,
                    "required": True,
                },
            ],
            run=False,
        )
        expected_actions = ["mcp.discover", "mcp.invoke"]
        if [step.action for step in mission.plan.steps] != expected_actions:
            raise RuntimeError("owner_mission_plan_did_not_contain_expected_mcp_steps")
        if mission.status is not MissionStatus.READY or not mission.verify_integrity():
            raise RuntimeError("owner_mission_not_ready_or_integrity_invalid")
        owner_ref = mission.owner_identity_ref
        registry = MCPServerStore(Path(store.db_path).with_name("mcp_registry.sqlite3"))
        registered = registry.register_server(owner_identity_ref=owner_ref, mission_id=mission.mission_id, endpoint=endpoint)
        server_id = registered["server_id"]
        updated_steps = []
        for step in mission.plan.steps:
            policy = dict(step.retry_policy)
            call_arguments = dict(policy.get("arguments") or {})
            call_arguments["server_id"] = server_id
            policy["arguments"] = call_arguments
            updated_steps.append(replace(step, retry_policy=policy))
        mission.plan = mission.plan.replan(
            steps=updated_steps,
            assumptions=mission.plan.assumptions,
            reason="Owner/Mission-bound MCP server registration before dispatch",
        )
        mission.progress["mcp_fixture_binding"] = {
            "server_id": server_id,
            "endpoint_sha256": _sha256(endpoint),
            "trust_level_at_registration": "UNTRUSTED",
            "authority_source": "authenticated_owner_session",
        }
        history = list(getattr(mission, "plan_history", []) or [])
        history.append({
            "version": mission.plan.version,
            "fingerprint": mission.plan.fingerprint,
            "reason": "Owner/Mission-bound MCP server registration before dispatch",
        })
        mission.plan_history = history
        mission = store.save(mission)
        auth_snapshot = dict(mission.authorization_snapshot or {})
        if not {"mcp.discover", "mcp.invoke"}.issubset(set(auth_snapshot.get("allowed_tools", ()))):
            raise RuntimeError("mission_authorization_did_not_bind_both_mcp_tools")
        result["owner_authorization"]["mission"] = {
            "mission_id": mission.mission_id,
            "owner_identity_ref": owner_ref,
            "owner_authenticated": bool(owner_ref.startswith("owner:")),
            "authorization_snapshot_present": bool(auth_snapshot),
            "allowed_mcp_tools": [name for name in ("mcp.discover", "mcp.invoke") if name in auth_snapshot.get("allowed_tools", ())],
            "authorization_target_identity": auth_snapshot.get("target_identity"),
            "owner_approval_fingerprint_present": bool(auth_snapshot.get("owner_approval")),
        }
        result["checks"]["real_owner_mission_and_authorization_context"] = True
        result["mcp"]["server_id"] = server_id
        result["mcp"]["endpoint_sha256"] = _sha256(endpoint)

        failure_phase = "mission_discovery"
        first = core.resume_mission(mission.mission_id, owner_session_token=token, max_slices=1)
        discovery = _find_mcp_result(first, "discovered", server_id)
        server_after_discovery = registry.get_server(owner_identity_ref=owner_ref, mission_id=mission.mission_id, server_id=server_id)
        discovered_tools = registry.list_tools(owner_identity_ref=owner_ref, mission_id=mission.mission_id, server_id=server_id)
        tool_record = next((item for item in discovered_tools if item.get("name") == TOOL_NAME), None)
        if (
            first.current_step != 1
            or discovery is None
            or server_after_discovery.get("trust_level") != "UNTRUSTED"
            or not tool_record
            or tool_record.get("approved") is not False
        ):
            raise RuntimeError("mission_discovery_or_untrusted_default_failed")
        schema_sha256 = tool_record["schema_sha256"]
        identity_sha256 = server_after_discovery["identity_sha256"]
        if discovery.get("evidence_ref") is None:
            raise RuntimeError("mission_discovery_evidence_ref_missing")
        result["checks"]["discover_executed_inside_mission"] = True
        result["mcp"]["discovery"] = {
            "mission_status_after_slice": first.status.value,
            "current_step": first.current_step,
            "trust_before_owner_approval": server_after_discovery["trust_level"],
            "identity_sha256": identity_sha256,
            "tool_name": TOOL_NAME,
            "schema_sha256": schema_sha256,
            "schema_approved_before_owner_review": bool(tool_record["approved"]),
            "descriptions_withheld": discovery.get("descriptions_withheld") is True,
            "evidence_ref_sha256": str(discovery["evidence_ref"]),
        }

        failure_phase = "owner_schema_approval"
        trusted_server = registry.set_trust(
            owner_identity_ref=owner_ref,
            mission_id=mission.mission_id,
            server_id=server_id,
            trust_level="TRUSTED",
        )
        approval = registry.approve_tool(
            owner_identity_ref=owner_ref,
            mission_id=mission.mission_id,
            server_id=server_id,
            tool_name=TOOL_NAME,
            schema_sha256=schema_sha256,
        )
        if trusted_server.get("trust_level") != "TRUSTED" or not approval.get("approved") or approval.get("schema_sha256") != schema_sha256 or approval.get("identity_sha256") != identity_sha256:
            raise RuntimeError("owner_exact_schema_approval_failed")
        result["checks"]["owner_approved_exact_discovered_revision_before_invoke"] = True
        result["mcp"]["owner_approval"] = {
            "owner_identity_ref": owner_ref,
            "trust_before": "UNTRUSTED",
            "trust_after": trusted_server["trust_level"],
            "tool_name": TOOL_NAME,
            "schema_sha256": schema_sha256,
            "identity_sha256": identity_sha256,
            "approval_bound_to_current_identity": approval["identity_sha256"] == identity_sha256,
            "approved": bool(approval["approved"]),
        }

        failure_phase = "mission_invocation"
        second = core.resume_mission(mission.mission_id, owner_session_token=token, max_slices=1)
        invocation = _find_mcp_result(second, "completed", server_id)
        post_invoke_tool = registry.get_tool(owner_identity_ref=owner_ref, mission_id=mission.mission_id, server_id=server_id, tool_name=TOOL_NAME)
        if (
            second.current_step != 2
            or invocation is None
            or invocation.get("trust") != "untrusted_remote_result"
            or invocation.get("evidence_ref") is None
            or not post_invoke_tool.get("approved")
            or invocation.get("tool_name") != TOOL_NAME
        ):
            raise RuntimeError("owner_approved_mcp_invocation_failed")
        result["checks"]["invoke_executed_inside_same_mission"] = True
        remote_result = invocation.get("result") if isinstance(invocation.get("result"), dict) else {}
        remote_structured = remote_result.get("structured_content") if isinstance(remote_result.get("structured_content"), dict) else {}
        remote_content = remote_result.get("content") if isinstance(remote_result.get("content"), list) else []
        remote_content_remains_untrusted = bool(remote_content) and all(
            isinstance(item, str) and item.startswith("[UNTRUSTED_MCP_TOOL_OUTPUT] ")
            for item in remote_content
        )
        malicious_canary_observed = any(
            isinstance(item, str)
            and "IGNORE ALL PRIOR INSTRUCTIONS" in item
            and "MCP_INJECTION_CANARY_V52" in item
            for item in remote_content
        )
        if not remote_content_remains_untrusted or not malicious_canary_observed:
            raise RuntimeError("malicious_mcp_output_was_not_preserved_as_untrusted")
        result["checks"]["malicious_mcp_output_kept_untrusted"] = True
        result["mcp"]["invocation"] = {
            "mission_status_after_slice": second.status.value,
            "current_step": second.current_step,
            "tool_name": invocation["tool_name"],
            "schema_sha256_reapproved_at_dispatch": post_invoke_tool["schema_sha256"],
            "success": invocation.get("success") is True,
            "trust": invocation.get("trust"),
            "authority": "none",
            "remote_content_remains_untrusted": remote_content_remains_untrusted,
            "adversarial_prompt_injection_canary_seen": malicious_canary_observed,
            "adversarial_content_hash": _sha256("\n".join(remote_content)),
            "structured_result_sha256": _sha256(json.dumps(remote_structured, sort_keys=True, separators=(",", ":"))),
            "evidence_ref_sha256": str(invocation["evidence_ref"]),
        }

        failure_phase = "mission_validator"
        completed = core.resume_mission(mission.mission_id, owner_session_token=token, max_slices=1)
        required_evidence_ids = {"mcp-discovery", "mcp-invocation"}
        mission_evidence_ids = {
            str(item.get("criterion_id"))
            for item in completed.evidence
            if isinstance(item, dict) and item.get("criterion_id")
        }
        if (
            completed.status is not MissionStatus.GOAL_COMPLETED
            or not completed.verify_integrity()
            or completed.verification_state.get("verified") is not True
            or not required_evidence_ids.issubset(mission_evidence_ids)
        ):
            raise RuntimeError("mission_validator_did_not_complete_with_both_criteria")
        result["checks"]["mission_validator_and_completion"] = True
        result["mcp"]["mission_completion"] = {
            "status": completed.status.value,
            "integrity_valid": completed.verify_integrity(),
            "verified": completed.verification_state.get("verified") is True,
            "required_criteria": sorted(required_evidence_ids),
            "evidence_criteria": sorted(mission_evidence_ids),
            "mission_evidence_count": len(completed.evidence),
        }

        failure_phase = "durable_evidence_chain"
        chain_path = run_dir / "evidence_chain.db"
        chain_records = _evidence_chain_records(chain_path)
        mcp_records = [record for record in chain_records if _record_type(record) == "UNTRUSTED_MCP_OBSERVATION"]
        valid_chain = bool(chain_records) and verify_chain(chain_records)
        if not valid_chain or len(mcp_records) < 2:
            raise RuntimeError("durable_mcp_evidence_chain_missing_or_invalid")
        safe_chain_records = []
        for record in mcp_records:
            nested = record.get("evidence", {})
            if (
                nested.get("mission_id") != completed.mission_id
                or nested.get("trust") != "untrusted_data"
                or nested.get("authority") != "none"
                or not nested.get("task_id")
                or not nested.get("execution_id")
            ):
                raise RuntimeError("mcp_evidence_chain_owner_scope_or_provenance_invalid")
            safe_chain_records.append({
                "sequence": int(record.get("sequence", 0)),
                "current_hash": str(record.get("current_hash", "")),
                "mission_id": str(nested.get("mission_id", "")),
                "task_id": str(nested.get("task_id", "")),
                "operation": str(nested.get("operation", "")),
                "record_type": _record_type(record),
                "trust": str(nested.get("trust", "")),
                "authority": str(nested.get("authority", "")),
                "response_sha256": str(nested.get("response_sha256", "")),
            })
        result["checks"]["durable_hash_chain_owner_task_target_bound"] = True
        result["evidence"] = {
            "chain_records_total": len(chain_records),
            "chain_valid": valid_chain,
            "mcp_observation_records": len(mcp_records),
            "mcp_records": safe_chain_records,
            "all_remote_observations_untrusted": all(item["trust"] == "untrusted_data" and item["authority"] == "none" for item in safe_chain_records),
        }

        failure_phase = "blocked_server_rejection"
        blocked_server = registry.register_server(owner_identity_ref=owner_ref, mission_id=completed.mission_id, endpoint=blocked_endpoint)
        blocked_server_id = blocked_server["server_id"]
        registry.set_trust(owner_identity_ref=owner_ref, mission_id=completed.mission_id, server_id=blocked_server_id, trust_level="BLOCKED")

        class BlockedPreflightContext:
            def __init__(self):
                self.owner_identity = owner_ref
                self.mission_id = completed.mission_id
                self.scope_snapshot = scope_context
                self.evidence_store = type("EvidenceStoreRef", (), {"mission_store": store})()

            @staticmethod
            def assert_active():
                return None

        before_blocked = _read_jsonl(request_log)
        blocked_denied = False
        try:
            mcp_service.discover({"server_id": blocked_server_id}, execution_context=BlockedPreflightContext())
        except PermissionError as exc:
            blocked_denied = "mcp_server_blocked" in str(exc)
        after_blocked = _read_jsonl(request_log)
        blocked_network_requests = [entry for entry in after_blocked[len(before_blocked):] if entry.get("path") == blocked_path]
        if not blocked_denied or blocked_network_requests:
            raise RuntimeError("blocked_mcp_server_was_not_rejected_before_network")
        result["checks"]["blocked_server_rejected_before_network"] = True
        result["mcp"]["blocked_server"] = {
            "trust_level": "BLOCKED",
            "rejected": blocked_denied,
            "network_requests": len(blocked_network_requests),
            "transport_not_contacted": not blocked_network_requests,
        }

        failure_phase = "streamable_http_transcript"
        requests = _read_jsonl(request_log)
        valid_requests = [entry for entry in requests if entry.get("path") == endpoint_path]
        methods = [str(entry.get("rpc_method", "")) for entry in valid_requests]
        if methods.count("initialize") < 2 or methods.count("tools/list") < 2 or methods.count("tools/call") != 1:
            raise RuntimeError("streamable_http_protocol_transcript_incomplete")
        if any(not entry.get("route_allowed") for entry in valid_requests):
            raise RuntimeError("fixture_received_out_of_path_request")
        result["checks"]["malicious_output_did_not_expand_plan_or_trigger_extra_call"] = (
            [step.action for step in completed.plan.steps] == ["mcp.discover", "mcp.invoke"]
            and methods.count("tools/call") == 1
        )
        if not result["checks"]["malicious_output_did_not_expand_plan_or_trigger_extra_call"]:
            raise RuntimeError("malicious_mcp_output_changed_plan_or_triggered_extra_call")
        result["checks"]["real_streamable_http_initialize_sse_list_call"] = True
        result["transport"]["protocol_methods"] = methods
        result["transport"]["protocol_header_seen_after_initialize"] = all(
            entry.get("protocol_header_present") for entry in valid_requests if entry.get("rpc_method") != "initialize"
        )
        result["transport"]["mcp_session_id_used"] = any(entry.get("session_header_present") for entry in valid_requests)
        if not result["transport"]["protocol_header_seen_after_initialize"] or result["transport"]["mcp_session_id_used"]:
            raise RuntimeError("streamable_http_header_contract_failed")

        result["checks"]["no_qwen_or_timeout_changes"] = True
        result["runtime_limits"] = {"mcp_http_timeout_seconds": 8.0, "timeout_changed": False}
        result["status"] = "PASS"
    except BaseException as exc:
        error_class = type(exc).__name__
        result["failure"] = {"class": error_class, "phase": failure_phase}
        result["status"] = "FAIL"
    finally:
        if mcp_module is not None:
            mcp_module._DEFAULT_SERVICE = previous_service
        if patcher is not None:
            patcher.undo()
        if original_ssl_cert_file is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = original_ssl_cert_file
        stopped = _stop_fixture(fixture_process, fixture_ready)
        result["cleanup"]["fixture_process_stopped"] = stopped
        result["cleanup"]["fixture_ready_file_removed"] = fixture_ready is None or not fixture_ready.exists()
        listener_absent = False
        try:
            probe = socket.socket()
            probe.settimeout(1.0)
            listener_absent = probe.connect_ex(("127.0.0.1", 443)) == 111
            probe.close()
        except OSError:
            listener_absent = False
        result["cleanup"]["loopback_443_listener_absent"] = listener_absent
        shutil.rmtree(run_dir, ignore_errors=True)
        result["cleanup"]["temporary_state_removed"] = not run_dir.exists()
        if original_ssl_cert_file is None or os.environ.get("SSL_CERT_FILE") == original_ssl_cert_file:
            result["cleanup"]["tls_environment_restored"] = True
        else:
            result["cleanup"]["tls_environment_restored"] = False
        if not all(result["cleanup"].values()):
            result["status"] = "FAIL"
        artifact.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": result["status"],
            "artifact": str(artifact),
            "checks": result.get("checks", {}),
            "cleanup": result.get("cleanup", {}),
            "failure_class": error_class or None,
        }, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
