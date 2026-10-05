from __future__ import annotations

"""Bounded MCP Streamable HTTP client and Mission-scoped server trust store.

Only the 2025-06-18 Streamable HTTP transport is supported. This module does
not launch local MCP subprocesses, follow redirects, forward credentials, or
trust server-provided descriptions/annotations. Discovery is data; invocation
is possible only for a TRUSTED server and an Owner-approved schema revision.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from typing import Any, Callable

from security.pinned_http import PinnedSession
from security.scope import ScopeError, canonical_url

MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_CLIENT_NAME = "CyberSentinel"
MCP_CLIENT_VERSION = "1.0.0"
MCP_MAX_RESPONSE_BYTES = 262_144
MCP_MAX_ARGUMENT_BYTES = 8_192
MCP_MAX_TOOL_COUNT = 32
MCP_MAX_TOOL_PAGES = 4
MCP_MAX_SERVERS_PER_MISSION = 8
MCP_MAX_CONTENT_ITEMS = 24
MCP_MAX_CONTENT_CHARS = 12_000
MCP_HTTP_TIMEOUT_SECONDS = 8.0
MCP_SERVER_ID_RE = re.compile(r"^mcp_[0-9a-f]{32}$")
MCP_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MCP_OWNER_RE = re.compile(r"^owner:[1-9][0-9]{0,18}$")
MCP_MISSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
MCP_TRUST_LEVELS = frozenset({"TRUSTED", "KNOWN", "UNTRUSTED", "BLOCKED"})
_SENSITIVE_RESULT_KEYS = frozenset({
    "apikey", "accesstoken", "refreshtoken", "idtoken", "token", "secret",
    "password", "passwd", "credential", "credentials", "authorization",
    "privatekey", "clientsecret", "cookie", "session", "sessionid", "auth",
})
_SCHEMA_KEYS = frozenset({
    "type", "properties", "required", "additionalProperties", "items", "enum",
    "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
})
_SCHEMA_ANNOTATIONS = frozenset({"title", "description", "$schema"})
_REMOTE_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cybersentinel-mcp-http")


class MCPClientError(RuntimeError):
    """A sanitized MCP client error; it never includes server text or secrets."""


class MCPProtocolError(MCPClientError):
    pass


class MCPTransportError(MCPClientError):
    pass


class MCPRequestTimeout(MCPClientError):
    pass


class MCPRequestCancelled(MCPClientError):
    pass


@dataclass(frozen=True)
class MCPDiscoveredTool:
    name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    schema_sha256: str

    def safe_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "schema_sha256": self.schema_sha256,
        }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_mcp_endpoint(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("invalid_mcp_endpoint")
    try:
        parts = urlsplit(value)
        port = parts.port
        normalized = canonical_url(value)
        normalized_parts = urlsplit(normalized)
    except (ValueError, ScopeError):
        raise ValueError("invalid_mcp_endpoint") from None
    if (
        parts.scheme.casefold() != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (port is not None and port != 443)
        or normalized_parts.scheme != "https"
        or normalized_parts.port not in (None, 443)
        or not normalized_parts.hostname
    ):
        raise ValueError("invalid_mcp_endpoint")
    return normalized


def _normalize_schema(node: Any, *, depth: int = 0) -> dict[str, Any]:
    """Reduce remote JSON Schema to a strict inert subset; drop all descriptions.

    Unsupported keywords (including $ref, pattern, executable/default hints,
    and combinators) fail closed. Object schemas reject extra properties.
    """
    if depth > 8 or not isinstance(node, dict) or len(node) > 80:
        raise MCPProtocolError("invalid_remote_schema")
    if set(node) - _SCHEMA_KEYS - _SCHEMA_ANNOTATIONS:
        raise MCPProtocolError("unsupported_remote_schema_keyword")
    kind = node.get("type")
    if kind not in {"object", "array", "string", "integer", "number", "boolean", "null"}:
        raise MCPProtocolError("invalid_remote_schema_type")
    result: dict[str, Any] = {"type": kind}
    if kind == "object":
        props = node.get("properties", {})
        if not isinstance(props, dict) or len(props) > 64:
            raise MCPProtocolError("invalid_remote_schema_properties")
        if node.get("additionalProperties", False) is not False:
            raise MCPProtocolError("remote_schema_extra_properties_not_allowed")
        normalized_props = {}
        for name, child in props.items():
            if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(c) < 0x20 for c in name):
                raise MCPProtocolError("invalid_remote_schema_property_name")
            normalized_props[name] = _normalize_schema(child, depth=depth + 1)
        required = node.get("required", [])
        if (
            not isinstance(required, list)
            or len(required) > 64
            or any(not isinstance(name, str) or name not in normalized_props for name in required)
            or len(set(required)) != len(required)
        ):
            raise MCPProtocolError("invalid_remote_schema_required")
        result.update({"properties": normalized_props, "required": required, "additionalProperties": False})
    elif kind == "array":
        items = node.get("items")
        if items is None:
            raise MCPProtocolError("remote_array_schema_requires_items")
        result["items"] = _normalize_schema(items, depth=depth + 1)
    if "enum" in node:
        enum = node["enum"]
        if not isinstance(enum, list) or not 1 <= len(enum) <= 64:
            raise MCPProtocolError("invalid_remote_schema_enum")
        for item in enum:
            if isinstance(item, (dict, list)) or not (item is None or isinstance(item, (str, int, float, bool))):
                raise MCPProtocolError("invalid_remote_schema_enum")
            if isinstance(item, str) and len(item) > 512:
                raise MCPProtocolError("invalid_remote_schema_enum")
            if isinstance(item, float) and (item != item or abs(item) == float("inf")):
                raise MCPProtocolError("invalid_remote_schema_enum")
        result["enum"] = enum
    for key in ("minLength", "maxLength", "minItems", "maxItems"):
        if key in node:
            value = node[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 16_384:
                raise MCPProtocolError("invalid_remote_schema_bound")
            result[key] = value
    for key in ("minimum", "maximum"):
        if key in node:
            value = node[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or abs(value) > 1e12:
                raise MCPProtocolError("invalid_remote_schema_bound")
            result[key] = value
    if result.get("minLength", 0) > result.get("maxLength", 16_384):
        raise MCPProtocolError("invalid_remote_schema_bound")
    if result.get("minItems", 0) > result.get("maxItems", 64):
        raise MCPProtocolError("invalid_remote_schema_bound")
    if result.get("minimum", float("-inf")) > result.get("maximum", float("inf")):
        raise MCPProtocolError("invalid_remote_schema_bound")
    from tools.registry import _schema_definition_valid
    if not _schema_definition_valid(result):
        raise MCPProtocolError("invalid_remote_schema")
    return result


def _normalize_tool(raw: Any) -> MCPDiscoveredTool:
    if not isinstance(raw, dict):
        raise MCPProtocolError("invalid_remote_tool")
    name = raw.get("name")
    if not isinstance(name, str) or not MCP_TOOL_NAME_RE.fullmatch(name):
        raise MCPProtocolError("invalid_remote_tool_name")
    input_schema = _normalize_schema(raw.get("inputSchema"))
    if input_schema.get("type") != "object":
        raise MCPProtocolError("remote_tool_input_must_be_object")
    output_schema = None
    if "outputSchema" in raw and raw["outputSchema"] is not None:
        output_schema = _normalize_schema(raw["outputSchema"])
        if output_schema.get("type") != "object":
            raise MCPProtocolError("remote_tool_output_must_be_object")
    revision = {"input": input_schema, "output": output_schema}
    revision_json = _canonical_json(revision)
    if len(revision_json.encode("utf-8")) > 8_192:
        raise MCPProtocolError("remote_tool_schema_too_large")
    schema_hash = _sha256(revision_json)
    # Remote descriptions, titles, annotations, and icons are intentionally discarded.
    return MCPDiscoveredTool(name, input_schema, output_schema, schema_hash)


def _scrub_text(value: str) -> str:
    from agent.intelligence_layer.specialist_memory import redact_specialist_text
    return redact_specialist_text(value)


def _scrub_json_strings(value: Any, *, depth: int = 0) -> Any:
    if depth > 16:
        raise MCPProtocolError("remote_result_too_deep")
    if isinstance(value, str):
        return _scrub_text(value[:4096])
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, list):
        return [_scrub_json_strings(item, depth=depth + 1) for item in value[:64]]
    if isinstance(value, dict):
        if len(value) > 64 or any(not isinstance(key, str) or len(key) > 128 for key in value):
            raise MCPProtocolError("remote_result_invalid")
        safe = {}
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", key.casefold())
            if normalized_key in _SENSITIVE_RESULT_KEYS or any(
                marker in normalized_key for marker in ("apikey", "token", "secret", "password", "credential", "privatekey", "authorization", "cookie")
            ):
                safe[key] = "[REDACTED]"
            else:
                safe[key] = _scrub_json_strings(item, depth=depth + 1)
        return safe
    raise MCPProtocolError("remote_result_invalid")


class MCPServerStore:
    """Durable, owner+Mission-scoped MCP server and exact tool-revision approvals."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.db_path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    server_id TEXT PRIMARY KEY,
                    owner_identity_ref TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    trust_level TEXT NOT NULL CHECK(trust_level IN ('TRUSTED','KNOWN','UNTRUSTED','BLOCKED')),
                    identity_sha256 TEXT,
                    protocol_version TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(owner_identity_ref, mission_id, endpoint)
                );
                CREATE INDEX IF NOT EXISTS idx_mcp_servers_owner_mission
                    ON mcp_servers(owner_identity_ref, mission_id, updated_at);
                CREATE TABLE IF NOT EXISTS mcp_tool_revisions (
                    owner_identity_ref TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    server_id TEXT NOT NULL,
                    remote_tool_name TEXT NOT NULL,
                    schema_json TEXT NOT NULL,
                    schema_sha256 TEXT NOT NULL,
                    present INTEGER NOT NULL DEFAULT 1 CHECK(present IN (0,1)),
                    approved_schema_sha256 TEXT,
                    approved_identity_sha256 TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(owner_identity_ref, mission_id, server_id, remote_tool_name),
                    FOREIGN KEY(server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
                );
                """
            )

    @staticmethod
    def _validate_binding(owner_identity_ref: str, mission_id: str) -> None:
        if not isinstance(owner_identity_ref, str) or not MCP_OWNER_RE.fullmatch(owner_identity_ref):
            raise PermissionError("canonical_owner_required")
        if not isinstance(mission_id, str) or not MCP_MISSION_RE.fullmatch(mission_id):
            raise PermissionError("canonical_mission_required")

    @staticmethod
    def _server_id(value: str) -> str:
        if not isinstance(value, str) or not MCP_SERVER_ID_RE.fullmatch(value):
            raise ValueError("invalid_mcp_server_id")
        return value

    def register_server(self, *, owner_identity_ref: str, mission_id: str, endpoint: str) -> dict[str, Any]:
        self._validate_binding(owner_identity_ref, mission_id)
        normalized = canonical_mcp_endpoint(endpoint)
        now = _utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? AND endpoint=?",
                (owner_identity_ref, mission_id, normalized),
            ).fetchone()
            if row:
                return self._safe_server(row)
            count = conn.execute(
                "SELECT COUNT(*) FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=?",
                (owner_identity_ref, mission_id),
            ).fetchone()[0]
            if count >= MCP_MAX_SERVERS_PER_MISSION:
                raise ValueError("mcp_server_count_exceeded")
            server_id = "mcp_" + uuid.uuid4().hex
            conn.execute(
                "INSERT INTO mcp_servers(server_id,owner_identity_ref,mission_id,endpoint,trust_level,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (server_id, owner_identity_ref, mission_id, normalized, "UNTRUSTED", now, now),
            )
            return {
                "server_id": server_id,
                "endpoint": normalized,
                "trust_level": "UNTRUSTED",
                "identity_sha256": "",
                "protocol_version": "",
                "updated_at": now,
            }

    @staticmethod
    def _safe_server(row: sqlite3.Row) -> dict[str, Any]:
        try:
            server_id = MCPServerStore._server_id(str(row["server_id"]))
            endpoint = canonical_mcp_endpoint(str(row["endpoint"]))
            trust_level = str(row["trust_level"])
            identity = str(row["identity_sha256"] or "")
            protocol = str(row["protocol_version"] or "")
            updated_at = str(row["updated_at"])
            if endpoint != str(row["endpoint"]):
                raise ValueError("noncanonical_endpoint")
            if trust_level not in MCP_TRUST_LEVELS:
                raise ValueError("invalid_trust")
            if identity and not re.fullmatch(r"[0-9a-f]{64}", identity):
                raise ValueError("invalid_identity")
            if bool(identity) != (protocol == MCP_PROTOCOL_VERSION):
                raise ValueError("invalid_protocol")
            if not updated_at or len(updated_at) > 64 or any(ord(char) < 0x20 for char in updated_at):
                raise ValueError("invalid_timestamp")
        except Exception:
            raise MCPProtocolError("stored_mcp_server_integrity_invalid") from None
        return {"server_id": server_id, "endpoint": endpoint, "trust_level": trust_level,
                "identity_sha256": identity, "protocol_version": protocol, "updated_at": updated_at}

    def get_server(self, *, owner_identity_ref: str, mission_id: str, server_id: str) -> dict[str, Any]:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (owner_identity_ref, mission_id, server_id),
            ).fetchone()
        if row is None:
            raise KeyError("unknown_mcp_server")
        return self._safe_server(row)

    def list_servers(self, *, owner_identity_ref: str, mission_id: str) -> list[dict[str, Any]]:
        self._validate_binding(owner_identity_ref, mission_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? ORDER BY created_at,server_id LIMIT ?",
                (owner_identity_ref, mission_id, MCP_MAX_SERVERS_PER_MISSION + 1),
            ).fetchall()
        if len(rows) > MCP_MAX_SERVERS_PER_MISSION:
            raise MCPProtocolError("mcp_server_inventory_exceeds_limit")
        result = []
        for row in rows:
            server = self._safe_server(row)
            server["tools"] = self.list_tools(owner_identity_ref=owner_identity_ref, mission_id=mission_id, server_id=server["server_id"])
            result.append(server)
        return result

    def set_trust(self, *, owner_identity_ref: str, mission_id: str, server_id: str, trust_level: str) -> dict[str, Any]:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        if not isinstance(trust_level, str) or trust_level not in MCP_TRUST_LEVELS:
            raise ValueError("invalid_mcp_trust_level")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (owner_identity_ref, mission_id, server_id),
            ).fetchone()
            if row is None:
                raise KeyError("unknown_mcp_server")
            self._safe_server(row)
            if trust_level in {"KNOWN", "TRUSTED"} and (not row["identity_sha256"] or row["protocol_version"] != MCP_PROTOCOL_VERSION):
                raise ValueError("discover_server_before_trusting")
            conn.execute(
                "UPDATE mcp_servers SET trust_level=?,updated_at=? WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (trust_level, _utc_now(), owner_identity_ref, mission_id, server_id),
            )
            if trust_level != "TRUSTED":
                conn.execute(
                    "UPDATE mcp_tool_revisions SET approved_schema_sha256=NULL,approved_identity_sha256=NULL "
                    "WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                    (owner_identity_ref, mission_id, server_id),
                )
        return self.get_server(owner_identity_ref=owner_identity_ref, mission_id=mission_id, server_id=server_id)

    def record_discovery(
        self, *, owner_identity_ref: str, mission_id: str, server_id: str,
        identity_sha256: str, protocol_version: str, tools: list[MCPDiscoveredTool],
    ) -> None:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        if not isinstance(identity_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", identity_sha256) or protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError("invalid_mcp_identity")
        if not isinstance(tools, list) or len(tools) > MCP_MAX_TOOL_COUNT:
            raise ValueError("mcp_tool_count_exceeded")
        seen_names: set[str] = set()
        for tool in tools:
            if not isinstance(tool, MCPDiscoveredTool) or not isinstance(tool.name, str) or not MCP_TOOL_NAME_RE.fullmatch(tool.name) or tool.name in seen_names:
                raise ValueError("invalid_mcp_discovery_record")
            seen_names.add(tool.name)
            try:
                normalized_input = _normalize_schema(tool.input_schema)
                normalized_output = None if tool.output_schema is None else _normalize_schema(tool.output_schema)
                revision_json = _canonical_json({"input": normalized_input, "output": normalized_output})
            except Exception:
                raise ValueError("invalid_mcp_discovery_record") from None
            if len(revision_json.encode("utf-8")) > 8_192 or not isinstance(tool.schema_sha256, str) or _sha256(revision_json) != tool.schema_sha256:
                raise ValueError("invalid_mcp_discovery_record")
        now = _utc_now()
        with self._connect() as conn:
            server = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (owner_identity_ref, mission_id, server_id),
            ).fetchone()
            if server is None:
                raise KeyError("unknown_mcp_server")
            self._safe_server(server)
            if server["trust_level"] not in MCP_TRUST_LEVELS:
                raise MCPProtocolError("stored_mcp_server_integrity_invalid")
            if server["trust_level"] == "BLOCKED":
                raise PermissionError("mcp_server_blocked")
            trust_level = str(server["trust_level"])
            previous_identity = str(server["identity_sha256"] or "")
            if previous_identity and previous_identity != identity_sha256 and trust_level == "TRUSTED":
                trust_level = "KNOWN"
                conn.execute(
                    "UPDATE mcp_tool_revisions SET approved_schema_sha256=NULL,approved_identity_sha256=NULL "
                    "WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                    (owner_identity_ref, mission_id, server_id),
                )
            conn.execute(
                "UPDATE mcp_servers SET identity_sha256=?,protocol_version=?,trust_level=?,updated_at=? WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (identity_sha256, protocol_version, trust_level, now, owner_identity_ref, mission_id, server_id),
            )
            conn.execute(
                "UPDATE mcp_tool_revisions SET present=0 WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (owner_identity_ref, mission_id, server_id),
            )
            for tool in tools:
                schema_json = _canonical_json({"input": tool.input_schema, "output": tool.output_schema})
                conn.execute(
                    "INSERT INTO mcp_tool_revisions(owner_identity_ref,mission_id,server_id,remote_tool_name,schema_json,schema_sha256,present,updated_at) "
                    "VALUES(?,?,?,?,?,?,1,?) ON CONFLICT(owner_identity_ref,mission_id,server_id,remote_tool_name) DO UPDATE SET "
                    "schema_json=excluded.schema_json,schema_sha256=excluded.schema_sha256,present=1,updated_at=excluded.updated_at",
                    (owner_identity_ref, mission_id, server_id, tool.name, schema_json, tool.schema_sha256, now),
                )
            conn.execute(
                "DELETE FROM mcp_tool_revisions WHERE owner_identity_ref=? AND mission_id=? AND server_id=? AND present=0",
                (owner_identity_ref, mission_id, server_id),
            )

    def list_tools(self, *, owner_identity_ref: str, mission_id: str, server_id: str) -> list[dict[str, Any]]:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        with self._connect() as conn:
            server = conn.execute(
                "SELECT * FROM mcp_servers WHERE owner_identity_ref=? AND mission_id=? AND server_id=?",
                (owner_identity_ref, mission_id, server_id),
            ).fetchone()
            if server is None:
                raise KeyError("unknown_mcp_server")
            self._safe_server(server)
            if server["trust_level"] not in MCP_TRUST_LEVELS:
                raise MCPProtocolError("stored_mcp_server_integrity_invalid")
            rows = conn.execute(
                "SELECT * FROM mcp_tool_revisions WHERE owner_identity_ref=? AND mission_id=? AND server_id=? AND present=1 ORDER BY remote_tool_name LIMIT ?",
                (owner_identity_ref, mission_id, server_id, MCP_MAX_TOOL_COUNT + 1),
            ).fetchall()
        if len(rows) > MCP_MAX_TOOL_COUNT:
            raise MCPProtocolError("mcp_tool_inventory_exceeds_limit")
        current_identity = str(server["identity_sha256"] or "")
        result = []
        for row in rows:
            try:
                revision = json.loads(row["schema_json"])
                if not isinstance(revision, dict) or set(revision) != {"input", "output"}:
                    raise ValueError("invalid_revision")
                if _sha256(_canonical_json(revision)) != str(row["schema_sha256"]):
                    raise ValueError("digest_mismatch")
                normalized_input = _normalize_schema(revision["input"])
                normalized_output = None if revision["output"] is None else _normalize_schema(revision["output"])
                if _canonical_json({"input": normalized_input, "output": normalized_output}) != _canonical_json(revision):
                    raise ValueError("noncanonical_revision")
            except Exception:
                raise MCPProtocolError("stored_mcp_schema_integrity_invalid") from None
            approved = (
                row["approved_schema_sha256"] == row["schema_sha256"]
                and row["approved_identity_sha256"] == current_identity
                and bool(current_identity)
                and server["trust_level"] == "TRUSTED"
            )
            result.append({
                "name": str(row["remote_tool_name"]),
                "schema": revision,
                "schema_sha256": str(row["schema_sha256"]),
                "approved": approved,
            })
        return result

    def get_tool(self, *, owner_identity_ref: str, mission_id: str, server_id: str, tool_name: str) -> dict[str, Any]:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        if not isinstance(tool_name, str) or not MCP_TOOL_NAME_RE.fullmatch(tool_name):
            raise ValueError("invalid_mcp_tool_name")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT t.*,s.identity_sha256,s.trust_level,s.endpoint,s.protocol_version,s.server_id,s.updated_at FROM mcp_tool_revisions t "
                "JOIN mcp_servers s ON s.server_id=t.server_id AND s.owner_identity_ref=t.owner_identity_ref AND s.mission_id=t.mission_id "
                "WHERE t.owner_identity_ref=? AND t.mission_id=? AND t.server_id=? AND t.remote_tool_name=? AND t.present=1",
                (owner_identity_ref, mission_id, server_id, tool_name),
            ).fetchone()
        if row is None:
            raise KeyError("unknown_mcp_tool")
        self._safe_server(row)
        try:
            revision = json.loads(row["schema_json"])
            if not isinstance(revision, dict) or set(revision) != {"input", "output"}:
                raise ValueError("invalid_revision")
            if _sha256(_canonical_json(revision)) != str(row["schema_sha256"]):
                raise ValueError("digest_mismatch")
            normalized_input = _normalize_schema(revision["input"])
            normalized_output = None if revision["output"] is None else _normalize_schema(revision["output"])
            if _canonical_json({"input": normalized_input, "output": normalized_output}) != _canonical_json(revision):
                raise ValueError("noncanonical_revision")
        except Exception:
            raise MCPProtocolError("stored_mcp_schema_invalid") from None
        approved = (
            row["approved_schema_sha256"] == row["schema_sha256"]
            and row["approved_identity_sha256"] == row["identity_sha256"]
            and bool(row["identity_sha256"])
            and row["trust_level"] == "TRUSTED"
        )
        return {
            "name": str(row["remote_tool_name"]),
            "schema": revision,
            "schema_sha256": str(row["schema_sha256"]),
            "approved": approved,
            "identity_sha256": str(row["identity_sha256"] or ""),
            "trust_level": str(row["trust_level"]),
            "endpoint": str(row["endpoint"]),
            "protocol_version": str(row["protocol_version"] or ""),
        }

    def approve_tool(
        self, *, owner_identity_ref: str, mission_id: str, server_id: str,
        tool_name: str, schema_sha256: str,
    ) -> dict[str, Any]:
        self._validate_binding(owner_identity_ref, mission_id)
        server_id = self._server_id(server_id)
        if not isinstance(tool_name, str) or not MCP_TOOL_NAME_RE.fullmatch(tool_name):
            raise ValueError("invalid_mcp_tool_name")
        if not isinstance(schema_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", schema_sha256):
            raise ValueError("invalid_mcp_schema_digest")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT t.*,s.identity_sha256,s.trust_level,s.endpoint,s.protocol_version,s.server_id,s.updated_at FROM mcp_tool_revisions t "
                "JOIN mcp_servers s ON s.server_id=t.server_id AND s.owner_identity_ref=t.owner_identity_ref AND s.mission_id=t.mission_id "
                "WHERE t.owner_identity_ref=? AND t.mission_id=? AND t.server_id=? AND t.remote_tool_name=?",
                (owner_identity_ref, mission_id, server_id, tool_name),
            ).fetchone()
            if row is None or not row["present"]:
                raise KeyError("unknown_mcp_tool")
            self._safe_server(row)
            try:
                revision = json.loads(row["schema_json"])
                if not isinstance(revision, dict) or set(revision) != {"input", "output"}:
                    raise ValueError("invalid_revision")
                normalized_input = _normalize_schema(revision["input"])
                normalized_output = None if revision["output"] is None else _normalize_schema(revision["output"])
                if _canonical_json({"input": normalized_input, "output": normalized_output}) != _canonical_json(revision):
                    raise ValueError("noncanonical_revision")
                if _sha256(_canonical_json(revision)) != str(row["schema_sha256"]):
                    raise ValueError("digest_mismatch")
            except Exception:
                raise MCPProtocolError("stored_mcp_schema_integrity_invalid") from None
            if row["trust_level"] != "TRUSTED" or not row["identity_sha256"]:
                raise PermissionError("trusted_mcp_server_required")
            if row["schema_sha256"] != schema_sha256:
                raise ValueError("mcp_schema_revision_changed")
            conn.execute(
                "UPDATE mcp_tool_revisions SET approved_schema_sha256=?,approved_identity_sha256=?,updated_at=? "
                "WHERE owner_identity_ref=? AND mission_id=? AND server_id=? AND remote_tool_name=?",
                (schema_sha256, row["identity_sha256"], _utc_now(), owner_identity_ref, mission_id, server_id, tool_name),
            )
        return self.get_tool(owner_identity_ref=owner_identity_ref, mission_id=mission_id, server_id=server_id, tool_name=tool_name)


class MCPRemoteClient:
    """Streamable HTTP client using PinnedSession and Mission-scope revalidation."""

    def __init__(
        self,
        endpoint: str,
        execution_context: Any,
        *,
        timeout: float = MCP_HTTP_TIMEOUT_SECONDS,
        session_factory: Callable[..., Any] | None = None,
    ):
        self.endpoint = canonical_mcp_endpoint(endpoint)
        self.context = execution_context
        self.timeout = min(max(float(timeout), 0.1), MCP_HTTP_TIMEOUT_SECONDS)
        self._session_factory = session_factory or PinnedSession
        self._session = self._session_factory(timeout=self.timeout, max_response_bytes=MCP_MAX_RESPONSE_BYTES)
        self._session_id = ""
        self._protocol_version = ""
        self._identity_sha256 = ""
        self._response_digests: list[str] = []
        self._tools: dict[str, MCPDiscoveredTool] = {}
        self._closed = False

    @property
    def response_transcript_sha256(self) -> str:
        return _sha256("\0".join(self._response_digests))

    def _authorize_scope(self, *, ignore_cancel: bool = False) -> None:
        context = self.context
        if ignore_cancel:
            try:
                context = replace(context, cancellation_event=None)
            except Exception:
                raise PermissionError("canonical_execution_context_required") from None
        context.assert_active()
        scope = context.scope_snapshot
        required = {"program_id", "target_id", "scope_snapshot_id"}
        if not isinstance(scope, dict) or not required.issubset(scope):
            raise PermissionError("complete_mcp_scope_required")
        from security.scope_resolver import resolve
        decision = resolve(
            str(scope["scope_snapshot_id"]), str(scope["target_id"]), self.endpoint,
            method="POST", expected_program_id=str(scope["program_id"]), consume_rate=True,
        )
        if not decision.allowed:
            raise PermissionError("mcp_scope_denied: " + str(decision.reason))

    def _post(self, message: dict[str, Any], *, ignore_cancel: bool = False, timeout: float | None = None):
        self._authorize_scope(ignore_cancel=ignore_cancel)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._protocol_version:
            headers["MCP-Protocol-Version"] = self._protocol_version
        return self._session.request(
            "POST", self.endpoint, headers=headers, json_body=message,
            timeout=self.timeout if timeout is None else timeout,
        )

    @staticmethod
    def _event_messages(body: bytes) -> list[dict[str, Any]]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise MCPProtocolError("invalid_mcp_sse_encoding") from None
        if len(text) > MCP_MAX_RESPONSE_BYTES:
            raise MCPProtocolError("mcp_response_too_large")
        messages: list[dict[str, Any]] = []
        data: list[str] = []
        for line in text.splitlines() + [""]:
            if line == "":
                if data:
                    payload = "\n".join(data)
                    try:
                        value = json.loads(payload)
                    except (TypeError, ValueError):
                        raise MCPProtocolError("invalid_mcp_sse_event") from None
                    if not isinstance(value, dict):
                        raise MCPProtocolError("invalid_mcp_sse_event")
                    messages.append(value)
                    if len(messages) > 64:
                        raise MCPProtocolError("too_many_mcp_sse_events")
                    data = []
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif line.startswith(":") or line.startswith(("event:", "id:", "retry:")):
                continue
        return messages

    def _decode_response(self, response: Any, request_id: str) -> dict[str, Any]:
        if int(getattr(response, "status", 0)) != 200:
            raise MCPTransportError(f"mcp_http_status_{int(getattr(response, 'status', 0))}")
        body = getattr(response, "body", None)
        headers = getattr(response, "headers", {})
        if not isinstance(body, bytes) or len(body) > MCP_MAX_RESPONSE_BYTES or not isinstance(headers, dict):
            raise MCPProtocolError("invalid_mcp_http_response")
        self._response_digests.append(_sha256(body))
        raw_content_type = str(headers.get("content-type", headers.get("Content-Type", "")))
        content_type = raw_content_type.split(";", 1)[0].strip().casefold()
        if content_type == "application/json":
            try:
                messages = [json.loads(body.decode("utf-8"))]
            except (UnicodeDecodeError, ValueError):
                raise MCPProtocolError("invalid_mcp_json_response") from None
        elif content_type == "text/event-stream":
            messages = self._event_messages(body)
        else:
            raise MCPProtocolError("unsupported_mcp_response_content_type")
        result = None
        for message in messages:
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise MCPProtocolError("invalid_mcp_jsonrpc_message")
            if str(message.get("id", "")) == request_id:
                if result is not None:
                    raise MCPProtocolError("duplicate_mcp_response")
                result = message
            elif message.get("method") == "notifications/progress":
                # Progress values are deliberately discarded as untrusted metadata.
                continue
            elif "id" in message or message.get("method"):
                # Never answer server-initiated requests or surface arbitrary notifications.
                raise MCPProtocolError("unexpected_mcp_server_message")
        if result is None:
            raise MCPProtocolError("missing_mcp_response")
        if "error" in result:
            err = result.get("error")
            code = err.get("code") if isinstance(err, dict) else None
            safe_code = str(code) if isinstance(code, int) and not isinstance(code, bool) else "unknown"
            raise MCPProtocolError("mcp_jsonrpc_error_" + safe_code[:16])
        value = result.get("result")
        if not isinstance(value, dict):
            raise MCPProtocolError("invalid_mcp_result")
        return value

    def _send_cancelled(self, request_id: str) -> None:
        if not self._session_id or not self._protocol_version:
            return
        try:
            response = self._post(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": request_id, "reason": "tool_cancelled"}},
                ignore_cancel=True,
                timeout=min(1.0, self.timeout),
            )
            if int(getattr(response, "status", 0)) != 202:
                return
        except Exception:
            # Cancellation is best-effort; the caller records the result as ambiguous.
            return

    def _rpc(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        request_id = uuid.uuid4().hex
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        future = _REMOTE_EXECUTOR.submit(self._post, message)
        deadline = time.monotonic() + self.timeout
        cancellation = getattr(self.context, "cancellation_event", None)
        while True:
            if cancellation is not None and cancellation.is_set():
                self._send_cancelled(request_id)
                raise MCPRequestCancelled("mcp_request_cancelled_outcome_ambiguous")
            if future.done():
                try:
                    response = future.result()
                except Exception:
                    raise MCPTransportError("mcp_transport_failure") from None
                result = self._decode_response(response, request_id)
                headers = getattr(response, "headers", {})
                normalized_headers = {str(k).casefold(): str(v) for k, v in headers.items()}
                return result, normalized_headers
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._send_cancelled(request_id)
                raise MCPRequestTimeout("mcp_request_timeout_outcome_ambiguous")
            time.sleep(min(0.025, remaining))

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        future = _REMOTE_EXECUTOR.submit(self._post, message)
        deadline = time.monotonic() + self.timeout
        cancellation = getattr(self.context, "cancellation_event", None)
        while not future.done():
            if cancellation is not None and cancellation.is_set():
                raise MCPRequestCancelled("mcp_request_cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPRequestTimeout("mcp_notification_timeout")
            time.sleep(min(0.025, remaining))
        try:
            response = future.result()
        except Exception:
            raise MCPTransportError("mcp_transport_failure") from None
        if int(getattr(response, "status", 0)) != 202 or getattr(response, "body", b""):
            raise MCPProtocolError("invalid_mcp_notification_response")

    @staticmethod
    def _safe_server_info(value: Any) -> dict[str, str]:
        if not isinstance(value, dict):
            raise MCPProtocolError("invalid_mcp_server_identity")
        safe = {}
        for key in ("name", "version"):
            item = value.get(key)
            if not isinstance(item, str) or not item or len(item) > 128 or any(ord(c) < 0x20 for c in item):
                raise MCPProtocolError("invalid_mcp_server_identity")
            safe[key] = item
        return safe

    def initialize(self) -> None:
        if self._protocol_version:
            return
        result, headers = self._rpc("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": MCP_CLIENT_NAME, "version": MCP_CLIENT_VERSION},
        })
        if result.get("protocolVersion") != MCP_PROTOCOL_VERSION:
            raise MCPProtocolError("unsupported_mcp_protocol_version")
        capabilities = result.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
            raise MCPProtocolError("mcp_tools_capability_required")
        server_info = self._safe_server_info(result.get("serverInfo"))
        session_id = headers.get("mcp-session-id", "")
        if session_id:
            if len(session_id) > 256 or any(not 0x21 <= ord(char) <= 0x7E for char in session_id):
                raise MCPProtocolError("invalid_mcp_session_id")
            self._session_id = session_id
        self._protocol_version = MCP_PROTOCOL_VERSION
        identity = {
            "endpoint": self.endpoint,
            "server_info": server_info,
            "protocol_version": MCP_PROTOCOL_VERSION,
            "tools_capability": {"available": True, "list_changed": capabilities["tools"].get("listChanged") is True},
        }
        self._identity_sha256 = _sha256(_canonical_json(identity))
        self._notify("notifications/initialized")

    def discover(self) -> tuple[str, list[MCPDiscoveredTool]]:
        self.initialize()
        tools: dict[str, MCPDiscoveredTool] = {}
        cursor = None
        for page in range(MCP_MAX_TOOL_PAGES):
            params = {} if cursor is None else {"cursor": cursor}
            result, _headers = self._rpc("tools/list", params)
            page_tools = result.get("tools")
            if not isinstance(page_tools, list) or len(page_tools) > MCP_MAX_TOOL_COUNT:
                raise MCPProtocolError("invalid_mcp_tools_list")
            for raw in page_tools:
                tool = _normalize_tool(raw)
                if tool.name in tools:
                    raise MCPProtocolError("duplicate_mcp_tool_name")
                tools[tool.name] = tool
                if len(tools) > MCP_MAX_TOOL_COUNT:
                    raise MCPProtocolError("mcp_tool_count_exceeded")
            cursor = result.get("nextCursor")
            if cursor is None:
                self._tools = tools
                return self._identity_sha256, list(tools.values())
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512 or any(ord(c) < 0x20 for c in cursor):
                raise MCPProtocolError("invalid_mcp_pagination_cursor")
        raise MCPProtocolError("mcp_tool_listing_incomplete")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(name)
        if tool is None:
            raise MCPProtocolError("mcp_tool_not_in_fresh_discovery")
        if not isinstance(arguments, dict):
            raise ValueError("mcp_arguments_must_be_object")
        try:
            encoded = _canonical_json(arguments).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise ValueError("mcp_arguments_must_be_bounded_json") from None
        if len(encoded) > MCP_MAX_ARGUMENT_BYTES:
            raise ValueError("mcp_arguments_too_large")
        from tools.registry import _validate_json_value
        error = _validate_json_value(arguments, tool.input_schema)
        if error:
            raise ValueError("mcp_arguments_schema_mismatch")
        result, _headers = self._rpc("tools/call", {"name": name, "arguments": arguments})
        is_error = result.get("isError", False)
        if not isinstance(is_error, bool):
            raise MCPProtocolError("invalid_mcp_tool_result")
        content = result.get("content", [])
        if not isinstance(content, list) or len(content) > MCP_MAX_CONTENT_ITEMS:
            raise MCPProtocolError("invalid_mcp_tool_content")
        text_items = []
        total = 0
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                # Images, audio, resource links and embedded resources are not fetched or returned.
                continue
            text = item.get("text")
            if not isinstance(text, str):
                raise MCPProtocolError("invalid_mcp_text_content")
            remaining = MCP_MAX_CONTENT_CHARS - total
            if remaining <= 0:
                break
            safe = _scrub_text(text[:remaining])
            text_items.append("[UNTRUSTED_MCP_TOOL_OUTPUT] " + safe)
            total += len(safe)
        output = {"is_error": is_error, "content": text_items, "content_truncated": total >= MCP_MAX_CONTENT_CHARS}
        structured = result.get("structuredContent")
        if structured is not None:
            if tool.output_schema is not None:
                error = _validate_json_value(structured, tool.output_schema)
                if error:
                    raise MCPProtocolError("mcp_structured_output_schema_mismatch")
                structured = _scrub_json_strings(structured)
                if len(_canonical_json(structured).encode("utf-8")) <= MCP_MAX_CONTENT_CHARS:
                    output["structured_content"] = structured
                else:
                    output["structured_content_sha256"] = _sha256(_canonical_json(structured))
                    output["structured_content_truncated"] = True
            else:
                output["structured_content_omitted"] = True
        return output

    @property
    def identity_sha256(self) -> str:
        return self._identity_sha256

    def close(self) -> None:
        if not self._closed:
            try:
                self._session.close()
            except Exception:
                pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class MCPToolService:
    """ExecutionContext-bound discovery and invocation handlers."""

    def __init__(self, *, client_factory: Callable[..., MCPRemoteClient] = MCPRemoteClient):
        self.client_factory = client_factory

    @staticmethod
    def _store(context: Any) -> MCPServerStore:
        evidence_store = getattr(context, "evidence_store", None)
        mission_store = getattr(evidence_store, "mission_store", None)
        db_path = getattr(mission_store, "db_path", None)
        if not db_path:
            raise PermissionError("mission_store_required_for_mcp")
        return MCPServerStore(Path(db_path).with_name("mcp_registry.sqlite3"))

    @staticmethod
    def _binding(context: Any) -> tuple[str, str]:
        context.assert_active()
        owner = str(getattr(context, "owner_identity", ""))
        mission = str(getattr(context, "mission_id", ""))
        MCPServerStore._validate_binding(owner, mission)
        return owner, mission

    @staticmethod
    def _append_evidence(context: Any, *, server: dict[str, Any], operation: str, result_digest: str, arguments_digest: str, payload: dict[str, Any]) -> str:
        now = _utc_now()
        target = str(context.scope_snapshot.get("target_id", ""))
        safe_payload = {
            "claim": "An MCP request completed; remote content is untrusted and any remote side effect is not independently verified.",
            "source": "mcp:streamable_http",
            "evidence": {
                "record_type": "UNTRUSTED_MCP_OBSERVATION",
                "trust": "untrusted_data",
                "authority": "none",
                "server_id": server["server_id"],
                "server_identity_sha256": server.get("identity_sha256", ""),
                "endpoint_sha256": _sha256(server["endpoint"]),
                "protocol_version": server.get("protocol_version", ""),
                "operation": operation,
                "request_arguments_sha256": arguments_digest,
                "response_sha256": result_digest,
                "retrieved_at": now,
                "mission_id": str(context.mission_id),
                "task_id": str(context.execution_fence.task_id),
                "execution_id": str(context.execution_id),
                "tool_id": str(context.tool_id),
                "content": payload,
            },
            "verification": "protocol_integrity_only_untrusted",
            "confidence": 0,
            "timestamp": now,
            "request_id": str(context.request_id),
            "mission_id": str(context.mission_id),
            "task_id": str(context.execution_fence.task_id),
            "chain": (f"mission:{context.mission_id}", f"task:{context.execution_fence.task_id}", f"target:{target}"),
        }
        receipt = context.evidence_store.append(safe_payload, execution_fence=context.execution_fence)
        receipt_hash = str(receipt.get("current_hash", "")) if isinstance(receipt, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{64}", receipt_hash):
            raise MCPClientError("mcp_evidence_receipt_unavailable")
        return _sha256(f"{context.mission_id}\0{context.execution_fence.task_id}\0{receipt_hash}")

    def discover(self, argument: dict[str, Any], *, execution_context: Any) -> dict[str, Any]:
        context = execution_context
        context.assert_active()
        owner, mission = self._binding(context)
        server_id = MCPServerStore._server_id(argument.get("server_id"))
        requested_tool = argument.get("tool_name")
        if requested_tool is not None and (not isinstance(requested_tool, str) or not MCP_TOOL_NAME_RE.fullmatch(requested_tool)):
            raise ValueError("invalid_mcp_tool_name")
        store = self._store(context)
        server = store.get_server(owner_identity_ref=owner, mission_id=mission, server_id=server_id)
        if server["trust_level"] == "BLOCKED":
            raise PermissionError("mcp_server_blocked")
        args_digest = _sha256(_canonical_json({"server_id": server_id, "tool_name": requested_tool}))
        with self.client_factory(server["endpoint"], context) as client:
            identity, tools = client.discover()
            store.record_discovery(
                owner_identity_ref=owner, mission_id=mission, server_id=server_id,
                identity_sha256=identity, protocol_version=MCP_PROTOCOL_VERSION, tools=tools,
            )
            server = store.get_server(owner_identity_ref=owner, mission_id=mission, server_id=server_id)
            safe_tools = store.list_tools(owner_identity_ref=owner, mission_id=mission, server_id=server_id)
            selected = None
            if requested_tool is not None:
                selected = store.get_tool(
                    owner_identity_ref=owner, mission_id=mission, server_id=server_id, tool_name=requested_tool
                )
            safe_catalog = [{"name": item["name"], "schema_sha256": item["schema_sha256"], "approved": item["approved"]} for item in safe_tools]
            ref = self._append_evidence(
                context, server=server, operation="tools/list", result_digest=client.response_transcript_sha256,
                arguments_digest=args_digest, payload={"tool_count": len(safe_tools), "tool_names_and_schema_hashes": [{"name": t["name"], "schema_sha256": t["schema_sha256"]} for t in safe_tools]},
            )
        context.assert_active()
        result = {
            "status": "discovered",
            "trust_level": server["trust_level"],
            "server_id": server_id,
            "identity_sha256": identity,
            "tools": safe_catalog,
            "schema_details_required": True,
            "descriptions_withheld": True,
            "evidence_ref": ref,
        }
        if selected is not None:
            result["tool_schema"] = {
                "name": selected["name"],
                "schema_sha256": selected["schema_sha256"],
                "schema": selected["schema"],
                "approved": selected["approved"],
            }
        return result

    def invoke(self, argument: dict[str, Any], *, execution_context: Any) -> dict[str, Any]:
        context = execution_context
        context.assert_active()
        owner, mission = self._binding(context)
        server_id = MCPServerStore._server_id(argument.get("server_id"))
        tool_name = argument.get("tool_name")
        if not isinstance(tool_name, str) or not MCP_TOOL_NAME_RE.fullmatch(tool_name):
            raise ValueError("invalid_mcp_tool_name")
        supplied_args = argument.get("arguments")
        if not isinstance(supplied_args, dict):
            raise ValueError("mcp_arguments_must_be_object")
        try:
            encoded_args = _canonical_json(supplied_args).encode("utf-8")
        except Exception:
            raise ValueError("mcp_arguments_invalid") from None
        if len(encoded_args) > MCP_MAX_ARGUMENT_BYTES:
            raise ValueError("mcp_arguments_too_large")
        server_store = self._store(context)
        server = server_store.get_server(owner_identity_ref=owner, mission_id=mission, server_id=server_id)
        if server["trust_level"] != "TRUSTED":
            raise PermissionError("trusted_mcp_server_required")
        args_digest = _sha256(_canonical_json({"server_id": server_id, "tool_name": tool_name, "arguments": supplied_args}))
        with self.client_factory(server["endpoint"], context) as client:
            identity, tools = client.discover()
            server_store.record_discovery(
                owner_identity_ref=owner, mission_id=mission, server_id=server_id,
                identity_sha256=identity, protocol_version=MCP_PROTOCOL_VERSION, tools=tools,
            )
            current = server_store.get_tool(owner_identity_ref=owner, mission_id=mission, server_id=server_id, tool_name=tool_name)
            if current["trust_level"] != "TRUSTED" or not current["approved"]:
                raise PermissionError("mcp_tool_revision_not_owner_approved")
            schema = current["schema"].get("input")
            if not isinstance(schema, dict):
                raise MCPProtocolError("stored_mcp_schema_invalid")
            encoded = _canonical_json(supplied_args).encode("utf-8")
            if len(encoded) > MCP_MAX_ARGUMENT_BYTES:
                raise ValueError("mcp_arguments_too_large")
            from tools.registry import _validate_json_value
            if _validate_json_value(supplied_args, schema):
                raise ValueError("mcp_arguments_schema_mismatch")
            result = client.call_tool(tool_name, supplied_args)
            result_text = _canonical_json(result)
            if len(result_text.encode("utf-8")) > MCP_MAX_CONTENT_CHARS + 16_384:
                raise MCPProtocolError("mcp_tool_result_too_large")
            result_digest = _sha256(result_text)
            safe_content = {"tool_name": tool_name, "schema_sha256": current["schema_sha256"], "result": result}
            ref = self._append_evidence(
                context, server=server_store.get_server(owner_identity_ref=owner, mission_id=mission, server_id=server_id),
                operation="tools/call", result_digest=result_digest, arguments_digest=args_digest, payload=safe_content,
            )
        context.assert_active()
        return {
            "status": "remote_tool_error" if result["is_error"] else "completed",
            "success": not result["is_error"],
            "server_id": server_id,
            "tool_name": tool_name,
            "trust": "untrusted_remote_result",
            "result": result,
            "evidence_ref": ref,
        }


_DEFAULT_SERVICE: MCPToolService | None = None
_DEFAULT_LOCK = threading.Lock()


def _service() -> MCPToolService:
    global _DEFAULT_SERVICE
    if _DEFAULT_SERVICE is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_SERVICE is None:
                _DEFAULT_SERVICE = MCPToolService()
    return _DEFAULT_SERVICE


def mcp_discover(argument: dict[str, Any], *, execution_context: Any) -> dict[str, Any]:
    return _service().discover(argument, execution_context=execution_context)


def mcp_invoke(argument: dict[str, Any], *, execution_context: Any) -> dict[str, Any]:
    return _service().invoke(argument, execution_context=execution_context)


__all__ = [
    "MCPClientError", "MCPProtocolError", "MCPTransportError", "MCPRequestTimeout", "MCPRequestCancelled",
    "MCPDiscoveredTool", "MCPServerStore", "MCPRemoteClient", "MCPToolService",
    "MCP_PROTOCOL_VERSION", "MCP_TRUST_LEVELS", "canonical_mcp_endpoint", "mcp_discover", "mcp_invoke",
]
