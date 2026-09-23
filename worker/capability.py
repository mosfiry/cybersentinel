from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class CapabilityStatus(str, Enum):
    """Deterministic capability statuses. UNKNOWN is a first-class state and
    is never treated as AVAILABLE anywhere in this package."""

    AVAILABLE = "AVAILABLE"
    AVAILABLE_WITH_LIMITATIONS = "AVAILABLE_WITH_LIMITATIONS"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class WorkerCapability:
    """One PROVEN capability of an external live worker.

    Attributes:
        name: stable capability identifier (e.g. "http_get").
        status: deterministic audit result — never inferred from code.
        constraints: what the capability CANNOT do (honest limitations).
        provenance: audit reference this status was read from.
        verified: True only if the audit executed the capability live.
        verified_at: ISO-8601 UTC timestamp of the audit execution.
    """

    name: str
    status: CapabilityStatus
    constraints: Mapping[str, Any] = field(default_factory=dict)
    provenance: str = ""
    verified: bool = False
    verified_at: str = ""

    def require_verified(self) -> None:
        """Guard: an unverified capability must never be consumed as fact."""
        if self.status is CapabilityStatus.AVAILABLE and not self.verified:
            raise ValueError("unverified capability must not be marked AVAILABLE: " + self.name)


@dataclass(frozen=True)
class WorkerCapabilitySet:
    """Immutable set of capabilities for one worker identity."""

    worker_id: str
    capabilities: Mapping[str, WorkerCapability]

    def get(self, name: str) -> WorkerCapability | None:
        return self.capabilities.get(name)

    def status_of(self, name: str) -> CapabilityStatus:
        cap = self.capabilities.get(name)
        return cap.status if cap else CapabilityStatus.UNKNOWN

    def all_verified(self) -> bool:
        for cap in self.capabilities.values():
            cap.require_verified()
        return True


_AUDIT = "vibe_live_capability_audit"
_AUDIT_AT = "2026-09-23T21:47:54Z"
_HTTP_GET_CONSTRAINTS = {
    "methods": ["GET"],
    "custom_headers": False,
    "custom_user_agent": False,
    "authorization_header_control": False,
    "cookie_control": False,
    "if_headers": False,
    "response_headers": False,
    "redirect_control": False,
    "timeout_control": False,
    "tls_certificate_info": False,
    "proxy": False,
    "transport": "connector_mediated_get_only",
}

# Only PROVEN capabilities from the live audit are recorded here.
# UNKNOWN entries stay UNKNOWN; nothing is promoted.
VIBE_CAPABILITY_SET = WorkerCapabilitySet(
    worker_id="vibe-live-worker",
    capabilities={
        # --- AVAILABLE (executed live during the audit) ---
        "filesystem": WorkerCapability("filesystem", CapabilityStatus.AVAILABLE, {"scope": "sandbox workspace", "hash_tools": ["md5"]}, _AUDIT, True, _AUDIT_AT),
        "bash": WorkerCapability("bash", CapabilityStatus.AVAILABLE, {"max_command_seconds": 300, "text_utilities_only": True}, _AUDIT, True, _AUDIT_AT),
        "posix_text_utilities": WorkerCapability("posix_text_utilities", CapabilityStatus.AVAILABLE, {"missing": ["sleep", "ps", "timeout", "nohup"]}, _AUDIT, True, _AUDIT_AT),
        "https_get": WorkerCapability("https_get", CapabilityStatus.AVAILABLE, dict(_HTTP_GET_CONSTRAINTS), _AUDIT, True, _AUDIT_AT),
        "response_body": WorkerCapability("response_body", CapabilityStatus.AVAILABLE, {"raw_headers_included": False}, _AUDIT, True, _AUDIT_AT),
        "body_length": WorkerCapability("body_length", CapabilityStatus.AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "body_comparison": WorkerCapability("body_comparison", CapabilityStatus.AVAILABLE, {"supports_byte_identical_check": True}, _AUDIT, True, _AUDIT_AT),
        "request_timing": WorkerCapability("request_timing", CapabilityStatus.AVAILABLE, {"clock": "sandbox monotonic wall clock"}, _AUDIT, True, _AUDIT_AT),
        "body_md5": WorkerCapability("body_md5", CapabilityStatus.AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "parallel_get_requests": WorkerCapability("parallel_get_requests", CapabilityStatus.AVAILABLE, {"mechanism": "connector Promise.allSettled", "observed_concurrency": 3}, _AUDIT, True, _AUDIT_AT),
        "github_read": WorkerCapability("github_read", CapabilityStatus.AVAILABLE, {"via": "github_app connector", "path_ref_support": True, "blob_sha_support": True}, _AUDIT, True, _AUDIT_AT),
        "github_push": WorkerCapability("github_push", CapabilityStatus.AVAILABLE, {"via": "github_app.push_files", "multi_file_commit": True}, _AUDIT, True, _AUDIT_AT),
        "github_commit_inspection": WorkerCapability("github_commit_inspection", CapabilityStatus.AVAILABLE, {"via": "github_app.list_commits"}, _AUDIT, True, _AUDIT_AT),
        "json_evidence_generation": WorkerCapability("json_evidence_generation", CapabilityStatus.AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        # --- AVAILABLE_WITH_LIMITATIONS ---
        "internet": WorkerCapability("internet", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"outbound": "connector-mediated GET only", "raw_sockets": False, "direct_dns": False}, _AUDIT, True, _AUDIT_AT),
        "terminal": WorkerCapability("terminal", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"no_package_install": True, "no_background_processes": True, "no_root": True}, _AUDIT, True, _AUDIT_AT),
        "cyber_reconnaissance": WorkerCapability("cyber_reconnaissance", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"passive_get_based_only": True, "no_browser": True, "no_raw_response_headers": True}, _AUDIT, True, _AUDIT_AT),
        "evidence_capture": WorkerCapability("evidence_capture", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"captures_body_hash_length_timing": True, "captures_raw_headers": False}, _AUDIT, True, _AUDIT_AT),
        "github_operations": WorkerCapability("github_operations", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"git_cli": False, "connector_api_only": True}, _AUDIT, True, _AUDIT_AT),
        "parallelism": WorkerCapability("parallelism", CapabilityStatus.AVAILABLE_WITH_LIMITATIONS, {"max_concurrency": "UNKNOWN"}, _AUDIT, True, _AUDIT_AT),
        # --- NOT_AVAILABLE (proven absent in the audit) ---
        "http_post": WorkerCapability("http_post", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "http_put": WorkerCapability("http_put", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "http_patch": WorkerCapability("http_patch", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "http_delete": WorkerCapability("http_delete", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "http_head": WorkerCapability("http_head", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "http_options": WorkerCapability("http_options", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "custom_request_headers": WorkerCapability("custom_request_headers", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "custom_user_agent": WorkerCapability("custom_user_agent", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "authorization_header_control": WorkerCapability("authorization_header_control", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "cookie_control": WorkerCapability("cookie_control", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "if_headers": WorkerCapability("if_headers", CapabilityStatus.NOT_AVAILABLE, {"if_none_match": False, "if_modified_since": False}, _AUDIT, True, _AUDIT_AT),
        "response_headers": WorkerCapability("response_headers", CapabilityStatus.NOT_AVAILABLE, {"reason": "connector returns body only; Age/ETag/Vary/CF-Cache-Status unreachable"}, _AUDIT, True, _AUDIT_AT),
        "cache_control_observation": WorkerCapability("cache_control_observation", CapabilityStatus.NOT_AVAILABLE, {"depends_on": "response_headers"}, _AUDIT, True, _AUDIT_AT),
        "raw_sockets": WorkerCapability("raw_sockets", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "direct_dns": WorkerCapability("direct_dns", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "browser": WorkerCapability("browser", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "playwright": WorkerCapability("playwright", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "puppeteer": WorkerCapability("puppeteer", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "selenium": WorkerCapability("selenium", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "javascript_browser_execution": WorkerCapability("javascript_browser_execution", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "dom_inspection": WorkerCapability("dom_inspection", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "screenshots": WorkerCapability("screenshots", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "devtools_protocol": WorkerCapability("devtools_protocol", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "har_capture": WorkerCapability("har_capture", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "curl": WorkerCapability("curl", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "wget": WorkerCapability("wget", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "python_runtime": WorkerCapability("python_runtime", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "node_runtime": WorkerCapability("node_runtime", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "git_cli": WorkerCapability("git_cli", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "docker": WorkerCapability("docker", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "openssl_cli": WorkerCapability("openssl_cli", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "background_processes": WorkerCapability("background_processes", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "long_running_worker": WorkerCapability("long_running_worker", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "inbound_rest_server": WorkerCapability("inbound_rest_server", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "websocket": WorkerCapability("websocket", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "mcp_network_server": WorkerCapability("mcp_network_server", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "external_ipc": WorkerCapability("external_ipc", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "package_installation": WorkerCapability("package_installation", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "root": WorkerCapability("root", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        "privileged_commands": WorkerCapability("privileged_commands", CapabilityStatus.NOT_AVAILABLE, {}, _AUDIT, True, _AUDIT_AT),
        # --- UNKNOWN / NOT VERIFIED (never promoted) ---
        "scheduled_tasks_execution": WorkerCapability("scheduled_tasks_execution", CapabilityStatus.UNKNOWN, {}, _AUDIT, False, _AUDIT_AT),
        "exact_rate_limits": WorkerCapability("exact_rate_limits", CapabilityStatus.UNKNOWN, {}, _AUDIT, False, _AUDIT_AT),
        "sha256_sandbox": WorkerCapability("sha256_sandbox", CapabilityStatus.UNKNOWN, {}, _AUDIT, False, _AUDIT_AT),
        "max_connector_concurrency": WorkerCapability("max_connector_concurrency", CapabilityStatus.UNKNOWN, {}, _AUDIT, False, _AUDIT_AT),
        "max_session_duration": WorkerCapability("max_session_duration", CapabilityStatus.UNKNOWN, {}, _AUDIT, False, _AUDIT_AT),
    },
)
