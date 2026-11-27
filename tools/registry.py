from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import os
import re
import sys

MAX_ARG_LENGTH = 256
VALID_RISK_CLASSES = frozenset({"read", "network-read", "state-write", "bounded-exec", "analysis"})
DEFAULT_TOOL_TIMEOUT = 30
TOOL_TIMEOUTS = {"run_project_tests": 65, "refresh_intel": 30}


class ToolTimeout(TimeoutError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk_class: str
    requires_owner: bool
    argument_type: type | None
    handler: Callable[[str | None], Any]
    owner_only: bool = False
    scope_required: bool = False
    version: str = "1.0.0"
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    network_access: str = "none"
    filesystem_access: str = "none"
    process_access: str = "none"
    credential_access: str = "none"
    scope_requirements: tuple[str, ...] = ()
    timeout: int = DEFAULT_TOOL_TIMEOUT
    rate_limit: str = "bounded"
    evidence_requirements: tuple[str, ...] = ("authorization_decision", "observation")

    @property
    def tool_id(self) -> str:
        return self.name

    @property
    def required_authorization(self) -> str:
        if self.scope_required:
            return "owner_and_scope_snapshot"
        return "owner" if self.requires_owner else "none"

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "version": self.version,
            "description": self.description,
            "input_schema": self.input_schema or {"type": "string" if self.argument_type is str else "null"},
            "output_schema": self.output_schema or {"type": "object"},
            "risk_class": self.risk_class,
            "required_authorization": self.required_authorization,
            "network_access": self.network_access,
            "filesystem_access": self.filesystem_access,
            "process_access": self.process_access,
            "credential_access": self.credential_access,
            "scope_requirements": list(self.scope_requirements),
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "evidence_requirements": list(self.evidence_requirements),
        }

    def validate(self, argument: Any) -> tuple[bool, str]:
        if self.argument_type is None:
            if argument is not None:
                return False, f"{self.name} does not accept an argument"
            return True, "valid"
        if not isinstance(argument, self.argument_type):
            return False, f"{self.name} requires a string argument"
        if not argument.strip():
            return False, f"{self.name} requires a non-empty string argument"
        if len(argument.strip()) > MAX_ARG_LENGTH:
            return False, "tool argument exceeds maximum length"
        return True, "valid"


def _status(_):
    from core.engine import status
    return status()


def _latest_intel(_):
    from core.intel import latest_intel
    return latest_intel(50)


def _refresh_intel(_):
    from core.intel import refresh_all
    return refresh_all()


def _local_security(_):
    from core.local_defense import local_security_check
    return local_security_check()


def _system_info(_):
    from core.local_defense import local_system_info
    return local_system_info()

def _process_info(_):
    from core.local_defense import local_process_info
    return local_process_info()


def _search(argument):
    from search.service import search_service
    from search.providers import SearchScope
    from search.exceptions import SearchError, ProviderUnavailableError

    query = argument or ""
    scope = None  # Auto-select based on query

    # Parse scope from argument if present
    # Format: "scope:github query" or "scope:nvd CVE-2021-1234"
    if ":" in query:
        parts = query.split(":", 1)
        scope_str = parts[0].lower()
        query = parts[1].strip()

        # Map scope string to SearchScope
        scope_map = {
            "local": SearchScope.LOCAL,
            "github": SearchScope.GITHUB,
            "nvd": SearchScope.NVD,
            "cve": SearchScope.CVE,
            "mitre": SearchScope.MITRE,
            "web": SearchScope.WEB,
        }
        scope = scope_map.get(scope_str)

    try:
        response = search_service.search(
            query=query,
            scope=scope,
            max_results=50,
        )

        # Format results for backward compatibility
        results = {
            "query": query,
            "scope": scope.value if scope else None,
            "total_results": response.total_results,
            "results": [
                {
                    "id": r.result_id,
                    "title": r.title,
                    "content": r.content,
                    "source": r.source,
                    "source_type": r.source_type,
                    "url": r.url,
                    "provenance": r.provenance,
                    "metadata": r.metadata,
                }
                for r in response.results
            ],
        }

        if response.error:
            results["error"] = response.error
        if response.error_type:
            results["error_type"] = response.error_type

        return results
    except ProviderUnavailableError as e:
        return {"error": str(e), "error_type": "provider_unavailable", "query": query}
    except SearchError as e:
        return {"error": str(e), "error_type": e.error_type, "query": query}
    except Exception as e:
        return {"error": str(e), "error_type": "unknown", "query": query}


def _watch(argument):
    from core.db import add_watch, watches
    add_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


def _unwatch(argument):
    from core.db import remove_watch, watches
    remove_watch(argument or "")
    return {"keyword": argument, "watches": watches()}


def _run_project_tests(argument, *, workspace=None):
    if workspace is None:
        raise PermissionError("run_project_tests requires governed Workspace")
    target = argument or "."
    try:
        if not workspace.resolve(target).is_dir():
            raise ValueError("project directory does not exist")
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("project directory is outside the configured test root") from exc
    result = workspace.develop((sys.executable, "-m", "pytest", "-q"), cwd=target, timeout=60)
    return {"ok": result.ok, "timed_out": result.timed_out, "returncode": result.exit_code, "output": (result.stdout + result.stderr)[-4000:]}


def _red_team_assess(argument):
    from reasoning.red_team import assess
    return assess(argument).to_dict()


def _scoped_http_probe(argument):
    """Real bounded HTTP observation behind the Scope Firewall and proof chain.

    The registry invokes this handler ONLY after: the ScopeGuard canonicalized
    the target against the typed ScopeSnapshot, the typed Owner
    AuthorizationDecision matched tool + argument fingerprint + request
    identity, the ExecutionAuthorizationProof verified, and the scope
    resolver re-resolved the request against the persisted typed snapshot.
    This handler then performs exactly ONE bounded observation:

    - ONE GET; redirects are NEVER followed (a redirect Location is recorded
      as OBSERVED data only — observation never widens scope)
    - hard timeout and hard response-size cap
    - deterministic fail-closed classification of network failures
    - the body is never returned, only its size and sha256
    """
    url = argument if isinstance(argument, str) else ""
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "operation": "scoped_http_probe", "error": "PROBE_ARGUMENT_INVALID", "reason": "the probe accepts exactly one canonical http(s) url"}
    return _probe_http_observation(url)


SCOPED_PROBE_TIMEOUT_SECONDS = 10
SCOPED_PROBE_MAX_BYTES = 65536


def _probe_fetch(request, timeout):
    """The single network seam of the probe: no shell, no sockets elsewhere."""
    import urllib.request

    class _NeverRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # redirects are observed, never followed

    return urllib.request.build_opener(_NeverRedirect).open(request, timeout=timeout)


def _probe_http_observation(url, *, timeout=SCOPED_PROBE_TIMEOUT_SECONDS, max_bytes=SCOPED_PROBE_MAX_BYTES):
    import hashlib
    import time
    from urllib.error import URLError
    from urllib.request import Request

    started = time.monotonic()
    try:
        request = Request(url, method="GET", headers={"User-Agent": "CyberSentinel-X-ScopedProbe/1.0", "Accept": "*/*"})
        response = _probe_fetch(request, timeout)
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "operation": "scoped_http_probe", "url": url, "error": "PROBE_FAILED", "reason": str(exc), "elapsed_ms": int((time.monotonic() - started) * 1000)}
    try:
        body = response.read(max_bytes + 1)
    except (TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "operation": "scoped_http_probe", "url": url, "error": "PROBE_READ_FAILED", "reason": str(exc), "elapsed_ms": int((time.monotonic() - started) * 1000)}
    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]
    status_code = int(getattr(response, "status", 0) or 0)
    headers: dict[str, str] = {}
    for key in ("server", "content-type", "content-length", "location"):
        try:
            value = response.headers.get(key) if response.headers is not None else None
        except Exception:
            value = None
        if value:
            headers[key] = str(value)[:512]
    return {
        "ok": True,
        "operation": "scoped_http_probe",
        "url": url,
        "status_code": status_code,
        "headers": headers,
        "body_size": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "truncated": truncated,
        "redirect_location": headers.get("location", ""),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def _scoped_dns_lookup(argument):
    """Real bounded DNS observation behind the Scope Firewall and proof chain.

    The registry invokes this handler ONLY after the same gate sequence as
    scoped_http_probe: the typed Owner AuthorizationDecision matched tool +
    argument fingerprint + request identity, the ExecutionAuthorizationProof
    verified, and the scope resolver re-resolved the request against the
    persisted typed snapshot. The executed argument is the ScopeGuard's
    CANONICAL url: this handler extracts the host from that url and resolves
    exactly that host — one name, one bounded lookup. Resolved addresses are
    OBSERVED data only; they can never widen scope (INV-OFF-2).
    """
    url = argument if isinstance(argument, str) else ""
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "operation": "scoped_dns_lookup", "error": "DNS_ARGUMENT_INVALID", "reason": "the dns observation accepts exactly one canonical http(s) url"}
    return _dns_observation(url)


SCOPED_DNS_TIMEOUT_SECONDS = 10  # the bound is enforced by the registry executor (spec timeout)
SCOPED_DNS_MAX_RECORDS = 32


def _dns_resolve(host):
    """The single DNS seam of the observation: no shell, no other resolver surface."""
    import socket

    return socket.getaddrinfo(host, None)


def _dns_observation(url, *, max_records=SCOPED_DNS_MAX_RECORDS):
    import socket
    import time
    from urllib.parse import urlsplit

    started = time.monotonic()
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    if not host:
        return {"ok": False, "operation": "scoped_dns_lookup", "url": url, "error": "DNS_ARGUMENT_INVALID", "reason": "the url carries no resolvable host", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    try:
        entries = _dns_resolve(host)
    except (socket.gaierror, OSError, UnicodeError, ValueError) as exc:
        return {"ok": False, "operation": "scoped_dns_lookup", "url": url, "host": host, "error": "DNS_FAILED", "reason": str(exc), "elapsed_ms": int((time.monotonic() - started) * 1000)}
    records: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries or []:
        family = entry[0]
        address = str(entry[4][0]) if len(entry) > 4 and entry[4] else ""
        family_name = "AF_INET" if family == socket.AF_INET else ("AF_INET6" if family == socket.AF_INET6 else "OTHER")
        if not address or (family_name, address) in seen:
            continue
        seen.add((family_name, address))
        records.append({"family": family_name, "address": address})
    records.sort(key=lambda record: (record["family"], record["address"]))
    truncated = len(records) > max_records
    if truncated:
        records = records[:max_records]
    return {
        "ok": True,
        "operation": "scoped_dns_lookup",
        "url": url,
        "host": host,
        "records": records,
        "record_count": len(records),
        "truncated": truncated,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def _scoped_tls_observation(argument):
    """Real bounded TLS observation behind the Scope Firewall and proof chain.

    The registry invokes this handler ONLY after the same gate sequence as
    the scoped probe and dns tools. The executed argument is the ScopeGuard's
    CANONICAL url: this handler derives the host and port from that url and
    nothing else. SNI is NOT an input — it is ALWAYS the canonical host, so a
    caller can never point the observation at a different virtual host.

    Verification semantics are FIXED and documented: the handshake runs
    under ssl.create_default_context() (CERT_REQUIRED, check_hostname=True).
    Handshake success and certificate validity are classified SEPARATELY:
    a successful-but-untrusted chain is TLS_CERTIFICATE_INVALID, never
    success. Certificate data (CN, SAN, issuer) is OBSERVED data only — it
    can never widen scope (INV-OFF-2).
    """
    url = argument if isinstance(argument, str) else ""
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "operation": "scoped_tls_observation", "error": "TLS_ARGUMENT_INVALID", "reason": "the tls observation accepts exactly one canonical http(s) url"}
    return _tls_observation(url)


SCOPED_TLS_TIMEOUT_SECONDS = 10  # enforced by the registry executor (spec/adapter timeout)
SCOPED_TLS_MAX_SANS = 32
SCOPED_TLS_FIELD_MAX = 512


def _tls_connect(host, port, timeout):
    """The single network/TLS seam: connect + verifying handshake. No shell.

    Verification is ON by construction (default context); it is never relaxed
    to make an observation succeed.
    """
    import socket
    import ssl

    context = ssl.create_default_context()
    raw = socket.create_connection((host, port), timeout=timeout)
    return context.wrap_socket(raw, server_hostname=host)  # SNI == the canonical host, always


def _tls_cert_fields(cert):
    """Deterministic public certificate metadata extraction (no key material)."""
    subject = ""
    for rdn in cert.get("subject", ()) or ():
        for key, value in rdn:
            if key == "commonName" and not subject:
                subject = str(value)[:512]
    issuer = ""
    for rdn in cert.get("issuer", ()) or ():
        for key, value in rdn:
            if key == "commonName" and not issuer:
                issuer = str(value)[:512]
    serial = str(cert.get("serialNumber") or "")[:128]
    not_before = str(cert.get("notBefore") or "")[:64]
    not_after = str(cert.get("notAfter") or "")[:64]
    sans = sorted({"{}:{}".format(str(key), str(value)[:SCOPED_TLS_FIELD_MAX]) for key, value in (cert.get("subjectAltName") or ())})
    return subject, issuer, serial, not_before, not_after, sans


def _tls_observation(url, *, timeout=SCOPED_TLS_TIMEOUT_SECONDS, max_sans=SCOPED_TLS_MAX_SANS):
    import hashlib
    import socket
    import ssl
    import time
    from datetime import datetime, timezone
    from urllib.parse import urlsplit

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    try:
        parts = urlsplit(url)
        host = str(parts.hostname or "")
        port = parts.port
    except ValueError:
        host, port = "", None
    if not host:
        return {"ok": False, "operation": "scoped_tls_observation", "url": url, "error": "TLS_ARGUMENT_INVALID", "reason": "the url carries no observable host", "elapsed_ms": elapsed()}
    if port is None:
        port = 443  # the default TLS port; an explicit canonical port is kept as-is
    common = {"operation": "scoped_tls_observation", "url": url, "host": host, "port": port}
    try:
        sock = _tls_connect(host, port, timeout)
    except ssl.SSLCertVerificationError as exc:
        # The handshake completed far enough to reject the chain: this is a
        # VERIFICATION classification, never a success.
        return dict(common, ok=False, error="TLS_CERTIFICATE_INVALID", connection_success=False, verification_result="TLS_CERTIFICATE_INVALID", verification_error=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except ssl.SSLError as exc:
        return dict(common, ok=False, error="TLS_HANDSHAKE_FAILED", connection_success=False, verification_result="TLS_CERTIFICATE_UNAVAILABLE", verification_error=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except TimeoutError as exc:
        return dict(common, ok=False, error="TLS_TIMEOUT", connection_success=False, verification_result="TLS_CERTIFICATE_UNAVAILABLE", verification_error=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except (socket.gaierror, ConnectionError, OSError, ValueError) as exc:
        return dict(common, ok=False, error="TLS_CONNECTION_FAILED", connection_success=False, verification_result="TLS_CERTIFICATE_UNAVAILABLE", verification_error=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        version = str(sock.version() or "")
        cipher = sock.cipher()
        cipher_name = str(cipher[0]) if cipher else ""
        try:
            peer = sock.getpeername()
            resolved_endpoint = str(peer) if peer else None
        except Exception:
            resolved_endpoint = None
        try:
            der = sock.getpeercert(binary_form=True)
        except Exception:
            der = None
        try:
            cert = sock.getpeercert() or {}
        except Exception:
            cert = {}
    except Exception as exc:
        return dict(common, ok=False, error="TLS_RUNTIME_ERROR", connection_success=True, verification_result="TLS_CERTIFICATE_UNAVAILABLE", verification_error=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    finally:
        try:
            sock.close()
        except Exception:
            pass
    fingerprint = hashlib.sha256(der).hexdigest() if der else ""
    subject, issuer, serial, not_before, not_after, sans = _tls_cert_fields(cert)
    truncated = len(sans) > max_sans
    if truncated:
        sans = sans[:max_sans]
    return {
        "ok": True,
        **common,
        "connection_success": True,
        "tls_version": version,  # the ACTUALLY negotiated protocol, never inferred
        "cipher": cipher_name,  # the ACTUALLY negotiated cipher, never inferred
        "certificate_subject": subject or None,
        "certificate_issuer": issuer or None,
        "certificate_serial": serial or None,
        "certificate_not_before": not_before or None,
        "certificate_not_after": not_after or None,
        "certificate_fingerprint": fingerprint or None,
        "fingerprint_algorithm": "SHA-256" if fingerprint else None,
        "subject_alt_names": sans,
        "sans_truncated": truncated,
        "verification_result": "TLS_CERTIFICATE_VALID",
        "verification_error": None,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "resolved_endpoint": resolved_endpoint,
        "elapsed_ms": elapsed(),
    }


def _scoped_port_observation(argument):
    """Real bounded port & service observation behind the Scope Firewall and
    proof chain (P1-D).

    The registry invokes this handler ONLY after the same gate sequence as
    the probe/dns/tls tools: typed Owner AuthorizationDecision matched to
    tool + argument fingerprint + request identity, ExecutionAuthorizationProof
    verified, and the scope resolver re-resolved the request (including the
    explicit canonical port) against the persisted typed snapshot. The
    executed argument is the ScopeGuard's CANONICAL url: the observed host
    and port are derived from that url and NOTHING else, so a caller can
    never point the observation at a different host or port. This performs
    exactly ONE plain TCP connect and ONE passive banner read — NO payload
    is ever written to the wire. Banner bytes are OBSERVED data only; they
    can never widen scope (INV-OFF-2).
    """
    url = argument if isinstance(argument, str) else ""
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "operation": "scoped_port_observation", "error": "PORT_ARGUMENT_INVALID", "reason": "the port observation accepts exactly one canonical http(s) url"}
    return _port_observation(url)


SCOPED_PORT_TIMEOUT_SECONDS = 10  # enforced by the registry executor (spec/adapter timeout)
SCOPED_PORT_BANNER_MAX_BYTES = 128


def _port_observe(host, port, timeout):
    """The single network/port seam: one TCP connect + one passive read.

    Returns the banner bytes read from the socket (possibly empty: many
    services stay silent until spoken to — silence is data, not failure).
    No shell, no other socket surface, nothing sent.
    """
    import socket

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        try:
            sock.settimeout(min(float(timeout), 2.0))
            banner = sock.recv(SCOPED_PORT_BANNER_MAX_BYTES)
        except socket.timeout:
            banner = b""
        except OSError:
            banner = b""
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return banner


def _port_observation(url, *, timeout=SCOPED_PORT_TIMEOUT_SECONDS, max_banner=SCOPED_PORT_BANNER_MAX_BYTES):
    import hashlib
    import socket
    import time
    from datetime import datetime, timezone
    from urllib.parse import urlsplit

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    try:
        parts = urlsplit(url)
        host = str(parts.hostname or "")
        port = parts.port
        scheme = str(parts.scheme or "")
    except ValueError:
        host, port, scheme = "", None, ""
    if not host:
        return {"ok": False, "operation": "scoped_port_observation", "url": url, "error": "PORT_ARGUMENT_INVALID", "reason": "the url carries no observable host", "elapsed_ms": elapsed()}
    if port is None:
        # the scheme-default port; an explicit canonical port is kept as-is
        port = 443 if scheme == "https" else 80
    common = {"operation": "scoped_port_observation", "url": url, "host": host, "port": port}
    try:
        banner = _port_observe(host, port, timeout)
    except TimeoutError as exc:
        return dict(common, ok=False, error="PORT_TIMEOUT", connect_success=False, reason=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except (socket.gaierror, ConnectionError, OSError, ValueError) as exc:
        return dict(common, ok=False, error="PORT_CONNECT_FAILED", connect_success=False, reason=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except Exception as exc:
        return dict(common, ok=False, error="PORT_RUNTIME_ERROR", connect_success=False, reason=str(exc)[:SCOPED_TLS_FIELD_MAX], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    banner = bytes(banner)
    truncated = len(banner) > max_banner
    if truncated:
        banner = banner[:max_banner]
    printable = "".join(chr(b) for b in banner if 32 <= b < 127)
    return {
        "ok": True,
        **common,
        "connect_success": True,
        "sends_payload": False,  # the observation never writes to the wire
        "banner_sha256": hashlib.sha256(banner).hexdigest() if banner else None,
        "banner_printable": printable if (printable or banner) else None,
        "banner_truncated": truncated,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }


def _scoped_tech_fingerprint(argument):
    """Real bounded technology fingerprinting behind the Scope Firewall and
    proof chain (P1-E).

    The registry invokes this handler ONLY after the same gate sequence as
    the probe/dns/tls/port tools: typed Owner AuthorizationDecision matched
    to tool + argument fingerprint + request identity, ExecutionAuthorizationProof
    verified, and the scope resolver re-resolved the request against the
    persisted typed snapshot. The executed argument is the ScopeGuard's
    CANONICAL url.

    The fingerprint is CLASSIFICATION OF ALREADY-OBSERVED DATA, never active
    probing:

    - ONE GET; redirects are NEVER followed (a redirect Location is OBSERVED
      data only — observation never widens scope)
    - hard timeout and hard read cap (the body prefix is hashed, size-capped,
      and never returned verbatim)
    - every signal is derived ONLY from what the target itself declares in
      the observed response (response headers + deterministic code-defined
      body markers); everything else is UNKNOWN, never guessed
    - every signal is OBSERVED data: UNTRUSTED classification with zero
      authority — evidence/provenance only, never scope, authorization, or
      plan input (INV-OFF-1/2, MODEL_OUTPUT/EXTERNAL_DATA stay
      non-authoritative)
    - the single network seam is _fingerprint_fetch; no other socket
      surface, no shell, nothing written to the wire beyond the GET itself
    """
    url = argument if isinstance(argument, str) else ""
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "operation": "scoped_tech_fingerprint", "error": "FP_ARGUMENT_INVALID", "reason": "the technology fingerprint accepts exactly one canonical http(s) url"}
    from datetime import datetime, timezone
    import time
    started = time.monotonic()
    try:
        return _tech_fingerprint(url)
    except Exception as exc:
        # Deterministic fail-closed classification (parity with the port
        # family): an unexpected handler error is a classified observation
        # failure, NEVER a crash out of the registry or a partial result.
        return {"ok": False, "operation": "scoped_tech_fingerprint", "url": url, "error": "FP_RUNTIME_ERROR", "reason": str(exc)[:SCOPED_FP_FIELD_MAX], "observed_at": datetime.now(timezone.utc).isoformat(), "elapsed_ms": int((time.monotonic() - started) * 1000)}


SCOPED_FP_TIMEOUT_SECONDS = 10  # enforced by the registry executor (spec/adapter timeout)
SCOPED_FP_MAX_BYTES = 32768
SCOPED_FP_MAX_SIGNALS = 32
SCOPED_FP_FIELD_MAX = 256

# Code-defined, deterministic, lowercase body markers. Classification only:
# a marker match is an observed-signal fact about the response bytes, never
# an authority claim about the target.
_TECHNOLOGY_BODY_MARKERS = (
    ("angular", "ng-version"),
    ("django", "csrfmiddlewaretoken"),
    ("drupal", "drupal"),
    ("joomla", "/media/jui/"),
    ("jquery", "jquery"),
    ("laravel", "laravel_session"),
    ("nextjs", "_next/static"),
    ("nuxt", "__nuxt"),
    ("react", "data-reactroot"),
    ("svelte", "svelte-"),
    ("vue", "data-v-app"),
    ("wordpress", "wp-content/"),
)

# Header-name -> signal family (values are recorded as observed, truncated).
_TECHNOLOGY_HEADERS = (
    ("server", "web_server"),
    ("x-powered-by", "powered_by"),
    ("x-generator", "generator"),
    ("x-aspnet-version", "aspnet"),
    ("via", "proxy_via"),
)


def _fingerprint_fetch(request, timeout):
    """The single network seam of the fingerprint observation: no shell, no
    sockets elsewhere. Redirects are observed, never followed."""
    import urllib.request

    class _NeverRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # redirects are observed, never followed

    return urllib.request.build_opener(_NeverRedirect).open(request, timeout=timeout)


def _tech_fingerprint(url, *, timeout=SCOPED_FP_TIMEOUT_SECONDS, max_bytes=SCOPED_FP_MAX_BYTES, max_signals=SCOPED_FP_MAX_SIGNALS):
    import hashlib
    import time
    from datetime import datetime, timezone
    from urllib.error import URLError
    from urllib.request import Request

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    try:
        request = Request(url, method="GET", headers={"User-Agent": "CyberSentinel-X-ScopedFingerprint/1.0", "Accept": "*/*"})
        response = _fingerprint_fetch(request, timeout)
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "operation": "scoped_tech_fingerprint", "url": url, "error": "FP_FAILED", "reason": str(exc)[:SCOPED_FP_FIELD_MAX], "observed_at": datetime.now(timezone.utc).isoformat(), "elapsed_ms": elapsed()}
    try:
        body = response.read(max_bytes + 1)
    except (TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "operation": "scoped_tech_fingerprint", "url": url, "error": "FP_READ_FAILED", "reason": str(exc)[:SCOPED_FP_FIELD_MAX], "observed_at": datetime.now(timezone.utc).isoformat(), "elapsed_ms": elapsed()}
    try:
        status_code = int(getattr(response, "status", 0) or 0)
        header_values: dict[str, str] = {}
        for key, _family in _TECHNOLOGY_HEADERS:
            try:
                value = response.headers.get(key) if response.headers is not None else None
            except Exception:
                value = None
            if value:
                header_values[key] = str(value)[:SCOPED_FP_FIELD_MAX]
    except Exception as exc:
        return {"ok": False, "operation": "scoped_tech_fingerprint", "url": url, "error": "FP_RUNTIME_ERROR", "reason": str(exc)[:SCOPED_FP_FIELD_MAX], "observed_at": datetime.now(timezone.utc).isoformat(), "elapsed_ms": elapsed()}
    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]
    observed_text = body.decode("latin-1", errors="replace").lower()
    signals: list[dict[str, str]] = []
    for key, family in _TECHNOLOGY_HEADERS:
        if key in header_values:
            signals.append({"family": family, "source": "header", "detail": header_values[key]})
    for family, needle in _TECHNOLOGY_BODY_MARKERS:
        if needle in observed_text:
            signals.append({"family": family, "source": "body_marker", "detail": needle})
    signals.sort(key=lambda s: (s["family"], s["source"], s["detail"]))
    signals_truncated = len(signals) > max_signals
    if signals_truncated:
        signals = signals[:max_signals]
    return {
        "ok": True,
        "operation": "scoped_tech_fingerprint",
        "url": url,
        "status_code": status_code,
        "sends_payload": False,  # the GET itself is the only wire traffic
        "signal_count": len(signals),
        "signals": signals,  # OBSERVED classification only — zero authority
        "signals_truncated": signals_truncated,
        "header_evidence": header_values or None,
        "body_size": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_truncated": truncated,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }



def _artifact_root():
    """The single root seam: the artifact store is a code-defined directory
    derived from the local database path — never from tool output, model
    output, or an untrusted argument."""
    from core.config import DB_PATH
    return Path(DB_PATH).expanduser().parent / "artifacts"


def _artifact_stat(path):
    """The single stat seam: FULL stat of the artifact path. The size is the
    observed size; st_dev/st_ino are the identity source for the post-open
    binding. A faked plain-int size (legacy test shape) simply carries no
    identity and skips the binding — production always carries it."""
    import os
    return os.stat(str(path))


def _artifact_open(path):
    """The single read seam: read-only, binary, capped by the caller."""
    return open(str(path), "rb")


def _artifact_fstat(handle):
    """The single identity seam: stat the OPEN file descriptor (never the
    path). Used to bind the bytes actually about to be read to the inode that
    was observed at the pre-open stat, closing the stat->open TOCTOU /
    symlink-swap window (fail closed on any mismatch)."""
    import os
    return os.fstat(handle.fileno())


def _artifact_identity_error(stat_before, handle, field_max: int = 256):
    """THE single post-open identity binding shared by every artifact-store
    analysis handler (P1-F/G/H/I convergence; session 51).

    Returns None when the OPEN descriptor is the exact regular-file inode
    observed at the pre-open stat; otherwise returns the fail-closed reason
    string (data only - the caller maps it to its own *_OPEN_FAILED
    classification). Raises nothing by contract: an identity-seam OSError is
    converted INTO a reason string, so a broken binding can never degrade
    into a permissive read. The binding engages only when the pre-open stat
    carries real identity metadata (production os.stat always does; the
    legacy plain-int test-fake shape carries none and skips the binding).
    """
    if not hasattr(stat_before, "st_ino"):
        return None
    try:
        stat_open = _artifact_fstat(handle)
    except OSError as exc:
        return "the opened artifact could not be identity-verified: " + str(exc)[:max(0, int(field_max) - 46)]
    import stat as _stat_mod
    if not _stat_mod.S_ISREG(stat_open.st_mode):
        return "the opened artifact is no longer a regular file (fail closed)"
    if (stat_open.st_dev, stat_open.st_ino) != (stat_before.st_dev, stat_before.st_ino):
        return "artifact identity changed between stat and open (fail closed)"
    return None

FORMAT_MAGIC_TABLE = (
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("mach_o_universal", b"\xca\xfe\xba\xbe"),
    ("mach_o_64", bytes([0xCF, 0xFA, 0xED, 0xFE])),
    ("mach_o_32", bytes([0xCE, 0xFA, 0xED, 0xFE])),
    ("zip", b"PK\x03\x04"),
    ("gzip", b"\x1f\x8b"),
    ("pdf", b"%PDF-"),
    ("sqlite", b"SQLite format 3\x00"),
    ("png", b"\x89PNG\r\n\x1a\n"),
)


def _classify_artifact_prefix(prefix: bytes) -> str:
    """Deterministic code-defined classification of the OBSERVED magic prefix.

    The file extension is never trusted; an unknown prefix stays unknown and
    is never guessed. Classification is data, never authority (INV-OFF-2).
    """
    for family, magic in FORMAT_MAGIC_TABLE:
        if prefix.startswith(magic):
            return family
    if prefix.startswith(b"#!"):
        return "script"
    return "unknown"


def _scoped_local_artifact(argument):
    """Real bounded local artifact-store metadata behind the proof chain (P1-F).

    The registry invokes this handler ONLY after the full gate sequence:
    the typed ExecutionAuthorizationProof verified against mission/request/
    run (or OWNER_DIRECT with the typed AuthorizationDecision). The executed
    argument is exactly ONE bare artifact file name; containment inside the
    code-defined artifact store is re-verified in code (defense in depth).

    - ONE stat + ONE capped read through the single seams
    - sha256 over the SIZE-CAPPED read; the observed bytes are never echoed
    - deterministic fail-closed classification of every failure
    """
    name = argument if isinstance(argument, str) else ""
    if (
        not name
        or len(name) > MAX_ARG_LENGTH
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or name.startswith(".")
    ):
        return {"ok": False, "operation": "local_artifact_metadata", "error": "META_ARGUMENT_INVALID", "reason": "the artifact metadata accepts exactly one bare file name inside the local artifact store"}
    return _artifact_metadata(name)


ARTIFACT_METADATA_TIMEOUT_SECONDS = 10  # enforced by the registry executor (spec/adapter timeout)
ARTIFACT_METADATA_MAX_BYTES = 65536
ARTIFACT_METADATA_FIELD_MAX = 256


def _artifact_metadata(name, *, max_bytes=ARTIFACT_METADATA_MAX_BYTES, field_max=ARTIFACT_METADATA_FIELD_MAX):
    import hashlib
    import time
    from datetime import datetime, timezone

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    common = {"operation": "local_artifact_metadata", "name": name}
    try:
        root = _artifact_root().resolve()
    except Exception as exc:
        return dict(common, ok=False, error="META_STORE_UNAVAILABLE", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        resolved = (root / name).resolve()
    except OSError as exc:
        return dict(common, ok=False, error="META_ARGUMENT_INVALID", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if resolved != root and root not in resolved.parents:
        # Defense in depth: even a name that slipped the bare-name validator
        # can never escape the artifact store here (fail closed, pre-open).
        return dict(common, ok=False, error="META_ARGUMENT_INVALID", reason="the artifact path escaped the artifact store (fail closed)", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if not resolved.is_file():
        return dict(common, ok=False, error="META_NOT_FOUND", reason="the artifact is not a regular file inside the store", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        stat_before = _artifact_stat(resolved)
        size = int(getattr(stat_before, "st_size", stat_before))
    except OSError as exc:
        return dict(common, ok=False, error="META_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        with _artifact_open(resolved) as handle:
            # Post-open identity binding (defense in depth against a
            # stat->open TOCTOU / symlink swap): stat the OPEN descriptor and
            # require the same regular-file inode observed at the pre-open
            # stat. Any mismatch fails closed BEFORE one byte is read. The
            # binding engages whenever the pre-open stat carries real
            # identity metadata (production always does); a legacy faked
            # plain-int stat carries none and skips the binding.
            binding_error = _artifact_identity_error(stat_before, handle, field_max)
            if binding_error is not None:
                return dict(common, ok=False, error="META_OPEN_FAILED", reason=binding_error, observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
            prefix = handle.read(max_bytes + 1)
    except OSError as exc:
        return dict(common, ok=False, error="META_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except Exception as exc:
        return dict(common, ok=False, error="META_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    prefix = bytes(prefix)
    truncated = len(prefix) > max_bytes
    if truncated:
        prefix = prefix[:max_bytes]
    family = _classify_artifact_prefix(prefix)
    return {
        "ok": True,
        **common,
        "sha256": hashlib.sha256(prefix).hexdigest(),
        "size_bytes": size,
        "read_cap_bytes": max_bytes,
        "read_truncated": truncated,
        "format_family": family,  # OBSERVED classification only — zero authority
        "classification_basis": "observed_magic_prefix",
        "content": None,  # the observed bytes are hashed and classified, never echoed
        "path_within_store": name,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }




def _scoped_binary_analysis(argument):
    """Argument gate for the bounded local binary static analysis (P1-G).

    Exactly ONE bare file name inside the local artifact store; traversal,
    separators, and hidden names are rejected BEFORE any filesystem seam is
    touched (fail closed, pre-open).
    """
    name = argument if isinstance(argument, str) else ""
    if (
        not name
        or len(name) > MAX_ARG_LENGTH
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or name.startswith(".")
    ):
        return {"ok": False, "operation": "local_binary_analysis", "error": "BIN_ARGUMENT_INVALID", "reason": "the binary analysis accepts exactly one bare file name inside the local artifact store"}
    return _binary_header_analysis(name)


BINARY_ANALYSIS_MAX_BYTES = 4096
BINARY_ANALYSIS_FIELD_MAX = 256


def _u(data, offset, size, *, signed=False, little=True):
    """Bounded integer field read over the CAPPED prefix. Out of bounds is
    never an error and never guessed: the field is simply not observable."""
    if offset < 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "little" if little else "big", signed=signed)


def _parse_elf_header(prefix):
    fields: dict[str, Any] = {}
    cls = prefix[4] if len(prefix) > 4 else None
    endian = prefix[5] if len(prefix) > 5 else None
    fields["elf_class"] = {1: "32-bit", 2: "64-bit"}.get(cls)
    fields["elf_data"] = {1: "little_endian", 2: "big_endian"}.get(endian)
    little = endian != 2
    fields["elf_type"] = _u(prefix, 16, 2, little=little)
    fields["elf_machine"] = _u(prefix, 18, 2, little=little)
    if cls == 2:
        fields["elf_entry_point"] = _u(prefix, 24, 8, little=little)
        fields["elf_program_header_count"] = _u(prefix, 56, 2, little=little)
        fields["elf_section_header_count"] = _u(prefix, 60, 2, little=little)
    elif cls == 1:
        fields["elf_entry_point"] = _u(prefix, 24, 4, little=little)
        fields["elf_program_header_count"] = _u(prefix, 44, 2, little=little)
        fields["elf_section_header_count"] = _u(prefix, 48, 2, little=little)
    return fields


def _parse_macho_header(prefix):
    fields: dict[str, Any] = {}
    fields["macho_cputype"] = _u(prefix, 4, 4, signed=True)
    fields["macho_filetype"] = _u(prefix, 8, 4)
    fields["macho_load_command_count"] = _u(prefix, 16, 4)
    return fields


def _parse_universal_header(prefix):
    fields: dict[str, Any] = {}
    fields["universal_fat_arch_count"] = _u(prefix, 4, 4, little=False)  # fat headers are big-endian
    return fields


def _parse_pe_header(prefix):
    fields: dict[str, Any] = {}
    lfanew = _u(prefix, 0x3C, 4)
    if lfanew is None or lfanew + 4 > len(prefix) or prefix[lfanew:lfanew + 4] != b"PE\x00\x00":
        fields["pe_signature"] = "outside_capped_prefix"
        return fields
    fields["pe_signature"] = "present"
    fields["pe_machine"] = _u(prefix, lfanew + 4, 2)
    fields["pe_number_of_sections"] = _u(prefix, lfanew + 6, 2)
    fields["pe_size_of_optional_header"] = _u(prefix, lfanew + 20, 2)
    return fields


_BINARY_HEADER_PARSERS = {
    "elf": _parse_elf_header,
    "mach_o_64": _parse_macho_header,
    "mach_o_32": _parse_macho_header,
    "mach_o_universal": _parse_universal_header,
    "pe": _parse_pe_header,
}


def _binary_header_analysis(name, *, max_bytes=BINARY_ANALYSIS_MAX_BYTES, field_max=BINARY_ANALYSIS_FIELD_MAX):
    """Bounded STATIC header analysis of one artifact-store binary (P1-G).

    The file is NEVER executed: ONE stat + ONE capped read through the same
    single filesystem seams as P1-F, then pure byte-offset arithmetic over
    the capped prefix. Fields outside the capped prefix are observable data
    (None), never guessed. Every parsed field is OBSERVED data with zero
    authority (INV-OFF-1/2).

    Deterministic fail-closed classification:
    BIN_ARGUMENT_INVALID / BIN_NOT_FOUND / BIN_STORE_UNAVAILABLE /
    BIN_OPEN_FAILED / BIN_RUNTIME_ERROR.
    """
    import hashlib
    import time
    from datetime import datetime, timezone

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    common = {"operation": "local_binary_analysis", "name": name}
    try:
        root = _artifact_root().resolve()
    except Exception as exc:
        return dict(common, ok=False, error="BIN_STORE_UNAVAILABLE", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        resolved = (root / name).resolve()
    except OSError as exc:
        return dict(common, ok=False, error="BIN_ARGUMENT_INVALID", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if resolved != root and root not in resolved.parents:
        return dict(common, ok=False, error="BIN_ARGUMENT_INVALID", reason="the artifact path escaped the artifact store (fail closed)", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if not resolved.is_file():
        return dict(common, ok=False, error="BIN_NOT_FOUND", reason="the artifact is not a regular file inside the store", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        stat_before = _artifact_stat(resolved)
        size = int(getattr(stat_before, "st_size", stat_before))
    except OSError as exc:
        return dict(common, ok=False, error="BIN_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        with _artifact_open(resolved) as handle:
            # Post-open identity binding (defense in depth against a
            # stat->open TOCTOU / symlink swap): stat the OPEN descriptor and
            # require the same regular-file inode observed at the pre-open
            # stat. Any mismatch fails closed BEFORE one byte is read. The
            # binding engages whenever the pre-open stat carries real
            # identity metadata (production always does); a legacy faked
            # plain-int stat carries none and skips the binding.
            binding_error = _artifact_identity_error(stat_before, handle, field_max)
            if binding_error is not None:
                return dict(common, ok=False, error="BIN_OPEN_FAILED", reason=binding_error, observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
            prefix = bytes(handle.read(max_bytes + 1))
    except OSError as exc:
        return dict(common, ok=False, error="BIN_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except Exception as exc:
        return dict(common, ok=False, error="BIN_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    truncated = len(prefix) > max_bytes
    if truncated:
        prefix = prefix[:max_bytes]
    family = _classify_artifact_prefix(prefix)
    try:
        parser = _BINARY_HEADER_PARSERS.get(family)
        header_fields = dict(parser(prefix)) if parser is not None else {}
    except Exception as exc:
        return dict(common, ok=False, error="BIN_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    return {
        "ok": True,
        **common,
        "sha256": hashlib.sha256(prefix).hexdigest(),
        "size_bytes": size,
        "read_cap_bytes": max_bytes,
        "read_truncated": truncated,
        "format_family": family,  # OBSERVED classification only — zero authority
        "classification_basis": "observed_magic_prefix",
        "header_fields": header_fields,  # static read-only observations — the file is never executed
        "analysis_kind": "static_header_read",
        "content": None,  # observed bytes are hashed and classified, never echoed
        "path_within_store": name,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }


def _scoped_string_extraction(argument):
    """Argument gate for the bounded local printable-string analysis (P1-H).

    Exactly ONE bare file name inside the local artifact store; traversal,
    separators, and hidden names are rejected BEFORE any filesystem seam is
    touched (fail closed, pre-open).
    """
    name = argument if isinstance(argument, str) else ""
    if (
        not name
        or len(name) > MAX_ARG_LENGTH
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or name.startswith(".")
    ):
        return {"ok": False, "operation": "local_string_extraction", "error": "STR_ARGUMENT_INVALID", "reason": "the string extraction accepts exactly one bare file name inside the local artifact store"}
    return _printable_string_analysis(name)


STRING_EXTRACTION_MAX_BYTES = 65536
STRING_EXTRACTION_FIELD_MAX = 256
STRING_EXTRACTION_MIN_RUN = 4
STRING_EXTRACTION_MAX_RUNS = 64

# Deterministic redaction of secret-like key/value strings that may occur
# inside captured artifacts: the VALUE after a code-defined key anchor is
# never recorded in evidence plaintext (fingerprints/redaction only). The
# table is fixed at code definition; a false positive loses nothing because
# redaction is the safe direction. Redaction is DATA hygiene, never
# classification of the file (an unredacted string is not "malicious").
_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b((?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd|pwd|secret|credential|client[_-]?secret|bearer)\s*[:=]\s*)([!-~]{1,128})"
)


def _redact_secret_value(value: str):
    """Redact a secret-like value with its own sha256 fingerprint prefix."""
    import hashlib

    def _repl(match):
        return match.group(1) + "REDACTED:" + hashlib.sha256(match.group(2).encode("utf-8")).hexdigest()[:12]

    return _SECRET_VALUE_PATTERN.subn(_repl, value)


def _printable_string_analysis(name, *, max_bytes=STRING_EXTRACTION_MAX_BYTES, field_max=STRING_EXTRACTION_FIELD_MAX, min_run=STRING_EXTRACTION_MIN_RUN, max_runs=STRING_EXTRACTION_MAX_RUNS):
    """Bounded STATIC printable-string extraction of one artifact (P1-H).

    The file is NEVER executed: ONE stat + ONE capped read through the same
    single filesystem seams as P1-F/P1-G, then ONE deterministic linear scan
    over the capped prefix. A run is a maximal sequence of printable ASCII
    bytes (0x20..0x7E) of at least STRING_EXTRACTION_MIN_RUN; the argument
    list never widens or filters the scan. Every extracted run is OBSERVED
    data with zero authority (INV-OFF-1/2). Secret-like values discovered by
    the fixed redaction table are fingerprint-redacted, never echoed.

    Deterministic fail-closed classification:
    STR_ARGUMENT_INVALID / STR_NOT_FOUND / STR_STORE_UNAVAILABLE /
    STR_OPEN_FAILED / STR_RUNTIME_ERROR.
    """
    import hashlib
    import time
    from datetime import datetime, timezone

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    common = {"operation": "local_string_extraction", "name": name}
    try:
        root = _artifact_root().resolve()
    except Exception as exc:
        return dict(common, ok=False, error="STR_STORE_UNAVAILABLE", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        resolved = (root / name).resolve()
    except OSError as exc:
        return dict(common, ok=False, error="STR_ARGUMENT_INVALID", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if resolved != root and root not in resolved.parents:
        return dict(common, ok=False, error="STR_ARGUMENT_INVALID", reason="the artifact path escaped the artifact store (fail closed)", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if not resolved.is_file():
        return dict(common, ok=False, error="STR_NOT_FOUND", reason="the artifact is not a regular file inside the store", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        stat_before = _artifact_stat(resolved)
        size = int(getattr(stat_before, "st_size", stat_before))
    except OSError as exc:
        return dict(common, ok=False, error="STR_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        with _artifact_open(resolved) as handle:
            # Post-open identity binding (defense in depth against a
            # stat->open TOCTOU / symlink swap): stat the OPEN descriptor and
            # require the same regular-file inode observed at the pre-open
            # stat. Any mismatch fails closed BEFORE one byte is read. The
            # binding engages whenever the pre-open stat carries real
            # identity metadata (production always does); a legacy faked
            # plain-int stat carries none and skips the binding.
            binding_error = _artifact_identity_error(stat_before, handle, field_max)
            if binding_error is not None:
                return dict(common, ok=False, error="STR_OPEN_FAILED", reason=binding_error, observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
            prefix = bytes(handle.read(max_bytes + 1))
    except OSError as exc:
        return dict(common, ok=False, error="STR_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except Exception as exc:
        return dict(common, ok=False, error="STR_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    truncated = len(prefix) > max_bytes
    if truncated:
        prefix = prefix[:max_bytes]
    family = _classify_artifact_prefix(prefix)

    def _record(run_start, run_end):
        text = prefix[run_start:run_end].decode("ascii")
        kept, redactions = _redact_secret_value(text[:field_max])
        return {
            "offset": run_start,
            "length": run_end - run_start,
            "value": kept,
            "value_truncated": len(text) > field_max,
            "value_redacted": bool(redactions),
            "value_sha256": hashlib.sha256(text.encode("ascii")).hexdigest(),
        }

    try:
        runs: list[dict[str, Any]] = []
        total_runs = 0
        qualifying_runs = 0
        run_start: int | None = None

        def _close(run_start_value, run_end):
            nonlocal total_runs, qualifying_runs
            total_runs += 1
            if (run_end - run_start_value) >= min_run:
                qualifying_runs += 1
                if len(runs) < max_runs:
                    runs.append(_record(run_start_value, run_end))

        for index, byte in enumerate(prefix):
            if 0x20 <= byte <= 0x7E:
                if run_start is None:
                    run_start = index
                continue
            if run_start is not None:
                _close(run_start, index)
                run_start = None
        if run_start is not None:
            _close(run_start, len(prefix))
        strings_truncated = qualifying_runs > len(runs)
    except Exception as exc:
        return dict(common, ok=False, error="STR_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    return {
        "ok": True,
        **common,
        "sha256": hashlib.sha256(prefix).hexdigest(),
        "size_bytes": size,
        "read_cap_bytes": max_bytes,
        "read_truncated": truncated,
        "format_family": family,  # OBSERVED classification only — zero authority
        "classification_basis": "observed_magic_prefix",
        "strings": runs,  # static read-only observations — the file is never executed
        "total_printable_runs": total_runs,
        "qualifying_printable_runs": qualifying_runs,
        "strings_returned": len(runs),
        "strings_truncated": strings_truncated,
        "min_run_length": min_run,
        "redaction_basis": "code_defined_secret_value_table",
        "redacted_values": sum(1 for record in runs if record["value_redacted"]),
        "analysis_kind": "static_string_read",
        "content": None,  # the observed bytes themselves are hashed, never echoed
        "path_within_store": name,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }


def _scoped_import_analysis(argument):
    """Argument gate for the bounded local import-table analysis (P1-I).

    Exactly ONE bare file name inside the local artifact store; traversal,
    separators, and hidden names are rejected BEFORE any filesystem seam is
    touched (fail closed, pre-open).
    """
    name = argument if isinstance(argument, str) else ""
    if (
        not name
        or len(name) > MAX_ARG_LENGTH
        or "/" in name
        or "\\" in name
        or name in (".", "..")
        or name.startswith(".")
    ):
        return {"ok": False, "operation": "local_import_analysis", "error": "IMP_ARGUMENT_INVALID", "reason": "the import analysis accepts exactly one bare file name inside the local artifact store"}
    return _import_analysis(name)


IMPORT_ANALYSIS_MAX_BYTES = 262144
IMPORT_ANALYSIS_FIELD_MAX = 256
IMPORT_ANALYSIS_MAX_IMPORTS = 64
IMPORT_ANALYSIS_MAX_FUNCTIONS_PER_IMPORT = 32
IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED = 1024


_MACHO_DYLIB_LOAD_COMMANDS = {
    0x0C: "LC_LOAD_DYLIB",
    0x18: "LC_LOAD_WEAK_DYLIB",
    0x1F: "LC_REEXPORT_DYLIB",
    0x20: "LC_LAZY_LOAD_DYLIB",
}


def _cstr(data, offset, max_len):
    """Bounded NUL-terminated ASCII read over the CAPPED prefix.

    Returns (value, unterminated_flag). Out-of-prefix offsets are observable
    data (None), never guessed and never an error.
    """
    if offset is None or offset < 0 or offset >= len(data):
        return None, False
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        if offset + max_len <= len(data):
            return None, True  # unterminated inside the bound: not observable
        return None, True  # ran out of capped prefix: not observable
    return data[offset:end].decode("ascii"), False


def _shannon_entropy(data: bytes, precision: int = 4):
    """Deterministic Shannon entropy (bits/byte) over the CAPPED prefix."""
    import math

    total = len(data)
    if total == 0:
        return 0.0
    counts = sorted((byte, data.count(byte)) for byte in set(data))
    ent = 0.0
    for _byte, count in counts:
        p = count / total
        ent -= p * math.log2(p)
    return round(ent, precision)


def _pe_rva_to_offset(prefix, rva, section_dir_offset, section_count):
    """Deterministic RVA -> file offset mapping over the section headers
    observable inside the CAPPED prefix. Unmapped is None, never guessed."""
    if rva is None or section_dir_offset is None:
        return None
    for index in range(min(section_count, IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED)):
        base = section_dir_offset + index * 40
        virtual_size = _u(prefix, base + 8, 4)
        virtual_address = _u(prefix, base + 12, 4)
        raw_size = _u(prefix, base + 16, 4)
        raw_pointer = _u(prefix, base + 20, 4)
        if virtual_address is None:
            continue  # section header outside the capped prefix
        bound = max(virtual_size or 0, raw_size or 0)
        if virtual_address <= rva < virtual_address + bound:
            if raw_pointer is None:
                return None
            return raw_pointer + (rva - virtual_address)
    return None


def _parse_pe_imports(prefix, field_max):
    """Static PE import-directory extraction over the CAPPED prefix."""
    imports: list[dict[str, Any]] = []
    lfanew = _u(prefix, 0x3C, 4)
    if lfanew is None or lfanew + 4 > len(prefix) or prefix[lfanew:lfanew + 4] != b"PE\x00\x00":
        return "pe_signature_outside_capped_prefix", imports, False
    optional_header = lfanew + 24
    magic = _u(prefix, optional_header, 2)
    if magic == 0x10B:
        data_dir_base = optional_header + 96
        thunk_size = 4
        ordinal_flag = 1 << 31
    elif magic == 0x20B:
        data_dir_base = optional_header + 112
        thunk_size = 8
        ordinal_flag = 1 << 63
    else:
        return "pe_optional_header_unknown", imports, False
    section_count = _u(prefix, lfanew + 6, 2) or 0
    size_of_optional = _u(prefix, lfanew + 20, 2) or 0
    section_dir = optional_header + size_of_optional
    number_of_rvas = _u(prefix, optional_header + (108 if magic == 0x20B else 92), 4)
    import_rva = _u(prefix, data_dir_base + 8, 4)
    if not number_of_rvas or number_of_rvas < 2 or import_rva in (None, 0):
        return "no_import_directory", imports, False
    import_table = _pe_rva_to_offset(prefix, import_rva, section_dir, section_count)
    if import_table is None:
        return "import_directory_outside_capped_prefix", imports, True
    imports_truncated = False
    for index in range(IMPORT_ANALYSIS_MAX_IMPORTS + 1):
        entry = import_table + index * 20
        original_first_thunk = _u(prefix, entry, 4)
        name_rva = _u(prefix, entry + 12, 4)
        first_thunk = _u(prefix, entry + 16, 4)
        if original_first_thunk in (None, 0) and name_rva in (None, 0) and first_thunk in (None, 0):
            break  # deterministic terminating descriptor
        if index == IMPORT_ANALYSIS_MAX_IMPORTS:
            imports_truncated = True
            break
        dll, _unterminated = _cstr(prefix, _pe_rva_to_offset(prefix, name_rva, section_dir, section_count), field_max)
        functions: list[dict[str, Any]] = []
        functions_truncated = False
        thunk_rva = original_first_thunk or first_thunk
        if thunk_rva:
            thunk_table = _pe_rva_to_offset(prefix, thunk_rva, section_dir, section_count)
            if thunk_table is None:
                functions_truncated = True
            else:
                for slot in range(IMPORT_ANALYSIS_MAX_FUNCTIONS_PER_IMPORT + 1):
                    thunk = _u(prefix, thunk_table + slot * thunk_size, thunk_size)
                    if thunk in (None, 0):
                        break
                    if slot == IMPORT_ANALYSIS_MAX_FUNCTIONS_PER_IMPORT:
                        functions_truncated = True
                        break
                    if thunk & ordinal_flag:
                        functions.append({"import_type": "ordinal", "ordinal": thunk & (ordinal_flag - 1)})
                    else:
                        function_offset = _pe_rva_to_offset(prefix, thunk, section_dir, section_count)
                        if function_offset is not None:
                            function_name = _cstr(prefix, function_offset + 2, field_max)[0]
                            if function_name:
                                functions.append({"import_type": "name", "name": function_name})
        imports.append({
            "library": dll,  # None when the name lies outside the capped prefix: observed, never guessed
            "functions": functions,
            "functions_truncated": functions_truncated,
        })
    return "ok", imports, imports_truncated


def _parse_elf_imports(prefix, field_max):
    """Static ELF DT_NEEDED shared-library extraction over the CAPPED prefix."""
    cls = prefix[4] if len(prefix) > 4 else None
    endian = prefix[5] if len(prefix) > 5 else None
    little = endian != 2
    if cls not in (1, 2):
        return "elf_class_not_observable", [], False
    if cls == 2:
        phoff = _u(prefix, 32, 8, little=little)
        phentsize = _u(prefix, 54, 2, little=little)
        phnum = _u(prefix, 56, 2, little=little)
    else:
        phoff = _u(prefix, 28, 4, little=little)
        phentsize = _u(prefix, 42, 2, little=little)
        phnum = _u(prefix, 44, 2, little=little)
    if not phoff or not phentsize or phnum in (None, 0):
        return "no_program_headers", [], False
    loads: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz)
    dynamic = None
    for index in range(min(phnum, IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED)):
        base = phoff + index * phentsize
        p_type = _u(prefix, base, 4, little=little)
        if p_type is None:
            break
        if p_type == 1:  # PT_LOAD
            if cls == 2:
                p_offset = _u(prefix, base + 8, 8, little=little)
                p_vaddr = _u(prefix, base + 16, 8, little=little)
                p_filesz = _u(prefix, base + 32, 8, little=little)
            else:
                p_offset = _u(prefix, base + 4, 4, little=little)
                p_vaddr = _u(prefix, base + 8, 4, little=little)
                p_filesz = _u(prefix, base + 16, 4, little=little)
            if None not in (p_offset, p_vaddr, p_filesz):
                loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:  # PT_DYNAMIC
            if cls == 2:
                d_offset = _u(prefix, base + 8, 8, little=little)
                d_filesz = _u(prefix, base + 32, 8, little=little)
                d_vaddr = _u(prefix, base + 16, 8, little=little)
            else:
                d_offset = _u(prefix, base + 4, 4, little=little)
                d_filesz = _u(prefix, base + 16, 4, little=little)
                d_vaddr = _u(prefix, base + 8, 4, little=little)
            if d_offset is not None:
                dynamic = (d_offset, d_filesz or 0, d_vaddr or 0)
    if dynamic is None:
        return "no_dynamic_segment", [], False
    dyn_offset, dyn_size, dyn_vaddr = dynamic
    entry_size = 16 if cls == 2 else 8
    entries = min(dyn_size // entry_size, IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED) if dyn_size else IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED
    needed: list[int] = []
    strtab_vaddr = None
    for index in range(entries):
        base = dyn_offset + index * entry_size
        if cls == 2:
            d_tag = _u(prefix, base, 8, little=little, signed=True)
            d_val = _u(prefix, base + 8, 8, little=little)
        else:
            d_tag = _u(prefix, base, 4, little=little, signed=True)
            d_val = _u(prefix, base + 4, 4, little=little)
        if d_tag is None:
            break
        if d_tag == 0:
            break  # DT_NULL terminator
        if d_tag == 1:
            needed.append(d_val)
        elif d_tag == 5:
            strtab_vaddr = d_val
    if not needed:
        return "ok", [], False
    strtab = None
    if strtab_vaddr is not None:
        for load_vaddr, load_offset, load_filesz in loads:
            if load_vaddr <= strtab_vaddr < load_vaddr + load_filesz:
                strtab = load_offset + (strtab_vaddr - load_vaddr)
                break
    imports: list[dict[str, Any]] = []
    for offset in needed[:IMPORT_ANALYSIS_MAX_IMPORTS]:
        library = None
        if strtab is not None:
            library = _cstr(prefix, strtab + offset, field_max)[0]
        imports.append({"library": library, "functions": [], "functions_truncated": False})
    return "ok", imports, len(needed) > IMPORT_ANALYSIS_MAX_IMPORTS


def _parse_macho_imports(prefix, field_max):
    """Static Mach-O dylib load-command extraction over the CAPPED prefix."""
    imports: list[dict[str, Any]] = []
    ncmds = _u(prefix, 16, 4)
    if ncmds is None:
        return "load_commands_outside_capped_prefix", imports, False
    offset = 32
    for _index in range(min(ncmds, IMPORT_ANALYSIS_MAX_ENTRIES_SCANNED)):
        cmd = _u(prefix, offset, 4)
        size = _u(prefix, offset + 4, 4)
        if cmd is None or size in (None, 0) or offset + size > len(prefix):
            return "ok", imports, True
        if cmd in _MACHO_DYLIB_LOAD_COMMANDS:
            name_offset = _u(prefix, offset + 8, 4)
            library = _cstr(prefix, offset + name_offset if name_offset is not None else None, field_max)[0]
            imports.append({"command": _MACHO_DYLIB_LOAD_COMMANDS[cmd], "library": library, "functions": [], "functions_truncated": False})
        offset += size
    return "ok", imports, False


def _parse_universal_imports(prefix, field_max):
    """Static observation of the fat-binary archive table; entry binaries
    themselves are not observable from the capped prefix (never guessed)."""
    count = _u(prefix, 4, 4, little=False)
    if count is None:
        return "load_commands_outside_capped_prefix", [], False
    return "ok", [], count > IMPORT_ANALYSIS_MAX_IMPORTS


_IMPORT_HEADER_PARSERS = {
    "pe": _parse_pe_imports,
    "elf": _parse_elf_imports,
    "mach_o_64": _parse_macho_imports,
    "mach_o_32": _parse_macho_imports,
    "mach_o_universal": _parse_universal_imports,
}


def _import_analysis(name, *, max_bytes=IMPORT_ANALYSIS_MAX_BYTES, field_max=IMPORT_ANALYSIS_FIELD_MAX):
    """Bounded STATIC import-table + entropy analysis of one artifact (P1-I).

    The file is NEVER executed: ONE stat + ONE capped read through the same
    single filesystem seams as P1-F/P1-G/P1-H, then deterministic fixed-offset
    arithmetic over the capped prefix. Libraries and imported names are
    OBSERVED data with zero authority (INV-OFF-1/2); imports beyond the caps
    are never invented (explicit truncated flags). An unknown/capped-out
    offset is an observable None. Every failure is classified fail-closed:
    IMP_ARGUMENT_INVALID / IMP_NOT_FOUND / IMP_STORE_UNAVAILABLE /
    IMP_OPEN_FAILED / IMP_RUNTIME_ERROR.
    """
    import hashlib
    import time
    from datetime import datetime, timezone

    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    common = {"operation": "local_import_analysis", "name": name}
    try:
        root = _artifact_root().resolve()
    except Exception as exc:
        return dict(common, ok=False, error="IMP_STORE_UNAVAILABLE", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        resolved = (root / name).resolve()
    except OSError as exc:
        return dict(common, ok=False, error="IMP_ARGUMENT_INVALID", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if resolved != root and root not in resolved.parents:
        return dict(common, ok=False, error="IMP_ARGUMENT_INVALID", reason="the artifact path escaped the artifact store (fail closed)", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    if not resolved.is_file():
        return dict(common, ok=False, error="IMP_NOT_FOUND", reason="the artifact is not a regular file inside the store", observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        stat_before = _artifact_stat(resolved)
        size = int(getattr(stat_before, "st_size", stat_before))
    except OSError as exc:
        return dict(common, ok=False, error="IMP_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    try:
        with _artifact_open(resolved) as handle:
            # Post-open identity binding (defense in depth against a
            # stat->open TOCTOU / symlink swap): stat the OPEN descriptor and
            # require the same regular-file inode observed at the pre-open
            # stat. Any mismatch fails closed BEFORE one byte is read. The
            # binding engages whenever the pre-open stat carries real
            # identity metadata (production always does); a legacy faked
            # plain-int stat carries none and skips the binding.
            binding_error = _artifact_identity_error(stat_before, handle, field_max)
            if binding_error is not None:
                return dict(common, ok=False, error="IMP_OPEN_FAILED", reason=binding_error, observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
            prefix = bytes(handle.read(max_bytes + 1))
    except OSError as exc:
        return dict(common, ok=False, error="IMP_OPEN_FAILED", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    except Exception as exc:
        return dict(common, ok=False, error="IMP_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    truncated = len(prefix) > max_bytes
    if truncated:
        prefix = prefix[:max_bytes]
    family = _classify_artifact_prefix(prefix)
    entropy = _shannon_entropy(prefix)
    try:
        parser = _IMPORT_HEADER_PARSERS.get(family)
        if parser is None:
            parse_status, imports, imports_truncated = "unsupported_format_for_imports", [], False
        else:
            parse_status, imports, imports_truncated = parser(prefix, field_max)
    except Exception as exc:
        return dict(common, ok=False, error="IMP_RUNTIME_ERROR", reason=str(exc)[:field_max], observed_at=datetime.now(timezone.utc).isoformat(), elapsed_ms=elapsed())
    return {
        "ok": True,
        **common,
        "sha256": hashlib.sha256(prefix).hexdigest(),
        "size_bytes": size,
        "read_cap_bytes": max_bytes,
        "read_truncated": truncated,
        "format_family": family,  # OBSERVED classification only — zero authority
        "classification_basis": "observed_magic_prefix",
        "parse_status": parse_status,  # OBSERVED: why imports may be absent (data, never guessed)
        "imports": imports,  # static read-only observations — the file is never executed
        "imports_returned": len(imports),
        "imports_truncated": imports_truncated,
        "max_imports": IMPORT_ANALYSIS_MAX_IMPORTS,
        "entropy_bits_per_byte": entropy,  # OBSERVED statistic over the capped prefix
        "redaction_basis": "code_defined_secret_value_table",
        "analysis_kind": "static_import_read",
        "content": None,  # the observed bytes themselves are hashed, never echoed
        "path_within_store": name,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed(),
    }


def build_registry(specs: list[ToolSpec]) -> dict[str, ToolSpec]:
    registry: dict[str, ToolSpec] = {}
    for spec in specs:
        if not isinstance(spec, ToolSpec) or not spec.name or spec.name in registry:
            raise ValueError("duplicate or invalid tool specification")
        scope_namespace = spec.name.split(".", 1)[0]
        scope_namespaces = {"bugbounty", "recon", "research", "evidence", "browser", "report"}
        if not spec.description or spec.risk_class not in VALID_RISK_CLASSES or not callable(spec.handler) or (spec.owner_only and not spec.requires_owner) or (scope_namespace in scope_namespaces and not spec.scope_required):
            raise ValueError(f"invalid registry metadata for {spec.name}")
        if spec.argument_type not in (None, str):
            raise ValueError(f"unsupported argument schema for {spec.name}")
        registry[spec.name] = spec
    return registry


REGISTRY = build_registry([
    ToolSpec("status", "ÙØ±Ø§Ø¡Ø© Ø­Ø§ÙØ© Ø§ÙØ®Ø¯ÙØ© ÙØ§ÙØ£Ø­Ø¯Ø§Ø« Ø§ÙØªØ¯ÙÙÙÙØ© Ø§ÙØ£Ø®ÙØ±Ø©", "read", True, None, _status),
    ToolSpec("latest_intel", "ÙØ±Ø§Ø¡Ø© Ø§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø§ÙØªÙØ¯ÙØ¯Ø§Øª Ø§ÙÙØ¬ÙØ¹Ø©", "read", True, None, _latest_intel),
    ToolSpec("refresh_intel", "Ø¬ÙØ¹ Ø§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø¯ÙØ§Ø¹ÙØ© Ø¶Ø¯ Ø§ÙØªÙØ¯ÙØ¯Ø§Øª", "network-read", True, None, _refresh_intel),
    ToolSpec("local_security_check", "ÙØ­Øµ ÙØ³ØªÙØ¹Ù TCP Ø§ÙÙØ­ÙÙØ©", "read", True, None, _local_security),
    ToolSpec("local_system_info", "ÙØ±Ø§Ø¡Ø© ÙØ¹ÙÙÙØ§Øª Ø§ÙÙØ¸Ø§Ù Ø§ÙÙØ­ÙÙ", "read", True, None, _system_info),
    ToolSpec("local_process_info", "قراءة قائمة العمليات المحلية الجارية (فحص دفاعي محلي)", "read", True, None, _process_info),
    ToolSpec("search", "Ø¨Ø­Ø« ÙÙ Ø§ÙØ£Ø­Ø¯Ø§Ø« ÙØ§ÙØ§Ø³ØªØ®Ø¨Ø§Ø±Ø§Øª Ø§ÙÙØ­ÙÙØ©", "read", True, str, _search),
    ToolSpec("watch", "Ø¥Ø¶Ø§ÙØ© ÙÙÙØ© ÙØ±Ø§ÙØ¨ Ø¯ÙØ§Ø¹ÙØ© ÙØ­ÙÙØ©", "state-write", True, str, _watch),
    ToolSpec("unwatch", "Ø¥Ø²Ø§ÙØ© ÙÙÙØ© ÙØ±Ø§ÙØ¨ Ø¯ÙØ§Ø¹ÙØ© ÙØ­ÙÙØ©", "state-write", True, str, _unwatch),
    ToolSpec("run_project_tests", "ØªØ´ØºÙÙ pytest -q Ø¯Ø§Ø®Ù Ø¬Ø°Ø± Ø§Ø®ØªØ¨Ø§Ø± Ø§ÙÙØ´Ø±ÙØ¹ Ø§ÙÙØ­Ø¯Ø¯", "bounded-exec", True, str, _run_project_tests),
    ToolSpec("red_team_assess", "ØªÙÙÙÙ ÙØ¬ÙÙÙ Ø¯ÙØ§Ø¹Ù ÙÙÙØ§ÙÙ ÙÙØ·; ÙØ§ ÙÙÙØ° Ø§Ø³ØªØºÙØ§ÙØ§Ù Ø£Ù Ø£ÙØ±Ø© ÙØ¸Ø§Ù", "analysis", True, str, _red_team_assess, True),
    ToolSpec("scoped_http_probe", "ÙØ±Ø§ÙØ¨Ø© HTTP ÙØ­Ø¯ÙØ¯Ø© ÙØ§ ØªØ¹ÙÙ Ø¥ÙØ§ ÙØ¹ Scope Snapshot ÙTarget ÙØµØ§Ø¯Ù Ø¹ÙÙÙ", "network-read", True, str, _scoped_http_probe, False, True),
    ToolSpec("scoped_dns_lookup", "مراقبة DNS محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_dns_lookup, False, True),
    ToolSpec("scoped_tls_observation", "مراقبة TLS محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_tls_observation, False, True),
    ToolSpec("scoped_port_observation", "مراقبة المنافذ والخدمات محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_port_observation, False, True),
    ToolSpec("scoped_tech_fingerprint", "بصمة التقنيات محدودة لا تعمل إلا مع Scope Snapshot وTarget مصادق عليه", "network-read", True, str, _scoped_tech_fingerprint, False, True),
    ToolSpec("local_artifact_metadata", "قراءة بيانات وصفية محدودة للملفات داخل مخزن المخرجات المحلي (فحص دفاعي لا يعمل إلا بمصادقة المالك)", "read", True, str, _scoped_local_artifact),
    ToolSpec("local_binary_analysis", "تحليل ساكن محدود لرأس الملف داخل مخزن المخرجات (قراءة فقط، لا ينفذ الملف، لا يعمل إلا بمصادقة المالك)", "analysis", True, str, _scoped_binary_analysis),
    ToolSpec("local_string_extraction", "استخراج سلاسل نصية ساكن محدود لملف داخل مخزن المخرجات (قراءة فقط، لا ينفذ الملف، لا يعمل إلا بمصادقة المالك)", "analysis", True, str, _scoped_string_extraction),
    ToolSpec("local_import_analysis", "تحليل ساكن محدود لجدول الاستيراد والإنتروبيا لملف داخل مخزن المخرجات (قراءة فقط، لا ينفذ الملف، لا يعمل إلا بمصادقة المالك)", "analysis", True, str, _scoped_import_analysis),
])

KNOWN_TOOLS = frozenset(REGISTRY)


def tool_definitions() -> list[dict[str, Any]]:
    """Build provider-neutral tool metadata from the canonical registry."""
    definitions: list[dict[str, Any]] = []
    for spec in REGISTRY.values():
        parameters: dict[str, Any] = {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        }
        if spec.argument_type is str:
            parameters["properties"]["query"] = {
                "type": "string",
                "maxLength": MAX_ARG_LENGTH,
            }
            parameters["required"] = ["query"]
        definitions.append({
            "name": spec.name,
            "description": spec.description[:512],
            "risk_class": spec.risk_class,
            "owner_required": spec.requires_owner,
            "parameters": parameters,
            **spec.metadata(),
        })
    return definitions


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def execute(name: str, argument: str | None = None, *, timeout: int | None = None, authorization_decision: Any = None, scope_context: dict[str, Any] | None = None, request_id: str | None = None, mission_authorization: Any = None, workspace: Any = None, evidence_store: Any = None, mission_id: str | None = None, target_identity: str | None = None, execution_proof: Any = None, execution_class: str | None = None, execution_run_id: str | None = None):
    spec = get_tool(name)
    if spec is None:
        raise ValueError("unknown tool")
    # The registry is the last line of defense, not a policy creator. There is
    # no implicit "not mission-bound" escape hatch: a caller cannot opt out of
    # the proof boundary by omitting mission_id. Every governed execution is
    # classified (MISSION_BOUND when mission governance kwargs are present,
    # OWNER_DIRECT otherwise) and must carry an ExecutionAuthorizationProof of
    # exactly that class, derived from authorization that already exists.
    from security.execution_proof import ExecutionAuthorizationProof, ExecutionClass, RejectionCode
    mission_bound = mission_authorization is not None or workspace is not None or evidence_store is not None or bool(mission_id)
    resolved_class = str(execution_class or (ExecutionClass.MISSION_BOUND.value if mission_bound else ExecutionClass.OWNER_DIRECT.value))
    if execution_proof is None:
        raise PermissionError(f"{RejectionCode.PROOF_REQUIRED.value}: {resolved_class} execution requires an ExecutionAuthorizationProof")
    proof_ok, proof_reason, proof_code = ExecutionAuthorizationProof.verify(execution_proof, name=name, argument=argument, mission_id=mission_id, request_id=request_id, run_id=execution_run_id)
    if not proof_ok:
        raise PermissionError(f"{proof_code}: {proof_reason}")
    if str(getattr(execution_proof, "execution_class", ExecutionClass.MISSION_BOUND.value)) != resolved_class:
        raise PermissionError(f"{RejectionCode.EXECUTION_CLASS_MISMATCH.value}: proof execution class {getattr(execution_proof, 'execution_class', '')} does not match {resolved_class} execution")
    if resolved_class == ExecutionClass.OWNER_DIRECT.value and authorization_decision is None:
        # B3-C5 second-pass attacker review: an OWNER_DIRECT execution must
        # carry the typed AuthorizationDecision that authorized it. Before
        # this check a captured owner-direct proof for a tool that is not
        # owner_only/scope_required could be replayed at the registry with
        # no decision at all, contradicting the documented OWNER_DIRECT
        # contract. Fail closed before any handler runs.
        raise PermissionError(f"{RejectionCode.PROOF_INCOMPLETE.value}: OWNER_DIRECT execution requires the typed AuthorizationDecision that authorized it")
    decision_valid = False
    if authorization_decision is not None:
        from security.authorization_context import AuthorizationDecision
        decision_valid = bool(request_id) and isinstance(authorization_decision, AuthorizationDecision) and authorization_decision.is_valid_for(name, argument, request_id)
        if not decision_valid:
            raise PermissionError("invalid or argument-mismatched AuthorizationDecision")
        # Decision binding: the proof must be bound to exactly this decision
        # (canonical signature) and its policy fingerprint. A proof derived
        # from a different decision can never authorize this execution.
        if str(getattr(authorization_decision, "decision_signature", "")) != str(getattr(execution_proof, "decision_fingerprint", "")):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: execution proof is not bound to the supplied AuthorizationDecision")
        if str(getattr(authorization_decision, "policy_fingerprint", "")) != str(getattr(execution_proof, "policy_fingerprint", "")):
            raise PermissionError(f"{RejectionCode.PROOF_BINDING_MISMATCH.value}: execution proof policy binding does not match the authorization decision policy")
    if spec.owner_only and not decision_valid:
        raise PermissionError("AuthorizationDecision required for this tool")
    if spec.scope_required and not decision_valid:
        raise PermissionError("scope-bound AuthorizationDecision required")
    if spec.scope_required:
        if not isinstance(scope_context, dict):
            raise PermissionError("scope context required")
        required = {"program_id", "target_id", "scope_snapshot_id", "url"}
        if not required.issubset(scope_context):
            raise PermissionError("incomplete scope context")
        from security.scope_resolver import resolve
        requested_url = argument if isinstance(argument, str) and "://" in argument else scope_context["url"]
        urls = [scope_context["url"]] if requested_url == scope_context["url"] else [scope_context["url"], requested_url]
        for checked_url in urls:
            decision = resolve(
                scope_context["scope_snapshot_id"],
                scope_context["target_id"],
                checked_url,
                method=scope_context.get("method", "GET"),
                expected_program_id=scope_context["program_id"],
                redirect_chain=scope_context.get("redirect_chain", []),
            )
            if not decision.allowed:
                raise PermissionError("scope denied: " + decision.reason)
    if mission_authorization is not None:
        from security.mission_authorization import MissionAuthorizationSnapshot
        snapshot = mission_authorization if isinstance(mission_authorization, MissionAuthorizationSnapshot) else MissionAuthorizationSnapshot.from_dict(dict(mission_authorization))
        if str(snapshot.authorization_hash) != str(getattr(execution_proof, "snapshot_hash", "")):
            raise PermissionError(f"{RejectionCode.SNAPSHOT_MISMATCH.value}: live mission authorization snapshot differs from the proof-bound snapshot")
        allowed, reason = snapshot.check(action=name, tool_id=name, target_identity=target_identity or snapshot.target_identity, at=None)
        if not allowed:
            raise PermissionError("mission authorization blocked: " + reason)
    valid, reason = spec.validate(argument)
    if not valid:
        raise ValueError(reason)
    limit = timeout or TOOL_TIMEOUTS.get(name, spec.timeout)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"cybersentinel-{name}")
    if name == "run_project_tests":
        # Legacy compatibility snapshot minting was removed: the registry must
        # never create authorization from a decision field. A governed
        # workspace and a real mission authorization snapshot are required
        # from the caller.
        if workspace is None or mission_authorization is None:
            raise PermissionError("run_project_tests requires a governed workspace and a mission authorization snapshot")
        workspace.bind(mission_id=str(mission_id or ""), request_id=str(request_id or ""), tool_id=name, authorization_snapshot=mission_authorization, evidence_store=evidence_store)
        future = executor.submit(spec.handler, argument, workspace=workspace)
    else:
        future = executor.submit(spec.handler, argument)
    try:
        return future.result(timeout=limit)
    except FutureTimeout as exc:
        future.cancel()
        raise ToolTimeout(f"tool {name} timed out after {limit}s") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

