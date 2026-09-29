from __future__ import annotations

"""Fail-closed, one-request HTTP GET transport for an Owner-authorized scope.

This module intentionally has no generic request API: it emits exactly one GET,
never forwards caller headers or credentials, never follows redirects, and only
returns bounded response metadata. The response is an untrusted observation.
"""

import hashlib
import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from security.scope import ScopeError, canonical_url


SCOPE_CONTEXT_FIELDS = frozenset({"program_id", "target_id", "scope_snapshot_id", "url"})
MAX_REQUEST_URL_LENGTH = 2048
MAX_RESPONSE_BODY_BYTES = 64 * 1024
MAX_RESPONSE_HEADER_BYTES = 16 * 1024
MAX_RESPONSE_HEADERS = 64
MAX_RESPONSE_HEADER_LINE_BYTES = 4096
MAX_OUTPUT_CHARS = 1024
CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 2.0
DNS_TIMEOUT_SECONDS = 1.5
TOTAL_TIMEOUT_SECONDS = 8.0
_MAX_DNS_ANSWERS = 32

_HEX_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]+\Z")

_DNS_LOCK = threading.Lock()
_DNS_BUSY = False


class _ProbeFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def validate_scope_context_fields(scope_context: Any) -> dict[str, str]:
    """Return the exact four-field context, rejecting omissions and additions."""
    if not isinstance(scope_context, dict):
        raise PermissionError("scope_context_required")
    keys = set(scope_context)
    if keys != SCOPE_CONTEXT_FIELDS:
        if SCOPE_CONTEXT_FIELDS - keys:
            raise PermissionError("scope_context_missing_required_fields")
        raise PermissionError("scope_context_has_unexpected_fields")
    if any(not isinstance(scope_context[key], str) or not scope_context[key].strip() or scope_context[key] != scope_context[key].strip() for key in SCOPE_CONTEXT_FIELDS):
        raise PermissionError("scope_context_fields_must_be_non_empty_strings")
    if any(len(scope_context[key]) > MAX_REQUEST_URL_LENGTH for key in SCOPE_CONTEXT_FIELDS):
        raise PermissionError("scope_context_field_exceeds_limit")
    return {key: scope_context[key] for key in SCOPE_CONTEXT_FIELDS}


def _canonical_probe_url(value: Any) -> tuple[str, Any, int]:
    if not isinstance(value, str) or not value or len(value) > MAX_REQUEST_URL_LENGTH:
        raise _ProbeFailure("invalid_url")
    if value != value.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise _ProbeFailure("invalid_url")
    try:
        if "#" in value:
            raise _ProbeFailure("url_fragment_not_allowed")
        normalized = canonical_url(value)
        parts = urlsplit(normalized)
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except (ScopeError, ValueError):
        raise _ProbeFailure("invalid_url") from None
    if parts.scheme not in {"http", "https"} or not parts.hostname or not 1 <= port <= 65535:
        raise _ProbeFailure("invalid_url")
    host = parts.hostname
    if "%" in host:
        # Zone-scoped IPv6 and percent-encoded host syntax are not valid targets.
        raise _ProbeFailure("invalid_url")
    path = parts.path or "/"
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        raise _ProbeFailure("non_canonical_path")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise _ProbeFailure("path_traversal_not_allowed")
    # Reject encoded separators, dot-segments, control bytes, and encoded '%' to
    # prevent server-side normalization and double-decoding from escaping scope.
    for match in _HEX_ESCAPE.finditer(path):
        byte = int(match.group(1), 16)
        if byte in {0x00, 0x2E, 0x2F, 0x5C, 0x25} or byte < 0x20 or byte == 0x7F:
            raise _ProbeFailure("non_canonical_path")
    if "%" in path and not _HEX_ESCAPE.sub("", path).find("%") == -1:
        raise _ProbeFailure("invalid_percent_escape")
    target = path + (("?" + parts.query) if parts.query else "")
    try:
        target.encode("ascii")
        normalized.encode("ascii")
    except UnicodeEncodeError:
        raise _ProbeFailure("url_must_be_ascii_or_percent_encoded") from None
    if any(ord(char) < 0x20 or ord(char) == 0x7F or char.isspace() for char in parts.query):
        raise _ProbeFailure("invalid_url_query")
    return normalized, parts, port


def _scope_authorized_url(argument: Any, scope_context: Any, *, consume_rate: bool) -> str:
    context = validate_scope_context_fields(scope_context)
    try:
        from security.scope_resolver import resolve
        from security.scope_store import get_snapshot

        snapshot = get_snapshot(context["scope_snapshot_id"])
    except Exception:
        raise PermissionError("scope_snapshot_unavailable") from None
    if snapshot is None:
        raise PermissionError("scope_snapshot_not_persisted")
    if snapshot.authorization.program_id != context["program_id"]:
        raise PermissionError("scope_program_mismatch")
    target = snapshot.target(context["target_id"])
    if target is None or target.program_id != context["program_id"]:
        raise PermissionError("scope_target_mismatch")

    try:
        requested_url, _parts, _port = _canonical_probe_url(argument)
        reference_url, _reference_parts, _reference_port = _canonical_probe_url(context["url"])
    except _ProbeFailure as exc:
        raise PermissionError("scope_url_invalid") from exc

    # GET is fixed by policy. No context-provided method or redirect list can
    # broaden this capability. The resolver binds each URL to the live snapshot,
    # program, target host/ports/paths, exclusions, and program method policy.
    reference = resolve(
        context["scope_snapshot_id"], context["target_id"], reference_url,
        method="GET", expected_program_id=context["program_id"],
        consume_rate=False,
    )
    if not reference.allowed:
        raise PermissionError("scope denied: " + reference.reason)
    requested = resolve(
        context["scope_snapshot_id"], context["target_id"], requested_url,
        method="GET", expected_program_id=context["program_id"],
        consume_rate=False,
    )
    if not requested.allowed:
        raise PermissionError("scope denied: " + requested.reason)
    if consume_rate:
        # Charge exactly one event for the actual request URL. Handler-level
        # revalidation uses consume_rate=False and cannot double-charge.
        requested = resolve(
            context["scope_snapshot_id"], context["target_id"], requested_url,
            method="GET", expected_program_id=context["program_id"],
            consume_rate=True,
        )
        if not requested.allowed:
            raise PermissionError("scope denied: " + requested.reason)
    return requested.canonical_url or requested_url


def _is_global_unicast(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_multicast
        and not address.is_unspecified
        and not (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
    )


def _resolve_public_addresses(host: str, port: int, deadline: float) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    global _DNS_BUSY
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_global_unicast(str(literal)):
            raise _ProbeFailure("dns_non_public_address")
        if literal.version == 4:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(literal), port))]
        return [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, (str(literal), port, 0, 0))]

    remaining = min(DNS_TIMEOUT_SECONDS, deadline - time.monotonic())
    if remaining <= 0:
        raise _ProbeFailure("total_timeout")
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
    with _DNS_LOCK:
        if _DNS_BUSY:
            raise _ProbeFailure("dns_resolver_busy")
        _DNS_BUSY = True

    def resolve_once() -> None:
        global _DNS_BUSY
        try:
            result = (True, socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP))
        except BaseException:
            result = (False, None)
        finally:
            with _DNS_LOCK:
                _DNS_BUSY = False
        try:
            result_queue.put(result)
        except queue.Full:
            pass

    threading.Thread(target=resolve_once, name="cybersentinel-scoped-probe-dns", daemon=True).start()
    try:
        ok, records = result_queue.get(timeout=remaining)
    except queue.Empty:
        raise _ProbeFailure("dns_timeout") from None
    if not ok or not isinstance(records, list) or not records or len(records) > _MAX_DNS_ANSWERS:
        raise _ProbeFailure("dns_failure")

    vetted: list[tuple[int, int, int, tuple[Any, ...]]] = []
    for record in records:
        try:
            family, socktype, proto, _canonname, sockaddr = record
            if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
                raise ValueError
            if not isinstance(sockaddr, tuple) or not sockaddr or not _is_global_unicast(str(sockaddr[0])):
                raise ValueError
            if family == socket.AF_INET6 and (len(sockaddr) < 4 or int(sockaddr[3]) != 0 or "%" in str(sockaddr[0])):
                raise ValueError
            vetted.append((family, socktype, proto or socket.IPPROTO_TCP, sockaddr))
        except (TypeError, ValueError, IndexError):
            # Any non-public or malformed answer invalidates the entire answer
            # set, including mixed public/private DNS responses.
            raise _ProbeFailure("dns_non_public_address") from None
    if not vetted:
        raise _ProbeFailure("dns_failure")
    return vetted


def _remaining(deadline: float, cap: float, code: str) -> float:
    value = min(cap, deadline - time.monotonic())
    if value <= 0:
        raise _ProbeFailure(code)
    return value


def _connect_pinned(addresses: list[tuple[int, int, int, tuple[Any, ...]]], *, host: str, port: int, https: bool, deadline: float) -> socket.socket:
    last_code = "connect_failure"
    for family, socktype, proto, sockaddr in addresses:
        raw: socket.socket | None = None
        try:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(_remaining(deadline, CONNECT_TIMEOUT_SECONDS, "connect_timeout"))
            raw.connect(sockaddr)
            if not https:
                return raw
            context = ssl.create_default_context()
            if context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True:
                raw.close()
                raise _ProbeFailure("tls_validation_unavailable")
            raw.settimeout(_remaining(deadline, READ_TIMEOUT_SECONDS, "tls_timeout"))
            secured = context.wrap_socket(raw, server_hostname=host)
            return secured
        except _ProbeFailure:
            if raw is not None:
                raw.close()
            raise
        except ssl.SSLCertVerificationError:
            if raw is not None:
                raw.close()
            raise _ProbeFailure("tls_certificate_invalid") from None
        except ssl.SSLError:
            if raw is not None:
                raw.close()
            raise _ProbeFailure("tls_failure") from None
        except socket.timeout:
            if raw is not None:
                raw.close()
            last_code = "connect_timeout"
        except OSError:
            if raw is not None:
                raw.close()
            last_code = "connect_failure"
    raise _ProbeFailure(last_code)


class _SocketReader:
    def __init__(self, sock: socket.socket, *, deadline: float):
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()

    def _recv(self, size: int) -> bytes:
        self.sock.settimeout(_remaining(self.deadline, READ_TIMEOUT_SECONDS, "read_timeout"))
        try:
            return self.sock.recv(size)
        except socket.timeout:
            raise _ProbeFailure("read_timeout") from None
        except OSError:
            raise _ProbeFailure("network_read_failure") from None

    def read_until(self, separator: bytes, limit: int, *, error_code: str) -> bytes:
        while True:
            index = self.buffer.find(separator)
            if index >= 0:
                end = index + len(separator)
                if end > limit:
                    raise _ProbeFailure(error_code)
                value = bytes(self.buffer[:index])
                del self.buffer[:end]
                return value
            if len(self.buffer) >= limit:
                raise _ProbeFailure(error_code)
            chunk = self._recv(min(4096, limit - len(self.buffer)))
            if not chunk:
                raise _ProbeFailure("incomplete_response")
            self.buffer.extend(chunk)

    def read_line(self, limit: int) -> bytes:
        return self.read_until(b"\r\n", limit, error_code="invalid_chunk_framing")

    def read_exact(self, size: int) -> bytes:
        if size < 0:
            raise _ProbeFailure("invalid_response_length")
        output = bytearray()
        while len(output) < size:
            if self.buffer:
                count = min(size - len(output), len(self.buffer))
                output.extend(self.buffer[:count])
                del self.buffer[:count]
                continue
            chunk = self._recv(min(8192, size - len(output)))
            if not chunk:
                raise _ProbeFailure("incomplete_response_body")
            output.extend(chunk)
        return bytes(output)

    def read_some(self, size: int) -> bytes:
        if self.buffer:
            count = min(size, len(self.buffer))
            value = bytes(self.buffer[:count])
            del self.buffer[:count]
            return value
        return self._recv(size)


def _parse_response_headers(reader: _SocketReader) -> tuple[int, dict[str, list[str]]]:
    raw = reader.read_until(b"\r\n\r\n", MAX_RESPONSE_HEADER_BYTES, error_code="response_headers_too_large")
    lines = raw.split(b"\r\n")
    if not lines:
        raise _ProbeFailure("invalid_response_status")
    try:
        status_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        raise _ProbeFailure("invalid_response_status") from None
    match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", status_line)
    if not match:
        raise _ProbeFailure("invalid_response_status")
    status = int(match.group(1))
    if status < 200:
        raise _ProbeFailure("interim_response_not_supported")
    headers: dict[str, list[str]] = {}
    if len(lines) - 1 > MAX_RESPONSE_HEADERS:
        raise _ProbeFailure("too_many_response_headers")
    for line in lines[1:]:
        if len(line) > MAX_RESPONSE_HEADER_LINE_BYTES or not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise _ProbeFailure("invalid_response_headers")
        name, value = line.split(b":", 1)
        try:
            header_name = name.decode("ascii")
            header_value = value.decode("latin-1").strip(" \t")
        except UnicodeDecodeError:
            raise _ProbeFailure("invalid_response_headers") from None
        if not _HEADER_NAME.fullmatch(header_name):
            raise _ProbeFailure("invalid_response_headers")
        if any((ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F for char in header_value):
            raise _ProbeFailure("invalid_response_headers")
        headers.setdefault(header_name.casefold(), []).append(header_value)
    return status, headers


def _read_chunked_body(reader: _SocketReader) -> tuple[bytes, bool]:
    body = bytearray()
    trailer_bytes = 0
    trailer_count = 0
    while True:
        size_line = reader.read_line(128)
        size_token = size_line.split(b";", 1)[0]
        if not size_token or not _CHUNK_SIZE.fullmatch(size_token):
            raise _ProbeFailure("invalid_chunk_framing")
        size = int(size_token, 16)
        if size == 0:
            while True:
                trailer = reader.read_line(MAX_RESPONSE_HEADER_LINE_BYTES)
                trailer_bytes += len(trailer) + 2
                trailer_count += 1
                if trailer_bytes > MAX_RESPONSE_HEADER_BYTES or trailer_count > MAX_RESPONSE_HEADERS:
                    raise _ProbeFailure("response_trailers_too_large")
                if not trailer:
                    return bytes(body), False
                if b":" not in trailer:
                    raise _ProbeFailure("invalid_chunk_framing")
        remaining = MAX_RESPONSE_BODY_BYTES + 1 - len(body)
        take = min(size, max(0, remaining))
        if take:
            body.extend(reader.read_exact(take))
        if size > take or len(body) > MAX_RESPONSE_BODY_BYTES:
            return bytes(body[:MAX_RESPONSE_BODY_BYTES]), True
        if reader.read_exact(2) != b"\r\n":
            raise _ProbeFailure("invalid_chunk_framing")


def _read_body(reader: _SocketReader, status: int, headers: dict[str, list[str]]) -> tuple[bytes, bool]:
    if 300 <= status < 400 or status in {204, 205, 304}:
        return b"", False
    transfer_values = headers.get("transfer-encoding", [])
    content_lengths = headers.get("content-length", [])
    if len(transfer_values) > 1 or len(content_lengths) > 1 or (transfer_values and content_lengths):
        raise _ProbeFailure("ambiguous_response_framing")
    if transfer_values:
        if transfer_values[0].casefold() != "chunked":
            raise _ProbeFailure("unsupported_transfer_encoding")
        return _read_chunked_body(reader)
    if content_lengths:
        value = content_lengths[0]
        if not value.isascii() or not value.isdecimal():
            raise _ProbeFailure("invalid_content_length")
        length = int(value)
        if length > MAX_RESPONSE_BODY_BYTES:
            return reader.read_exact(MAX_RESPONSE_BODY_BYTES + 1)[:MAX_RESPONSE_BODY_BYTES], True
        return reader.read_exact(length), False

    body = bytearray()
    while len(body) <= MAX_RESPONSE_BODY_BYTES:
        chunk = reader.read_some(min(8192, MAX_RESPONSE_BODY_BYTES + 1 - len(body)))
        if not chunk:
            return bytes(body), False
        body.extend(chunk)
    return bytes(body[:MAX_RESPONSE_BODY_BYTES]), True


def _safe_content_type(headers: dict[str, list[str]]) -> str:
    values = headers.get("content-type", [])
    if not values:
        return ""
    value = values[0]
    safe = "".join(char for char in value if 0x20 <= ord(char) <= 0x7E)
    return safe[:128]


def _bounded_result(*, success: bool, outcome: str, status: int | None = None, content_type: str = "", body: bytes = b"", truncated: bool = False, error_code: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": bool(success),
        "outcome": str(outcome),
        "observation_only": True,
        "status": status,
        "content_type": content_type[:128],
        "byte_count": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "truncated": bool(truncated),
    }
    if error_code:
        result["error_code"] = error_code
    if len(json.dumps(result, ensure_ascii=True, separators=(",", ":"))) > MAX_OUTPUT_CHARS:
        return {
            "success": False,
            "outcome": "output_limit",
            "observation_only": True,
            "error_code": "result_metadata_too_large",
        }
    return result


def _perform_get(canonical: str, *, deadline: float) -> dict[str, Any]:
    parts = urlsplit(canonical)
    host = parts.hostname or ""
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    addresses = _resolve_public_addresses(host, port, deadline)
    sock = _connect_pinned(addresses, host=host, port=port, https=parts.scheme == "https", deadline=deadline)
    try:
        host_header = f"[{host}]" if ":" in host else host
        default_port = 443 if parts.scheme == "https" else 80
        if port != default_port:
            host_header = f"{host_header}:{port}"
        request_target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        request = (
            f"GET {request_target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: CyberSentinel scoped HTTP GET\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.settimeout(_remaining(deadline, READ_TIMEOUT_SECONDS, "total_timeout"))
        try:
            sock.sendall(request)
        except socket.timeout:
            raise _ProbeFailure("write_timeout") from None
        except OSError:
            raise _ProbeFailure("network_write_failure") from None
        reader = _SocketReader(sock, deadline=deadline)
        status, headers = _parse_response_headers(reader)
        content_type = _safe_content_type(headers)
        if time.monotonic() > deadline:
            raise _ProbeFailure("total_timeout")
        if 300 <= status < 400:
            # Deterministic no-redirect policy: do not parse or connect to the
            # Location value; close immediately and expose no redirect target.
            return _bounded_result(success=False, outcome="redirect_blocked", status=status, content_type=content_type)
        body, truncated = _read_body(reader, status, headers)
        if time.monotonic() > deadline:
            raise _ProbeFailure("total_timeout")
        return _bounded_result(success=True, outcome="response_received", status=status, content_type=content_type, body=body, truncated=truncated)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def scoped_http_probe(argument: str | None, *, scope_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fetch one in-scope URL with exactly one credential-free GET."""
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    canonical = _scope_authorized_url(argument, scope_context, consume_rate=False)
    if time.monotonic() > deadline:
        return _bounded_result(success=False, outcome="request_blocked_or_failed", error_code="total_timeout")
    try:
        return _perform_get(canonical, deadline=deadline)
    except _ProbeFailure as exc:
        return _bounded_result(success=False, outcome="request_blocked_or_failed", error_code=exc.code)
    except Exception:
        # Never surface resolver, socket, TLS, or parser exception text to a
        # model or user; external error text is untrusted and may contain data.
        return _bounded_result(success=False, outcome="request_blocked_or_failed", error_code="internal_transport_failure")


__all__ = [
    "MAX_RESPONSE_BODY_BYTES",
    "MAX_RESPONSE_HEADER_BYTES",
    "MAX_OUTPUT_CHARS",
    "SCOPE_CONTEXT_FIELDS",
    "scoped_http_probe",
    "validate_scope_context_fields",
]
