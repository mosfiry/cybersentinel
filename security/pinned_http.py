from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit, urlunsplit


class PinnedRequestError(ValueError):
    """Raised when a request cannot be made without violating network policy."""


@dataclass(frozen=True)
class PinnedHTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def status_code(self) -> int:
        return self.status

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class PinnedSession:
    """Small requests-compatible wrapper that never delegates DNS to a client."""

    def __init__(self, *, headers: dict[str, str] | None = None, timeout: float = 15.0,
                 max_response_bytes: int = 2_000_000, allow_loopback: bool = False):
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.allow_loopback = allow_loopback

    def request(self, method: str, url: str, *, params: dict | None = None,
                timeout: float | None = None, headers: dict[str, str] | None = None,
                json_body=None, data: bytes | str | None = None, **kwargs) -> PinnedHTTPResponse:
        if kwargs:
            raise PinnedRequestError("unsupported HTTP request options")
        if params:
            parsed = urlsplit(url)
            query = parsed.query
            encoded = urlencode(params, doseq=True)
            query = f"{query}&{encoded}" if query and encoded else query or encoded
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
        request_headers = {**self.headers, **(headers or {})}
        if json_body is not None:
            if data is not None:
                raise PinnedRequestError("request body cannot be both JSON and data")
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        return pinned_http_request(
            url,
            method=method,
            headers=request_headers,
            body=data,
            timeout=self.timeout if timeout is None else timeout,
            max_response_bytes=self.max_response_bytes,
            allow_loopback=self.allow_loopback,
        )

    def get(self, url: str, **kwargs) -> PinnedHTTPResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> PinnedHTTPResponse:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        return None


_LOCAL_NAMES = frozenset({"localhost", "localhost."})
_MAX_URL_LENGTH = 8192


def _is_explicit_loopback(host: str, addresses: list[str]) -> bool:
    normalized = host.casefold()
    if normalized not in _LOCAL_NAMES:
        try:
            return ipaddress.ip_address(normalized.split("%", 1)[0]).is_loopback and all(
                ipaddress.ip_address(item.split("%", 1)[0]).is_loopback for item in addresses
            )
        except ValueError:
            return False
    try:
        return bool(addresses) and all(
            ipaddress.ip_address(item.split("%", 1)[0]).is_loopback for item in addresses
        )
    except ValueError:
        return False


def resolve_public_addresses(host: str, port: int, *, allow_loopback: bool = False) -> list[str]:
    """Resolve once, reject mixed/private answers, and return addresses to pin."""
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise PinnedRequestError("hostname resolution failed") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    else:
        addresses = [str(literal)]

    if not addresses:
        raise PinnedRequestError("hostname has no usable addresses")
    local_override = allow_loopback and _is_explicit_loopback(host, addresses)
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise PinnedRequestError("hostname resolved to an invalid address") from exc
        if not ip.is_global and not (local_override and ip.is_loopback):
            raise PinnedRequestError("hostname resolved to a non-public address")
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def pinned_http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 15.0,
    max_response_bytes: int = 2_000_000,
    allow_loopback: bool = False,
) -> PinnedHTTPResponse:
    """Send one bounded HTTP request to a DNS-pinned address without redirects.

    Environment proxies are intentionally ignored so that they cannot redirect
    the request around the validated destination. Only explicitly configured
    loopback model endpoints may use clear-text HTTP or a private address.
    """
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise PinnedRequestError("URL is empty or exceeds the limit")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PinnedRequestError("URL is malformed") from exc
    scheme = parsed.scheme.casefold()
    host = parsed.hostname
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(ord(char) < 0x20 for char in url)
    ):
        raise PinnedRequestError("URL scheme, authority, or path is not allowed")
    if port == 0:
        raise PinnedRequestError("URL port is invalid")
    port = port if port is not None else (443 if scheme == "https" else 80)
    addresses = resolve_public_addresses(host, port, allow_loopback=allow_loopback)
    local_override = allow_loopback and _is_explicit_loopback(host, addresses)
    expected_port = 443 if scheme == "https" else 80
    if not local_override and port != expected_port:
        raise PinnedRequestError("non-standard public HTTP port is not allowed")
    if scheme == "http" and not local_override:
        raise PinnedRequestError("clear-text HTTP is allowed only for explicit loopback endpoints")
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 600:
        raise PinnedRequestError("request timeout is outside the allowed range")
    if not isinstance(max_response_bytes, int) or max_response_bytes < 0:
        raise PinnedRequestError("response size limit is invalid")
    method = str(method).upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD"}:
        raise PinnedRequestError("HTTP method is not allowed")

    request_headers = {str(key): str(value) for key, value in (headers or {}).items()}
    if any(key.casefold() in {"host", "proxy-authorization", "connection"} for key in request_headers):
        raise PinnedRequestError("restricted HTTP header supplied")
    request_headers["Connection"] = "close"
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    connection_class = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    connection = connection_class(host, port, addresses[0], timeout=float(timeout))
    try:
        connection.request(method, target, body=body, headers=request_headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            response.close()
            raise PinnedRequestError("HTTP redirects are not allowed")
        content = response.read(max_response_bytes + 1)
        if len(content) > max_response_bytes:
            raise PinnedRequestError("HTTP response exceeds the configured size limit")
        return PinnedHTTPResponse(
            int(response.status),
            {str(key).lower(): str(value) for key, value in response.getheaders()},
            content,
        )
    finally:
        connection.close()


__all__ = ["PinnedHTTPResponse", "PinnedRequestError", "PinnedSession", "pinned_http_request", "resolve_public_addresses"]
