from __future__ import annotations

import http.client
import ipaddress
import json
import math
import socket
import ssl
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit, urlunsplit


class PinnedRequestError(ValueError):
    """Raised when a request cannot be made without violating network policy."""


class PinnedRequestCancelled(PinnedRequestError):
    """Raised after the request cancellation event aborts an in-flight socket."""


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
                json_body=None, data: bytes | str | None = None,
                dispatch_guard: Callable[[], Any] | None = None,
                request_guard: Callable[[], Any] | None = None,
                send_guard: Callable[[], Any] | None = None,
                cancellation_event: Any | None = None,
                cancel_intent_event: Any | None = None, **kwargs) -> PinnedHTTPResponse:
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
        timeout_value = self.timeout if timeout is None else timeout
        _parsed, _scheme, host, port = _parse_pinned_url(url)
        if (
            isinstance(timeout_value, bool)
            or not isinstance(timeout_value, (int, float))
            or not math.isfinite(float(timeout_value))
            or timeout_value <= 0
            or timeout_value > 600
        ):
            raise PinnedRequestError("request timeout is outside the allowed range")
        deadline = time.monotonic() + float(timeout_value)
        addresses = resolve_public_addresses_cancellable(
            host,
            port,
            allow_loopback=self.allow_loopback,
            deadline=deadline,
            cancellation_event=cancellation_event,
            cancel_intent_event=cancel_intent_event,
        )
        request_context = request_guard() if request_guard is not None else nullcontext()
        with request_context:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
            return pinned_http_request(
                url,
                method=method,
                headers=request_headers,
                body=data,
                timeout=remaining,
                max_response_bytes=self.max_response_bytes,
                allow_loopback=self.allow_loopback,
                dispatch_guard=dispatch_guard,
                send_guard=send_guard,
                cancellation_event=cancellation_event,
                cancel_intent_event=cancel_intent_event,
                resolved_addresses=addresses,
            )

    def get(self, url: str, **kwargs) -> PinnedHTTPResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> PinnedHTTPResponse:
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        return None


_LOCAL_NAMES = frozenset({"localhost", "localhost."})
_MAX_URL_LENGTH = 8192
_DNS_SLOTS = threading.BoundedSemaphore(4)


def _parse_pinned_url(url: str):
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
    return parsed, scheme, host, port


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

    return _validate_public_addresses(host, addresses, allow_loopback=allow_loopback)


def _validate_public_addresses(
    host: str,
    addresses: list[str],
    *,
    allow_loopback: bool = False,
) -> list[str]:
    if not isinstance(addresses, list) or not addresses:
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


def resolve_public_addresses_cancellable(
    host: str,
    port: int,
    *,
    allow_loopback: bool = False,
    deadline: float,
    cancellation_event: Any | None = None,
    cancel_intent_event: Any | None = None,
) -> list[str]:
    """Resolve DNS without holding request locks and stop waiting on cancel/deadline.

    The OS resolver call itself is not forcibly killable on every platform, so
    it runs in a daemon thread from a bounded four-slot pool. A timed-out or
    cancelled resolver cannot authorize a later socket: its caller exits, and
    all callers recheck cancellation/deadline before acquiring the request gate.
    """
    def cancellation_requested() -> bool:
        for event in (cancellation_event, cancel_intent_event):
            check = getattr(event, "is_set", None)
            if callable(check) and check():
                return True
        return False

    if cancellation_requested():
        raise PinnedRequestCancelled("HTTP request was cancelled during hostname resolution")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
    if not _DNS_SLOTS.acquire(blocking=False):
        raise PinnedRequestError("hostname resolution capacity is unavailable")

    future: Future[list[str]] = Future()

    def resolve() -> None:
        if not future.set_running_or_notify_cancel():
            _DNS_SLOTS.release()
            return
        try:
            result = resolve_public_addresses(host, port, allow_loopback=allow_loopback)
        except BaseException as exc:
            future.set_exception(exc)
        else:
            future.set_result(result)
        finally:
            _DNS_SLOTS.release()

    worker = threading.Thread(target=resolve, name="cybersentinel-pinned-dns", daemon=True)
    try:
        worker.start()
    except BaseException:
        _DNS_SLOTS.release()
        raise

    while True:
        if cancellation_requested():
            future.cancel()
            raise PinnedRequestCancelled("HTTP request was cancelled during hostname resolution")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            future.cancel()
            raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
        try:
            addresses = future.result(timeout=min(0.01, remaining))
            break
        except FutureTimeout:
            continue
    if cancellation_requested():
        raise PinnedRequestCancelled("HTTP request was cancelled during hostname resolution")
    if time.monotonic() >= deadline:
        raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
    return addresses


def _connect_pinned_socket(connection: Any, pinned_ip: str) -> socket.socket:
    parsed_ip = ipaddress.ip_address(pinned_ip.split("%", 1)[0])
    family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    # Publish before bind/connect so the deadline/cancellation watcher can close
    # the exact in-flight descriptor rather than waiting for connect() to return.
    with connection._pinned_socket_lock:
        connection.sock = sock
    try:
        sock.settimeout(connection.timeout)
        if connection.source_address:
            source = connection.source_address
            if family == socket.AF_INET6 and len(source) == 2:
                source = (source[0], source[1], 0, 0)
            sock.bind(source)
        address = (pinned_ip, connection.port, 0, 0) if family == socket.AF_INET6 else (pinned_ip, connection.port)
        sock.connect(address)
        return sock
    except BaseException:
        with connection._pinned_socket_lock:
            if connection.sock is sock:
                connection.sock = None
        try:
            sock.close()
        except OSError:
            pass
        raise


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip
        self._pinned_socket_lock = threading.RLock()

    def connect(self) -> None:
        _connect_pinned_socket(self, self._pinned_ip)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, *, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip
        self._pinned_socket_lock = threading.RLock()

    def connect(self) -> None:
        raw = _connect_pinned_socket(self, self._pinned_ip)
        wrapped = None
        try:
            # Create the SSLSocket without network I/O, publish it under the
            # close lock, and only then perform a potentially blocking handshake.
            with self._pinned_socket_lock:
                wrapped = self._context.wrap_socket(
                    raw,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                )
                self.sock = wrapped
            wrapped.do_handshake()
        except BaseException:
            with self._pinned_socket_lock:
                if self.sock is raw or (wrapped is not None and self.sock is wrapped):
                    self.sock = None
            try:
                (wrapped or raw).close()
            except OSError:
                pass
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
    allow_redirect_response: bool = False,
    dispatch_guard: Callable[[], Any] | None = None,
    send_guard: Callable[[], Any] | None = None,
    cancellation_event: Any | None = None,
    cancel_intent_event: Any | None = None,
    resolved_addresses: list[str] | None = None,
) -> PinnedHTTPResponse:
    """Send one bounded HTTP request to a DNS-pinned address without redirects.

    Environment proxies are intentionally ignored so that they cannot redirect
    the request around the validated destination. Redirects are not followed;
    an intercepting browser may explicitly request the bounded 3xx response so
    its next URL can receive a separate scope decision. Only explicitly
    configured loopback model endpoints may use clear-text HTTP/private hosts.
    """
    parsed, scheme, host, port = _parse_pinned_url(url)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
        or timeout > 600
    ):
        raise PinnedRequestError("request timeout is outside the allowed range")
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 0:
        raise PinnedRequestError("response size limit is invalid")
    def cancellation_requested() -> bool:
        for event in (cancellation_event, cancel_intent_event):
            check = getattr(event, "is_set", None)
            if callable(check) and check():
                return True
        return False

    if cancellation_requested():
        raise PinnedRequestCancelled("HTTP request was cancelled before connect")
    deadline = time.monotonic() + float(timeout)
    if resolved_addresses is None:
        addresses = resolve_public_addresses_cancellable(
            host,
            port,
            allow_loopback=allow_loopback,
            deadline=deadline,
            cancellation_event=cancellation_event,
            cancel_intent_event=cancel_intent_event,
        )
    else:
        addresses = _validate_public_addresses(
            host,
            list(resolved_addresses),
            allow_loopback=allow_loopback,
        )
    if cancellation_requested():
        raise PinnedRequestCancelled("HTTP request was cancelled before connect")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
    local_override = allow_loopback and _is_explicit_loopback(host, addresses)
    expected_port = 443 if scheme == "https" else 80
    if not local_override and port != expected_port:
        raise PinnedRequestError("non-standard public HTTP port is not allowed")
    if scheme == "http" and not local_override:
        raise PinnedRequestError("clear-text HTTP is allowed only for explicit loopback endpoints")
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
    connection = connection_class(host, port, addresses[0], timeout=remaining)
    deadline_expired = threading.Event()
    request_cancelled = threading.Event()
    first_send_committing = threading.Event()
    first_send_lock = threading.Lock()
    monitor_stop = threading.Event()

    def close_active_socket() -> None:
        def close_current_socket() -> None:
            sock = connection.sock
            if sock is None:
                return
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError):
                pass
            try:
                sock.close()
            except (OSError, AttributeError):
                pass

        socket_lock = getattr(connection, "_pinned_socket_lock", None)
        if socket_lock is None:
            close_current_socket()
        else:
            with socket_lock:
                close_current_socket()

    def abort_deadline() -> None:
        deadline_expired.set()
        with first_send_lock:
            if not first_send_committing.is_set():
                close_active_socket()

    def abort_cancellation() -> None:
        request_cancelled.set()
        with first_send_lock:
            if not first_send_committing.is_set():
                close_active_socket()

    def raise_if_deadline_expired() -> None:
        if deadline_expired.is_set() or time.monotonic() >= deadline:
            abort_deadline()
            raise socket.timeout("HTTP request exceeded its total wall-clock deadline")

    def raise_if_stopped() -> None:
        raise_if_deadline_expired()
        if request_cancelled.is_set() or cancellation_requested():
            abort_cancellation()
            raise PinnedRequestCancelled("HTTP request was cancelled")

    timeout_timer = threading.Timer(max(0.0, deadline - time.monotonic()), abort_deadline)
    timeout_timer.daemon = True
    timeout_timer.start()
    def watch_abort_conditions() -> None:
        while not monitor_stop.wait(0.005):
            if cancellation_requested():
                # Keep watching after the signal: the connect thread may have
                # published its socket just after an earlier close attempt.
                abort_cancellation()
            elif deadline_expired.is_set() or time.monotonic() >= deadline:
                abort_deadline()

    abort_watcher = threading.Thread(target=watch_abort_conditions, daemon=True)
    abort_watcher.start()

    first_send = True
    original_send = getattr(connection, "send", None)
    has_socket_send = callable(original_send)

    def run_in_dispatch_guard(callback: Callable[[], Any]):
        if dispatch_guard is None:
            return callback()
        with dispatch_guard():
            return callback()

    def guarded_socket_send(data) -> None:
        def send_while_guarded() -> None:
            nonlocal first_send
            raise_if_stopped()
            if first_send:
                # Once the callback durably records DISPATCHED, do not let the
                # deadline/cancel watcher close the socket before this first
                # write. The Owner marker waits on this same guard; after this
                # write returns, a pending interrupt closes the socket before
                # any subsequent write.
                with first_send_lock:
                    if deadline_expired.is_set() or time.monotonic() >= deadline:
                        deadline_expired.set()
                        close_active_socket()
                        raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
                    if request_cancelled.is_set() or cancellation_requested():
                        request_cancelled.set()
                        close_active_socket()
                        raise PinnedRequestCancelled("HTTP request was cancelled")
                    first_send_committing.set()
                try:
                    if send_guard is not None:
                        send_guard()
                    first_send = False
                    original_send(data)
                finally:
                    with first_send_lock:
                        first_send_committing.clear()
                        if request_cancelled.is_set() or cancellation_requested():
                            request_cancelled.set()
                            close_active_socket()
                        elif deadline_expired.is_set() or time.monotonic() >= deadline:
                            deadline_expired.set()
                            close_active_socket()
                return
            # Hold the same short gate used by Owner cancellation through each
            # actual socket write; no write can start after the durable marker.
            original_send(data)

        run_in_dispatch_guard(send_while_guarded)

    if has_socket_send:
        connection.send = guarded_socket_send

    def issue_request() -> None:
        nonlocal first_send

        def request_while_guarded() -> None:
            nonlocal first_send
            raise_if_stopped()
            if not has_socket_send and first_send:
                if send_guard is not None:
                    send_guard()
                raise_if_stopped()
                first_send = False
            connection.request(method, target, body=body, headers=request_headers)

        if has_socket_send:
            # HTTPConnection.send() is guarded per write by guarded_socket_send.
            request_while_guarded()
        else:
            # Adapter transports have no observable socket write; guard request entry.
            run_in_dispatch_guard(request_while_guarded)

    try:
        raise_if_stopped()
        # Finish pinned TCP/TLS setup before crossing the Owner/effect dispatch
        # gate. The gate below then rechecks cancellation, deadline and scope
        # with no blocking connect between that check and the first request send.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("HTTP request exceeded its total wall-clock deadline")
        connection.timeout = remaining
        connection.connect()
        raise_if_stopped()
        issue_request()
        raise_if_stopped()
        response = connection.getresponse()
        if 300 <= response.status < 400 and not allow_redirect_response:
            response.close()
            raise PinnedRequestError("HTTP redirects are not allowed")
        content = response.read(max_response_bytes + 1)
        raise_if_stopped()
        if len(content) > max_response_bytes:
            raise PinnedRequestError("HTTP response exceeds the configured size limit")
        return PinnedHTTPResponse(
            int(response.status),
            {str(key).lower(): str(value) for key, value in response.getheaders()},
            content,
        )
    except Exception as exc:
        if deadline_expired.is_set() or time.monotonic() >= deadline:
            raise socket.timeout("HTTP request exceeded its total wall-clock deadline") from exc
        if request_cancelled.is_set() or cancellation_requested():
            raise PinnedRequestCancelled("HTTP request was cancelled") from None
        raise
    finally:
        monitor_stop.set()
        timeout_timer.cancel()
        socket_lock = getattr(connection, "_pinned_socket_lock", None)
        if socket_lock is None:
            connection.close()
        else:
            with socket_lock:
                connection.close()
        abort_watcher.join(timeout=0.05)


__all__ = ["PinnedHTTPResponse", "PinnedRequestCancelled", "PinnedRequestError", "PinnedSession", "pinned_http_request", "resolve_public_addresses"]
