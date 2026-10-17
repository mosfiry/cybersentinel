from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from security.pinned_http import (
    PinnedRequestCancelled,
    PinnedRequestError,
    _PinnedHTTPConnection,
    pinned_http_request,
    resolve_public_addresses,
)


def _dns_record(host: str, address: str, port: int = 443):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_dns_resolutions_with_private_or_mixed_addresses_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "security.pinned_http.socket.getaddrinfo",
        lambda host, port, **kwargs: [_dns_record(host, "8.8.8.8", port), _dns_record(host, "10.1.2.3", port)],
    )

    with pytest.raises(PinnedRequestError, match="non-public address"):
        resolve_public_addresses("rebinding.example", 443)


def test_private_dns_answer_cannot_use_localhost_exception(monkeypatch):
    monkeypatch.setattr(
        "security.pinned_http.socket.getaddrinfo",
        lambda host, port, **kwargs: [_dns_record(host, "127.0.0.1", port)],
    )

    with pytest.raises(PinnedRequestError, match="non-public address"):
        resolve_public_addresses("attacker.example", 443, allow_loopback=True)


def test_invalid_ports_fail_before_connection():
    with pytest.raises(PinnedRequestError, match="port"):
        pinned_http_request("https://example.invalid:0")
    with pytest.raises(PinnedRequestError, match="malformed"):
        pinned_http_request("https://example.invalid:70000")


def test_explicit_localhost_is_allowed_only_for_loopback_results(monkeypatch):
    monkeypatch.setattr(
        "security.pinned_http.socket.getaddrinfo",
        lambda host, port, **kwargs: [_dns_record(host, "127.0.0.1", port)],
    )

    assert resolve_public_addresses("localhost", 11434, allow_loopback=True) == ["127.0.0.1"]
    with pytest.raises(PinnedRequestError, match="non-public address"):
        resolve_public_addresses("localhost", 11434)


def test_http_connection_uses_the_validated_ip_without_resolving_again(monkeypatch):
    observed = {}

    class FakeSocket:
        def settimeout(self, timeout):
            observed["timeout"] = timeout

        def connect(self, address):
            observed["address"] = address

        def close(self):
            pass

    def fake_socket(*args):
        observed["family"] = args[0]
        return FakeSocket()

    monkeypatch.setattr("security.pinned_http.socket.socket", fake_socket)
    connection = _PinnedHTTPConnection("api.example", 80, "93.184.216.34", timeout=4)
    connection.connect()
    connection.close()

    assert observed == {
        "address": ("93.184.216.34", 80),
        "timeout": 4.0,
        "family": socket.AF_INET,
    }


@pytest.mark.parametrize("interrupt_kind", ["owner_cancel", "deadline"])
def test_dns_resolution_wait_is_bounded_and_cancellable(monkeypatch, interrupt_kind):
    from security import pinned_http

    dns_started = threading.Event()
    release_dns = threading.Event()
    connection_created = threading.Event()
    cancellation_event = threading.Event()
    outcome = []

    def blocked_resolver(*_args, **_kwargs):
        dns_started.set()
        release_dns.wait(timeout=3)
        return ["93.184.216.34"]

    class UnexpectedConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def connect(self):
            connection_created.set()

        def close(self):
            return None

    monkeypatch.setattr(pinned_http, "resolve_public_addresses", blocked_resolver)
    monkeypatch.setattr(pinned_http, "_PinnedHTTPSConnection", UnexpectedConnection)

    def make_request():
        try:
            pinned_http.pinned_http_request(
                "https://public.example/",
                timeout=2.0 if interrupt_kind == "owner_cancel" else 0.05,
                cancellation_event=cancellation_event,
            )
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=make_request)
    worker.start()
    try:
        assert dns_started.wait(timeout=1)
        if interrupt_kind == "owner_cancel":
            cancellation_event.set()
            expected = PinnedRequestCancelled
        else:
            expected = socket.timeout
        worker.join(timeout=1)
        assert not worker.is_alive()
        assert outcome and isinstance(outcome[0], expected)
        assert not connection_created.is_set()
    finally:
        release_dns.set()
        worker.join(timeout=1)


def test_total_deadline_closes_raw_socket_during_tls_handshake(monkeypatch):
    from security import pinned_http

    handshake_started = threading.Event()
    socket_closed = threading.Event()

    class FakeSocket:
        def settimeout(self, _timeout):
            return None

        def connect(self, _address):
            return None

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    raw_socket = FakeSocket()

    class FakeSSLSocket:
        def do_handshake(self):
            assert connections and connections[0].sock is self
            assert socket_closed.wait(timeout=2)
            raise OSError("handshake interrupted by request deadline")

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    connections = []
    original_connection = pinned_http._PinnedHTTPSConnection

    def make_connection(*args, **kwargs):
        connection = original_connection(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(pinned_http, "_PinnedHTTPSConnection", make_connection)

    class BlockingTLSContext:
        def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
            assert raw is raw_socket
            assert server_hostname == "public.example"
            assert do_handshake_on_connect is False
            handshake_started.set()
            wrapped = FakeSSLSocket()
            assert connections and connections[0].sock is raw
            return wrapped

    monkeypatch.setattr(pinned_http, "resolve_public_addresses", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_args, **_kwargs: raw_socket)
    monkeypatch.setattr(pinned_http.ssl, "create_default_context", BlockingTLSContext)
    started = time.monotonic()
    with pytest.raises(socket.timeout, match="total wall-clock deadline"):
        pinned_http.pinned_http_request("https://public.example/data", timeout=0.1)
    assert handshake_started.is_set()
    assert socket_closed.is_set()
    assert time.monotonic() - started < 0.75


@pytest.mark.parametrize("phase", ["tcp_connect", "tls_handshake"])
def test_owner_cancellation_closes_socket_during_connect_or_tls_handshake(monkeypatch, phase):
    from security import pinned_http

    cancellation = threading.Event()
    socket_started = threading.Event()
    socket_closed = threading.Event()
    handshake_started = threading.Event()
    outcome = []

    class FakeSocket:
        def settimeout(self, _timeout):
            return None

        def bind(self, _address):
            return None

        def connect(self, _address):
            socket_started.set()
            if phase == "tcp_connect":
                assert socket_closed.wait(timeout=2)
                raise OSError("connect interrupted by Owner cancellation")

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    raw_socket = FakeSocket()

    class FakeSSLSocket:
        def do_handshake(self):
            assert connections and connections[0].sock is self
            handshake_started.set()
            assert socket_closed.wait(timeout=2)
            raise OSError("handshake interrupted by Owner cancellation")

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    connections = []
    original_connection = pinned_http._PinnedHTTPSConnection

    def make_connection(*args, **kwargs):
        connection = original_connection(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(pinned_http, "_PinnedHTTPSConnection", make_connection)

    class BlockingTLSContext:
        def wrap_socket(self, raw, *, server_hostname, do_handshake_on_connect):
            assert raw is raw_socket
            assert server_hostname == "public.example"
            assert do_handshake_on_connect is False
            wrapped = FakeSSLSocket()
            assert connections and connections[0].sock is raw
            return wrapped

    monkeypatch.setattr(pinned_http, "resolve_public_addresses", lambda *_args, **_kwargs: [
        "127.0.0.1" if phase == "tcp_connect" else "93.184.216.34"
    ])
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_args, **_kwargs: raw_socket)
    if phase == "tls_handshake":
        monkeypatch.setattr(pinned_http.ssl, "create_default_context", BlockingTLSContext)

    def request():
        try:
            pinned_http.pinned_http_request(
                "http://127.0.0.1/local" if phase == "tcp_connect" else "https://public.example/mcp",
                timeout=2,
                allow_loopback=phase == "tcp_connect",
                cancellation_event=cancellation,
            )
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=request)
    worker.start()
    assert socket_started.wait(timeout=1)
    if phase == "tls_handshake":
        assert handshake_started.wait(timeout=1)
    cancellation.set()
    worker.join(timeout=1)

    assert not worker.is_alive()
    assert socket_closed.is_set()
    assert outcome and isinstance(outcome[0], PinnedRequestCancelled)


def test_http_is_denied_for_remote_hosts_even_if_dns_is_public(monkeypatch):
    monkeypatch.setattr(
        "security.pinned_http.socket.getaddrinfo",
        lambda host, port, **kwargs: [_dns_record(host, "8.8.8.8", port)],
    )

    with pytest.raises(PinnedRequestError, match="clear-text HTTP"):
        pinned_http_request("http://public.example/data", max_response_bytes=64)


def test_loopback_http_works_for_local_provider_but_redirect_is_not_followed():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            self.wfile.write(b"local-model")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/ok"
        response = pinned_http_request(url, max_response_bytes=64, allow_loopback=True)
        assert response.status == 200
        assert response.body == b"local-model"

        with pytest.raises(PinnedRequestError, match="redirects are not allowed"):
            pinned_http_request(
                f"http://127.0.0.1:{server.server_port}/redirect",
                max_response_bytes=64,
                allow_loopback=True,
            )
        redirect = pinned_http_request(
            f"http://127.0.0.1:{server.server_port}/redirect",
            max_response_bytes=64,
            allow_loopback=True,
            allow_redirect_response=True,
        )
        assert redirect.status == 302
        assert redirect.headers["location"] == "http://169.254.169.254/latest/meta-data/"
        assert redirect.body == b"local-model"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_slow_drip_response_obeys_total_wall_clock_deadline():
    class SlowHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(20):
                try:
                    self.wfile.write(b"1\r\nx\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
                time.sleep(0.05)
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(socket.timeout, match="total wall-clock deadline"):
            pinned_http_request(
                f"http://127.0.0.1:{server.server_port}/slow",
                timeout=0.25,
                max_response_bytes=64,
                allow_loopback=True,
            )
        assert time.monotonic() - started < 0.8
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_owner_cancellation_aborts_partial_http_request_before_body_send(monkeypatch):
    from security import pinned_http

    cancellation = threading.Event()
    header_send_started = threading.Event()
    socket_closed = threading.Event()
    body_send_attempted = threading.Event()
    sent_chunks = []

    class FakeSocket:
        def sendall(self, data):
            if socket_closed.is_set():
                raise OSError("socket is already closed")
            sent_chunks.append(data)
            if data == b"request-headers":
                header_send_started.set()
                assert cancellation.wait(timeout=2)
            if data == b"request-body":
                body_send_attempted.set()

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    class SendingConnection:
        def __init__(self, *_args, **_kwargs):
            self.sock = None

        def connect(self):
            self.sock = FakeSocket()

        def send(self, data):
            self.sock.sendall(data)

        def request(self, *_args, **_kwargs):
            self.send(b"request-headers")
            self.send(b"request-body")

        def close(self):
            if self.sock is not None:
                self.sock.close()

    monkeypatch.setattr(pinned_http, "resolve_public_addresses", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(pinned_http, "_PinnedHTTPSConnection", SendingConnection)
    outcome = []

    def send_request():
        try:
            pinned_http.pinned_http_request(
                "https://public.example/mcp",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=b"{}",
                timeout=2,
                send_guard=lambda: None,
                cancellation_event=cancellation,
            )
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=send_request)
    worker.start()
    assert header_send_started.wait(timeout=1)
    cancellation.set()
    worker.join(timeout=1)

    assert not worker.is_alive()
    assert outcome and isinstance(outcome[0], PinnedRequestCancelled)
    assert socket_closed.is_set()
    assert sent_chunks == [b"request-headers"]
    assert not body_send_attempted.is_set()


def test_deadline_expiring_inside_dispatch_callback_still_performs_first_write(monkeypatch):
    from security import pinned_http

    sent_chunks = []
    socket_closed = threading.Event()
    callback_calls = []

    class FakeSocket:
        def sendall(self, data):
            if socket_closed.is_set():
                raise OSError("socket closed before first write")
            sent_chunks.append(data)

        def shutdown(self, *_args):
            socket_closed.set()

        def close(self):
            socket_closed.set()

    class SendingConnection:
        def __init__(self, *_args, **_kwargs):
            self.sock = None

        def connect(self):
            self.sock = FakeSocket()

        def send(self, data):
            self.sock.sendall(data)

        def request(self, *_args, **_kwargs):
            self.send(b"request-headers")

        def getresponse(self):
            raise AssertionError("expired deadline must stop before response read")

        def close(self):
            if self.sock is not None:
                self.sock.close()

    def slow_dispatch_commit():
        callback_calls.append("committed")
        time.sleep(0.04)

    monkeypatch.setattr(pinned_http, "resolve_public_addresses", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(pinned_http, "_PinnedHTTPSConnection", SendingConnection)

    with pytest.raises(socket.timeout, match="total wall-clock deadline"):
        pinned_http.pinned_http_request(
            "https://public.example/mcp",
            method="POST",
            body=b"{}",
            timeout=0.01,
            send_guard=slow_dispatch_commit,
        )

    assert callback_calls == ["committed"]
    assert sent_chunks == [b"request-headers"]
    assert socket_closed.is_set()
