from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from security.pinned_http import (
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
        def close(self):
            pass

    def fake_create_connection(address, timeout, source_address):
        observed["address"] = address
        observed["timeout"] = timeout
        return FakeSocket()

    monkeypatch.setattr("security.pinned_http.socket.create_connection", fake_create_connection)
    connection = _PinnedHTTPConnection("api.example", 80, "93.184.216.34", timeout=4)
    connection.connect()
    connection.close()

    assert observed == {"address": ("93.184.216.34", 80), "timeout": 4.0}


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
