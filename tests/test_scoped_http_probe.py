"""Real bounded scoped_http_probe handler battery.

The probe is a REAL observation behind the full authorization chain. These
tests exercise the handler's own deterministic bounds directly at its single
network seam (_probe_fetch): no test performs a real network call.

Adversarial/boundary coverage:
- success observation (status, headers subset, body size + sha, elapsed)
- redirects are OBSERVED, never followed (Location recorded, one fetch only)
- huge responses are truncated at the hard cap
- network failure / timeout classify fail-closed (ok False, no exception)
- non-http(s) arguments are rejected before any fetch
- non-string arguments are rejected before any fetch
"""

from __future__ import annotations

import pytest

import tools.registry
from tools.registry import SCOPED_PROBE_MAX_BYTES, _probe_http_observation, _scoped_http_probe


class _FakeHeaders:
    def __init__(self, data):
        self._data = {str(k).lower(): v for k, v in dict(data).items()}

    def get(self, key, default=None):
        return self._data.get(str(key).lower(), default)


class _FakeResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = _FakeHeaders(headers)
        self._body = body
        self.read_calls = 0

    def read(self, n=-1):
        self.read_calls += 1
        return self._body[:n] if n >= 0 else self._body


@pytest.fixture
def fetch_log(monkeypatch):
    log: list = []

    def fake_fetch(request, timeout):
        log.append({"url": request.full_url, "timeout": timeout, "method": request.get_method()})
        return _FAKE[0]

    monkeypatch.setattr(tools.registry, "_probe_fetch", fake_fetch)
    return log


_FAKE: list = [_FakeResponse(200, {"Server": "nginx", "Content-Type": "text/html"}, b"<html>ok</html>")]


def test_success_observation_is_structured(fetch_log):
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is True
    assert result["operation"] == "scoped_http_probe"
    assert result["url"] == "https://target.example/api"
    assert result["status_code"] == 200
    assert result["headers"]["server"] == "nginx"
    assert result["headers"]["content-type"] == "text/html"
    assert result["body_size"] == len(b"<html>ok</html>")
    assert result["truncated"] is False
    assert result["redirect_location"] == ""
    assert isinstance(result["elapsed_ms"], int)
    assert len(fetch_log) == 1
    assert fetch_log[0]["method"] == "GET"
    assert fetch_log[0]["timeout"] == 10


def test_body_is_hashed_never_returned(fetch_log):
    import hashlib

    body = b"x" * 1000
    _FAKE[0] = _FakeResponse(200, {}, body)
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is True
    assert result["body_sha256"] == hashlib.sha256(body).hexdigest()
    # The body itself is never part of the normalized observation.
    assert "body" not in result


def test_redirect_is_observed_never_followed(fetch_log):
    _FAKE[0] = _FakeResponse(302, {"Location": "https://other.example/next"}, b"")
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is True
    assert result["status_code"] == 302
    # The redirect target is OBSERVED data, not an authorized target.
    assert result["redirect_location"] == "https://other.example/next"
    # Exactly ONE fetch: the probe never follows the redirect.
    assert len(fetch_log) == 1


def test_huge_response_is_truncated_at_hard_cap(fetch_log):
    _FAKE[0] = _FakeResponse(200, {}, b"y" * (SCOPED_PROBE_MAX_BYTES + 10))
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is True
    assert result["truncated"] is True
    assert result["body_size"] == SCOPED_PROBE_MAX_BYTES


def test_network_failure_fails_closed(monkeypatch):
    from urllib.error import URLError

    def failing_fetch(request, timeout):
        raise URLError("name resolution failed")

    monkeypatch.setattr(tools.registry, "_probe_fetch", failing_fetch)
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is False
    assert result["error"] == "PROBE_FAILED"
    assert "name resolution failed" in result["reason"]


def test_timeout_fails_closed(monkeypatch):
    def timing_out(request, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tools.registry, "_probe_fetch", timing_out)
    result = _scoped_http_probe("https://target.example/api")
    assert result["ok"] is False
    assert result["error"] == "PROBE_FAILED"


def test_non_http_argument_is_rejected_before_fetch(fetch_log):
    for bad in ("ftp://target.example/file", "file:///etc/passwd", "", "javascript:alert(1)"):
        result = _scoped_http_probe(bad)
        assert result["ok"] is False
        assert result["error"] == "PROBE_ARGUMENT_INVALID"
    assert fetch_log == []


def test_non_string_argument_is_rejected_before_fetch(fetch_log):
    for bad in (None, 123, {"url": "https://target.example/"}, ["https://target.example/"]):
        result = _scoped_http_probe(bad)
        assert result["ok"] is False
        assert result["error"] == "PROBE_ARGUMENT_INVALID"
    assert fetch_log == []


def test_observation_output_carries_no_authority_keys(fetch_log):
    _FAKE[0] = _FakeResponse(200, {"Server": "nginx"}, b"data")
    result = _scoped_http_probe("https://target.example/api")
    # The observation is UNTRUSTED DATA: it can never carry authority fields.
    for key in ("authorization", "allowed_actions", "allowed_tools", "scope", "policy", "proof"):
        assert key not in result
