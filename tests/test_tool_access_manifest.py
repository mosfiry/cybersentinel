from __future__ import annotations

import ast
from email.message import Message
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
import urllib.error

import pytest

from core import intel
from core.config import CISA_KEV_URL, RSS_FEEDS
import tools.registry as registry


EXPECTED_TOOL_ACCESS = {
    "status": ("_status", "none", "application_db_read_and_policy_file_read", "none", "none"),
    "latest_intel": ("_latest_intel", "none", "application_db_read", "none", "none"),
    "refresh_intel": ("_refresh_intel", "fixed_cisa_https_get", "application_db_read_write", "none", "none"),
    "local_security_check": ("_local_security", "none", "procfs_read_and_application_db_write", "none", "none"),
    "local_system_info": ("_system_info", "none", "runtime_metadata_and_application_db_write", "none", "none"),
    "search": ("_search", "fixed_public_search_apis", "application_db_read", "none", "optional_github_token"),
    "watch": ("_watch", "none", "application_db_read_write", "none", "none"),
    "unwatch": ("_unwatch", "none", "application_db_read_write", "none", "none"),
    "run_project_tests": ("_run_project_tests", "none", "secret_filtered_read_only_snapshot", "bubblewrap+prlimit", "none"),
    "red_team_assess": ("_red_team_assess", "none", "none", "none", "none"),
    "scoped_http_probe": ("_scoped_http_probe", "none", "none", "none", "none"),
}


def _literal_assignments(path: str | Path, *, class_name: str | None = None) -> dict[str, object]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    statements = tree.body
    if class_name is not None:
        node = next(item for item in statements if isinstance(item, ast.ClassDef) and item.name == class_name)
        statements = node.body
    values = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            try:
                value = ast.literal_eval(statement.value)
            except (TypeError, ValueError):
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    return values


def test_builtin_access_declarations_are_explicit_and_match_handlers():
    assert set(registry.REGISTRY) == set(EXPECTED_TOOL_ACCESS)
    for name, expected in EXPECTED_TOOL_ACCESS.items():
        spec = registry.REGISTRY[name]
        actual = (
            spec.handler.__name__,
            spec.network_access,
            spec.filesystem_access,
            spec.process_access,
            spec.credential_access,
        )
        assert actual == expected
        assert all(isinstance(value, str) and value != "unspecified" for value in actual[1:])

    assert registry.REGISTRY["scoped_http_probe"].available is False


def test_search_metadata_matches_fixed_public_provider_endpoints_and_optional_token():
    source_root = Path(__file__).resolve().parents[1]
    github = _literal_assignments(source_root / "search/github_provider.py", class_name="GitHubProvider")
    nvd = _literal_assignments(source_root / "core/config.py")
    mitre = _literal_assignments(source_root / "search/mitre_provider.py", class_name="MITREProvider")
    provider_urls = (
        github["GITHUB_API_URL"],
        nvd["NVD_CVE_API"],
        mitre["MITRE_API_URL"],
        mitre["MITRE_STIX_API_URL"],
    )
    assert {urlsplit(url).scheme for url in provider_urls} == {"https"}
    assert {urlsplit(url).hostname for url in provider_urls} == {
        "api.github.com",
        "services.nvd.nist.gov",
        "attack.mitre.org",
        "raw.githubusercontent.com",
    }
    assert github["GITHUB_TOKEN_ENV"] == "GITHUB_TOKEN"
    assert registry.REGISTRY["search"].credential_access == "optional_github_token"


def test_registry_rejects_missing_or_unknown_access_metadata():
    unspecified = registry.ToolSpec("missing", "test", "read", True, None, lambda _: None)
    with pytest.raises(ValueError, match="access metadata"):
        registry.build_registry([unspecified])

    valid = {
        "network_access": "none",
        "filesystem_access": "none",
        "process_access": "none",
        "credential_access": "none",
    }
    for field in valid:
        invalid = dict(valid)
        invalid[field] = "unrecognized"
        spec = registry.ToolSpec("invalid", "test", "read", True, None, lambda _: None, **invalid)
        with pytest.raises(ValueError, match="access metadata"):
            registry.build_registry([spec])


class _FakeResponse:
    def __init__(self, body=b"", headers=None):
        self.body = body
        self.headers = headers or {}
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        self.read_limit = size
        return self.body[:size]


class _FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, _request, *, timeout):
        self.timeout = timeout
        return self.response


class _RedirectingOpener:
    def __init__(self, handler, target):
        self.handler = handler
        self.target = target

    def open(self, request, *, timeout):
        return self.handler.redirect_request(
            request, BytesIO(), 302, "Found", Message(), self.target
        )


def test_get_rejects_oversized_content_length_before_read(monkeypatch):
    monkeypatch.setattr(intel, "MAX_CISA_RESPONSE_BYTES", 4)
    response = _FakeResponse(headers={"Content-Length": "5"})
    monkeypatch.setattr(
        intel.urllib.request,
        "build_opener",
        lambda *_handlers: _FakeOpener(response),
    )

    with pytest.raises(ValueError, match="exceeds byte limit"):
        intel._get(CISA_KEV_URL)
    assert response.read_limit is None


def test_get_rejects_oversized_streamed_body_without_content_length(monkeypatch):
    monkeypatch.setattr(intel, "MAX_CISA_RESPONSE_BYTES", 4)
    response = _FakeResponse(body=b"12345")
    monkeypatch.setattr(
        intel.urllib.request,
        "build_opener",
        lambda *_handlers: _FakeOpener(response),
    )

    with pytest.raises(ValueError, match="exceeds byte limit"):
        intel._get(RSS_FEEDS["CISA Advisories"])
    assert response.read_limit == 5


def test_get_rejects_cross_origin_redirect_without_network(monkeypatch):
    def fake_build_opener(handler):
        return _RedirectingOpener(handler, "https://example.invalid/redirect")

    monkeypatch.setattr(intel.urllib.request, "build_opener", fake_build_opener)

    with pytest.raises(urllib.error.HTTPError, match="CISA redirect rejected by policy"):
        intel._get(CISA_KEV_URL)


def test_cisa_refresh_preserves_redirect_provider_errors(monkeypatch):
    def fake_build_opener(handler):
        return _RedirectingOpener(handler, "https://example.invalid/redirect")

    monkeypatch.setattr(intel.urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(intel, "add_event", lambda *_args, **_kwargs: None)

    result = intel.refresh_all()

    assert result["ok"] is False
    assert result["results"] == []
    assert [item["source"] for item in result["errors"]] == [
        "collect_cisa_kev",
        "collect_cisa_advisories",
    ]
    assert all("CISA redirect rejected by policy" in item["error"] for item in result["errors"])


def test_cisa_get_accepts_only_the_two_fixed_feed_urls():
    assert intel.CISA_FEED_URLS == {CISA_KEV_URL, RSS_FEEDS["CISA Advisories"]}
    with pytest.raises(ValueError, match="unsupported CISA feed URL"):
        intel._get("https://example.invalid/feed")
