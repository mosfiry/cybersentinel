"""Owner Master Directive security invariants.

Deterministic invariants from the Owner directive that are provable without a
live model provider. Capabilities that can only be proven with a real provider
(real 20+ model-turn missions, live process crash/restart) are deliberately
NOT claimed by this module.

Mapping to the directive invariants:
- I1  model output / boolean flag cannot grant authorization
- I5  memory/knowledge cannot grant permission (authorization ignores provenance)
- I8  tool success cannot expand scope (scope-bound tool requires typed context)
- I15 sensitive tools always require a typed AuthorizationContext, never a bare flag
"""

import pytest

from search.ssrf import check_url_ssrf, is_private_ip, validate_url
from security.authorization import authorize_plan, authorize_tool
from security.plan_integrity import plan_hash
from tools.registry import KNOWN_TOOLS, get_tool


def _item(name, argument="probe"):
    spec = get_tool(name)
    assert spec is not None, f"registry is missing tool {name}"
    return name if spec.argument_type is None else [name, argument]


def test_i1_boolean_owner_flag_is_never_authority():
    for name in sorted(KNOWN_TOOLS):
        result = authorize_tool(_item(name), owner_authenticated=True)
        assert result.allowed is False, name
        assert result.reason == "typed Owner authentication evidence required"


def test_i1_false_flag_is_denied():
    for name in sorted(KNOWN_TOOLS):
        result = authorize_tool(_item(name), owner_authenticated=False)
        assert result.allowed is False, name


class _StaleEvidence:
    def is_valid(self, request_id):
        return False


def test_stale_owner_evidence_is_rejected():
    result = authorize_tool(_item("search"), owner_evidence=_StaleEvidence(), request_id="req-1")
    assert result.allowed is False
    assert result.reason == "invalid or stale Owner authentication evidence"


def test_unknown_tool_is_rejected():
    result = authorize_tool("definitely_not_a_tool")
    assert result.allowed is False
    assert result.reason == "unknown tool"


def test_i15_sensitive_tool_requires_typed_context():
    result = authorize_tool(_item("red_team_assess"))
    assert result.allowed is False
    assert result.reason == "sensitive tool requires AuthorizationContext"


def test_i8_scope_bound_tool_requires_scope_snapshot_context():
    result = authorize_tool(_item("scoped_http_probe"))
    assert result.allowed is False
    assert result.reason == "scope-bound tool requires AuthorizationContext with ScopeSnapshot"


def test_argument_length_limit_is_enforced():
    result = authorize_tool(["search", "x" * 300])
    assert result.allowed is False
    assert result.reason == "tool argument exceeds maximum length"


def test_plan_size_limit_is_enforced():
    plan = [["watch", f"k{index}"] for index in range(9)]
    result = authorize_plan(plan)
    accepted, errors = result
    assert not accepted
    assert any("maximum tool count" in error for error in errors)


def test_plan_integrity_hash_detects_mutation():
    original = plan_hash(["status"])
    mutated = plan_hash(["search"])
    assert original != mutated
    assert plan_hash(["status"]) == original


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/admin",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://172.16.1.1/",
        "http://192.168.1.1/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[fd12:3456::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:10.0.0.1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://corporate.internal/",
        "http://example.com:8080/",
        "ftp://example.com/",
    ],
)
def test_ssrf_battery_blocks_private_and_unsupported(url):
    valid, reason = validate_url(url)
    assert valid is False, url


def test_ssrf_private_ipv6_ula_is_blocked():
    assert is_private_ip("fc00::1") is True
    assert is_private_ip("fd12:3456::1") is True


def test_ssrf_unresolvable_host_fails_closed():
    assert check_url_ssrf("https://owner-directive-unresolvable.invalid/") is False
