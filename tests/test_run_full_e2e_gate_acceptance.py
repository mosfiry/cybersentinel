import pytest

from scripts.run_full_e2e_gate_acceptance import _scoped_acceptance_mcp_endpoint_canonicalizer
import tools.mcp_client as mcp_client
from tools.mcp_client import canonical_mcp_endpoint


def test_acceptance_mcp_override_is_limited_to_exact_loopback_fixture() -> None:
    endpoint_path = "/mcp/" + "a" * 40
    endpoint = f"https://127.0.0.1:53127{endpoint_path}"
    canonicalize = _scoped_acceptance_mcp_endpoint_canonicalizer(
        canonical_mcp_endpoint,
        expected_endpoint=endpoint,
        fixture_port=53127,
        endpoint_path=endpoint_path,
    )

    with pytest.raises(ValueError, match="invalid_mcp_endpoint"):
        canonical_mcp_endpoint(endpoint)
    assert canonicalize(endpoint) == endpoint

    rejected = (
        f"https://127.0.0.1:53127{endpoint_path}/other",
        f"https://127.0.0.2:53127{endpoint_path}",
        f"https://example.invalid:53127{endpoint_path}",
        f"http://127.0.0.1:53127{endpoint_path}",
        f"https://127.0.0.1:53127{endpoint_path}?query=1",
        f"https://127.0.0.1:53127{endpoint_path}#fragment",
    )
    for candidate in rejected:
        with pytest.raises(ValueError, match="invalid_mcp_endpoint"):
            canonicalize(candidate)


def test_acceptance_mcp_override_delegates_standard_https_endpoints() -> None:
    endpoint_path = "/mcp/" + "b" * 40
    endpoint = f"https://127.0.0.1:53127{endpoint_path}"
    canonicalize = _scoped_acceptance_mcp_endpoint_canonicalizer(
        canonical_mcp_endpoint,
        expected_endpoint=endpoint,
        fixture_port=53127,
        endpoint_path=endpoint_path,
    )

    assert canonicalize("https://127.0.0.1:443/mcp/other") == "https://127.0.0.1/mcp/other"


def test_mcp_registry_accepts_only_the_scoped_acceptance_endpoint(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_path = "/mcp/" + "c" * 40
    endpoint = f"https://127.0.0.1:53127{endpoint_path}"
    monkeypatch.setattr(
        mcp_client,
        "canonical_mcp_endpoint",
        _scoped_acceptance_mcp_endpoint_canonicalizer(
            canonical_mcp_endpoint,
            expected_endpoint=endpoint,
            fixture_port=53127,
            endpoint_path=endpoint_path,
        ),
    )
    registry = mcp_client.MCPServerStore(tmp_path / "mcp_registry.sqlite3")
    owner_identity_ref = "owner:1"
    mission_id = "mission-acceptance-1"

    registered = registry.register_server(
        owner_identity_ref=owner_identity_ref,
        mission_id=mission_id,
        endpoint=endpoint,
    )
    duplicate = registry.register_server(
        owner_identity_ref=owner_identity_ref,
        mission_id=mission_id,
        endpoint=endpoint,
    )

    assert registered["endpoint"] == endpoint
    assert duplicate["server_id"] == registered["server_id"]
    with pytest.raises(ValueError, match="invalid_mcp_endpoint"):
        registry.register_server(
            owner_identity_ref=owner_identity_ref,
            mission_id=mission_id,
            endpoint=f"https://example.invalid:53127{endpoint_path}",
        )
