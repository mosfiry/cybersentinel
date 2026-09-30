"""Active docs terminology guard (X-G, Mission 1).

Pins the operator-facing docs to the canonical Owner authentication model:
username+password login -> server-side session (X-CyberSentinel-Owner-Session),
BRIDGE_TOKEN transport-only, scrypt verifier-only password storage.

Fails if any active doc regresses to the legacy OWNER_TOKEN-era wording or
drops the canonical markers. Historical/dated records are intentionally not
scanned (they document the past state by design).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ACTIVE_DOCS = (
    "README.md",
    "docs/OPERATIONS.md",
    "docs/SECURITY_MODEL.md",
    "docs/TESTING.md",
    "docs/OWNER_POLICY.md",
    "docs/AGENT_ARCHITECTURE.md",
    "docs/PUBLIC_WEB_ARCHITECTURE.md",
    "docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md",
)

FORBIDDEN_TERMS = (
    "OWNER_TOKEN",
    "owner_token",
    "verify_owner",
    "owner_challenge",
    "X-CyberSentinel-Owner-Token",
    "OwnerSession",
)

REQUIRED_TERMS = {
    "README.md": ("owner_password_bootstrap", "BRIDGE_TOKEN"),
    "docs/OPERATIONS.md": ("api/auth/login", "X-CyberSentinel-Owner-Session", "owner_password_bootstrap"),
    "docs/SECURITY_MODEL.md": ("api/auth/login", "X-CyberSentinel-Owner-Session"),
    "docs/TESTING.md": ("owner_password_bootstrap", "OWNER_SESSION_TOKEN"),
    "docs/OWNER_POLICY.md": ("api/auth/login", "scrypt"),
    "docs/AGENT_ARCHITECTURE.md": ("api/auth/login", "X-CyberSentinel-Owner-Session"),
    "docs/PUBLIC_WEB_ARCHITECTURE.md": ("username+password", "server-side sessions"),
    "docs/GITHUB_ONLY_DEPLOYMENT_ANALYSIS.md": ("OWNER_SESSION_TOKEN",),
}


def _read(path: str) -> str:
    file = REPO_ROOT / path
    assert file.exists(), f"missing active doc: {path}"
    return file.read_text(encoding="utf-8")


def test_active_docs_contain_no_legacy_owner_credential_terms() -> None:
    violations: list[str] = []
    for path in ACTIVE_DOCS:
        text = _read(path)
        for term in FORBIDDEN_TERMS:
            if term in text:
                violations.append(f"{path}: contains legacy term {term!r}")
    assert not violations, (
        "legacy Owner authentication terms in active docs: " + "; ".join(violations)
    )


def test_active_docs_describe_canonical_owner_authentication() -> None:
    missing: list[str] = []
    for path, terms in REQUIRED_TERMS.items():
        text = _read(path)
        for term in terms:
            if term not in text:
                missing.append(f"{path}: missing canonical term {term!r}")
    assert not missing, (
        "active docs no longer describe the canonical model: " + "; ".join(missing)
    )
