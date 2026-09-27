"""F8 CI guard: legacy Owner-token terminology must not re-enter active docs.

Canonical Owner authentication model (live runtime):
  BRIDGE_TOKEN  -> transport/channel authentication (X-CyberSentinel-Token)
  Owner session -> Owner identity (username/password login at POST
                   /api/auth/login, carried in X-CyberSentinel-Owner-Session)

There is no static OWNER_TOKEN environment variable and no
X-CyberSentinel-Owner-Token header in the live runtime. Active documentation
must describe the canonical model. Historical records (audit reports,
migration checkpoints, PoC results) are exempt: they document past states
and must not be rewritten.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ACTIVE_DOCS = [
    "README.md",
    "docs/OPERATIONS.md",
    "docs/SECURITY_MODEL.md",
    "docs/TESTING.md",
    "docs/OWNER_POLICY.md",
    "docs/AGENT_ARCHITECTURE.md",
    "docs/PUBLIC_WEB_ARCHITECTURE.md",
    ".env.example",
    ".env.agent.example",
]
LEGACY_TERMS = ("OWNER_TOKEN", "X-CyberSentinel-Owner-Token")


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_active_docs_have_no_legacy_owner_token_terminology():
    violations = []
    for path in ACTIVE_DOCS:
        content = _read(path)
        for term in LEGACY_TERMS:
            if term in content:
                violations.append((path, term))
    assert not violations, f"legacy terminology in active docs: {violations}"


def test_active_docs_describe_canonical_owner_session_model():
    security = _read("docs/SECURITY_MODEL.md")
    assert "X-CyberSentinel-Owner-Session" in security
    assert "/api/auth/login" in security
    operations = _read("docs/OPERATIONS.md")
    assert "owner_password_bootstrap" in operations
    architecture = _read("docs/AGENT_ARCHITECTURE.md")
    assert "X-CyberSentinel-Owner-Session" in architecture
    readme = _read("README.md")
    assert "owner_password_bootstrap" in readme


def test_env_examples_do_not_define_owner_token():
    for path in (".env.example", ".env.agent.example"):
        content = _read(path)
        assert "OWNER_TOKEN=" not in content, path
        assert "owner_password_bootstrap" in content, path
