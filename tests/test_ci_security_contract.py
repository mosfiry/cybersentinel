from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    Path(".github/workflows/tests.yml"),
    Path(".github/workflows/owner-charter-audit.yml"),
)
LEGACY_CI_WORKFLOWS = (
    Path(".github/workflows/pytest-diagnostics.yml"),
    Path(".github/workflows/docs-export.yml"),
)


def test_ci_workflows_do_not_export_source_or_push_from_test_jobs():
    for relative_path in WORKFLOWS:
        source = (ROOT / relative_path).read_text(encoding="utf-8").lower()
        assert "contents: write" not in source, relative_path
        assert "git push" not in source, relative_path
        assert "base64" not in source, relative_path
        assert "persist-credentials: false" in source, relative_path


def test_redundant_diagnostics_and_source_export_workflows_are_removed():
    for relative_path in LEGACY_CI_WORKFLOWS:
        assert not (ROOT / relative_path).exists(), relative_path


def test_primary_secret_scan_includes_archived_diagnostics():
    source = (ROOT / WORKFLOWS[0]).read_text(encoding="utf-8").lower()
    assert ":!diagnostics" not in source
