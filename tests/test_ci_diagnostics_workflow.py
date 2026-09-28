from pathlib import Path


def test_main_ci_publishes_diagnostics_as_artifact_not_repository_commits():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")

    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "git commit" not in workflow
    assert "git push" not in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "if: always()" in workflow
    assert "diagnostics/" not in workflow


def test_branch_diagnostics_workflow_excludes_main_and_ignores_its_own_exports():
    workflow = Path(".github/workflows/pytest-diagnostics.yml").read_text(encoding="utf-8")
    assert "branches-ignore: [main]" in workflow
    assert "'diagnostics/**'" in workflow
