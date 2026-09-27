"""Validate that CI checks the COMMIT RANGE, not the working tree.

The workflow must fetch full history and run `git diff --check` between the
push before-SHA (or the PR merge-base) and the current commit SHA. A
working-tree diff after checkout proves nothing about the pushed commit.
"""
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "tests.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_checkout_fetches_full_history():
    assert "fetch-depth: 0" in _text()


def test_whitespace_check_uses_commit_range():
    text = _text()
    assert "github.event.before" in text
    assert 'git diff --check "$BASE" "$GITHUB_SHA"' in text


def test_pr_range_uses_merge_base():
    assert "merge-base" in _text()


def test_no_working_tree_only_diff_check():
    assert "git diff --check >" not in _text()
