"""The LPAC primitive gate is exact-SHA native evidence, not Mission acceptance."""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_appcontainer_gate_requires_exact_native_tests_and_no_soft_failures():
    workflow = (ROOT / ".github/workflows/windows-sandbox-contract.yml").read_text(encoding="utf-8")
    source = workflow.split("  native-appcontainer-workspace:\n", 1)[1]
    assert "github.repository == 'mosfiry/cybersentinel'" in source
    assert "github.ref == 'refs/heads/fix/blocker-d-review-20261010'" in source
    assert "runs-on: windows-latest" in source
    assert "ref: ${{ github.sha }}" in source
    assert "persist-credentials: false" in source
    assert "continue-on-error" not in source
    assert "tests/test_windows_appcontainer_workspace_native.py" in source
    guard = source.split("      - name: Reject missing", 1)[1].split("      - name: Upload", 1)[0]
    python_source = textwrap.dedent(guard.split("@'\n", 1)[1].rsplit("'@ | python -", 1)[0])
    module = ast.parse(python_source)
    expected = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "expected" for target in node.targets))
    test_source = (ROOT / "tests/test_windows_appcontainer_workspace_native.py").read_text(encoding="utf-8")
    test_names = set(re.findall(r"^def (test_native_lpac_\w+)\(", test_source, re.MULTILINE))
    assert len(expected) == 4
    assert expected == test_names
    assert '"skipped"' in python_source
    assert "len(native_cases) == len(expected)" in python_source
    assert "set(names) == expected" in python_source
    assert '"source_commit": os.environ["GITHUB_SHA"]' in python_source
    assert '"mission_acceptance": "BLOCKED"' in python_source
    assert '"backend_enabled_by_slice": False' in python_source
    assert 'raise SystemExit("native_appcontainer_workspace_coverage_failed")' in python_source
    upload = source.split("      - name: Upload", 1)[1]
    assert "if: always()" in upload
    assert "if-no-files-found: error" in upload
    assert "${{ github.sha }}" in upload
