"""The independent Windows gate proves refusal/lifecycle, not sandbox acceptance."""
from __future__ import annotations

import ast
import re
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/windows-sandbox-contract.yml"


def test_windows_sandbox_gate_requires_exact_native_tests_without_soft_failure():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "permissions:\n  contents: read\n" in source
    assert "branches: [fix/blocker-d-review-20261010]" in source
    assert "runs-on: windows-latest" in source
    assert "timeout-minutes: 15" in source
    assert "continue-on-error" not in source
    assert "ref: ${{ github.sha }}" in source
    assert "persist-credentials: false" in source
    nodes = re.findall(r"tests/\w+\.py::(\w+)", source)
    assert len(nodes) == len(set(nodes)) == 6
    assert all(name.startswith("test_native_") for name in nodes)
    assert "test_native_windows_governed_refusal_is_durable" in nodes
    guard = source.split("      - name: Reject missing", 1)[1].split("      - name: Upload", 1)[0]
    assert "if: always()" in guard
    python_source = guard.split("@'\n", 1)[1].rsplit("'@ | python -", 1)[0]
    import textwrap

    python_source = textwrap.dedent(python_source)
    module = ast.parse(python_source)
    expected = next(node.value for node in module.body if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "expected" for target in node.targets
    ))
    assert ast.literal_eval(expected) == set(nodes)
    assert '"skipped"' in python_source
    assert 'len(cases) == len(expected)' in python_source
    assert 'set(names) == expected' in python_source
    assert '"mission_acceptance": "BLOCKED" if blocked else "NOT_VALIDATED"' in python_source
    assert 'raise SystemExit("native_contract_coverage_failed")' in python_source
    upload = source.split("      - name: Upload", 1)[1]
    assert "if: always()" in upload
    assert "${{ github.sha }}" in upload
    assert "if-no-files-found: error" in upload
