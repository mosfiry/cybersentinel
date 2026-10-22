"""Trace orchestration guards; not native Windows isolation evidence."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location("lpac_trace", ROOT / "scripts/windows_lpac_trace.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_trace_setup_failure_preserves_test_failure_and_records_measured_limit(tmp_path, monkeypatch):
    module = load()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module, "bounded", lambda *a, **kw: {"error": "PermissionError"})
    seen = []
    def run(command, **kwargs):
        seen.append((command, kwargs))
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(module.subprocess, "run", run)
    assert module.main(["python", "-m", "pytest", "unchanged.py"]) == 1
    import json
    report = json.loads((tmp_path / "lpac-forensics/capability.json").read_text())
    assert report["test_exit_code"] == 1
    assert report["capture_setup_error"] == "existing_procmon_or_unmeasured_process_state"
    assert seen[0][0] == ["python", "-m", "pytest", "unchanged.py"]
    assert seen[0][1]["timeout"] == 180


def test_trace_does_not_change_security_or_gate_and_verifies_vendor():
    source = (ROOT / "scripts/windows_lpac_trace.py").read_text()
    assert '"/Runtime", "60"' in source
    assert '"/Terminate"' in source
    assert 'verified.get("status") != "Valid"' in source
    assert '"Microsoft Corporation"' in source
    assert "SetNamedSecurityInfo" not in source
    assert "CreateAppContainerProfile" not in source
    workflow = (ROOT / ".github/workflows/windows-sandbox-contract.yml").read_text()
    assert "python scripts/windows_lpac_trace.py --" in workflow
    assert "lpac-forensics/launch.pml" in workflow
