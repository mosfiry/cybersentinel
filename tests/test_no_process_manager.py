"""F6 regression: ProcessManager/ProcessHandle are REMOVED dead code.

ProcessManager.start() spawned raw Popen processes calling only
policy.authorize() — it bypassed the mission authorization boundary
(workspace._authorize), produced no audit event and no evidence. Dead code
with a latent authorization bypass must not reappear; process execution
belongs exclusively to Workspace.run_process / run_shell, which are
authorization-bound and audited.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_no_process_manager_in_environment_module():
    import workspace.environment as env
    assert not hasattr(env, "ProcessManager")
    assert not hasattr(env, "ProcessHandle")


def test_workspace_package_exports_no_process_manager():
    import workspace
    assert not hasattr(workspace, "ProcessManager")
    assert not hasattr(workspace, "ProcessHandle")
    assert "ProcessManager" not in getattr(workspace, "__all__", ())
    assert "ProcessHandle" not in getattr(workspace, "__all__", ())


def test_no_raw_popen_outside_audited_path():
    source = (ROOT / "workspace" / "environment.py").read_text(encoding="utf-8")
    assert "Popen" not in source
    assert 'self._authorize("process"' in source
    assert 'self._record("process"' in source
