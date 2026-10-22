"""Portable control generation guards, not native isolation proof."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def variants():
    path = ROOT / "scripts/windows_lpac_experiments.py"
    tree = ast.parse(path.read_text())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    def assigns(node, name):
        return isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
    start = next(i for i, node in enumerate(main.body) if assigns(node, "stop"))
    end = next(i for i, node in enumerate(main.body) if assigns(node, "vswhere"))
    source = (ROOT / "tests/native/appcontainer_acl_probe.c").read_text()
    namespace = {"source": source}
    exec(compile(ast.Module(body=main.body[start:end], type_ignores=[]), str(path), "exec"), namespace)
    return namespace["variants"]


def test_all_controls_preserve_lpac_capability_boundary_and_stop_before_resume():
    controls = variants()
    assert set(controls) == {"baseline_suspended", "null_application_name", "cwd_control_directory", "system32_image", "no_create_no_window", "sorted_same_environment"}
    for text in controls.values():
        assert "caps.Capabilities = NULL; caps.CapabilityCount = 0" in text
        assert "PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT" in text
        assert "CREATE_SUSPENDED" in text
        assert text.index("suspended_control:") < text.index("if (ResumeThread")
        assert "status = 0; goto done;" in text
        assert "CreateAppContainerProfile(" not in text


def test_control_deltas_are_independent():
    controls = variants()
    baseline = controls["baseline_suspended"]
    assert controls["null_application_name"] == baseline.replace("if (!CreateProcessW(argv[0], command,", "if (!CreateProcessW(NULL, command,")
    assert controls["no_create_no_window"] == baseline.replace(" | CREATE_NO_WINDOW", "")
    assert "env_block, control_dir," in controls["cwd_control_directory"]
    assert 'L"C:\\\\Windows\\\\System32\\\\whoami.exe"' in controls["system32_image"]
    env = controls["sorted_same_environment"].split("wchar_t item[MAX_PATH * 2];", 1)[1].split("env_block[env_used]", 1)[0]
    assert env.index("APPEND_ENV(path_env)") < env.index("SystemRoot") < env.index("TEMP") < env.index("TMP") < env.index("windir")
