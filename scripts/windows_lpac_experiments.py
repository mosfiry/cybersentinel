"""Trusted native launch controls. No successful control child is ever resumed."""
from __future__ import annotations
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid


def main():
    if sys.platform != "win32":
        raise SystemExit("native Windows required")
    repo = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo))
    spec = importlib.util.spec_from_file_location("native_helpers", repo / "tests/test_windows_appcontainer_workspace_native.py")
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    from workspace.windows_appcontainer_workspace import WindowsAppContainerWorkspace
    output = repo / "lpac-experiments"
    output.mkdir(exist_ok=False)
    source = (repo / "tests/native/appcontainer_acl_probe.c").read_text(encoding="utf-8")
    # Common instrumentation only: after real token verification, kill without
    # ResumeThread. This cannot turn a control into product isolation proof.
    stop = '''    if (argc == 8) {
    fwprintf(stderr, L"suspended_control: token_verified=true; child_never_resumed=true\\n");
    TerminateProcess(process.hProcess, 0);
    WaitForSingleObject(process.hProcess, 5000);
    status = 0; goto done;
    }
'''
    anchor = '    if (ResumeThread(process.hThread) == (DWORD)-1)'
    assert source.count(anchor) == 1
    common = source.replace(anchor, stop + anchor)
    variants = {"baseline_suspended": common}
    variants["null_application_name"] = common.replace('if (!CreateProcessW(argv[0], command,', 'if (!CreateProcessW(NULL, command,')
    variants["cwd_control_directory"] = common.replace('env_block, argv[4], &startup.StartupInfo, &process)', 'env_block, control_dir, &startup.StartupInfo, &process)').replace('    if (argc != 8) return 21;\n    if (!ConvertStringSidToSidW(argv[2], &sid)) return fail(L"parse launcher SID", GetLastError());', '    wchar_t control_dir[32768];\n    wchar_t *last_slash;\n    if (argc != 8) return 21;\n    wcscpy_s(control_dir, _countof(control_dir), argv[0]);\n    last_slash = wcsrchr(control_dir, L\'\\\\\');\n    if (!last_slash) return 21;\n    *last_slash = L\'\\0\';\n    if (!ConvertStringSidToSidW(argv[2], &sid)) return fail(L"parse launcher SID", GetLastError());')
    variants["system32_image"] = common.replace('if (!CreateProcessW(argv[0], command,', 'if (!CreateProcessW(L"C:\\\\Windows\\\\System32\\\\whoami.exe", command,')
    variants["no_create_no_window"] = common.replace(' | CREATE_NO_WINDOW', '')
    # Sort only the same five keys; values and double-NUL termination unchanged.
    lines = common.splitlines(keepends=True)
    first = next(i for i, line in enumerate(lines) if 'L"SystemRoot=%ls", windows_dir); APPEND_ENV(item);' in line)
    block = lines[first:first+5]
    assert 'windir' in block[1] and 'APPEND_ENV(path_env)' in block[2] and 'TEMP' in block[3] and 'TMP' in block[4]
    lines[first:first+5] = [block[2], block[0], block[3], block[4], block[1]]
    variants["sorted_same_environment"] = ''.join(lines)
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    located = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], capture_output=True, text=True, timeout=30, check=True)
    devcmd = Path(located.stdout.strip().splitlines()[-1]) / "Common7/Tools/VsDevCmd.bat"
    root = Path(os.environ["SystemRoot"]).anchor
    test_root = Path(root) / ("cs-native-lpac-" + uuid.uuid4().hex)
    test_root.mkdir()
    workspace = None
    results = []
    try:
        helpers._create_protected_test_root(test_root)
        workspace = WindowsAppContainerWorkspace.create(test_root)
        control = test_root / "native-control"
        for name, text in variants.items():
            build = output / name
            build.mkdir()
            c = build / "probe.c"
            c.write_text(text, encoding="utf-8")
            (build / "source.diff").write_text(''.join(difflib.unified_diff(source.splitlines(True), text.splitlines(True), fromfile="baseline.c", tofile=name+".c")), encoding="utf-8")
            exe = build / "appcontainer_acl_probe.exe"
            command = (f'call "{devcmd}" -no_logo -arch=amd64 -host_arch=amd64 && '
                       f'cl /nologo /W4 /WX /MT /DUNICODE /D_UNICODE /TC "{c}" '
                       f'/Fo:"{build / "probe.obj"}" /Fe:"{exe}" /link advapi32.lib')
            compiled = helpers._run_compile_command(command, build)
            (build / "compile.log").write_text(compiled.stdout, encoding="utf-8")
            if compiled.returncode:
                raise RuntimeError("control_compile_failed:" + name)
            if not control.exists():
                probe = helpers._prepare_root_and_probe(test_root, workspace, exe)
            else:
                probe = control / "appcontainer_acl_probe.exe"
                shutil.copy2(exe, probe)
            proc = subprocess.run([str(probe), "--launch", workspace.sid_string, "rw", str(workspace.workspace_path), "ignored", "ignored", str(workspace.workspace_path / "never-written.json")], stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=40, check=False)
            row = {"name": name, "exit_code": proc.returncode, "stderr": proc.stderr,
                   "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                   "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
                   "same_sid_workspace_image_path": True, "child_resumed": False}
            results.append(row)
            print(json.dumps(row), flush=True)
    finally:
        if workspace is not None:
            workspace.close()
        shutil.rmtree(test_root)
        (output / "results.json").write_text(json.dumps({"source_commit": os.environ.get("GITHUB_SHA"), "baseline_source_sha256": hashlib.sha256(source.encode()).hexdigest(), "controls": results}, indent=2) + "\n", encoding="utf-8")
    if len(results) != len(variants):
        raise SystemExit("incomplete_controls")


if __name__ == "__main__":
    main()
